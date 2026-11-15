import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import webauthn
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

# ============================================================================
# 配置区 (支持通过环境变量覆盖，适配本地无域名测试与阿里云/隧道部署)
# ============================================================================
DEFAULT_RP_ID = os.getenv("PASSKEY_RP_ID", "myjustfun.fun")
DEFAULT_RP_NAME = os.getenv("PASSKEY_RP_NAME", "SecTrade 证券终端 Passkey")
APPLE_APP_ID = os.getenv("APPLE_APP_ID", "TEAMID1234.com.sectrade.passkeydemo")
DB_PATH = Path(__file__).parent / "passkeys.db"

app = FastAPI(
    title="SecTrade Passkey Relying Party Server",
    description="跨平台 (Windows / macOS / iOS) C++ Qt Passkey 认证服务端 (FastAPI + py_webauthn)",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 内存暂存 Challenge (challenge_key -> {"challenge": bytes, "rp_id": str, "username": str, "expires_at": float})
PENDING_CHALLENGES: Dict[str, dict] = {}


# ============================================================================
# SQLite 数据库初始化与操作
# ============================================================================
def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                user_handle BLOB NOT NULL,
                display_name TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                credential_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                public_key BLOB NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                rp_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_used_at INTEGER,
                FOREIGN KEY (username) REFERENCES users (username) ON DELETE CASCADE
            )
            """
        )
        conn.commit()


init_db()


def resolve_rp_id(override_rp_id: Optional[str] = None) -> str:
    if override_rp_id and override_rp_id.strip():
        return override_rp_id.strip()
    return DEFAULT_RP_ID


def build_expected_origins(rp_id: str) -> List[str]:
    origins = [
        f"https://{rp_id}",
        f"http://{rp_id}",
        f"https://{rp_id}:8000",
        f"http://{rp_id}:8000",
    ]
    return list(dict.fromkeys(origins))


# ============================================================================
# 请求模型定义
# ============================================================================
class RegisterOptionsRequest(BaseModel):
    username: str
    display_name: Optional[str] = None
    rp_id: Optional[str] = None


class RegisterVerifyRequest(BaseModel):
    username: str
    rp_id: Optional[str] = None
    credential: dict


class LoginOptionsRequest(BaseModel):
    username: Optional[str] = ""
    rp_id: Optional[str] = None


class LoginVerifyRequest(BaseModel):
    username: Optional[str] = ""
    rp_id: Optional[str] = None
    credential: dict


# ============================================================================
# 1. 健康检查与 Apple Associated Domains (AASA) 托管接口
# ============================================================================
@app.get("/health")
def health_check():
    with sqlite3.connect(DB_PATH) as conn:
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        cred_count = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    return {
        "status": "ok",
        "default_rp_id": DEFAULT_RP_ID,
        "rp_name": DEFAULT_RP_NAME,
        "apple_app_id": APPLE_APP_ID,
        "registered_users": user_count,
        "registered_credentials": cred_count,
    }


@app.get("/.well-known/apple-app-site-association")
def apple_app_site_association():
    """
    macOS 与 iOS 调用原生 AuthenticationServices Passkey API 时，
    苹果系统后台守护进程 swcagent 会请求此接口验证 App 的 Associated Domains 签名。
    """
    aasa_payload = {
        "webcredentials": {
            "apps": [APPLE_APP_ID]
        }
    }
    return JSONResponse(content=aasa_payload, media_type="application/json")


# ============================================================================
# 2. Passkey 注册接口 (MakeCredential)
# ============================================================================
@app.post("/api/passkey/register/options")
def register_options(req: RegisterOptionsRequest):
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="用户名不能为空")

    display_name = (req.display_name or username).strip()
    rp_id = resolve_rp_id(req.rp_id)

    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT user_handle FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row:
            user_handle = bytes(row[0])
        else:
            user_handle = secrets.token_bytes(32)
            conn.execute(
                "INSERT INTO users (username, user_handle, display_name, created_at) VALUES (?, ?, ?, ?)",
                (username, user_handle, display_name, int(time.time())),
            )
            conn.commit()

        existing_rows = conn.execute(
            "SELECT credential_id FROM credentials WHERE username = ? AND rp_id = ?",
            (username, rp_id),
        ).fetchall()

    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(r[0]))
        for r in existing_rows
    ]

    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=DEFAULT_RP_NAME,
        user_id=user_handle,
        user_name=username,
        user_display_name=display_name,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    PENDING_CHALLENGES[f"reg:{username}"] = {
        "challenge": options.challenge,
        "rp_id": rp_id,
        "username": username,
        "expires_at": time.time() + 300,
    }

    return json.loads(options_to_json(options))


@app.post("/api/passkey/register/verify")
def register_verify(req: RegisterVerifyRequest):
    username = req.username.strip()
    pending = PENDING_CHALLENGES.get(f"reg:{username}")
    if not pending or pending["expires_at"] < time.time():
        raise HTTPException(status_code=400, detail="注册 Challenge 已过期或不存在，请重新发起注册")

    rp_id = resolve_rp_id(req.rp_id or pending["rp_id"])
    expected_origins = build_expected_origins(rp_id)

    try:
        verification = verify_registration_response(
            credential=req.credential,
            expected_challenge=pending["challenge"],
            expected_rp_id=rp_id,
            expected_origin=expected_origins,
            require_user_verification=False,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Passkey 注册验签失败: {exc}") from exc

    PENDING_CHALLENGES.pop(f"reg:{username}", None)
    cred_id_b64 = bytes_to_base64url(verification.credential_id)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO credentials
            (credential_id, username, public_key, sign_count, rp_id, created_at, last_used_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cred_id_b64,
                username,
                verification.credential_public_key,
                verification.sign_count,
                rp_id,
                int(time.time()),
                int(time.time()),
            ),
        )
        conn.commit()

    return {
        "verified": True,
        "username": username,
        "rp_id": rp_id,
        "credential_id": cred_id_b64,
        "sign_count": verification.sign_count,
        "message": f"用户 [{username}] Passkey 硬件凭证注册成功！",
    }


# ============================================================================
# 3. Passkey 登录接口 (GetAssertion)
# ============================================================================
@app.post("/api/passkey/login/options")
def login_options(req: LoginOptionsRequest):
    username = (req.username or "").strip()
    rp_id = resolve_rp_id(req.rp_id)

    allow_credentials: List[PublicKeyCredentialDescriptor] = []
    if username:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT credential_id FROM credentials WHERE username = ? AND rp_id = ?",
                (username, rp_id),
            ).fetchall()
        if not rows:
            raise HTTPException(
                status_code=404,
                detail=f"未找到用户 [{username}] 在 RP_ID [{rp_id}] 下注册的 Passkey，请先注册",
            )
        allow_credentials = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(r[0])) for r in rows
        ]

    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    challenge_key = f"auth:{username or 'discoverable'}"
    PENDING_CHALLENGES[challenge_key] = {
        "challenge": options.challenge,
        "rp_id": rp_id,
        "username": username,
        "expires_at": time.time() + 300,
    }

    payload = json.loads(options_to_json(options))
    payload["challenge_key"] = challenge_key
    return payload


@app.post("/api/passkey/login/verify")
def login_verify(req: LoginVerifyRequest):
    username = (req.username or "").strip()
    challenge_key = f"auth:{username or 'discoverable'}"
    pending = PENDING_CHALLENGES.get(challenge_key) or PENDING_CHALLENGES.get("auth:discoverable")

    if not pending or pending["expires_at"] < time.time():
        raise HTTPException(status_code=400, detail="登录 Challenge 已过期或不存在，请重新发起登录")

    rp_id = resolve_rp_id(req.rp_id or pending["rp_id"])
    expected_origins = build_expected_origins(rp_id)

    cred_id = req.credential.get("id") or req.credential.get("rawId")
    if not cred_id:
        raise HTTPException(status_code=400, detail="请求缺少 credential id")

    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT username, public_key, sign_count FROM credentials WHERE credential_id = ?",
            (cred_id,),
        ).fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail=f"服务端未找到该 Passkey 凭证 ({cred_id[:16]}...)，可能尚未在服务端注册",
        )

    db_username, public_key_bytes, current_sign_count = row[0], bytes(row[1]), int(row[2])

    try:
        verification = verify_authentication_response(
            credential=req.credential,
            expected_challenge=pending["challenge"],
            expected_rp_id=rp_id,
            expected_origin=expected_origins,
            credential_public_key=public_key_bytes,
            credential_current_sign_count=current_sign_count,
            require_user_verification=False,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Passkey 登录签名验证失败: {exc}") from exc

    PENDING_CHALLENGES.pop(challenge_key, None)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE credentials SET sign_count = ?, last_used_at = ? WHERE credential_id = ?",
            (verification.new_sign_count, int(time.time()), cred_id),
        )
        conn.commit()

    # 签发模拟证券行情/交易会话 Token
    session_token = f"sectrade_jwt_{secrets.token_urlsafe(24)}"
    return {
        "verified": True,
        "username": db_username,
        "rp_id": rp_id,
        "credential_id": cred_id,
        "new_sign_count": verification.new_sign_count,
        "token": session_token,
        "message": f"欢迎回来，{db_username}！Passkey 硬件签名验证通过。",
    }


# ============================================================================
# 4. 辅助管理接口 (查询已注册凭证列表 / 删除测试用户)
# ============================================================================
@app.get("/api/passkey/users")
def list_registered_users():
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT c.credential_id, c.username, u.display_name, c.rp_id, c.sign_count, c.created_at, c.last_used_at
            FROM credentials c
            JOIN users u ON u.username = c.username
            ORDER BY c.created_at DESC
            """
        ).fetchall()

    items = [
        {
            "credential_id": r[0],
            "username": r[1],
            "display_name": r[2],
            "rp_id": r[3],
            "sign_count": r[4],
            "created_at": r[5],
            "last_used_at": r[6],
        }
        for r in rows
    ]
    return {"count": len(items), "credentials": items}


@app.delete("/api/passkey/users/{username}")
def delete_user(username: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM credentials WHERE username = ?", (username,))
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
    return {"deleted": True, "username": username}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
