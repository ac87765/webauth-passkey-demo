#include "PasskeyManager.h"

#include <QDateTime>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>
#include <QWindow>

namespace sectrade::passkey {

PasskeyManager::PasskeyManager(QObject* parent)
    : QObject(parent)
    , provider_(createPlatformPasskeyProvider()) {

    if (provider_) {
        hardwareAvailable_ = provider_->isPlatformAuthenticatorAvailable(&hardwareDetail_);
    } else {
        hardwareDetail_ = QStringLiteral("当前平台尚未提供 PasskeyProvider 实现");
    }

    appendLog(QStringLiteral("INIT"), QStringLiteral("平台驱动: %1").arg(platformName()));
    appendLog(QStringLiteral("INIT"), QStringLiteral("硬件状态: %1").arg(hardwareDetail_));

    checkServerHealth();
}

void PasskeyManager::setServerUrl(const QString& url) {
    QString cleaned = url.trimmed();
    while (cleaned.endsWith(QLatin1Char('/'))) {
        cleaned.chop(1);
    }
    if (serverUrl_ != cleaned) {
        serverUrl_ = cleaned;
        emit serverUrlChanged();
        checkServerHealth();
    }
}

void PasskeyManager::setRpId(const QString& id) {
    QString cleaned = id.trimmed();
    if (rpId_ != cleaned) {
        rpId_ = cleaned;
        emit rpIdChanged();
        appendLog(QStringLiteral("CFG"), QStringLiteral("切换 RP_ID = %1").arg(rpId_));
    }
}

QString PasskeyManager::platformName() const {
    return provider_ ? provider_->platformName() : QStringLiteral("Unknown Platform");
}

void PasskeyManager::setBusy(bool b) {
    if (busy_ != b) {
        busy_ = b;
        emit busyChanged();
    }
}

void PasskeyManager::setStatus(const QString& msg) {
    if (statusMessage_ != msg) {
        statusMessage_ = msg;
        emit statusMessageChanged();
    }
}

void PasskeyManager::appendLog(const QString& tag, const QString& message) {
    QString ts = QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz"));
    QString line = QStringLiteral("[%1] [%2] %3\n").arg(ts, tag, message);
    protocolLog_.append(line);
    emit protocolLogChanged();
}

quintptr PasskeyManager::currentWindowHandle() const {
    QWindow* win = QGuiApplication::focusWindow();
    if (!win && !QGuiApplication::topLevelWindows().isEmpty()) {
        win = QGuiApplication::topLevelWindows().first();
    }
    return win ? static_cast<quintptr>(win->winId()) : 0;
}

void PasskeyManager::checkServerHealth() {
    QUrl url(serverUrl_ + QStringLiteral("/health"));
    QNetworkRequest req(url);
    QNetworkReply* reply = net_.get(req);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            serverOnline_ = false;
            emit serverOnlineChanged();
            setStatus(QStringLiteral("无法连接服务端 (%1): %2")
                          .arg(serverUrl_, reply->errorString()));
            appendLog(QStringLiteral("NET"), QStringLiteral("服务端连接失败: %1").arg(reply->errorString()));
            return;
        }
        serverOnline_ = true;
        emit serverOnlineChanged();
        QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
        setStatus(QStringLiteral("服务端在线 (%1) | 已注册凭证数: %2")
                      .arg(serverUrl_)
                      .arg(obj.value(QStringLiteral("registered_credentials")).toInt()));
        refreshRegisteredUsers();
    });
}

void PasskeyManager::refreshRegisteredUsers() {
    QUrl url(serverUrl_ + QStringLiteral("/api/passkey/users"));
    QNetworkRequest req(url);
    QNetworkReply* reply = net_.get(req);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            return;
        }
        QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
        QJsonArray arr = obj.value(QStringLiteral("credentials")).toArray();
        QVariantList list;
        for (const auto& item : arr) {
            list.append(item.toObject().toVariantMap());
        }
        registeredCredentials_ = list;
        emit registeredCredentialsChanged();
    });
}

void PasskeyManager::registerPasskey(const QString& username, const QString& displayName) {
    QString cleanUser = username.trimmed();
    if (cleanUser.isEmpty()) {
        setStatus(QStringLiteral("请输入要注册 Passkey 的证券账号/用户名"));
        emit operationFailed(QStringLiteral("参数错误"), QStringLiteral("用户名不能为空"));
        return;
    }
    if (busy_) {
        return;
    }

    setBusy(true);
    setStatus(QStringLiteral("正在向服务端请求注册 Challenge (%1)...").arg(cleanUser));
    appendLog(QStringLiteral("REG-1"),
              QStringLiteral("POST /api/passkey/register/options (username=%1, rp_id=%2)")
                  .arg(cleanUser, rpId_));

    QJsonObject reqBody;
    reqBody[QStringLiteral("username")] = cleanUser;
    reqBody[QStringLiteral("display_name")] = displayName.trimmed().isEmpty() ? cleanUser : displayName.trimmed();
    reqBody[QStringLiteral("rp_id")] = rpId_;

    QNetworkRequest netReq(QUrl(serverUrl_ + QStringLiteral("/api/passkey/register/options")));
    netReq.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    QNetworkReply* reply = net_.post(netReq, QJsonDocument(reqBody).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply, cleanUser]() {
        reply->deleteLater();
        QByteArray rawResp = reply->readAll();

        if (reply->error() != QNetworkReply::NoError) {
            setBusy(false);
            QString errDetail = QString::fromUtf8(rawResp);
            setStatus(QStringLiteral("获取注册 Challenge 失败: %1").arg(errDetail));
            appendLog(QStringLiteral("ERROR"), QStringLiteral("注册 Options 失败: %1").arg(errDetail));
            emit operationFailed(QStringLiteral("获取注册参数失败"), errDetail);
            return;
        }

        QJsonObject optionsObj = QJsonDocument::fromJson(rawResp).object();
        QString challengeB64 = optionsObj.value(QStringLiteral("challenge")).toString();
        QJsonObject rpObj = optionsObj.value(QStringLiteral("rp")).toObject();
        QJsonObject userObj = optionsObj.value(QStringLiteral("user")).toObject();

        MakeCredentialRequest makeReq;
        makeReq.rpId = rpObj.value(QStringLiteral("id")).toString(rpId_);
        makeReq.rpName = rpObj.value(QStringLiteral("name")).toString(QStringLiteral("SecTrade"));
        makeReq.userId = fromBase64Url(userObj.value(QStringLiteral("id")).toString());
        makeReq.userName = userObj.value(QStringLiteral("name")).toString(cleanUser);
        makeReq.userDisplayName = userObj.value(QStringLiteral("displayName")).toString(cleanUser);
        makeReq.challengeBase64Url = challengeB64;
        makeReq.challenge = fromBase64Url(challengeB64);
        makeReq.timeoutMs = static_cast<quint32>(optionsObj.value(QStringLiteral("timeout")).toInt(60000));
        makeReq.nativeWindowHandle = currentWindowHandle();

        QJsonArray excludeArr = optionsObj.value(QStringLiteral("excludeCredentials")).toArray();
        for (const auto& val : excludeArr) {
            QJsonObject eo = val.toObject();
            PublicKeyCredentialDescriptorDto dto;
            dto.id = fromBase64Url(eo.value(QStringLiteral("id")).toString());
            dto.type = eo.value(QStringLiteral("type")).toString(QStringLiteral("public-key"));
            makeReq.excludeCredentials.append(dto);
        }

        appendLog(QStringLiteral("REG-2"),
                  QStringLiteral("收到 Challenge=%1... 正在唤起系统生物识别弹窗 (HWND=0x%2)")
                      .arg(challengeB64.left(20))
                      .arg(makeReq.nativeWindowHandle, 0, 16));
        setStatus(QStringLiteral("请在弹出的系统窗口中完成指纹 / 人脸 / PIN 验证..."));

        provider_->makeCredentialAsync(makeReq, [this, cleanUser](const MakeCredentialResult& credRes) {
            if (!credRes.success) {
                setBusy(false);
                setStatus(credRes.errorMessage);
                appendLog(credRes.cancelled ? QStringLiteral("CANCEL") : QStringLiteral("ERROR"),
                          credRes.errorMessage);
                if (!credRes.cancelled) {
                    emit operationFailed(QStringLiteral("系统 Passkey 注册未完成"), credRes.errorMessage);
                }
                return;
            }

            appendLog(QStringLiteral("REG-3"),
                      QStringLiteral("硬件生成密钥对成功! CredentialID=%1... Attestation=%2 bytes")
                          .arg(credRes.credentialIdBase64Url.left(24))
                          .arg(credRes.attestationObject.size()));
            setStatus(QStringLiteral("硬件签名完成，正在发送公钥至服务端验签入库..."));

            QJsonObject verifyBody;
            verifyBody[QStringLiteral("username")] = cleanUser;
            verifyBody[QStringLiteral("rp_id")] = rpId_;
            verifyBody[QStringLiteral("credential")] = credRes.toWebAuthnJson();

            QNetworkRequest verifyReq(QUrl(serverUrl_ + QStringLiteral("/api/passkey/register/verify")));
            verifyReq.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

            QNetworkReply* verifyReply = net_.post(
                verifyReq, QJsonDocument(verifyBody).toJson(QJsonDocument::Compact));

            connect(verifyReply, &QNetworkReply::finished, this, [this, verifyReply, cleanUser]() {
                verifyReply->deleteLater();
                setBusy(false);
                QByteArray verifyRaw = verifyReply->readAll();
                QJsonObject respObj = QJsonDocument::fromJson(verifyRaw).object();

                if (verifyReply->error() != QNetworkReply::NoError) {
                    QString detail = respObj.value(QStringLiteral("detail")).toString(QString::fromUtf8(verifyRaw));
                    setStatus(QStringLiteral("服务端注册验签失败: %1").arg(detail));
                    appendLog(QStringLiteral("ERROR"), QStringLiteral("服务端注册验签失败: %1").arg(detail));
                    emit operationFailed(QStringLiteral("服务端注册验签失败"), detail);
                    return;
                }

                QString credId = respObj.value(QStringLiteral("credential_id")).toString();
                QString msg = respObj.value(QStringLiteral("message")).toString();
                setStatus(msg);
                appendLog(QStringLiteral("SUCCESS"), msg);
                refreshRegisteredUsers();
                checkServerHealth();
                emit registrationSucceeded(cleanUser, credId);
            });
        });
    });
}

void PasskeyManager::loginWithPasskey(const QString& username) {
    if (busy_) {
        return;
    }

    QString cleanUser = username.trimmed();
    setBusy(true);
    setStatus(cleanUser.isEmpty()
                  ? QStringLiteral("正在请求免用户名 (Discoverable) 登录 Challenge...")
                  : QStringLiteral("正在为用户 [%1] 请求登录 Challenge...").arg(cleanUser));

    appendLog(QStringLiteral("AUTH-1"),
              QStringLiteral("POST /api/passkey/login/options (username=%1, rp_id=%2)")
                  .arg(cleanUser.isEmpty() ? QStringLiteral("<discoverable>") : cleanUser, rpId_));

    QJsonObject reqBody;
    reqBody[QStringLiteral("username")] = cleanUser;
    reqBody[QStringLiteral("rp_id")] = rpId_;

    QNetworkRequest netReq(QUrl(serverUrl_ + QStringLiteral("/api/passkey/login/options")));
    netReq.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    QNetworkReply* reply = net_.post(netReq, QJsonDocument(reqBody).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply, cleanUser]() {
        reply->deleteLater();
        QByteArray rawResp = reply->readAll();
        QJsonObject optionsObj = QJsonDocument::fromJson(rawResp).object();

        if (reply->error() != QNetworkReply::NoError) {
            setBusy(false);
            QString detail = optionsObj.value(QStringLiteral("detail")).toString(QString::fromUtf8(rawResp));
            setStatus(QStringLiteral("获取登录 Challenge 失败: %1").arg(detail));
            appendLog(QStringLiteral("ERROR"), QStringLiteral("登录 Options 失败: %1").arg(detail));
            emit operationFailed(QStringLiteral("无法发起 Passkey 登录"), detail);
            return;
        }

        QString challengeB64 = optionsObj.value(QStringLiteral("challenge")).toString();
        GetAssertionRequest assertReq;
        assertReq.rpId = optionsObj.value(QStringLiteral("rpId")).toString(rpId_);
        assertReq.challengeBase64Url = challengeB64;
        assertReq.challenge = fromBase64Url(challengeB64);
        assertReq.timeoutMs = static_cast<quint32>(optionsObj.value(QStringLiteral("timeout")).toInt(60000));
        assertReq.nativeWindowHandle = currentWindowHandle();

        QJsonArray allowArr = optionsObj.value(QStringLiteral("allowCredentials")).toArray();
        for (const auto& val : allowArr) {
            QJsonObject ao = val.toObject();
            PublicKeyCredentialDescriptorDto dto;
            dto.id = fromBase64Url(ao.value(QStringLiteral("id")).toString());
            dto.type = ao.value(QStringLiteral("type")).toString(QStringLiteral("public-key"));
            assertReq.allowCredentials.append(dto);
        }

        appendLog(QStringLiteral("AUTH-2"),
                  QStringLiteral("收到 Challenge=%1... 允许凭证数=%2，正在唤起系统生物识别验证")
                      .arg(challengeB64.left(20))
                      .arg(assertReq.allowCredentials.size()));
        setStatus(QStringLiteral("请在系统弹窗中验证指纹 / 人脸 / PIN 完成登录..."));

        provider_->getAssertionAsync(assertReq, [this, cleanUser](const GetAssertionResult& assertRes) {
            if (!assertRes.success) {
                setBusy(false);
                setStatus(assertRes.errorMessage);
                appendLog(assertRes.cancelled ? QStringLiteral("CANCEL") : QStringLiteral("ERROR"),
                          assertRes.errorMessage);
                if (!assertRes.cancelled) {
                    emit operationFailed(QStringLiteral("Passkey 登录未完成"), assertRes.errorMessage);
                }
                return;
            }

            appendLog(QStringLiteral("AUTH-3"),
                      QStringLiteral("硬件私钥签名成功! CredentialID=%1... Signature=%2 bytes")
                          .arg(assertRes.credentialIdBase64Url.left(24))
                          .arg(assertRes.signature.size()));
            setStatus(QStringLiteral("正在向服务端提交硬件断言签名进行验证..."));

            QJsonObject verifyBody;
            verifyBody[QStringLiteral("username")] = cleanUser;
            verifyBody[QStringLiteral("rp_id")] = rpId_;
            verifyBody[QStringLiteral("credential")] = assertRes.toWebAuthnJson();

            QNetworkRequest verifyReq(QUrl(serverUrl_ + QStringLiteral("/api/passkey/login/verify")));
            verifyReq.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

            QNetworkReply* verifyReply = net_.post(
                verifyReq, QJsonDocument(verifyBody).toJson(QJsonDocument::Compact));

            connect(verifyReply, &QNetworkReply::finished, this, [this, verifyReply]() {
                verifyReply->deleteLater();
                setBusy(false);
                QByteArray verifyRaw = verifyReply->readAll();
                QJsonObject respObj = QJsonDocument::fromJson(verifyRaw).object();

                if (verifyReply->error() != QNetworkReply::NoError) {
                    QString detail = respObj.value(QStringLiteral("detail")).toString(QString::fromUtf8(verifyRaw));
                    setStatus(QStringLiteral("服务端登录验签失败: %1").arg(detail));
                    appendLog(QStringLiteral("ERROR"), QStringLiteral("服务端登录验签失败: %1").arg(detail));
                    emit operationFailed(QStringLiteral("服务端登录验签失败"), detail);
                    return;
                }

                loggedInUser_ = respObj.value(QStringLiteral("username")).toString();
                sessionToken_ = respObj.value(QStringLiteral("token")).toString();
                QString msg = respObj.value(QStringLiteral("message")).toString();
                emit authStateChanged();

                setStatus(msg);
                appendLog(QStringLiteral("SUCCESS"),
                          QStringLiteral("%1 | 签发会话 Token=%2")
                              .arg(msg, sessionToken_));
                refreshRegisteredUsers();
                emit authenticationSucceeded(loggedInUser_, sessionToken_);
            });
        });
    });
}

void PasskeyManager::deleteUser(const QString& username) {
    if (username.trimmed().isEmpty()) {
        return;
    }
    QUrl url(serverUrl_ + QStringLiteral("/api/passkey/users/") + QUrl::toPercentEncoding(username.trimmed()));
    QNetworkRequest req(url);
    QNetworkReply* reply = net_.deleteResource(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, username]() {
        reply->deleteLater();
        appendLog(QStringLiteral("DEL"), QStringLiteral("已删除测试用户 [%1] 的服务端 Passkey 记录").arg(username));
        refreshRegisteredUsers();
        checkServerHealth();
    });
}

void PasskeyManager::logout() {
    loggedInUser_.clear();
    sessionToken_.clear();
    emit authStateChanged();
    setStatus(QStringLiteral("已退出登录会话"));
    appendLog(QStringLiteral("LOGOUT"), QStringLiteral("已清除本地证券终端登录 Token"));
}

void PasskeyManager::cancelOperation() {
    if (provider_) {
        provider_->cancelCurrentOperation();
    }
    setBusy(false);
    setStatus(QStringLiteral("已取消当前 Passkey 操作"));
}

void PasskeyManager::clearLogs() {
    protocolLog_.clear();
    emit protocolLogChanged();
}

} // namespace sectrade::passkey
