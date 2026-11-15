# SecTrade Passkey Demo (Qt 6 C++/QML + 原生系统 API + Python FastAPI)

面向 **PC/移动端证券分析软件 (`Qt + CEF + C++`)** 的跨平台 **Passkey (WebAuthn / FIDO2)** 完整参考实现，支持 **Windows + macOS + iOS** 原生生物识别认证与无域名测试方案。

## 目录结构

```text
webauth/
├── server/                                  # Python FastAPI + py_webauthn 认证服务端 (可跑在本地或阿里云)
│   ├── main.py                              # 注册/登录 Challenge 生成与验签 + Apple AASA 托管
│   └── requirements.txt
└── client/                                  # Qt 6 C++ & QML 跨平台客户端
    ├── CMakeLists.txt
    ├── resources.qrc
    ├── apple/
    │   └── SecTradePasskey.entitlements     # macOS / iOS Associated Domains 权限声明
    ├── qml/
    │   └── Main.qml                         # 证券终端暗黑风格 Passkey 登录与协议追踪界面
    └── src/
        ├── main.cpp
        ├── bridge/
        │   └── CefPasskeyBridge.h           # CEF (window.cefQuery) <-> Qt C++ 桥接适配器
        └── passkey/
            ├── PasskeyTypes.h               # W3C WebAuthn 标准数据模型与 Base64URL 工具
            ├── IPasskeyProvider.h           # 跨平台纯虚接口
            ├── PasskeyProvider_win.cpp      # Windows 原生实现 (<webauthn.h> / webauthn.dll)
            ├── PasskeyProvider_apple.mm     # macOS & iOS 原生实现 (AuthenticationServices.framework)
            ├── PasskeyManager.h
            └── PasskeyManager.cpp
```

## 快速开始

### 1. 启动 Passkey 服务端 (`server/`)

```bash
cd server
uv venv
uv pip install -r requirements.txt
uv run python main.py
```
默认监听 `http://0.0.0.0:8000`，默认 `RP_ID = localhost`（无需购买域名即可在 Windows 真机唤起 Windows Hello 完成全套注册与登录）。

### 2. 编译并运行 Qt 6 客户端 (`client/`)

```bash
cd client
cmake -B build -G Ninja -DCMAKE_PREFIX_PATH="C:/Qt/6.8.3/mingw_64"
cmake --build build
./build/SecTradePasskeyClient.exe
```
