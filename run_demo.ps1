$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "==> 正在检查阿里云 Passkey 认证服务端 (https://120.79.245.99/passkey-demo/health) ..." -ForegroundColor Cyan
try {
    $health = Invoke-RestMethod -Uri "https://120.79.245.99/passkey-demo/health" -TimeoutSec 5
    Write-Host "    阿里云服务端在线! RP_NAME=$($health.rp_name), 已注册凭证数=$($health.registered_credentials)" -ForegroundColor Green
} catch {
    Write-Host "    警告: 阿里云连接异常 ($($_.Exception.Message))，可在客户端界面切换为本地 http://127.0.0.1:8000" -ForegroundColor Yellow
}

Write-Host "==> 启动 Qt 6 C++/QML (MSVC 64-bit) 原生 Passkey 证券终端客户端 ..." -ForegroundColor Green
Start-Process -FilePath "$RootDir\client\build-msvc\SecTradePasskeyClient.exe" -WorkingDirectory "$RootDir\client\build-msvc"
