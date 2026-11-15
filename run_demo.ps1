$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "==> 1. 启动本地 Passkey 认证服务端 (FastAPI + py_webauthn, http://127.0.0.1:8000) ..." -ForegroundColor Cyan
$ServerProcess = Start-Process -FilePath "$RootDir\server\.venv\Scripts\python.exe" `
    -ArgumentList "main.py" `
    -WorkingDirectory "$RootDir\server" `
    -PassThru -WindowStyle Minimized

Start-Sleep -Seconds 2

Write-Host "==> 2. 启动 Qt 6 C++/QML 原生 Passkey 证券终端客户端 ..." -ForegroundColor Green
$env:PATH = "$RootDir\.qt\6.8.3\mingw_64\bin;$env:PATH"
& "$RootDir\client\build\SecTradePasskeyClient.exe"

if ($ServerProcess -and !$ServerProcess.HasExited) {
    Write-Host "==> 关闭本地 Passkey 认证服务端..." -ForegroundColor Yellow
    Stop-Process -Id $ServerProcess.Id -Force -ErrorAction SilentlyContinue
}
