@echo off
chcp 65001 >nul
setlocal
set "TSA_CA_CERT=tsa_ca.crt"

fltmc >nul 2>&1 || (
    echo ❌ 需要管理员权限运行！
    pause
    exit /b 1
)

if not exist "%TSA_CA_CERT%" (
    echo ❌ 找不到 %TSA_CA_CERT%
    pause
    exit /b
)

echo 正在安装 tsa_ca.crt 到本地计算机【受信任根证书】
certutil -addstore -f "Root" "%TSA_CA_CERT%"
if errorlevel 1 (
    echo 安装失败
) else (
    echo ✅ 证书安装成功
)
pause
