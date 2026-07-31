@echo off
:: ============================================================
:: Watch-CmdPopups 一键启动器 (需管理员权限)
:: ============================================================
:: 获取脚本所在目录
set "SCRIPT_DIR=%~dp0"

:: 以管理员权限重新启动自身
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c cd /d %SCRIPT_DIR% && %~nx0' -Verb RunAs"
    exit /b
)

title [CMD弹窗监听器]
color 0A
echo.
echo  ============================================================
echo   CMD 弹窗监听器  -  一键启动
echo  ============================================================
echo.
echo  [1] 开始监听 (默认 5 分钟)
echo  [2] 开始监听 (10 分钟)
echo  [3] 开始监听 (30 分钟)
echo  [4] 持续监听 (手动 Ctrl+C 停止)
echo  [Q] 退出
echo.
choice /c 1234Q /n /m "请选择 [1/2/3/4/Q]: "

set "SCRIPT_PATH=%SCRIPT_DIR%Watch-CmdPopups.ps1"

if %errorlevel%==1 (
    echo.
    echo [启动] 监听 5 分钟...
    powershell -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" -DurationSec 300
    pause
)
if %errorlevel%==2 (
    echo.
    echo [启动] 监听 10 分钟...
    powershell -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" -DurationSec 600
    pause
)
if %errorlevel%==3 (
    echo.
    echo [启动] 监听 30 分钟...
    powershell -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" -DurationSec 1800
    pause
)
if %errorlevel%==4 (
    echo.
    echo [启动] 持续监听 (按 Ctrl+C 停止)...
    powershell -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" -DurationSec 86400
    pause
)
if %errorlevel%==5 (
    exit /b
)
