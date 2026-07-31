@echo off
echo 注意：win11及以上系统需要禁用PrintScreen截图才能正常打开使用“锁屏广告定位”
echo.
echo 请选择操作，默认使用1、禁用PrintScreen截图。
echo.&choice /C 12 /T 10 /D 1 /M "1、禁用PrintScreen截图 2、启用PrintScreen截图"
if errorlevel 2 goto :enable1
if errorlevel 1 goto :enable0
:enable0
reg add "HKCU\Control Panel\Keyboard" /v  PrintScreenKeyForSnippingEnabled /t reg_dword /d 0 /f
echo 已禁用PrintScreen截图...
pause&exit
:enable1
reg add "HKCU\Control Panel\Keyboard" /v  PrintScreenKeyForSnippingEnabled /t reg_dword /d 1 /f
echo 已启用PrintScreen截图...
pause&exit