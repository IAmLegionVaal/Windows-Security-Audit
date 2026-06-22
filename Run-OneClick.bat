@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-WindowsSecurityAudit.ps1"
set "RC=%ERRORLEVEL%"
echo.
echo Windows Security Audit finished with exit code %RC%.
pause
exit /b %RC%
