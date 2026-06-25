@echo off
setlocal
fltmc >nul 2>&1
if errorlevel 1 (
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-WindowsSecurityAudit.ps1"
set "RC=%ERRORLEVEL%"
echo.
echo Windows Security Audit finished with exit code %RC%.
pause
exit /b %RC%
