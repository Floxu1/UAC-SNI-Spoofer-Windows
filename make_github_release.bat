@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0release.ps1"
if errorlevel 1 (
    echo.
    echo Build failed. Close any running UAC-Spoofer-Desktop.exe and run this file again.
    pause
    exit /b 1
)
echo.
echo GitHub release is ready: %~dp0github_release
pause
