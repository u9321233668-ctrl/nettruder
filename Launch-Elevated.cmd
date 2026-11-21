@echo off
setlocal
rem NetTruder - elevated launcher. IPS (firewall) actions need administrator.
net session >nul 2>&1
if %errorlevel%==0 goto run
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b 0
:run
cd /d "%~dp0"
start "" mshta.exe "%~dp0NetTruder.hta"
exit /b 0
