@echo off
setlocal
cd /d "%~dp0"
start "" mshta.exe "%~dp0NetTruder.hta"
exit /b 0
