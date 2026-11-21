@echo off
setlocal
title NetTruder LOLBAS Research Lab
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-NetTruderPosture.ps1" %*
echo.
pause
