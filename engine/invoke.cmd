@echo off
rem NetTruder engine launcher.
rem The HTA passes one JSON request file. Keeping the arguments in a file means
rem target lists and terminal commands never have to survive cmd quoting, and
rem the launcher command line stays short and constant.
setlocal
if "%~1"=="" exit /b 2
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0NetTruder.ps1" -RequestFile "%~1"
exit /b 0
