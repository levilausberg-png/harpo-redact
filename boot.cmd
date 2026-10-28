@echo off
rem Start Harpo. Bypasses the PowerShell execution policy for this run only, so it works on
rem Windows PowerShell 5.1 and PowerShell 7 alike. Double-click it, or run it from a terminal with options:
rem   boot.cmd -Provider anthropic -SlmModel phi3:latest
setlocal
set "PS=powershell"
where pwsh >nul 2>nul && set "PS=pwsh"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0boot.ps1" %*
set "CODE=%ERRORLEVEL%"
rem Keep the window open when started by double-click, so the summary can be read.
echo %CMDCMDLINE% | find /i "%~nx0" >nul && pause
exit /b %CODE%
