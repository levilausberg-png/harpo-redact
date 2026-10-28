@echo off
rem Stop Harpo (and the local model, and Ollama if boot started it).
setlocal
set "PS=powershell"
where pwsh >nul 2>nul && set "PS=pwsh"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop.ps1" %*
set "CODE=%ERRORLEVEL%"
echo %CMDCMDLINE% | find /i "%~nx0" >nul && pause
exit /b %CODE%
