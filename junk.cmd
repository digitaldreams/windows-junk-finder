@powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0junk.ps1" %*
@set "rc=%errorlevel%"
@rem ponytail: scripts that run "cmd /c junk.cmd" also hit the pause; with redirected stdin pause returns at once.
@echo %cmdcmdline% | find /i "%~nx0" >nul && pause
@exit /b %rc%
