@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py acl_cli.py %*
) else (
    python acl_cli.py %*
)
