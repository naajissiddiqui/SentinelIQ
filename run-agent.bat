@echo off
cd /d "%~dp0agent"
echo [SentinelIQ] Starting Endpoint Agent...
call ".\.venv\Scripts\python.exe" main.py %*
