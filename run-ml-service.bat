@echo off
cd /d "%~dp0apps\ml-service"
echo [SentinelIQ] Starting ML Microservice on http://localhost:8000...
call ".\.venv\Scripts\uvicorn.exe" app.main:app --host 0.0.0.0 --port 8000 --reload
