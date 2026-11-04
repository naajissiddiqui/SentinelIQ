@echo off
cd /d "%~dp0"
echo [SentinelIQ] Starting Backend Server on http://localhost:4000...
call npm.cmd --workspace=apps/backend run dev
