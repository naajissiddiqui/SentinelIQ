@echo off
cd /d "%~dp0"
echo [SentinelIQ] Starting Next.js Frontend on http://localhost:3000...
call npm.cmd --workspace=apps/web run dev
