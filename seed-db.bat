@echo off
cd /d "%~dp0"
echo [SentinelIQ] Seeding Database Demo Data...
call npm.cmd --workspace=apps/backend run seed
