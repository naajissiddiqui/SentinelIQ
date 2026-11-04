@echo off
cd /d "%~dp0"
echo [SentinelIQ] Seeding 7-Day Demo Detection Records...
call npm.cmd --workspace=apps/backend run seed:detections
