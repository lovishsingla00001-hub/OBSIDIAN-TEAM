@echo off
title SiteCheck Local Server
cd /d "%~dp0"
echo Starting SiteCheck on localhost...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-server.ps1"
pause
