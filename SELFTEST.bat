@echo off
title Spoor self-test
cd /d "%~dp0"
"runtime\python\python.exe" -m spoor selftest
echo.
pause
