@echo off
setlocal
title Spoor - keep this window open while you use the dashboard
cd /d "%~dp0"
if not exist "runtime\python\python.exe" (
  echo The bundled Python is missing: runtime\python\python.exe
  echo Copy the whole Spoor folder again.
  pause
  exit /b 1
)
"runtime\python\python.exe" -m spoor serve %*
if errorlevel 1 pause
