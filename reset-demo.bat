@echo off
REM Windows wrapper: reset-demo.bat vulnerable ^| fixed ^| agent-secret-only ^| agent-image-only
if "%~1"=="" (
  echo Usage: reset-demo.bat ^<vulnerable^|fixed^|agent-secret-only^|agent-image-only^>
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\reset-demo.ps1" -State %1
