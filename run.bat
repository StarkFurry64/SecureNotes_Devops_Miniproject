@echo off
REM SecureNotes local launcher for Windows: finds Python, creates/activates a venv,
REM installs dependencies and opens the browser.
setlocal
cd /d "%~dp0"

set PY=
where py >nul 2>nul && set PY=py -3
if not defined PY (where python >nul 2>nul && set PY=python)
if not defined PY (
  echo Python 3 was not found. Install it from https://www.python.org/downloads/
  exit /b 1
)

if not exist .venv (
  echo Creating virtual environment...
  %PY% -m venv .venv || exit /b 1
)
call .venv\Scripts\activate.bat

echo Installing dependencies...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt || exit /b 1

if not exist .env if exist .env.example copy .env.example .env >nul
if not defined FLASK_PORT set FLASK_PORT=5000

start "" http://127.0.0.1:%FLASK_PORT%
python app.py
