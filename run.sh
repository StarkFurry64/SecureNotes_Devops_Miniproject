#!/usr/bin/env bash
# SecureNotes local launcher for macOS / Linux.
set -euo pipefail
cd "$(dirname "$0")"
[[ -d .venv ]] || python3 -m venv .venv
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
[[ -f .env ]] || cp .env.example .env
echo "SecureNotes on http://127.0.0.1:${FLASK_PORT:-5000}"
python app.py
