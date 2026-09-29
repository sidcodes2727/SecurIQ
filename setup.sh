#!/bin/bash
# SecurIQ setup (Linux / macOS / WSL). Windows PowerShell: .\setup.ps1
# Installs the `securiq` terminal command. The React web UI is optional (needs Node.js 18+).
set -e
cd "$(dirname "$0")"

echo "[1/4] Python environment + the securiq command"
command -v python3 >/dev/null || { echo "Python 3.9+ is required"; exit 1; }
python3 -m venv backend/venv
backend/venv/bin/python -m pip install --quiet --upgrade pip
backend/venv/bin/python -m pip install --quiet -r backend/requirements.txt
backend/venv/bin/python -m pip install --quiet -e .

echo "[2/4] Tests"
(cd backend && ./venv/bin/python -m pytest -q)

echo "[3/4] First-run data (testbed captures + classifier, ~30 s)"
backend/venv/bin/securiq init

echo "[4/4] Optional web UI"
if command -v npm >/dev/null; then
  (cd frontend && npm install --silent)
  WEB="  web:       backend/venv/bin/python -m uvicorn backend.main:app --port 8000   and   cd frontend && npm run dev"
else
  WEB="  web:       skipped (Node.js not found); the terminal package is complete without it"
fi

echo
echo "Done. Start the console:"
echo "  backend/venv/bin/securiq          (or activate the venv:  source backend/venv/bin/activate && securiq)"
echo "$WEB"
