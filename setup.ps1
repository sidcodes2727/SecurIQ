# SecurIQ setup for Windows PowerShell. Linux/macOS/WSL: ./setup.sh
# Installs the `securiq` terminal command. The React web UI is optional (needs Node.js 18+).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "[1/4] Python environment + the securiq command"
python -m venv backend\venv
& backend\venv\Scripts\python -m pip install --quiet --upgrade pip
& backend\venv\Scripts\python -m pip install --quiet -r backend\requirements.txt
& backend\venv\Scripts\python -m pip install --quiet -e .

Write-Host "[2/4] Tests"
Push-Location backend
& .\venv\Scripts\python -m pytest -q
Pop-Location

Write-Host "[3/4] First-run data (testbed captures + classifier, ~30 s)"
& backend\venv\Scripts\securiq init

Write-Host "[4/4] Optional web UI"
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Push-Location frontend
    npm install --silent
    Pop-Location
    $web = "  web:      backend\venv\Scripts\python -m uvicorn backend.main:app --port 8000   and   cd frontend; npm run dev"
} else {
    $web = "  web:      skipped (Node.js not found); the terminal package is complete without it"
}

Write-Host ""
Write-Host "Done. Start the console:"
Write-Host "  backend\venv\Scripts\securiq        (or activate the venv:  backend\venv\Scripts\Activate.ps1; securiq)"
Write-Host $web
