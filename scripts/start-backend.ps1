# Start FastAPI backend (BaitBlocker Analysis Engine)
# This script sets PYTHONPATH and launches uvicorn with hot-reload enabled

param(
    [int]$Port = 8000,
    [string]$BindAddr = "127.0.0.1"
)

# Get the repo root (parent of scripts folder)
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# Set PYTHONPATH to include src/ so Python can import baitblocker package
$env:PYTHONPATH = Join-Path $RepoRoot "src"

Write-Host "Starting FastAPI backend..." -ForegroundColor Green
Write-Host "PYTHONPATH: $env:PYTHONPATH" -ForegroundColor Cyan
Write-Host "Listening on http://$BindAddr`:$Port" -ForegroundColor Cyan
Write-Host "API docs available at http://$BindAddr`:$Port/docs" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop the server." -ForegroundColor Yellow
Write-Host ""

# Start uvicorn with auto-reload enabled for development
python -m uvicorn baitblocker.backend_api:app `
    --host $BindAddr `
    --port $Port `
    --reload



