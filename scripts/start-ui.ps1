# Start Streamlit UI (BaitBlocker Dashboard)
# This script sets PYTHONPATH and launches streamlit

param(
    [int]$Port = 8501,
    [string]$BindAddr = "127.0.0.1"
)

# Get the repo root (parent of scripts folder)
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# Set PYTHONPATH to include src/ so Python can import baitblocker package
$env:PYTHONPATH = Join-Path $RepoRoot "src"

Write-Host "Starting Streamlit UI..." -ForegroundColor Green
Write-Host "PYTHONPATH: $env:PYTHONPATH" -ForegroundColor Cyan
Write-Host ""
Write-Host "Once ready, open your browser to:" -ForegroundColor Cyan
Write-Host "  Local:     http://localhost:$Port" -ForegroundColor Cyan
Write-Host "  Network:   http://$(hostname):$Port" -ForegroundColor Cyan
Write-Host ""
Write-Host "Ensure FastAPI backend is running on http://127.0.0.1:8000" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
Write-Host ""

# Start streamlit pointing to the UI file under src/baitblocker/ui/
$UiPath = Join-Path $RepoRoot "src" | Join-Path -ChildPath "baitblocker" | Join-Path -ChildPath "ui" | Join-Path -ChildPath "streamlit_ui.py"
streamlit run "$UiPath" `
    --server.port $Port `
    --logger.level=info



