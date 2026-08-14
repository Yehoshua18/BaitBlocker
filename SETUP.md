# BaitBlocker Setup & Run Guide

## Quick Start (Recommended)

### 1. Prerequisites
- Python 3.8+
- Virtual environment activated (see Installation below)
- All dependencies installed: `pip install -r requirements.txt`

### 2. Using Start Scripts

**Terminal 1 - Start the Backend (FastAPI)**
```powershell
.\scripts\start-backend.ps1
```

You should see output like:
```
Starting FastAPI backend...
PYTHONPATH: C:\...\src
Listening on http://127.0.0.1:8000
API docs available at http://127.0.0.1:8000/docs
```

**Terminal 2 - Start the Frontend (Streamlit)**
```powershell
.\scripts\start-ui.ps1
```

You should see output like:
```
Starting Streamlit UI...
Once ready, open your browser to:
  Local:     http://localhost:8501
  Network:   http://LAPTOP-XXXX:8501
```

**Browser**
- Open http://localhost:8501
- The UI will connect to the backend at http://127.0.0.1:8000
- Enter a URL or email text to analyze

### 3. Ports and Services
| Service | Port | URL |
|---------|------|-----|
| FastAPI Backend | 8000 | http://127.0.0.1:8000 |
| FastAPI Docs | 8000 | http://127.0.0.1:8000/docs |
| Streamlit UI | 8501 | http://localhost:8501 |

---

## Manual Start (Without Scripts)

If you prefer to start services manually, set `PYTHONPATH` and run commands directly.

### Backend (FastAPI)
```powershell
$env:PYTHONPATH = "$PWD\src"
python -m uvicorn baitblocker.backend_api:app --reload --host 127.0.0.1 --port 8000
```

### Frontend (Streamlit)
```powershell
$env:PYTHONPATH = "$PWD\src"
streamlit run src\baitblocker\ui\streamlit_ui.py
```

---

## Troubleshooting

### Port Already in Use
If you see "error while attempting to bind" or "port X is already in use":

**Find and kill the process:**
```powershell
# Check what's listening on port 8000 or 8501
netstat -ano | findstr ":8000"
netstat -ano | findstr ":8501"

# Kill the process (replace XXXX with PID from netstat output)
taskkill /F /PID XXXX
```

**Or use different ports in scripts:**
```powershell
# Backend on custom port
.\scripts\start-backend.ps1 -Port 9000

# UI on custom port
.\scripts\start-ui.ps1 -Port 9501
```

### PYTHONPATH Issues
If you see "No module named 'baitblocker'":
- Ensure `PYTHONPATH` includes `src/`:
```powershell
$env:PYTHONPATH = "$PWD\src"
# Then run your command
```

### Streamlit Can't Find UI File
- Verify the file exists at `src\baitblocker\ui\streamlit_ui.py`
- Run from repo root directory
- Ensure PYTHONPATH is set correctly

### Backend Not Responding
- Check if FastAPI is running: `curl http://127.0.0.1:8000/test-keys`
- Review `.env` file for required API keys (VT_API_KEY, GOOGLE_API_KEY, GROK_KEY)
- Check firewall/antivirus isn't blocking port 8000

---

## Configuration

### Environment Variables (.env)
Create a `.env` file in the repo root with your API keys:

```bash
# Threat Intelligence API Keys
VT_API_KEY=your_virustotal_api_key_here
GOOGLE_API_KEY=your_google_safe_browsing_api_key_here

# LLM Configuration (for email analysis)
GROK_KEY=your_groq_llm_api_key_here
```

**Getting API Keys:**
- **VirusTotal**: https://www.virustotal.com/gui/home/upload
- **Google Safe Browsing**: https://console.cloud.google.com/
- **Groq**: https://console.groq.com/

---

## Train / Retrain the ML Model

Use these steps any time you want to refresh the logistic regression model used for URL phishing prediction.

### Train with default paths

This reads `src/baitblocker/ml/PhishingData.csv` and writes model artifacts back into `src/baitblocker/ml/`.

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\src"
python -m baitblocker.ml.model_training train
```

Expected output artifacts:
- `src/baitblocker/ml/phishing_logreg_model.joblib`
- `src/baitblocker/ml/phishing_logreg_metrics.json`

### Quick prediction sanity check

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m baitblocker.ml.model_training predict "https://youtube.com"
python -m baitblocker.ml.model_training predict "http://192.168.1.5/login/verify"
```

### Retrain and version outputs (optional)

```powershell
$env:PYTHONPATH = "$PWD\src"
python -c "from pathlib import Path; from baitblocker.ml.model_training import train_logistic_regression; r=train_logistic_regression(model_path=Path('src/baitblocker/ml/phishing_logreg_model_v2.joblib'), metrics_path=Path('src/baitblocker/ml/phishing_logreg_metrics_v2.json')); print(r)"
```

### Verify metrics file

```powershell
Get-Content .\src\baitblocker\ml\phishing_logreg_metrics.json
```

---

## Testing the Backend

### Health Check
```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/test-keys
```

### Analyze a URL
```powershell
$Body = @{
    url = "https://example.com"
    run_sandbox = $false
} | ConvertTo-Json

Invoke-RestMethod -Uri http://127.0.0.1:8000/analyze `
    -Method Post `
    -ContentType 'application/json' `
    -Body $Body
```

### View API Documentation
- Open http://127.0.0.1:8000/docs in your browser
- Interactive Swagger UI for all endpoints

---

## Project Structure

After the package restructure, the layout is:

```
PythonProject/
├── src/
│   └── baitblocker/
│       ├── __init__.py
│       ├── backend_api.py          # FastAPI app (main entry point for backend)
│       ├── core/                   # Local analysis logic
│       │   ├── local_analysis.py
│       │   └── emailchecker.py
│       ├── db/                     # Database & keyword matching
│       │   ├── database.py
│       │   └── matcher.py
│       ├── interfaces/             # Third-party integrations
│       │   ├── phishing_dbs.py
│       │   ├── sandbox.py
│       │   └── whois_lookup.py
│       └── ui/
│           └── streamlit_ui.py     # Streamlit frontend
├── scripts/
│   ├── start-backend.ps1           # Backend launcher
│   └── start-ui.ps1                # Frontend launcher
├── main.py                         # Legacy entry point (for reference)
└── requirements.txt                # Python dependencies
```

### Legacy Modules (Deprecated)
The old top-level modules (e.g., `db/`, `interfaces/`, `local_logic/`, `ui/`) are now small wrappers that import from `src/baitblocker/` for backward compatibility. They emit a DeprecationWarning. Use the new package paths in `src/baitblocker/` instead.

---

## Next Steps

1. **Install dependencies**: `pip install -r requirements.txt`
2. **Configure API keys**: Create `.env` with your keys
3. **Start backend**: `.\scripts\start-backend.ps1`
4. **Start UI**: `.\scripts\start-ui.ps1`
5. **Open browser**: http://localhost:8501

---

## Support
For issues or questions, check the README.md or open an issue on the repository.

