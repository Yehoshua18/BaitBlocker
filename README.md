# BaitBlocker

Real-time phishing and social engineering defense powered by local analysis, external threat intelligence, and a Streamlit dashboard.

## Key Features

- **Local and external URL analysis** - Scans suspicious links using lexical, database, and third-party signals
- **Social engineering detection** - Flags urgent, deceptive, or impersonation-style content in URLs and emails
- **Interactive UI** - Streamlit dashboard for quick manual analysis
- **Sandbox screenshot capture** - Optional Playwright-based visual inspection of suspicious targets

### 📸 Screenshot of Test
<img width="1911" height="773" alt="image" src="https://github.com/user-attachments/assets/e9812a42-192d-4e4e-b355-d1326642a986" />
<img width="1450" height="471" alt="image" src="https://github.com/user-attachments/assets/52c6aa06-bd34-498e-9ad3-982dc8c876a5" />
<img width="1410" height="827" alt="image" src="https://github.com/user-attachments/assets/5cdfe99a-86da-47e3-bbdb-48acc78575e9" />
<img width="1042" height="530" alt="image" src="https://github.com/user-attachments/assets/6ab2dcda-fdf3-4d23-8785-20eeac33d83e" />
<img width="1451" height="863" alt="image" src="https://github.com/user-attachments/assets/f66f26d8-c9f1-4b68-ab5a-cb952bc23e3b" />

## Installation

### Prerequisites

- Python 3.7+
- A virtual environment is recommended

### Install from source

```powershell
git clone https://github.com/Yehoshua18/baitblocker.git
cd baitblocker
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

If you want the development/test tools as well:

```powershell
pip install -e ".[dev]"
```

### Configuration

Create a `.env` file in the project root to configure your external application keys:

```bash
# Threat Intelligence API Keys
VT_API_KEY=your_virustotal_api_key_here
GOOGLE_API_KEY=your_google_safe_browsing_api_key_here

# LLM Configuration (for email analysis)
GROK_KEY=your_groq_llm_api_key_here
```

## How to Run

The application uses a `src/` layout with the canonical package under `src/baitblocker/`.

For detailed setup, troubleshooting, and configuration instructions, see [SETUP.md](./SETUP.md).

### Using Start Scripts (Recommended)

Start the backend in one terminal:
```bash
.\scripts\start-backend.ps1
```

Start the Streamlit UI in another terminal:
```bash
.\scripts\start-ui.ps1
```

The UI opens at `http://localhost:8501` and connects to the backend at `http://127.0.0.1:8000`.

### Manual Start (Alternative)

If you prefer manual control, set `PYTHONPATH` and run directly:

*Backend (FastAPI):*
```bash
$env:PYTHONPATH = "$PWD\src"
python -m uvicorn baitblocker.backend_api:app --reload --host 127.0.0.1 --port 8000
```

*Frontend (Streamlit):*
```bash
$env:PYTHONPATH = "$PWD\src"
streamlit run src\baitblocker\ui\streamlit_ui.py
```

## Architecture
<img width="945" height="518" alt="image" src="https://github.com/user-attachments/assets/edb07325-6f63-4a5d-967b-0384ce8ab381" />

All analysis layers run asynchronously via **FastAPI** to optimize runtime processing. If a cache hit occurs in Layer 1, the engine short-circuits the remaining pipeline to serve immediate results for the URL while email analysis still occurs.
A full report and explanation can be found in the Report.html file.

## Tech Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | Python / FastAPI | Async request handling & input validation |
| **Frontend UI** | Streamlit | Minimalist, interactive user dashboard |
| **Database/Cache** | SQLite3 / FastAPI Cache | Persistent keyword storage & temporary TTL cache |
| **Automation Sandbox**| Playwright | Headless browser rendering for visual auditing |

## Testing
Details on testing and test coverage can be found in [TESTING.md](./TESTING.md).

## Roadmap / Future Plans
- **Incorporating ML:** By incorporating ML, the false positive rate can be lowered while also cutting down on AI usage for email analysis.
- **Payload Extraction:** Enhance the Playwright sandbox layer to intercept and log forced background malware downloads automatically

## Author
**Built by Yehoshua Grunespecht**
B.Sc. Computer Science
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
