# Bait Blocker v1.0
## 🐟 Real-time phishing and social engineering defense powered by intelligent threat analysis.

### Key Features:
- **Local and external URL analysis** - Scans and blocks malicious URLs instantly
- **Social engineering detection and prevention** - Identifies psychological manipulation patterns and deceptive tactics
- **Easy everyday use** - Simple and effective Streamlit UI 
- **Sandbox screenshot of suspicious links** - For better understanding of the program's findings

### 📸 Screenshot of Test
<img width="1911" height="773" alt="image" src="https://github.com/user-attachments/assets/e9812a42-192d-4e4e-b355-d1326642a986" />
<img width="1450" height="471" alt="image" src="https://github.com/user-attachments/assets/52c6aa06-bd34-498e-9ad3-982dc8c876a5" />
<img width="1410" height="827" alt="image" src="https://github.com/user-attachments/assets/5cdfe99a-86da-47e3-bbdb-48acc78575e9" />
<img width="1042" height="530" alt="image" src="https://github.com/user-attachments/assets/6ab2dcda-fdf3-4d23-8785-20eeac33d83e" />
<img width="1451" height="863" alt="image" src="https://github.com/user-attachments/assets/f66f26d8-c9f1-4b68-ab5a-cb952bc23e3b" />

### 💻 Installation
**Prerequisites**
- Python 3.8+
- Redis (for caching and rate limiting)

**From Source**

```bash
git clone https://github.com/Yehoshua18/baitblocker.git
cd baitblocker
pip install -r requirements.txt
```

**Environment Setup**
```bash
python -bin venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```
### ⚙️ Configuration
Create a .env file in the root directory of the project to configure your external application keys:

```Code snippet
# Server Configuration
HOST=127.0.0.1
PORT=8000

# Threat Intelligence API Keys
VIRUSTOTAL_API_KEY=your_virustotal_key_here
GOOGLE_SAFE_BROWSING_KEY=your_google_safe_browsing_key_here

# LLM Configuration
LLM_API_KEY=your_llm_provider_key_here
```

### 🏃 How to Run
The full program can be run in the main or each file separately

**Run FastAPI**
```bash
uvicorn backendAPI:app --reload
```
**Run UI**
```bash
streamlit run streamlit_ui.py
```

### 🏗️ Architecture
<img width="945" height="518" alt="image" src="https://github.com/user-attachments/assets/edb07325-6f63-4a5d-967b-0384ce8ab381" />

All analysis layers run asynchronously via **FastAPI** to optimize runtime processing. If a cache hit occurs in Layer 1, the engine short-circuits the remaining pipeline to serve immediate results for the URL while email analysis still occurs.
A full report and explanation can be found in the Report.html file.

### 💻 Tech Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | Python / FastAPI | Async request handling & input validation |
| **Frontend UI** | Streamlit | Minimalist, interactive user dashboard |
| **Database/Cache** | SQLite3 / FastAPI Cache | Persistent keyword storage & temporary TTL cache |
| **Automation Sandbox**| Playwright | Headless browser rendering for visual auditing |


### 🗺️ Roadmap / Future Plans
- **Incorporating ML:** By incorporating ML, the false positive rate can be lowered while also cutting down on AI usage for email analysis.
- **Payload Extraction:** Enhance the Playwright sandbox layer to intercept and log forced background malware downloads automatically

### 🖋️ Author
**Built by Yehoshua Grunespecht**
B.Sc. Computer Science
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
