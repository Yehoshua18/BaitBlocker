# Bait Blocker v1.0
## 🐟 Real-time phishing and social engineering defense powered by intelligent threat analysis.

### Key Features:
- **Local and external URL analysis** - Scans and blocks malicious URLs instantly
- **Social engeneering detection and prevention** - Identifies psychological manipulation patterns and deceptive tactics
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
- Python 3.9+
- Redis (for caching and rate limiting)

**From Source**

```bash
git clone https://github.com/Yehoshua18/baitblocker.git
cd baitblocker
pip install -r requirements.txt
```

### 🏃 How to Run
**Run FastAPI**
```bash
uvicorn main:app --reload
```
**Run UI**
```bash
streamlit run streamlit_ui.py
```

### 🏗️ Arcitecture
Can be found in the Report.html file

[
Performance (benchmarks, metrics)
Deployment (enterprise focus)
Roadmap / Future Plans
Contributing
License
]

### 🖋️ Author
**Built by Yehoshua Grunespecht**
B.Sc. Computer Science
