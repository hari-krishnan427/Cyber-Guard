# 🛡️ Cyber-Guard AI Security & Phishing Protection Assistant

**Cyber-Guard** is an advanced AI-powered web security assistant and phishing detection engine featuring Machine Learning URL analysis, real-time security scanning, automated threat explanation, and a browser protection Chrome Extension.

---

## 📁 Architecture Overview

```
Cyber-Guard/
├── backend/                        # Flask Security Scanning Engine
│   ├── app.py                      # Security API endpoints & domain blocking
│   ├── features.py                 # URL feature extraction pipeline
│   ├── security_checks.py          # SSL, WHOIS age, redirect & threat engine
│   └── phishing_model.pkl          # Trained ML Phishing Classifier
├── extension/                      # Real-time Chrome Web Protection Extension
│   ├── manifest.json               # Extension configuration (Manifest V3)
│   ├── popup.html                  # Security status popup UI
│   ├── popup.js                    # Extension logic & API client
│   └── background.js               # Background threat listener
├── static/                         # Frontend Styling & Assets
│   └── style.css                   # Cybersecurity dashboard glassmorphism CSS
├── templates/                      # Flask HTML Views
│   └── index.html                  # Interactive Threat Intelligence Dashboard
├── requirements.txt                # Backend dependencies
├── .gitignore
└── README.md
```

---

## 🛠️ Key Features

- **Machine Learning Phishing Detection**: ML model trained on URL feature sets (URL length, subdomain count, IP usage, special character ratios, brand impersonation).
- **Multi-Vector Security Engine**:
  - SSL Certificate Validation
  - WHOIS Domain Age Lookup
  - Redirect Chain Analysis
  - Fake Login Form Detection
  - Malicious Download Detection
  - Suspicious TLD & Host Verification
- **Automated AI Threat Explanations**: Generates plain-language security summaries explaining risk factors.
- **Real-Time Chrome Extension**: Scans browsing activity live and blocks threats.

---

## 🚀 Setup & Running Instructions

### 1. Backend Server Setup

Navigate to the project directory and install requirements:
```bash
pip install -r requirements.txt
```

Run the security server:
```bash
python backend/app.py
```
- Server URL: `http://localhost:5000`
- Scan Endpoint: `POST http://localhost:5000/scan`

### 2. Loading the Chrome Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer Mode** in the top right corner.
3. Click **Load unpacked** and select the `extension/` directory.
4. Cyber-Guard will now inspect and protect your active browsing sessions!
