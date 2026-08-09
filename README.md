# 🛡️ Cyber-Guard AI Security & Phishing Protection Engine

[![Live Web Application](https://img.shields.io/badge/Live%20App-Vercel-black?style=for-the-badge&logo=vercel)](https://cyber-guard-pi.vercel.app)
[![Python](https://img.shields.io/badge/Python-Flask-3776AB?style=for-the-badge&logo=python)](https://flask.palletsprojects.com)
[![Scikit-Learn](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn)](https://scikit-learn.org)

**Cyber-Guard** is an advanced AI-powered web security platform and phishing detection engine featuring Machine Learning URL classification, real-time threat intelligence, automated SSL/WHOIS security audits, and browser protection extensions.

🔗 **Live Web Application:** [https://cyber-guard-pi.vercel.app](https://cyber-guard-pi.vercel.app)

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
├── vercel.json                     # Vercel Serverless Deployment Config
├── requirements.txt                # Backend dependencies
├── .gitignore
└── README.md
```

---

## 🛠️ Key Capabilities

- 🤖 **Machine Learning Phishing Detection**: ML model trained on URL feature sets (URL length, subdomain count, IP usage, special character ratios, brand impersonation).
- 🔍 **Multi-Vector Security Engine**:
  - SSL Certificate Validation
  - WHOIS Domain Age Lookup
  - Redirect Chain Analysis
  - Fake Login Form Detection
  - Malicious Download Detection
  - Suspicious TLD & Host Verification
- 💡 **Automated AI Threat Explanations**: Generates plain-language security summaries explaining risk factors.
- 🧩 **Browser Protection Extension**: Includes Chrome & Firefox web protection extensions in `extension/`.

---

## 🚀 Setup & Execution

### 1. Live Cloud Server
Access the live deployment on Vercel: [https://cyber-guard-pi.vercel.app](https://cyber-guard-pi.vercel.app)

### 2. Local Setup
```bash
git clone https://github.com/hari-krishnan427/Cyber-Guard.git
cd Cyber-Guard
pip install -r requirements.txt
python backend/app.py
```
Access at `http://localhost:5000`.
