# CyberShield PhishGuard 🛡️
### AI-Powered Phishing URL Detection & Explainable Threat Analysis Engine

A full-stack cybersecurity application that inspects and classifies website URLs into **Legitimate**, **Suspicious**, or **Phishing / Malicious** using a hybrid of **Machine Learning (Random Forest)** and an **Explainable Rule Engine**.

---

## 🌟 Key Features

1. **URL Entry & Real-time Inspection**: Enter any standard or obfuscated URL to perform instant security decomposition.
2. **Comprehensive URL Characteristic Extraction (35 Features)**:
   - **Lexical & Structural Metrics**: URL length, hostname length, path length, query length, directory depths.
   - **Delimiter & Character Counts**: Counts of dots, hyphens, underscores, digits, `@`, `//`, `%`, `=`, `?`, `&`.
   - **Statistical & Entropy Profiling**: Shannon entropy of domain names (detects Domain Generation Algorithms / DGA) and character ratios.
   - **Security Indicators**: Direct IP hostnames, non-standard web ports, unencrypted HTTP vs TLS/SSL HTTPS.
   - **Deception & Evasion Detection**: Brand impersonation across foreign domains, IDN homograph / Punycode (`xn--`), known URL shorteners, and high-abuse TLDs (`.xyz`, `.top`, `.buzz`, `.club`, `.tk`, etc.).
3. **Machine Learning Classifier**:
   - Random Forest model trained on a balanced corpus of legitimate web topology and adversarial phishing archetypes.
   - Outputs calibrated probability distributions alongside feature importance weights.
4. **Hybrid Explainable AI (XAI)**:
   - Translates statistical patterns into **clear, human-readable threat explanations** and severity ratings (Critical, Warning, Informational).
   - Identifies positive trust signals (e.g., verified institutional TLDs, clean domain hierarchy, HTTPS encryption).
5. **Interactive Cybersecurity SOC Dashboard**:
   - Animated SVG circular risk gauge (0 - 100%).
   - Dynamic classification badge (`Safe`, `Suspicious`, `Dangerous`).
   - Detailed tabbed interface: Threat Breakdown, URL Anatomy, 35-Feature Inspector, and Actionable Guidance.
   - Quick-test sample preset chips.
   - Local session scan history with 1-click re-testing.
   - Batch URL Scanner (up to 50 URLs at once).
   - Model Telemetry modal displaying live ML metrics and feature weights.
6. **REST API**:
   - `/api/analyze` - Single URL scan.
   - `/api/batch-analyze` - Bulk URL scan.
   - `/api/model-info` - Live model telemetry and top feature rankings.

---

## 📂 Project Architecture

```
phishing-url-detector/
├── app.py                     # Flask web server & REST API
├── analyzer.py                # Core analyzer coordinating ML + XAI
├── feature_extractor.py       # 35-feature URL lexical & statistical extractor
├── explainability.py          # Human-readable threat explanations & risk rules
├── model_trainer.py           # ML training pipeline (Random Forest)
├── dataset.py                 # Balanced dataset generator (legitimate + phishing)
├── models/
│   ├── phishing_model.joblib  # Serialized trained model
│   ├── feature_names.json     # Feature schema
│   └── training_metrics.json  # Model accuracy and evaluation metrics
├── templates/
│   └── index.html             # Sleek dark-mode SOC dashboard
├── static/
│   ├── css/
│   │   └── style.css          # Responsive glassmorphism styling
│   └── js/
│       └── app.js             # Client interactivity, gauge animations, batch & history
├── tests/
│   └── test_analyzer.py       # Comprehensive unit and integration test suite
├── requirements.txt           # Python dependencies
└── README.md                  # Documentation
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Pip

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. (Optional) Re-train the Machine Learning Model
The model is pre-trained and saved in `models/phishing_model.joblib`. If you wish to retrain or adjust hyperparameters:
```bash
python model_trainer.py
```

### 4. Run the Flask Web Application
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

### 5. Run the Automated Test Suite
```bash
python -m unittest discover -s tests -v
```

---

## 📡 REST API Reference

### 1. Single URL Analysis
- **Endpoint**: `POST /api/analyze`
- **Headers**: `Content-Type: application/json`
- **Request Body**:
  ```json
  {
    "url": "http://192.168.1.100/paypal/login.php?cmd=verify"
  }
  ```
- **Response**:
  ```json
  {
    "status": "success",
    "input_url": "http://192.168.1.100/paypal/login.php?cmd=verify",
    "normalized_url": "http://192.168.1.100/paypal/login.php?cmd=verify",
    "assessment": {
      "risk_score": 81.6,
      "risk_level": "High",
      "verdict": "Phishing / Malicious",
      "badge_color": "danger",
      "ml_probability": 100.0,
      "heuristic_score": 59.0
    },
    "components": {
      "scheme": "http",
      "hostname": "192.168.1.100",
      "root_domain": "192.168.1.100",
      "subdomain": "(none)",
      "domain_name": "192.168.1.100",
      "tld": "",
      "path": "/paypal/login.php",
      "query": "cmd=verify",
      "port": 80
    },
    "threats": [
      {
        "severity": "critical",
        "title": "Raw IP Address Hostname",
        "description": "The URL uses a raw IP address (192.168.1.100) instead of a registered domain name...",
        "points": 35
      },
      {
        "severity": "critical",
        "title": "Targeted Brand Impersonation ('Paypal')",
        "description": "The brand keyword 'paypal' was detected in the path...",
        "points": 35
      }
    ],
    "trust_signals": [],
    "recommendations": [
      "DO NOT enter usernames, passwords, credit card numbers, or personal data on this site.",
      "DO NOT download or execute any files prompted by this web address."
    ]
  }
  ```

### 2. Batch URL Analysis
- **Endpoint**: `POST /api/batch-analyze`
- **Request Body**:
  ```json
  {
    "urls": [
      "https://www.google.com",
      "http://192.168.1.100/paypal/login.php"
    ]
  }
  ```

### 3. Model Information & Telemetry
- **Endpoint**: `GET /api/model-info`

---

## 🔬 Machine Learning & Threat Detection Methodology

| Feature Group | Indicators Analyzed | Cybersecurity Rationale |
|---|---|---|
| **Structural** | Length, Subdomain count, Path depth | Phishers use deep subdomains and lengthy paths to hide the actual host on mobile screens. |
| **Statistical** | Shannon Domain Entropy, Vowel-to-consonant ratios | Algorithmic domain generation (DGA) generates high-entropy strings distinct from human language. |
| **Obfuscation** | Userinfo `@`, Hex `%20`, Double slash `//` | Exploits browser RFC URL handling to camouflage the true destination server. |
| **Impersonation** | Subdomain brand matching vs Root domain | Detects patterns like `paypal.com.account-update.xyz` where the genuine brand is placed into a foreign domain's subdomain. |
| **Network & Transport** | Raw IP addresses, non-standard ports, unencrypted HTTP | Legitimate consumer services rely on DNS domain resolution and TLS encryption. |
