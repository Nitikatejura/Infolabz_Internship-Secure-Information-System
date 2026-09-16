# 🛡️ AegisPoint Enterprise Security Platform

<div align="center">

![Version](https://img.shields.io/badge/version-v3.1--LTS-0ea5e9?style=for-the-badge&logo=shield)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=for-the-badge&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-ff4b4b?style=for-the-badge&logo=streamlit)
![License](https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge)
![NIST CSF](https://img.shields.io/badge/NIST_CSF-Aligned-0ea5e9?style=for-the-badge)
![ISO 27001](https://img.shields.io/badge/ISO_27001-Aligned-10b981?style=for-the-badge)

**Modular Cyber Defense, Reconnaissance & Digital Forensics Suite**

*Unified threat monitoring, cryptographic assurance, and digital forensics in a modern SOC dashboard.*

</div>

---

## 🏛️ Executive Overview

**AegisPoint Enterprise Security Platform (v3.1-LTS)** is a modular, production-ready cybersecurity framework designed for proactive threat assessment, host integrity monitoring, perimeter network reconnaissance, and post-incident digital forensics.

Aligned with the **NIST Cybersecurity Framework (CSF)** (Identify, Protect, Detect, Respond, Recover) and **ISO/IEC 27001** information security controls, AegisPoint consolidates 7 defensive capabilities into a unified telemetry pipeline.

| Module | Capability | Standard |
|--------|------------|----------|
| 🔑 **Identity Resilience** | Password Shannon entropy scoring + HIBP k-anonymity breach lookup | NIST SP 800-63B |
| 🔒 **Data Fingerprinting** | SHA-256, SHA-512, MD5, BLAKE2b hashing & verification | FIPS 180-4 / RFC 7693 |
| 🛡️ **Tamper Detection (FIM)** | File integrity monitoring, recursive baselining & cryptographic diff | PCI DSS 10.5.5 / HIPAA §164.312 |
| 📡 **Attack Surface Scanner** | Concurrent TCP port enumeration & risk exposure scoring | CIS Controls v8 |
| 🔍 **Incident Triage** | EXIF, PDF, ZIP artifact extraction & browser history forensics | ISO/IEC 27043 |
| 📊 **SIEM Telemetry** | SQLite WAL audit persistence with full-text search & CSV export | ISO 27001 Annex A.12.4 |
| 💻 **SOC Terminal Console** | In-browser interactive CLI simulator for rapid incident response | — |

---

## 📐 System Architecture

```text
Infolabz_Internship-Secure-Information-System/
├── app.py                     # Streamlit Web GUI (8-tab SOC dashboard)
├── launcher.py                # Unified launch controller ([1] Web GUI, [2] Terminal CLI)
├── sis_main.py                # Rich terminal CLI dashboard
├── requirements.txt           # Pinned production dependencies
├── .gitignore                 # Secure exclusion of bytecode, env, and runtime DBs
│
├── core/                      # Modular security engines
│   ├── __init__.py
│   ├── password_checker.py    # Entropy analysis & HIBP k-anonymity API
│   ├── create_hash.py         # Multi-algorithm cryptographic hash generator
│   ├── file_integrity_scanner.py  # Recursive baseline hashing & tamper diffing
│   ├── networkscanner.py      # Async / ThreadPool concurrent port scanner
│   ├── info_scanner.py        # Web security headers, SSL & DNS inspection
│   ├── dft_kit.py             # File evidence analyzer (magic bytes, EXIF, PDF, ZIP)
│   ├── browser_forensic_toolkit.py # Shadow-copy browser history extractor
│   └── database.py            # SQLite audit trail & event logger
│
├── database/                  # Centralized persistence schema
│   ├── __init__.py
│   └── db_manager.py          # Database operations layer
│
└── reports/                   # Exported forensic & audit reports (JSON / CSV)
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- `pip` package manager

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/Nitikatejura/Infolabz_Internship-Secure-Information-System.git
cd Infolabz_Internship-Secure-Information-System

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # macOS / Linux

# Install dependencies
pip install -r requirements.txt
```

### 2. Launching AegisPoint

#### Option A: Unified Launch Controller (Recommended)
```bash
python launcher.py
```
*Presents an interactive selector to launch either the Web GUI dashboard or the Terminal Console.*

#### Option B: Enterprise Web GUI Directly
```bash
streamlit run app.py
```
*Access the SOC dashboard at `http://localhost:8501`.*

#### Option C: SOC Terminal Console Directly
```bash
python sis_main.py
```

---

## 🌐 Deploying to Streamlit Community Cloud (3 Clicks)

1. Fork or push this repository to GitHub.
2. Visit [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
3. Click **New app**, select this repository and branch `main`, set the main file path to `app.py`, and click **Deploy!**

> **Cloud Note:** All file operations in the Web GUI support direct in-memory byte uploads via `st.file_uploader`, allowing full functionality in containerized cloud environments without requiring local host filesystem permissions.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
