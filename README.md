# 🛡️ Sentinel-AI: Zero-Trust URL Forensic Analyzer

![Python Version](https://img.shields.io/badge/Python-3.9+-blue.svg?style=for-the-badge&logo=python)
![Framework](https://img.shields.io/badge/Streamlit-UI-FF4B4B.svg?style=for-the-badge&logo=streamlit)
![Security Standard](https://img.shields.io/badge/OWASP-Hardened-brightgreen.svg?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-purple.svg?style=for-the-badge)

> **Developed by RootGuard Labs** | Enterprise-grade phishing detection that doesn't rely on guesswork—it forensically investigates infrastructure.

---

## 📖 Executive Summary

Traditional phishing detectors rely heavily on static blacklists or text-based Machine Learning models. When threat actors launch **Zero-Day Attacks** using freshly registered domains, traditional tools fail because the URL isn't in their database yet. 

**Sentinel-AI introduces a paradigm shift.** Built on a **Zero-Trust Architecture**, it actively interrogates a target's server infrastructure, DNS configurations, cryptographic certificates, and visual assets in real-time to determine authenticity.

---

## 🏗️ Core Architecture (The 3-Layer Engine)

### 1️⃣ Layer 1: Threat Intelligence & Heuristics
Before touching the live web, the engine analyzes the URL structure:
* **Live Feed Integration:** Cross-references URLs against localized datasets and open-source threat feeds.
* **Cryptographic De-Obfuscation:** Detects Typosquatting and Homoglyph (Punycode/Lookalike) attacks using perceptual math algorithms.
* **TLD Risk Scoring:** Penalizes domains utilizing high-risk top-level extensions (e.g., `.xyz`, `.top`, `.zip`).

### 2️⃣ Layer 2: Deep Infrastructure Forensics
The engine acts as an automated penetration tester:
* **DNS MX Topology:** Verifies the existence of a Mail Exchange server (threat actors rarely configure corporate email infrastructure).
* **WHOIS Zero-Day Check:** Pulls domain registration age live to flag highly volatile domains created within the last 180 days.
* **Security Header Analysis:** Checks for anti-clickjacking armor (`X-Frame-Options`, `Strict-Transport-Security`).
* **SSL/TLS Integrity:** Validates cryptographic certificates to ensure data encryption.

### 3️⃣ Layer 3: Visual Cryptographic AI
* **Visual Identity Theft Detection:** Employs `imagehash` (Perceptual pHash) to fetch target favicons and compute bit-distance against official enterprise brand assets, catching spoofing attempts even if the text appears safe.

---

## 🔒 OWASP Top 10 (2025) Hardened

Sentinel-AI is secured against critical enterprise vulnerabilities:
* **A01 (Broken Access Control):** Policy-level restrictions prevent the scanning of high-security `.gov` and `.mil` assets.
* **A02 (Security Misconfiguration):** Streamlit developer modes and error tracebacks are strictly obfuscated via `config.toml` to prevent Server Information Disclosure.
* **A06 (SSRF Blocked):** Built-in IP Socket Firewall actively blocks internal network routing (e.g., preventing scans on `127.0.0.1` or `localhost`).
* **A10 (Unrestricted Resource Consumption):** Implements strict network timeouts and graceful exception handling for offline targets.

---

## ⚙️ Quick Start & Installation

No need to hunt for dependencies. Just copy, paste, and run.

**1. Clone the repository**
```bash
git clone [https://github.com/Dhanuskiruthick/URL_Safety_Checker.git](https://github.com/Dhanuskiruthick/URL_Safety_Checker.git)
cd URL_Safety_Checker
## 💻 How to Run Locally
1. Clone the repository.
2. Install dependencies: `pip install -r requirements.txt`
3. Launch the Secure Dashboard: `streamlit run app.py`

*Built with passion by Team AURA HACKERS for CYBER CARNIVAL.*
