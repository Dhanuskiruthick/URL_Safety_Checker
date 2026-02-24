# 🛡️ Sentinel-AI: Global Threat Intelligence Vector Processor

![Sentinel-AI Banner](https://img.shields.io/badge/Status-Active-brightgreen) ![OWASP](https://img.shields.io/badge/OWASP-Top_10_Compliant-blue) ![Python](https://img.shields.io/badge/Python-3.9%2B-yellow) ![Streamlit](https://img.shields.io/badge/UI-Streamlit-red)

## 📌 The Problem
Traditional phishing scanners only rely on blacklists. If a hacker registers a new domain 5 minutes ago, standard tools will flag it as "Safe." 

## 🚀 The Solution: Sentinel-AI
Sentinel-AI is a next-generation, **Zero-Trust Enterprise Phishing Defense Engine**. We do not just look at URL strings; we analyze the deep infrastructure of the target website in real-time.

### ✨ Core Forensics Features:
- **DNS MX Record Analysis:** Checks if the domain actually has email servers configured (Catching disposable domains).
- **SSL & MITM Detection:** Validates the cryptographic integrity of the site's certificates.
- **Typosquatting & Homograph Engine:** Detects fake brand spellings (e.g., `g00gle.com`) and Punycode trap links (`xn--`).
- **Deep Redirection Tracing:** Tracks hidden payload hops.
- **WHOIS Infrastructure Check:** Analyzes domain age to flag zero-day registered domains.

### 🔒 OWASP Top 10 (2025) Compliance
Sentinel-AI is hardened against modern web vulnerabilities:
- **A01 (Broken Access Control):** Government/Military asset scanning is restricted.
- **A06 (SSRF):** DNS Rebinding & internal IP routing (127.0.0.1) are blocked by our Firewall.
- **A09 (Security Logging):** Secure internal logging of malicious execution traces.
- **A10 (Exceptional Conditions):** Safe execution halting during network drops (No false penalties).

## 💻 How to Run Locally
1. Clone the repository.
2. Install dependencies: `pip install -r requirements.txt`
3. Launch the Secure Dashboard: `streamlit run app.py`

*Built with passion by Team AURA HACKERS for CYBER CARNIVAL.*
