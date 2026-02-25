# 🛡️ Sentinel-AI: Zero-Trust URL Forensic Analyzer

**Team AURA HACKERS | Cyber Carnival 2026**

![Python Version](https://img.shields.io/badge/Python-3.9+-blue.svg?style=for-the-badge&logo=python)
![Framework](https://img.shields.io/badge/Streamlit-UI-FF4B4B.svg?style=for-the-badge&logo=streamlit)
![Security Standard](https://img.shields.io/badge/OWASP-Hardened-brightgreen.svg?style=for-the-badge)
![Event](https://img.shields.io/badge/Event-CYBER_CARNIVAL-orange.svg?style=for-the-badge)

> *Traditional URL checkers ask: "Is this URL known?" Sentinel-AI asks: "Is this infrastructure trustworthy?"*
> **Trust Nothing. Verify Everything.**

---

## 🚨 The Zero-Day Detection Gap
Phishing attacks are evolving faster than blacklist databases. When attackers register a fresh domain, deploy a cloned login page, and add a valid SSL certificate, most detection tools fail because the domain is not yet reported. This creates a critical **Zero-Day Detection Gap**.

## 💡 Our Solution
Sentinel-AI is a **Zero-Trust Infrastructure-Based Phishing Detection Engine**. Instead of checking reputation alone, it performs live forensic interrogation of DNS topology, WHOIS registration age, SSL/TLS certificate integrity, HTTP security headers, and visual brand spoofing. **It does not trust. It verifies.**

---

## 🏗️ The 3-Layer Defense Engine

### 1. Structural Threat Heuristics
Before network calls, we analyze the URL itself.
* **Typosquatting & Homoglyph Analysis:** Catches Punycode and lookalike attacks.
* **Suspicious Keyword Detection:** Flags common phishing terminology.
* **High-Risk TLD Scoring:** Penalizes extensions like `.xyz`, `.top`, `.zip`.
* **Threat Intelligence Cross-Check:** Validates against known malicious feeds.

### 2. Deep Infrastructure Forensics
Sentinel-AI behaves like an automated SOC analyst interrogating the server.
* **MX Record Verification:** Phishing domains rarely configure legitimate corporate email servers.
* **Domain Age Analysis:** Flags highly volatile domains registered within the last 180 days.
* **Security Header Inspection:** Checks for X-Frame-Options, Strict-Transport-Security, and Content-Security-Policy.
* **SSL/TLS Validation:** Ensures valid, non-expired certificates with proper encryption handshakes.

### 3. Visual Cryptographic AI (Favicon Spoofing)
Attackers often clone brand visuals perfectly. We combat this by fetching the target's favicon, generating a **perceptual hash (pHash)**, and computing the Hamming distance against verified brand assets.

---

## 🔐 Security by Design (OWASP 2025 Aligned)
* **[A01] Broken Access Control:** Blocks scanning of sensitive .gov and .mil domains.
* **[A06] SSRF Protection:** Internal IP ranges (127.0.0.1, RFC1918) are strictly blocked.
* **[A10] Resource Exhaustion:** Strict network timeouts prevent denial-of-service via slow endpoints.
* **[A02] Security Misconfiguration:** Production-ready configuration disables debug leaks.

---

## ⚙️ Quick Setup (One-Click Run)

Copy and paste the following single command into your terminal to automatically clone the repo, install dependencies, and launch the forensic engine:


git clone https://github.com/Dhanuskiruthick/URL_Safety_Checker.git && cd URL_Safety_Checker && pip install streamlit pandas requests python-whois dnspython beautifulsoup4 Pillow ImageHash && python -m streamlit run app.py

---

🚀 Scalability Roadmap (Post-Hackathon)
Headless JS Sandbox: Render dynamic phishing kits using Playwright and entropy analysis.

Async Architecture: Move to asyncio + aiohttp for concurrent large-scale scanning.

Redis Caching Layer: Ultra-low latency revalidation of trusted enterprise domains.

API Deployment: Convert engine into a REST API for SOC and enterprise integration.

<div align="center">
🛡 Team AURA HACKERS
Cyber Carnival 2026

Trust Nothing. Verify Everything.

</div>


                                                                       
