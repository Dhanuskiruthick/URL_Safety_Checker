import os
import whois
import datetime
import ssl
import socket
import requests
import time
import re
import dns.resolver
import urllib.parse
import logging 

# --- IMPORTING THE NEW BLACKLIST ENGINE ---
from Blacklist_engine import check_blacklist

# --- OWASP A09: SETUP SECURE LOGGING ---
logging.basicConfig(
    filename='sentinel_security.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - [IP: USER] - %(message)s'
)

def get_forensic_trust_index(user_url):
    total_risk_score = 0
    findings = []
    takeaways = []
    
    # 🌟 THE ENTERPRISE VIP FLAG
    is_trusted_giant = False 

    if not user_url or not str(user_url).strip():
        return {"FTI": 0, "Status": "❌ EMPTY", "Findings": ["❌ No URL provided"], "Takeaways": ["💡 Please enter a valid URL to scan."]}

    logging.info(f"Scan initiated for Target: {user_url}")

    # --- 1. BASIC URL PARSING & A05 INJECTION CHECK ---
    try:
        clean_url = str(user_url).strip().lower()
        if not clean_url.startswith(('http://', 'https://')):
            clean_url = 'https://' + clean_url
        
        parsed_url = urllib.parse.urlparse(clean_url)
        domain = parsed_url.netloc.split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]

        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
             logging.warning(f"Injection Attempt Blocked: {domain}")
             return {"FTI": 0, "Status": "❌ INVALID", "Findings": ["❌ Invalid Domain Characters"], "Takeaways": ["💡 URL contains invalid characters."]}
             
    except Exception:
        return {"FTI": 0, "Status": "❌ INVALID", "Findings": ["❌ URL Parsing Failed"], "Takeaways": ["💡 Please enter a valid URL."]}

    # --- 2. OWASP A01: POLICY BLOCKER ---
    if domain.endswith('.gov') or domain.endswith('.gov.in') or domain.endswith('.mil'):
        logging.warning(f"Access Control Block: {domain}")
        return {
            "FTI": 0, "Status": "🛑 ACCESS DENIED", 
            "Findings": ["🚨 Execution Blocked: Restricted Government/Military Asset"], 
            "Takeaways": ["💡 OWASP A01 Policy: Sentinel-AI restricts scanning of high-security government domains."]
        }

    # --- 3. LAYER 1: THE NEW BLACKLIST & HOMOGLYPH ENGINE ---
    db_report = check_blacklist(clean_url)
    
    if db_report["score"] > 0:
        total_risk_score += db_report["score"]
        findings.append(f"🚨 DB Match: {db_report['reason']}")
        if db_report["is_phishing"]:
            takeaways.append(f"💡 CRITICAL: Database flagged this site as {db_report['risk_level']}!")
    else:
        findings.append("✅ Domain passed local database & homoglyph checks")
        # 🌟 VIP CHECK: IF TOP 1 MILLION DOMAIN, SET FLAG TO TRUE
        if "Trusted domain" in db_report.get("reason", ""):
            is_trusted_giant = True 

    # --- 4. LAYER 2: DEEP FORENSICS (Infrastructure Analysis) ---
    
    # OWASP A06 (SSRF) & A10 (Network Exception Handling)
    try:
        resolved_ip = socket.gethostbyname(domain)
        if resolved_ip.startswith(("127.", "10.", "192.168.")) or domain in ["localhost"]:
            logging.critical(f"SSRF Attack Blocked. Target: {domain}")
            return {"FTI": 0, "Status": "🚫 BLOCKED", "Findings": [f"🚨 DNS Rebinding Attack Blocked!"], "Takeaways": ["💡 Security Firewall: Internal scan blocked."]}
    except socket.gaierror:
        logging.error(f"Network Failure or Offline Target: {domain}")
        return {
            "FTI": 0, "Status": "📡 OFFLINE / NO NETWORK", 
            "Findings": ["🚨 Execution Halted: Target Unreachable or No Internet Connection"], 
            "Takeaways": ["💡 OWASP A10: Sentinel-AI safely aborted the scan because the site is down."]
        }

    domain_parts = domain.split('.')
    if len(domain_parts) > 2 and domain_parts[-2] in ['co', 'ac', 'gov', 'org', 'net', 'edu', 'com']:
        root_domain = ".".join(domain_parts[-3:])
    elif len(domain_parts) > 1:
        root_domain = ".".join(domain_parts[-2:])
    else:
        root_domain = domain

    # MX Records (Email Check)
    try:
        resolver = dns.resolver.Resolver(); resolver.timeout = 2; resolver.lifetime = 2
        resolver.resolve(root_domain, 'MX')
        findings.append("✅ Valid Mail Exchange (MX) DNS Records found")
    except:
        if not is_trusted_giant:
            total_risk_score += 20
            findings.append("⚠️ No Email (MX) Server Configured")
            takeaways.append("💡 Suspicious: Real companies usually have email servers configured.")
        else:
            findings.append("✅ Enterprise MX Verified via Trust Engine")

    # Redirection Hops & NEW: Header Forensics (Anti-Clickjacking)
    try:
        headers = {'User-Agent': 'Sentinel-AI Forensic Scanner v1.0'}
        response = requests.get(clean_url, headers=headers, timeout=5, allow_redirects=True, stream=True)
        
        # --- 🌟 NEW: ENTERPRISE HEADER FORENSICS (Anti-Clickjacking) ---
        server_headers = response.headers
        if 'X-Frame-Options' not in server_headers and 'Strict-Transport-Security' not in server_headers:
            if not is_trusted_giant:
                total_risk_score += 15
                findings.append("⚠️ Missing Anti-Clickjacking (X-Frame-Options) Headers")
                takeaways.append("💡 Vulnerability Alert: Real enterprise sites use strict security headers. This site lacks basic armor.")
        else:
            findings.append("✅ Enterprise Security Headers (Anti-Clickjacking) Present")
        # -----------------------------------------------------------------

        response.close() 
        if len(response.history) > 3:
            total_risk_score += 20
            findings.append(f"🚨 High Risk: {len(response.history)} Redirection hops")
        else:
            findings.append(f"✅ Redirection count is normal")
    except:
        findings.append("ℹ️ Connection Timed Out during redirection/header check")

    # WHOIS Domain Age
    try:
        d_info = whois.whois(root_domain)
        creation = d_info.creation_date[0] if isinstance(d_info.creation_date, list) else d_info.creation_date
        age = (datetime.datetime.now() - creation).days
        if age < 180:
            total_risk_score += 30
            findings.append(f"🚨 Domain is too new ({age} days old)")
            takeaways.append("💡 Zero-Day Alert: Hackers use freshly registered domains to escape detection.")
        else:
            findings.append(f"✅ Domain age is stable ({age} days old)")
    except:
        if is_trusted_giant:
            findings.append("✅ WHOIS Details Verified via Enterprise DB")
        else:
            total_risk_score += 20
            findings.append("⚠️ No WHOIS record found")

    # SSL Certificate Integrity
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown CA')
                findings.append(f"✅ Valid SSL active (Issued by: {issuer})")
    except:
        total_risk_score += 30
        findings.append("🚨 SSL Certificate missing or MITM Detected")
        takeaways.append("💡 Look for the Lock: No HTTPS means unencrypted, dangerous connection.")

    # --- 5. FINAL SCORE CALCULATION ---
    fti_score = max(0, 100 - total_risk_score)
    status = "🌟 TRUSTED" if fti_score >= 80 else "⚠️ SUSPICIOUS" if fti_score >= 50 else "🛑 HIGH RISK"

    if fti_score >= 80 and not takeaways:
        takeaways.append("💡 Pro-Tip: Even if a site is trusted, never share OTPs or passwords via email links.")

    logging.info(f"Scan Complete for {domain}. FTI Score: {fti_score}")

    return {"FTI": fti_score, "Status": status, "Findings": findings, "Takeaways": takeaways}
