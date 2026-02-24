import os
import whois
import datetime
import ssl
import socket
import requests
import pandas as pd
import time
import re
import dns.resolver
import urllib.parse
from difflib import SequenceMatcher
import logging # OWASP A09: Security Logging

# --- OWASP A09: SETUP SECURE LOGGING ---
logging.basicConfig(
    filename='sentinel_security.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - [IP: USER] - %(message)s'
)

GLOBAL_WHITELIST = set()

def load_massive_whitelist(csv_filename="top_1m.csv"):
    global GLOBAL_WHITELIST
    if not GLOBAL_WHITELIST:
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            df = pd.read_csv(os.path.join(script_dir, csv_filename), header=None)
            GLOBAL_WHITELIST = set(df[0].dropna().astype(str).str.lower().str.strip())
            logging.info("System Boot: Whitelist Engine loaded securely.")
        except Exception:
            GLOBAL_WHITELIST = {'google.com', 'pinterest.com', 'vit.ac.in', 'vitbhopal.ac.in', 'youtube.com', 'amazon.com'} 
            logging.warning("System Boot: Fallback Whitelist loaded.")

def get_forensic_trust_index(user_url):
    total_risk_score = 0
    findings = []
    takeaways = []

    load_massive_whitelist()

    if not user_url or not str(user_url).strip():
        return {"FTI": 0, "Status": "❌ EMPTY", "Findings": ["❌ No URL provided"], "Takeaways": ["💡 Please enter a valid URL to scan."]}

    # Log the scan attempt securely
    logging.info(f"Scan initiated for Target: {user_url}")

    try:
        clean_url = str(user_url).strip().lower()
        if not clean_url.startswith(('http://', 'https://')):
            clean_url = 'https://' + clean_url
        
        parsed_url = urllib.parse.urlparse(clean_url)
        domain = parsed_url.netloc.split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
            
        domain_parts = domain.split('.')
        if len(domain_parts) > 2:
            if domain_parts[-2] in ['co', 'ac', 'gov', 'org', 'net', 'edu', 'com']:
                root_domain = ".".join(domain_parts[-3:])
            else:
                root_domain = ".".join(domain_parts[-2:])
        else:
            root_domain = domain

        # OWASP A05: Injection Protection
        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
             logging.warning(f"Injection Attempt Blocked: {domain}")
             return {"FTI": 0, "Status": "❌ INVALID", "Findings": ["❌ Invalid Domain Characters"], "Takeaways": ["💡 URL contains invalid characters."]}
             
    except Exception:
        return {"FTI": 0, "Status": "❌ INVALID", "Findings": ["❌ URL Parsing Failed"], "Takeaways": ["💡 Please enter a valid URL."]}

    # --- OWASP A01: BROKEN ACCESS CONTROL (Policy Enforcement) ---
    if domain.endswith('.gov') or domain.endswith('.gov.in') or domain.endswith('.mil'):
        logging.warning(f"Access Control Block: Attempted to scan restricted government/military asset - {domain}")
        return {
            "FTI": 0, 
            "Status": "🛑 ACCESS DENIED", 
            "Findings": ["🚨 Execution Blocked: Restricted Government/Military Asset"], 
            "Takeaways": ["💡 OWASP A01 Policy: Sentinel-AI restricts scanning of high-security government and military domains to prevent unauthorized reconnaissance."]
        }

    if domain.startswith("xn--"):
        logging.warning(f"Punycode Attack Detected: {domain}")
        return {"FTI": 0, "Status": "🚨 FAKE BRAND", "Findings": ["🚨 Punycode Attack Detected!"], "Takeaways": ["💡 Fake Alphabet Trap: Highly dangerous!"]}

    is_whitelisted = root_domain in GLOBAL_WHITELIST

    if not is_whitelisted:
        critical_brands = ['amazon.com', 'google.com', 'hdfcbank.com', 'paypal.com', 'apple.com', 'microsoft.com', 'pinterest.com']
        for brand in critical_brands:
            if 0.75 < SequenceMatcher(None, root_domain, brand).ratio() < 1.0:
                total_risk_score += 50
                findings.append(f"🚨 Typosquatting Detected: Similar to '{brand}'")
                takeaways.append(f"💡 Brand Spoofing Alert: Trying to trick you by misspelling '{brand}'.")

    # --- OWASP A06 (SSRF) & A10 (Network Exception Handling) ---
    try:
        resolved_ip = socket.gethostbyname(domain)
        if resolved_ip.startswith(("127.", "10.", "192.168.")) or domain in ["localhost"]:
            logging.critical(f"SSRF Attack Blocked. Target: {domain} resolved to {resolved_ip}")
            return {"FTI": 0, "Status": "🚫 BLOCKED", "Findings": [f"🚨 DNS Rebinding Attack Blocked!"], "Takeaways": ["💡 Security Firewall: Internal scan blocked."]}
    except socket.gaierror:
        # FIX FOR A10: Do not deduct score, just abort cleanly!
        logging.error(f"Network Failure or Offline Target: {domain}")
        return {
            "FTI": 0, 
            "Status": "📡 OFFLINE / NO NETWORK", 
            "Findings": ["🚨 Execution Halted: Target Unreachable or No Internet Connection"], 
            "Takeaways": ["💡 OWASP A10 Handled: Sentinel-AI safely aborted the scan because the site is down or your network dropped. We do not penalize offline infrastructure!"]
        }

    if not is_whitelisted:
        if domain.count('-') >= 2:
            total_risk_score += 20
            findings.append(f"⚠️ High Domain Entropy: Hyphens detected")
            takeaways.append("💡 Suspicious Name: Legitimate brands rarely use multiple hyphens.")
            
        try:
            resolver = dns.resolver.Resolver(); resolver.timeout = 2; resolver.lifetime = 2
            resolver.resolve(root_domain, 'MX')
            findings.append("✅ Valid Mail Exchange (MX) DNS Records found")
        except:
            total_risk_score += 30
            findings.append("🚨 No Email (MX) Server Configured")
            takeaways.append("💡 Disposable Domain: Real companies have email servers.")

    try:
        headers = {'User-Agent': 'Sentinel-AI Forensic Scanner v1.0'}
        response = requests.get(clean_url, headers=headers, timeout=5, allow_redirects=True, stream=True)
        response.close() 
        if len(response.history) > 3 and not is_whitelisted:
            total_risk_score += 30
            findings.append(f"🚨 High Risk: {len(response.history)} Redirection hops")
        else:
            findings.append(f"✅ Redirection count is normal")
    except:
        findings.append("ℹ️ Connection Timed Out")

    if is_whitelisted:
        findings.append(f"✅ '{root_domain}' found in Trusted Database")
    else:
        try:
            d_info = whois.whois(root_domain)
            creation = d_info.creation_date[0] if isinstance(d_info.creation_date, list) else d_info.creation_date
            age = (datetime.datetime.now() - creation).days
            if age < 180:
                total_risk_score += 40
                findings.append(f"🚨 Domain is too new ({age} days old)")
                takeaways.append("💡 Hackers use fresh domains to escape detection.")
            else:
                findings.append(f"✅ Domain age is stable ({age} days old)")
        except:
            total_risk_score += 30
            findings.append("🚨 No WHOIS record found")

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
        takeaways.append("💡 Look for the Lock: No HTTPS means unencrypted connection.")

    fti_score = max(0, 100 - total_risk_score)
    status = "🌟 TRUSTED" if fti_score >= 80 else "⚠️ SUSPICIOUS" if fti_score >= 50 else "🛑 HIGH RISK"

    if fti_score >= 80 and not takeaways:
        takeaways.append("💡 Pro-Tip: Always verify the exact spelling of the domain.")

    logging.info(f"Scan Complete for {domain}. FTI Score: {fti_score}")

    return {"FTI": fti_score, "Status": status, "Findings": findings, "Takeaways": takeaways}
    

