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
    
    # 🌟 INTERNAL VIP FLAG (Hidden from user)
    is_trusted_giant = False 

    if not user_url or not str(user_url).strip():
        return {"FTI": 0, "Status": "❌ EMPTY", "Findings": ["❌ No link provided"], "Takeaways": ["💡 Please paste a link to scan."]}

    logging.info(f"Scan initiated for Target: {user_url}")

    # --- 1. BASIC URL PARSING ---
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
             return {"FTI": 0, "Status": "❌ INVALID", "Findings": ["❌ Link contains bad characters"], "Takeaways": ["💡 The link looks broken or unsafe."]}
             
    except Exception:
        return {"FTI": 0, "Status": "❌ INVALID", "Findings": ["❌ Could not read the link"], "Takeaways": ["💡 Please check the link and try again."]}

    # --- 2. POLICY BLOCKER ---
    if domain.endswith('.gov') or domain.endswith('.gov.in') or domain.endswith('.mil'):
        logging.warning(f"Access Control Block: {domain}")
        return {
            "FTI": 0, "Status": "🛑 RESTRICTED", 
            "Findings": ["🚨 Scanning Blocked: Government Website"], 
            "Takeaways": ["💡 For safety, we do not scan official government or military websites."]
        }

    # --- 3. LAYER 1: KNOWN THREAT CHECK ---
    db_report = check_blacklist(clean_url)
    
    if db_report["score"] > 0:
        total_risk_score += db_report["score"]
        # SIMPLE ENGLISH:
        findings.append(f"🚨 Warning: This site is in our list of known bad sites")
        if db_report["is_phishing"]:
            takeaways.append(f"💡 DANGER: This website is confirmed as dangerous/phishing.")
    else:
        # SIMPLE ENGLISH:
        findings.append("✅ Basic safety check passed")
        
        # Internal Flag
        if "Trusted domain" in db_report.get("reason", ""):
            is_trusted_giant = True 

    # --- 4. LAYER 2: DEEP SCAN ---
    
    # Internal Security (SSRF)
    try:
        resolved_ip = socket.gethostbyname(domain)
        if resolved_ip.startswith(("127.", "10.", "192.168.")) or domain in ["localhost"]:
            logging.critical(f"SSRF Attack Blocked. Target: {domain}")
            return {"FTI": 0, "Status": "🚫 BLOCKED", "Findings": [f"🚨 Blocked internal network access"], "Takeaways": ["💡 Security Alert: You cannot scan local router addresses."]}
    except socket.gaierror:
        logging.error(f"Network Failure: {domain}")
        return {
            "FTI": 0, "Status": "📡 OFFLINE", 
            "Findings": ["🚨 Site is unreachable or offline"], 
            "Takeaways": ["💡 We couldn't connect to this site. It might be down."]
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
        # SIMPLE ENGLISH:
        findings.append("✅ This site has a valid email system")
    except:
        if not is_trusted_giant:
            total_risk_score += 20
            findings.append("⚠️ No email system found for this site")
            takeaways.append("💡 Suspicious: Real companies usually have official emails.")
        else:
            findings.append("✅ Email system verified (Popular Site)")

    # Redirection & Header Security
    try:
        headers = {'User-Agent': 'Sentinel-AI Forensic Scanner v1.0'}
        response = requests.get(clean_url, headers=headers, timeout=5, allow_redirects=True, stream=True)
        
        server_headers = response.headers
        if 'X-Frame-Options' not in server_headers and 'Strict-Transport-Security' not in server_headers:
            if not is_trusted_giant:
                total_risk_score += 15
                # SIMPLE ENGLISH:
                findings.append("⚠️ Site lacks advanced security shields")
                takeaways.append("💡 Note: This site is missing some modern security protections (Anti-Hacking headers).")
        else:
            findings.append("✅ Site has strong security shields")

        response.close() 
        if len(response.history) > 3:
            total_risk_score += 20
            findings.append(f"🚨 High Risk: Site redirects you too many times")
        else:
            findings.append("✅ Connection path is direct and safe")
    except:
        findings.append("ℹ️ Could not verify connection path")

    # Domain Age (WHOIS)
    try:
        d_info = whois.whois(root_domain)
        creation = d_info.creation_date[0] if isinstance(d_info.creation_date, list) else d_info.creation_date
        age = (datetime.datetime.now() - creation).days
        if age < 180:
            total_risk_score += 30
            # SIMPLE ENGLISH:
            findings.append(f"🚨 This website is very new ({age} days old)")
            takeaways.append("💡 Be Careful: Scammers often use brand new websites.")
        else:
            findings.append(f"✅ Website is established and old ({age} days)")
    except:
        if is_trusted_giant:
            findings.append("✅ Verified as a popular, trusted website")
        else:
            total_risk_score += 20
            findings.append("⚠️ Could not find website owner details")

    # SSL (Lock Icon)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown CA')
                # SIMPLE ENGLISH:
                findings.append(f"✅ Secure Connection (HTTPS) is active")
    except:
        total_risk_score += 30
        findings.append("🚨 Connection is NOT secure (No HTTPS)")
        takeaways.append("💡 Danger: Never enter passwords here. Your data can be stolen.")

    # --- 5. FINAL SCORE ---
    fti_score = max(0, 100 - total_risk_score)
    status = "🌟 TRUSTED" if fti_score >= 80 else "⚠️ SUSPICIOUS" if fti_score >= 50 else "🛑 HIGH RISK"

    if fti_score >= 80 and not takeaways:
        takeaways.append("💡 Pro-Tip: Even if a site is safe, never share OTPs or passwords via email links.")

    logging.info(f"Scan Complete for {domain}. FTI Score: {fti_score}")

    return {"FTI": fti_score, "Status": status, "Findings": findings, "Takeaways": takeaways}

