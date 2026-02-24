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

# --- IMPORTING THE ENGINES ---
from Blacklist_engine import check_blacklist
from favicon_scanner import check_favicon_spoofing 

# --- OWASP A09: SECURE LOGGING ---
logging.basicConfig(
    filename='sentinel_security.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - [IP: USER] - %(message)s'
)

def get_forensic_trust_index(user_url):
    total_risk_score = 0
    findings = []
    takeaways = []
    
    # 🌟 INTERNAL STEALTH FLAG
    is_trusted_giant = False 

    if not user_url or not str(user_url).strip():
        return {"FTI": 0, "Status": "❌ EMPTY", "Findings": ["❌ No link provided"], "Takeaways": ["💡 Please paste a link to scan."]}

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
             return {"FTI": 0, "Status": "❌ INVALID", "Findings": ["❌ Link contains broken characters"], "Takeaways": ["💡 This link looks suspicious or incorrectly typed."]}
             
    except Exception:
        return {"FTI": 0, "Status": "❌ INVALID", "Findings": ["❌ Could not read the link"], "Takeaways": ["💡 Please check the link and try again."]}

    # --- 2. POLICY BLOCKER ---
    if domain.endswith('.gov') or domain.endswith('.gov.in') or domain.endswith('.mil'):
        return {
            "FTI": 0, "Status": "🛑 RESTRICTED", 
            "Findings": ["🚨 Scanning Blocked: Official Government Website"], 
            "Takeaways": ["💡 Sentinel-AI policy: We do not scan high-security official government assets."]
        }

    # --- 3. LAYER 1: GLOBAL THREAT CHECK ---
    db_report = check_blacklist(clean_url)
    
    if db_report["score"] > 0:
        total_risk_score += db_report["score"]
        findings.append(f"🚨 Known Safety Alert: This link is flagged as dangerous")
        if db_report["is_phishing"]:
            takeaways.append(f"💡 DANGER: This website is confirmed to be a phishing trap.")
    else:
        findings.append("✅ Passed global safety heuristics")
        if "Trusted domain" in db_report.get("reason", ""):
            is_trusted_giant = True 

    # --- 4. LAYER 2: DEEP SCAN (Infrastructure) ---
    
    # TLD Risk Scoring (New Feature!)
    high_risk_tlds = ['.xyz', '.top', '.tk', '.ru', '.cn', '.zip', '.info']
    if any(domain.endswith(tld) for tld in high_risk_tlds):
        total_risk_score += 15
        findings.append(f"⚠️ Warning: This website uses a high-risk domain extension")
        takeaways.append("💡 Scammer Alert: Phishing sites often use cheap extensions like .xyz or .zip.")
    else:
        findings.append("✅ Website extension is standard and safe")

    # Email System Check
    try:
        resolver = dns.resolver.Resolver(); resolver.timeout = 2; resolver.lifetime = 2
        resolver.resolve(root_domain := ".".join(domain.split('.')[-2:]), 'MX')
        findings.append("✅ Official email system detected for this domain")
    except:
        if not is_trusted_giant:
            total_risk_score += 20
            findings.append("⚠️ No official email system found")
            takeaways.append("💡 Note: Legitimate companies usually have professional email setups.")

    # Redirection & Shield Check
    try:
        headers = {'User-Agent': 'Sentinel-AI/1.0'}
        response = requests.get(clean_url, headers=headers, timeout=5, allow_redirects=True, stream=True)
        
        server_headers = response.headers
        if 'X-Frame-Options' not in server_headers and 'Strict-Transport-Security' not in server_headers:
            if not is_trusted_giant:
                total_risk_score += 15
                findings.append("⚠️ Site lacks advanced hacking protection (Security Headers)")
                takeaways.append("💡 Safety Note: This site is missing some modern technical shields.")
        else:
            findings.append("✅ Advanced anti-hacking shields are active")

        response.close() 
        if len(response.history) > 3:
            total_risk_score += 20
            findings.append(f"🚨 High Risk: This site redirects you too many times")
        else:
            findings.append("✅ Direct and safe connection path")
    except:
        findings.append("ℹ️ Connection path could not be fully verified")

    # Website Age (WHOIS)
    try:
        d_info = whois.whois(domain)
        creation = d_info.creation_date[0] if isinstance(d_info.creation_date, list) else d_info.creation_date
        age = (datetime.datetime.now() - creation).days
        if age < 180:
            total_risk_score += 30
            findings.append(f"🚨 This website is very new (only {age} days old)")
            takeaways.append("💡 Zero-Day Warning: Scammers frequently use brand new websites.")
        else:
            findings.append(f"✅ Website is established and stable ({age} days old)")
    except:
        if is_trusted_giant:
            findings.append("✅ Website identity verified via established trust network")
        else:
            total_risk_score += 20
            findings.append("⚠️ Ownership details are hidden or unavailable")

    # SSL (Lock Icon)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                findings.append(f"✅ Secure Connection (HTTPS) is active and valid")
    except:
        total_risk_score += 30
        findings.append("🚨 Connection is NOT secure (No HTTPS)")
        takeaways.append("💡 Critical: Never enter passwords on this site. Your data could be stolen.")

    # --- 5. LAYER 3: VISUAL AI SCAN (FAVICON) ---
    try:
        if not is_trusted_giant:
            fav_report = check_favicon_spoofing(clean_url)
            if fav_report["risk_penalty"] > 0:
                total_risk_score += fav_report["risk_penalty"]
                # Friendly text
                findings.append("🚨 Visual Identity Alert: This site is trying to look like another brand!")
                takeaways.append(fav_report["takeaway"])
            else:
                findings.append("✅ Visual identity matches the source (No spoofing)")
        else:
            findings.append("✅ Brand identity verified via trust network")
    except:
        findings.append("ℹ️ Visual integrity scan skipped")

    # --- 6. FINAL SCORE ---
    fti_score = max(0, 100 - total_risk_score)
    status = "🌟 TRUSTED" if fti_score >= 80 else "⚠️ SUSPICIOUS" if fti_score >= 50 else "🛑 HIGH RISK"

    if fti_score >= 80 and not takeaways:
        takeaways.append("💡 Safe Tip: Always use two-factor authentication for extra security.")

    return {"FTI": fti_score, "Status": status, "Findings": findings, "Takeaways": takeaways}

