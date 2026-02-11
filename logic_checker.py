import re

def perform_security_scan(url):
    """
    This function analysis the URLs and give the result 
    """
    analysis_report = {
        "is_safe": True,
        "warnings": [],
        "risk_score": 0
    }

    # 1. Parameter: Length Check 
    # Scammers use long URLs to hide the real domain.
    if len(url) > 75:
        analysis_report["warnings"].append("URL length is too long (>75 chars).")
        analysis_report["risk_score"] += 2
        analysis_report["is_safe"] = False

    # 2. Parameter: Symbols Check 
    # '@' symbol can be used to redirect users to a different site.
    suspicious_symbols = ['@', '!', '$', '?', '=']
    for char in suspicious_symbols:
        if char in url:
            analysis_report["warnings"].append(f"Suspicious symbol found: '{char}'")
            analysis_report["risk_score"] += 1
            analysis_report["is_safe"] = False

    # 3. Parameter: Keywords Check [cite: 59, 62]
    # Common phishing keywords used to create urgency.
    risky_keywords = ['login', 'verify', 'bank', 'secure', 'update', 'signin', 'account']
    for word in risky_keywords:
        if word in url.lower():
            analysis_report["warnings"].append(f"High-risk keyword detected: '{word}'")
            analysis_report["risk_score"] += 2
            analysis_report["is_safe"] = False

    # 4. Protocol Check (Cybersecurity Angle) 
    # Teaching safe browsing habits by flagging non-HTTPS links[cite: 54].
    if not url.lower().startswith("https://"):
        analysis_report["warnings"].append("Insecure connection (HTTP instead of HTTPS).")
        analysis_report["risk_score"] += 3
        analysis_report["is_safe"] = False


    return analysis_report
