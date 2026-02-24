import pandas as pd
from urllib.parse import urlparse
import requests
import threading
import time
import difflib
import math
import unicodedata
import os

# GLOBAL CONFIGURATION
_blacklist_set = set()
_legit_domains = set()
_refresh_interval = 5400  # 1.5 hours
_lock = threading.Lock()

PHISHTANK_API_KEY = None  # Optional

# URL NORMALIZATION
def normalize_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path
    return domain.lower().replace("www.", "").strip()

# HOMOGLYPH NORMALIZATION
homoglyph_map = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
    "@": "a", "$": "s", "rn": "m", "!": "i"
}

def normalize_unicode(text):
    return unicodedata.normalize("NFKD", text)

def deobfuscate_domain(domain):
    domain = normalize_unicode(domain)
    for fake, real in homoglyph_map.items():
        domain = domain.replace(fake, real)
    return domain

# LOAD LEGITIMATE DOMAINS
def load_legitimate_domains(csv_path="top_1m.csv"):
    try:
        # Check if file exists first to avoid hard crashes
        if not os.path.exists(csv_path):
            print(f"Warning: {csv_path} not found. Loading defaults.")
            return {"google.com", "amazon.com", "paypal.com", "microsoft.com", "apple.com"}
            
        df = pd.read_csv(csv_path, header=None) # Adjusted for standard top 1m lists
        # Assuming domain is in the first column for top_1m.csv
        return set(df[0].dropna().astype(str).apply(normalize_url))
    except Exception as e:
        print("Legitimate domain load failed:", e)
        return {"google.com", "amazon.com", "paypal.com", "microsoft.com"}

# LOAD LOCAL BLACKLIST
def load_local_blacklist(csv1="Phishing URLs.csv", csv2="URL dataset.csv"):
    combined_set = set()
    try:
        if os.path.exists(csv1):
            f1 = pd.read_csv(csv1)
            f1.columns = f1.columns.str.lower()
            if "url" in f1.columns:
                combined_set.update(f1["url"].dropna().apply(normalize_url))
                
        if os.path.exists(csv2):
            f2 = pd.read_csv(csv2)
            f2.columns = f2.columns.str.lower()
            if "url" in f2.columns:
                combined_set.update(f2["url"].dropna().apply(normalize_url))
                
        return combined_set
    except Exception as e:
        print("Local dataset load failed:", e)
        return set()

# LIVE FEEDS
def fetch_openphish():
    urls_set = set()
    try:
        response = requests.get("https://openphish.com/feed.txt", timeout=5)
        if response.status_code == 200:
            for url in response.text.splitlines():
                urls_set.add(normalize_url(url))
    except Exception as e:
        print("OpenPhish fetch failed:", e)
    return urls_set

def fetch_phishtank():
    urls_set = set()
    # Simplified for hackathon: returning empty if no API key to avoid rate limits
    if not PHISHTANK_API_KEY:
        return urls_set
    try:
        response = requests.get("https://data.phishtank.com/data/online-valid.json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                if "url" in entry:
                    urls_set.add(normalize_url(entry["url"]))
    except Exception as e:
        print("PhishTank fetch failed:", e)
    return urls_set

# REFRESH ENGINE
def refresh_blacklist():
    global _blacklist_set, _legit_domains
    with _lock:
        local_set = load_local_blacklist()
        openphish_set = fetch_openphish()
        phishtank_set = fetch_phishtank()

        _blacklist_set = local_set.union(openphish_set).union(phishtank_set)

        if not _legit_domains:
            _legit_domains.update(load_legitimate_domains())

def background_updater():
    while True:
        time.sleep(_refresh_interval)
        refresh_blacklist()

# Initialize data immediately
refresh_blacklist()
# Start background thread
threading.Thread(target=background_updater, daemon=True).start()

# TYPO + HOMOGLYPH DETECTION
def detect_typosquatting(domain):
    parts = domain.rsplit(".", 1)
    root = parts[0]
    
    # Fast Optimization: Only check top 1000 to prevent freezing the UI
    legit_sample = list(_legit_domains)[:1000]

    for legit in legit_sample:
        legit_root = legit.rsplit(".", 1)[0]
        
        # Speed hack: if length difference is too high, don't run sequence matcher
        if abs(len(root) - len(legit_root)) > 2:
            continue
            
        similarity = difflib.SequenceMatcher(None, root, legit_root).ratio()
        if 0.82 <= similarity < 1.0:
            return True, legit
    return False, None

def detect_homoglyph_attack(domain):
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        root, tld = parts
    else:
        root, tld = domain, ""
        
    cleaned_root = deobfuscate_domain(root)

    if cleaned_root != root:
        test_domain = f"{cleaned_root}.{tld}" if tld else cleaned_root
        if test_domain in _legit_domains:
            return True, test_domain
    return False, None

# RISK TIER MAPPING
def map_risk_tier(score):
    if score <= 25: return "Safe"
    elif score <= 49: return "Low Risk"
    elif score <= 69: return "Suspicious"
    elif score <= 89: return "High Risk"
    else: return "Critical"

# MAIN CHECK FUNCTION (FINAL CALIBRATED)
def check_blacklist(user_url):
    normalized_url = normalize_url(user_url)
    raw_score = 0
    reasons = []

    # 1. Whitelist
    if normalized_url in _legit_domains:
        return {
            "is_phishing": False,
            "score": 0,
            "risk_level": "Safe",
            "reason": "Trusted domain (Top ranked legitimate site)"
        }

    # 2. Exact blacklist match
    if normalized_url in _blacklist_set:
        raw_score += 100
        reasons.append("Exact blacklist match")

    # 3. Subdomain match
    for bad_domain in _blacklist_set:
        if bad_domain in normalized_url:
            raw_score += 75
            reasons.append("Subdomain match")
            break

    # 4. Homoglyph detection
    homoglyph_detected, legit_match = detect_homoglyph_attack(normalized_url)
    if homoglyph_detected:
        raw_score += 75
        reasons.append(f"Homoglyph attack mimicking {legit_match}")

    # 5. Typosquatting detection
    typo_detected, legit_match = detect_typosquatting(normalized_url)
    if typo_detected:
        raw_score += 65
        reasons.append(f"Typosquatting of {legit_match}")

    # 6. Keyword scoring (capped)
    suspicious_keywords = [
        "login", "verify", "secure", "account",
        "update", "bank", "free", "gift", "prize"
    ]
    keyword_hits = sum(keyword in normalized_url for keyword in suspicious_keywords)
    raw_score += min(keyword_hits * 20, 40)

    if keyword_hits:
        reasons.append("Suspicious keywords detected")

    # 7. Structural signals
    if len(user_url) > 75:
        raw_score += 10
        reasons.append("Long URL")

    if user_url.count("-") > 4:
        raw_score += 10
        reasons.append("Excessive hyphens")

    # FINAL SIGMOID CALIBRATION
    calibrated_score = int(100 * (1 - math.exp(-raw_score / 75)))
    calibrated_score = min(max(calibrated_score, 0), 100)

    risk_level = map_risk_tier(calibrated_score)

    return {
        "is_phishing": calibrated_score >= 60,
        "score": calibrated_score,
        "risk_level": risk_level,
        "reason": ", ".join(reasons) if reasons else "No significant risk indicators"
    }
