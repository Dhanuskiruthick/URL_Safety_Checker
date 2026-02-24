import io
import socket
from typing import Dict
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from PIL import Image
import imagehash

# ---------------------------------------------------------
# CONFIGURATION & AUTO-CALIBRATION
# ---------------------------------------------------------

REQUEST_TIMEOUT = 5

# 🌟 NEW: Dynamic Calibration Database
TRUSTED_BRANDS = {
    "google": {"official_domain": "google.com", "url": "https://www.google.com", "hash": None},
    "amazon": {"official_domain": "amazon.com", "url": "https://www.amazon.com", "hash": None},
    "microsoft": {"official_domain": "microsoft.com", "url": "https://www.microsoft.com", "hash": None},
}

def _safe_request(url: str) -> requests.Response | None:
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": "Sentinel-AI/1.0"}, verify=True)
        response.raise_for_status()
        return response
    except Exception:
        return None

def _extract_favicon_url(base_url: str, html: str) -> str | None:
    soup = BeautifulSoup(html, "html.parser")
    for link in soup.find_all("link", href=True):
        rel = " ".join(link.get("rel", [])).lower()
        if "icon" in rel:
            return urljoin(base_url, link["href"])
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

def _download_image(image_url: str) -> Image.Image | None:
    response = _safe_request(image_url)
    if not response:
        return None
    try:
        return Image.open(io.BytesIO(response.content)).convert("RGB")
    except Exception:
        return None

def _get_official_hash(brand: str):
    """Dynamically fetches and caches the official brand's favicon hash"""
    if TRUSTED_BRANDS[brand]["hash"] is not None:
        return TRUSTED_BRANDS[brand]["hash"]
    
    url = TRUSTED_BRANDS[brand]["url"]
    resp = _safe_request(url)
    if resp:
        fav_url = _extract_favicon_url(resp.url, resp.text)
        if fav_url:
            img = _download_image(fav_url)
            if img:
                trusted_hash = imagehash.phash(img)
                TRUSTED_BRANDS[brand]["hash"] = trusted_hash
                return trusted_hash
    return None

def _similarity_percentage(hash1, hash2) -> float:
    max_bits = len(hash1.hash) ** 2
    distance = hash1 - hash2
    return (1 - distance / max_bits) * 100

# ---------------------------------------------------------
# MAIN ENTRY FUNCTION
# ---------------------------------------------------------

def check_favicon_spoofing(url: str) -> Dict:
    response = _safe_request(url)
    if not response:
        return {"risk_penalty": 0, "finding": "ℹ️ Target asset offline or unreachable", "takeaway": "No visual components could be fetched."}

    parsed = urlparse(response.url)
    actual_domain = parsed.netloc.lower().replace("www.", "")

    favicon_url = _extract_favicon_url(response.url, response.text)
    favicon_image = _download_image(favicon_url) if favicon_url else None

    if not favicon_image:
        return {"risk_penalty": 0, "finding": "✅ No Visual Identity (Favicon) present", "takeaway": "Site does not attempt to spoof logos visually."}

    target_hash = imagehash.phash(favicon_image)

    for brand in TRUSTED_BRANDS.keys():
        official_hash = _get_official_hash(brand)
        if official_hash is None:
            continue # Skip if we couldn't calibrate the official brand

        similarity = _similarity_percentage(target_hash, official_hash)

        if similarity >= 85:
            official_domain = TRUSTED_BRANDS[brand]["official_domain"]
            if not (actual_domain == official_domain or actual_domain.endswith("." + official_domain)):
                return {
                    "risk_penalty": 40,
                    "finding": f"🚨 [CRITICAL] Visual Identity Theft: Perceptual Hash matches {brand.title()}",
                    "takeaway": f"💡 High Risk: This site is stealing the official {brand.title()} logo to trick you.",
                }

    return {"risk_penalty": 0, "finding": "✅ Visual Integrity Passed (No Spoofed Logos)", "takeaway": "Favicon analysis shows no known brand theft."}
