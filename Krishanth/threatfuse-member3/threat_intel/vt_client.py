"""
Module 1: VirusTotal API v3 Client
Queries VirusTotal v3 GET /api/v3/files/{sha256}, parses detection statistics,
threat classifications, and handles rate limits/offline network fallback.
"""

import os
import requests
from typing import Dict, Any, Optional

from .cache_manager import get_cached_threat_intel

VT_ENDPOINT = "https://www.virustotal.com/api/v3/files/{}"

def query_virustotal(sha256: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Queries VirusTotal API v3 for a given SHA-256 hash.
    Falls back gracefully to offline simulation cache if API key is absent,
    rate limit is hit (429), or network fails.
    """
    clean_hash = (sha256 or "").strip().lower()

    # Read from environment if not explicitly provided
    if not api_key:
        api_key = os.environ.get("VT_API_KEY")

    # If no API key provided, immediately consult offline cache
    if not api_key or api_key.strip() == "":
        cached = get_cached_threat_intel(clean_hash)
        vt_data = cached.get("virustotal", {})
        vt_data["source"] = "offline_cache (No API key provided)"
        return vt_data

    headers = {
        "x-apikey": api_key.strip(),
        "accept": "application/json"
    }

    try:
        url = VT_ENDPOINT.format(clean_hash)
        response = requests.get(url, headers=headers, timeout=10)

        # 1. Zero-Day / Hash Not Found
        if response.status_code == 404:
            return {
                "found": False,
                "status_code": 404,
                "message": "Resource not found on VirusTotal (Zero-Day file)",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "total_engines": 0,
                "detection_ratio_pct": 0.0,
                "threat_label": None,
                "reputation": 0,
                "times_submitted": 0,
                "source": "live_api"
            }

        # 2. Rate Limit Hit (HTTP 429) -> Fallback to Cache
        if response.status_code == 429:
            cached = get_cached_threat_intel(clean_hash)
            vt_data = cached.get("virustotal", {})
            vt_data["source"] = "offline_cache (VirusTotal 429 Rate Limit Exceeded)"
            return vt_data

        # 3. Successful 200 OK Response
        if response.status_code == 200:
            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            det_pct = round((malicious / total * 100), 2) if total > 0 else 0.0

            # Threat classification label
            pop_threat = attributes.get("popular_threat_classification", {})
            threat_label = pop_threat.get("suggested_threat_label")

            reputation = attributes.get("reputation", 0)
            times_sub = attributes.get("times_submitted", 0)

            return {
                "found": True,
                "status_code": 200,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "undetected": undetected,
                "total_engines": total,
                "detection_ratio_pct": det_pct,
                "threat_label": threat_label,
                "reputation": reputation,
                "times_submitted": times_sub,
                "source": "live_api"
            }

        # Other HTTP errors -> fallback
        cached = get_cached_threat_intel(clean_hash)
        vt_data = cached.get("virustotal", {})
        vt_data["source"] = f"offline_cache (HTTP {response.status_code})"
        return vt_data

    except Exception as ex:
        # Network unreachable or timeout -> fallback to offline cache
        cached = get_cached_threat_intel(clean_hash)
        vt_data = cached.get("virustotal", {})
        vt_data["source"] = f"offline_cache (Network Error: {ex})"
        return vt_data
