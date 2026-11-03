"""
Offline Threat Intelligence Cache Manager
Ensures 100% reliable demonstration even without internet or when API rate limits are hit.
"""

import os
import json
from typing import Dict, Any, Optional

CACHE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "offline_ti_cache.json")

def load_cache() -> Dict[str, Any]:
    """Loads offline threat intelligence cache file."""
    if not os.path.exists(CACHE_PATH):
        return {"scenarios": {}}
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"scenarios": {}}

def get_cached_threat_intel(sha256: str) -> Optional[Dict[str, Any]]:
    """
    Looks up threat intelligence by SHA-256 hash or scenario name in the offline cache.
    Returns matched VT & MalwareBazaar payloads with 'is_cached': True.
    """
    cache = load_cache()
    scenarios = cache.get("scenarios", {})

    sha_clean = (sha256 or "").strip().lower()

    # Direct match by SHA-256
    for key, data in scenarios.items():
        if data.get("sha256", "").lower() == sha_clean:
            res = dict(data)
            res["is_cached"] = True
            return res

    # Match by key (e.g. 'scenario_2_fake_chrome_trojan' or '2')
    if sha_clean in scenarios:
        res = dict(scenarios[sha_clean])
        res["is_cached"] = True
        return res

    # Fallback for unrecognized hash (Zero-Day Simulation)
    return {
        "sha256": sha256,
        "name": "Zero-Day Unknown Executable",
        "is_cached": True,
        "virustotal": {
            "found": False,
            "status_code": 404,
            "message": "Resource not found on VirusTotal (Zero-Day or Unsubmitted)",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_engines": 0,
            "detection_ratio_pct": 0.0,
            "threat_label": None,
            "reputation": 0,
            "times_submitted": 0
        },
        "malwarebazaar": {
            "found": False,
            "query_status": "hash_not_found",
            "signature_family": None,
            "file_type": None,
            "tags": [],
            "yara_rules": []
        }
    }

def save_to_cache(sha256: str, vt_data: Dict[str, Any], mb_data: Dict[str, Any], name: Optional[str] = None):
    """Saves live API responses to the offline cache."""
    cache = load_cache()
    scenarios = cache.get("scenarios", {})
    key = f"hash_{sha256[:12]}"
    scenarios[key] = {
        "sha256": sha256,
        "name": name or f"Binary {sha256[:8]}",
        "virustotal": vt_data,
        "malwarebazaar": mb_data
    }
    cache["scenarios"] = scenarios
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass
