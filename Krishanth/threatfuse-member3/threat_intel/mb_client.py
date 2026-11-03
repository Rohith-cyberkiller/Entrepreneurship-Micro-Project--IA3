"""
Module 2: MalwareBazaar API Client (abuse.ch)
Queries MalwareBazaar POST /api/v1/ by SHA-256 and PE Imphash,
extracts malware signatures, YARA rules, threat tags, and handles offline fallback.
"""

import os
import requests
from typing import Dict, Any, Optional

from .cache_manager import get_cached_threat_intel

MB_ENDPOINT = "https://mb-api.abuse.ch/api/v1/"

def query_malwarebazaar(sha256: str, imphash: Optional[str] = None, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Queries MalwareBazaar API for file hash intelligence.
    Extracts malware family signature, triggered YARA rules, and threat tags.
    """
    clean_hash = (sha256 or "").strip().lower()

    if not api_key:
        api_key = os.environ.get("MB_API_KEY")

    # If no API key provided or explicitly requested offline, check offline cache first
    if not api_key or api_key.strip() == "":
        cached = get_cached_threat_intel(clean_hash)
        mb_data = cached.get("malwarebazaar", {})
        if mb_data.get("found"):
            mb_data["source"] = "offline_cache (No MB_API_KEY provided)"
            return mb_data

    headers = {}
    if api_key:
        headers["Auth-Key"] = api_key.strip()

    try:
        response = requests.post(
            MB_ENDPOINT,
            data={"query": "get_info", "hash": clean_hash},
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            query_status = data.get("query_status", "hash_not_found")

            if query_status == "ok":
                items = data.get("data", [])
                primary = items[0] if items else {}

                signature = primary.get("signature")
                file_type = primary.get("file_type")
                tags = primary.get("tags") or []
                
                # Extract YARA rules
                yara_rules = []
                for y in primary.get("yara_rules") or []:
                    rule_name = y.get("rule_name")
                    if rule_name:
                        yara_rules.append(rule_name)

                return {
                    "found": True,
                    "query_status": "ok",
                    "signature_family": signature,
                    "file_type": file_type,
                    "tags": tags,
                    "yara_rules": yara_rules,
                    "source": "live_api"
                }
            elif query_status == "hash_not_found":
                # Check imphash if available
                if imphash and "N/A" not in imphash:
                    imphash_res = query_malwarebazaar_imphash(imphash, api_key)
                    if imphash_res.get("found"):
                        imphash_res["source"] = "live_api_imphash_match"
                        return imphash_res

                return {
                    "found": False,
                    "query_status": "hash_not_found",
                    "signature_family": None,
                    "file_type": None,
                    "tags": [],
                    "yara_rules": [],
                    "source": "live_api"
                }

        # Non-200 response -> fallback
        cached = get_cached_threat_intel(clean_hash)
        mb_data = cached.get("malwarebazaar", {})
        mb_data["source"] = f"offline_cache (HTTP {response.status_code})"
        return mb_data

    except Exception as ex:
        # Network error -> fallback to cache
        cached = get_cached_threat_intel(clean_hash)
        mb_data = cached.get("malwarebazaar", {})
        mb_data["source"] = f"offline_cache (Network Error: {ex})"
        return mb_data

def query_malwarebazaar_imphash(imphash: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Imphash Family Hunter:
    Queries MalwareBazaar for known malware families sharing the identical Import Table Hash.
    """
    clean_imphash = (imphash or "").strip().lower()
    if not clean_imphash or "n/a" in clean_imphash:
        return {"found": False, "query_status": "invalid_imphash"}

    headers = {}
    if api_key:
        headers["Auth-Key"] = api_key.strip()

    try:
        response = requests.post(
            MB_ENDPOINT,
            data={"query": "get_imphash", "imphash": clean_imphash, "limit": 5},
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok":
                items = data.get("data", [])
                families = list(set(it.get("signature") for it in items if it.get("signature")))
                tags = list(set(tag for it in items for tag in (it.get("tags") or [])))
                return {
                    "found": True,
                    "query_status": "imphash_family_match",
                    "signature_family": families[0] if families else "Generic Recompiled Threat",
                    "matched_families": families,
                    "tags": tags,
                    "yara_rules": [f"matched_imphash_{clean_imphash}"]
                }
    except Exception:
        pass

    return {"found": False, "query_status": "imphash_not_found"}
