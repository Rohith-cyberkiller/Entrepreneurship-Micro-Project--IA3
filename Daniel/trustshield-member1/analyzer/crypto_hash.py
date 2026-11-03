"""
Module 2: Cryptographic Hashing & Imphash Pipeline
Computes MD5, SHA-1, SHA-256 in a single streaming pass,
computes PE Import Hash (imphash), and checks offline threat databases.
"""

import os
import json
import hashlib
from typing import Dict, Any, Optional
import pefile

CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks

def calculate_hashes(filepath: str, pe_obj: Optional[pefile.PE] = None) -> Dict[str, Any]:
    """
    Simultaneously computes MD5, SHA-1, and SHA-256 in a single streaming pass.
    Computes PE imphash if file is a valid PE.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    md5_hex = md5.hexdigest().lower()
    sha1_hex = sha1.hexdigest().lower()
    sha256_hex = sha256.hexdigest().lower()

    # Calculate imphash
    imphash_val = None
    if pe_obj is not None:
        try:
            imphash_val = pe_obj.get_imphash()
        except Exception:
            imphash_val = None
    else:
        # Try parsing with pefile if not provided
        try:
            pe = pefile.PE(filepath, fast_load=True)
            try:
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
                ])
                imphash_val = pe.get_imphash()
            finally:
                pe.close()
        except Exception:
            imphash_val = None

    hashes_result = {
        "md5": md5_hex,
        "sha1": sha1_hex,
        "sha256": sha256_hex,
        "imphash": imphash_val if imphash_val else "N/A (Non-PE or No Imports)"
    }

    return hashes_result

def check_known_bad_hash(sha256_hash: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Checks the computed SHA-256 hash against data/known_bad_hashes.json.
    Returns matched threat information or None.
    """
    if db_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = os.path.join(base_dir, "data", "known_bad_hashes.json")

    if not os.path.exists(db_path):
        return None

    try:
        with open(db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        threat_table = data.get("known_malicious_hashes", {})
        return threat_table.get(sha256_hash.lower())
    except Exception:
        return None
