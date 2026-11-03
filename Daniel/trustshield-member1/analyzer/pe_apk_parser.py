"""
Module 5: PE & APK Static Metadata and Heuristic Anomalies
Analyzes compiler timestamps, W+X memory section permissions,
scans imported APIs against threat dictionaries, and inspects APK packages.
"""

import os
import json
import zipfile
import datetime
from typing import Dict, Any, List, Tuple, Optional
import pefile

from .entropy_math import calculate_shannon_entropy

def parse_pe_metadata(pe_obj: pefile.PE, suspicious_apis_path: Optional[str] = None) -> Tuple[Dict[str, Any], List[str], Dict[str, Any]]:
    """
    Parses PE File Header timestamp, section flags, and imported APIs.
    Detects timestamp tampering, W+X permissions, and matches dangerous APIs.
    """
    reasons = []

    # 1. Compiler Timestamp Analysis
    timestamp_raw = pe_obj.FILE_HEADER.TimeDateStamp
    timestamp_iso = None
    timestamp_anomaly = False

    try:
        dt = datetime.datetime.fromtimestamp(timestamp_raw, tz=datetime.timezone.utc)
        timestamp_iso = dt.isoformat()
        now_utc = datetime.datetime.now(datetime.timezone.utc)

        # Future timestamp check (allowing 1 day skew)
        if dt > now_utc + datetime.timedelta(days=1):
            timestamp_anomaly = True
            reasons.append(f"Compiler timestamp anomaly: Date is in the future ({timestamp_iso})")
        # Pre-2000 timestamp check
        elif dt.year < 2000:
            timestamp_anomaly = True
            reasons.append(f"Compiler timestamp anomaly: Date predates year 2000 ({timestamp_iso}), suggesting timestamp wiping or tampering")
    except Exception:
        timestamp_anomaly = True
        timestamp_iso = "INVALID_TIMESTAMP"
        reasons.append("Compiler timestamp is invalid or corrupted")

    # 2. Section Analysis (W+X permissions and metadata)
    sections_list = []
    for section in pe_obj.sections:
        try:
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00").strip()
        except Exception:
            name = "UNKNOWN"

        raw_size = section.SizeOfRawData
        virtual_size = section.Misc_VirtualSize
        entropy = calculate_shannon_entropy(section.get_data())

        chars = section.Characteristics
        is_writable = bool(chars & 0x80000000)
        is_executable = bool(chars & 0x20000000)
        wx_risk = is_writable and is_executable

        sec_entry = {
            "name": name,
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "entropy": entropy,
            "wx_risk": wx_risk
        }
        sections_list.append(sec_entry)

        if wx_risk:
            reasons.append(f"Section '{name}' has both Writable and Executable (W+X) permissions (Self-Modifying / Shellcode Unpacking Risk)")

    # 3. Suspicious IAT API Scanner
    suspicious_imports = []
    categorized_api_matches = {}

    if suspicious_apis_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        suspicious_apis_path = os.path.join(base_dir, "data", "suspicious_apis.json")

    api_dict = {}
    if os.path.exists(suspicious_apis_path):
        try:
            with open(suspicious_apis_path, "r", encoding="utf-8") as f:
                api_dict = json.load(f)
        except Exception:
            pass

    # Extract all imported function names
    all_imported_apis = set()
    if hasattr(pe_obj, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    try:
                        func_name = imp.name.decode("utf-8", errors="ignore")
                        all_imported_apis.add(func_name)
                    except Exception:
                        pass

    # Match against threat categories
    for category, details in api_dict.items():
        danger_list = details.get("apis", [])
        matched_in_cat = [api for api in danger_list if api in all_imported_apis]
        if matched_in_cat:
            categorized_api_matches[category] = {
                "severity": details.get("severity", "MEDIUM"),
                "threat_score": details.get("threat_score", 15),
                "mitre_technique": details.get("mitre_technique", ""),
                "description": details.get("description", ""),
                "matched_apis": matched_in_cat
            }
            suspicious_imports.extend(matched_in_cat)

    # Detect Process Injection Triad: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    has_va = "VirtualAllocEx" in all_imported_apis or "VirtualAlloc" in all_imported_apis
    has_wpm = "WriteProcessMemory" in all_imported_apis
    has_crt = "CreateRemoteThread" in all_imported_apis or "CreateThread" in all_imported_apis
    if has_va and has_wpm and has_crt:
        reasons.append("High-Risk API Pattern: Classic Process Injection Triad imported (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)")

    pe_metadata = {
        "compile_timestamp": timestamp_iso,
        "timestamp_anomaly": timestamp_anomaly,
        "sections": sections_list,
        "suspicious_imports": list(set(suspicious_imports))
    }

    return pe_metadata, reasons, categorized_api_matches

def parse_apk_metadata(filepath: str) -> Tuple[Dict[str, Any], List[str]]:
    """
    Analyzes Android Package (.apk) ZIP structure:
    Checks for AndroidManifest.xml, classes.dex, META-INF signature files,
    and calculates Shannon entropy of classes.dex bytecode.
    """
    reasons = []
    apk_meta = {
        "has_manifest": False,
        "has_dex": False,
        "dex_entropy": 0.0,
        "is_signed_apk": False,
        "cert_files": [],
        "total_files": 0
    }

    try:
        with zipfile.ZipFile(filepath, "r") as z:
            namelist = z.namelist()
            apk_meta["total_files"] = len(namelist)

            if "AndroidManifest.xml" in namelist:
                apk_meta["has_manifest"] = True

            dex_files = [n for n in namelist if n.endswith(".dex")]
            if dex_files:
                apk_meta["has_dex"] = True
                # Compute classes.dex entropy
                primary_dex = dex_files[0]
                dex_data = z.read(primary_dex)
                dex_entropy = calculate_shannon_entropy(dex_data)
                apk_meta["dex_entropy"] = dex_entropy

                if dex_entropy > 7.4:
                    reasons.append(f"High Shannon entropy ({dex_entropy:.4f}) in '{primary_dex}' suggests packed or obfuscated Android bytecode")

            # Check META-INF for signatures
            meta_inf_certs = [
                n for n in namelist 
                if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))
            ]
            if meta_inf_certs:
                apk_meta["is_signed_apk"] = True
                apk_meta["cert_files"] = meta_inf_certs
            else:
                reasons.append("APK lacks valid META-INF signature certificates (Unsigned Android APK)")

    except Exception as ex:
        reasons.append(f"APK archive analysis error: {ex}")

    return apk_meta, reasons
