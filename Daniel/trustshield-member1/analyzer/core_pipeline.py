"""
Module 7: Core Analysis Pipeline & Unified IA3 JSON Engine
Orchestrates ingestion, cryptographic hashing, Authenticode verification,
Shannon entropy evaluation, and PE/APK heuristic parsing into a standardized IA3 JSON report.
"""

import os
import pefile
from typing import Dict, Any, List

from .ingestion import inspect_file_header
from .crypto_hash import calculate_hashes, check_known_bad_hash
from .entropy_math import calculate_file_entropy, analyze_pe_sections_entropy
from .cert_verifier import verify_authenticode
from .pe_apk_parser import parse_pe_metadata, parse_apk_metadata

def analyze_binary(filepath: str) -> Dict[str, Any]:
    """
    Main orchestration pipeline that ingests a binary and produces the standardized
    IA3 JSON analysis payload.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    # 1. Safe Ingestion & Magic Bytes
    header_info = inspect_file_header(filepath)
    filename = header_info["filename"]
    size_bytes = header_info["size_bytes"]
    magic_bytes = header_info["magic_bytes"]
    detected_format = header_info["detected_format"]
    extension_masquerading = header_info["extension_masquerading"]
    masquerade_reason = header_info["masquerading_reason"]

    # 2. Overall File Shannon Entropy
    overall_entropy = calculate_file_entropy(filepath)

    # 3. Load PE if applicable
    pe_obj = None
    is_pe = False
    if "PE Executable" in detected_format or magic_bytes.startswith("4D 5A"):
        try:
            pe_obj = pefile.PE(filepath)
            is_pe = True
        except Exception:
            pe_obj = None

    # 4. Cryptographic Hashes & Imphash
    hashes = calculate_hashes(filepath, pe_obj=pe_obj)

    # Check Known Bad Hash Feed
    bad_hash_match = check_known_bad_hash(hashes["sha256"])

    # 5. Digital Signature & Counterfeit Clone Verification
    cert_status, cert_reasons = verify_authenticode(filepath, pe_obj=pe_obj)

    # 6. Sections & Entropy / Packing Analysis
    sections = []
    is_likely_packed = overall_entropy > 7.3
    entropy_reasons = []

    if is_pe and pe_obj:
        sections, is_pe_packed, entropy_reasons = analyze_pe_sections_entropy(pe_obj)
        if is_pe_packed:
            is_likely_packed = True

    # 7. PE Metadata & Suspicious API Scanner
    pe_metadata = {
        "compile_timestamp": None,
        "timestamp_anomaly": False,
        "sections": sections,
        "suspicious_imports": []
    }
    categorized_apis = {}
    pe_reasons = []

    if is_pe and pe_obj:
        pe_metadata, pe_reasons, categorized_apis = parse_pe_metadata(pe_obj)
    elif detected_format.startswith("Android") or filepath.lower().endswith(".apk"):
        apk_meta, apk_reasons = parse_apk_metadata(filepath)
        pe_metadata["apk_info"] = apk_meta
        pe_reasons.extend(apk_reasons)

    # Clean up PE object
    if pe_obj:
        try:
            pe_obj.close()
        except Exception:
            pass

    # 8. Consolidate Reasons & Calculate Dynamic Risk Score (0 - 100)
    reasons = []
    risk_score = 0

    if masquerade_reason:
        reasons.append(masquerade_reason)
        risk_score += 35

    if bad_hash_match:
        family = bad_hash_match.get("family", "Unknown Malware")
        threat_type = bad_hash_match.get("threat_type", "Malicious Binary")
        reasons.append(f"CRITICAL: Matched Threat Intelligence Feed: {family} ({threat_type})")
        risk_score = 100

    # Clone mismatch (Counterfeit identity spoofing)
    if cert_status.get("clone_mismatch_detected"):
        risk_score += 70
    reasons.extend(cert_reasons)

    # High entropy / packing
    if is_likely_packed and not any("entropy" in r.lower() for r in entropy_reasons):
        entropy_reasons.append(f"Overall file Shannon entropy ({overall_entropy:.4f}) is exceptionally high (> 7.2000), indicating packed or encrypted content")
    if is_likely_packed:
        risk_score += 25
    reasons.extend(entropy_reasons)

    # Known packer section signature
    if any("packer signature" in r.lower() for r in entropy_reasons):
        risk_score += 15

    # W+X section presence (Self-Modifying / Shellcode)
    has_wx = any(s.get("wx_risk", False) for s in pe_metadata.get("sections", []))
    if has_wx:
        risk_score += 25

    # PE anomaly reasons (Timestamp tampering, etc.)
    reasons.extend(pe_reasons)
    if pe_metadata.get("timestamp_anomaly", False):
        risk_score += 15

    # Suspicious imports score
    suspicious_count = len(pe_metadata.get("suspicious_imports", []))
    if suspicious_count > 0:
        if any("Process Injection" in r for r in pe_reasons):
            risk_score += 30
        else:
            risk_score += min(suspicious_count * 5, 20)

    # Unsigned executable check (if normal PE, not a clone, but unsigned)
    if is_pe and not cert_status.get("is_signed") and not cert_status.get("clone_mismatch_detected"):
        risk_score += 10
        if not any("unsigned" in r.lower() for r in reasons):
            reasons.append("Binary does not contain an embedded digital signature (Unsigned Executable)")

    # Deduplicate reasons while preserving order
    deduped_reasons = []
    seen = set()
    for r in reasons:
        if r and r not in seen:
            deduped_reasons.append(r)
            seen.add(r)

    # Bound risk score between 0 and 100
    risk_score = max(0, min(100, risk_score))

    # Determine Verdict
    if cert_status.get("clone_mismatch_detected"):
        verdict = "COUNTERFEIT / HIGH RISK"
    elif bad_hash_match:
        verdict = "COUNTERFEIT / MALICIOUS"
    elif risk_score >= 65:
        verdict = "COUNTERFEIT / HIGH RISK"
    elif risk_score > 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
        if not deduped_reasons:
            deduped_reasons.append("No structural anomalies, packing indicators, or counterfeit markers detected")

    # Assemble Final Standardized IA3 JSON Payload
    report = {
        "file_info": {
            "filename": filename,
            "size_bytes": size_bytes,
            "magic_bytes": magic_bytes,
            "detected_format": detected_format,
            "extension_masquerading": extension_masquerading,
            "overall_shannon_entropy": overall_entropy,
            "is_likely_packed": is_likely_packed
        },
        "hashes": hashes,
        "certificate_status": cert_status,
        "pe_metadata": pe_metadata,
        "risk_assessment": {
            "risk_score": risk_score,
            "verdict": verdict,
            "reasons": deduped_reasons
        },
        # Integration helper fields for Members 2, 3, 4
        "clone_detection": {
            "mismatch_detected": cert_status.get("clone_mismatch_detected", False),
            "claimed_product": cert_status.get("claimed_product_name"),
            "claimed_company": cert_status.get("claimed_company_name"),
            "signer_cn": cert_status.get("signer_common_name")
        },
        "categorized_apis": categorized_apis
    }

    return report

def analyze_file(filepath: str) -> Dict[str, Any]:
    """
    Alias for analyze_binary to fulfill Module 7 specifications.
    """
    return analyze_binary(filepath)
