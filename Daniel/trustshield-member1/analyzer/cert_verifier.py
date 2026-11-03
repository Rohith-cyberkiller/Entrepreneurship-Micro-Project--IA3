"""
Module 3: Digital Signature & Authenticode Verification
Parses Authenticode signatures using signify, validates certificate chains,
and implements Identity Mismatch & Counterfeit Clone Detection against known publishers.
"""

import os
import json
import re
from typing import Dict, Any, Optional, Tuple, List
import pefile

try:
    from signify.authenticode.signed_file import SignedPEFile
    from signify.authenticode.verification_result import AuthenticodeVerificationResult
except ImportError:
    try:
        from signify.authenticode import AuthenticodeFile as SignedPEFile
        from signify.authenticode import AuthenticodeVerificationResult
    except ImportError:
        SignedPEFile = None
        AuthenticodeVerificationResult = None

def extract_dn_attribute(dn_obj: Any, attribute_name: str) -> Optional[str]:
    """
    Safely extracts an attribute (e.g. CN, O, C) from an X.509 Distinguished Name string or object.
    """
    if not dn_obj:
        return None
    dn_str = str(dn_obj)
    # Match pattern e.g. CN=Google LLC, or O=Microsoft Corporation
    match = re.search(rf"\b{attribute_name}\s*=\s*([^,]+)", dn_str, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None

def extract_pe_version_info(pe_obj: Optional[pefile.PE]) -> Dict[str, str]:
    """
    Extracts StringFileInfo entries (CompanyName, ProductName, FileDescription, OriginalFilename)
    from the PE resource directory.
    """
    info = {
        "CompanyName": "",
        "ProductName": "",
        "FileDescription": "",
        "OriginalFilename": ""
    }
    if not pe_obj or not hasattr(pe_obj, "FileInfo"):
        return info

    try:
        for file_info_list in pe_obj.FileInfo:
            for item in file_info_list:
                if hasattr(item, "StringTable"):
                    for st in item.StringTable:
                        for k, v in st.entries.items():
                            key_str = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
                            val_str = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
                            if key_str in info:
                                info[key_str] = val_str
    except Exception:
        pass
    return info

def verify_authenticode(filepath: str, pe_obj: Optional[pefile.PE] = None) -> Dict[str, Any]:
    """
    Inspects embedded Authenticode signature using signify and parses signer identity.
    Returns certificate_status dictionary and list of signature anomaly reasons.
    """
    cert_status = {
        "is_signed": False,
        "verification_status": "UNSIGNED",
        "signer_common_name": None,
        "issuer_ca": None,
        "serial_number": None,
        "valid_from": None,
        "valid_to": None,
        "claimed_product_name": None,
        "claimed_company_name": None,
        "clone_mismatch_detected": False,
        "signature_algorithm": None
    }
    reasons = []

    # Extract version info if PE is available
    version_info = extract_pe_version_info(pe_obj)
    claimed_product = version_info.get("ProductName") or version_info.get("FileDescription") or None
    claimed_company = version_info.get("CompanyName") or None

    cert_status["claimed_product_name"] = claimed_product
    cert_status["claimed_company_name"] = claimed_company

    if SignedPEFile is None or not os.path.exists(filepath):
        # Run clone check even if unsigned
        clone_detected, clone_reasons = check_counterfeit_clone(cert_status)
        cert_status["clone_mismatch_detected"] = clone_detected
        reasons.extend(clone_reasons)
        return cert_status, reasons

    try:
        with open(filepath, "rb") as f:
            signed_pe = SignedPEFile(f)
            signatures = list(signed_pe.signatures)

            if not signatures:
                cert_status["is_signed"] = False
                cert_status["verification_status"] = "UNSIGNED"
            else:
                cert_status["is_signed"] = True
                sig = signatures[0]

                # Try explain_verify()
                try:
                    result, err = signed_pe.explain_verify()
                    if result == AuthenticodeVerificationResult.OK:
                        cert_status["verification_status"] = "SIGNED_VERIFIED"
                    else:
                        cert_status["verification_status"] = str(result.name) if hasattr(result, "name") else "UNVERIFIED"
                        if err:
                            reasons.append(f"Authenticode verification warning: {err}")
                except Exception as ex:
                    cert_status["verification_status"] = "UNVERIFIED_ROOT"
                    reasons.append(f"Authenticode verification note: {ex}")

                # Locate leaf certificate
                leaf_cert = None
                signer_info = getattr(sig, "signer_info", None)
                if signer_info:
                    s_issuer = getattr(signer_info, "issuer", None)
                    s_serial = getattr(signer_info, "serial_number", None)
                    for cert in sig.certificates:
                        if cert.issuer == s_issuer and cert.serial_number == s_serial:
                            leaf_cert = cert
                            break

                # Fallback to first cert in list
                if not leaf_cert and sig.certificates:
                    leaf_cert = sig.certificates[0]

                if leaf_cert:
                    subject_str = str(leaf_cert.subject)
                    issuer_str = str(leaf_cert.issuer)
                    cn = extract_dn_attribute(leaf_cert.subject, "CN") or subject_str
                    issuer_cn = extract_dn_attribute(leaf_cert.issuer, "CN") or issuer_str

                    cert_status["signer_common_name"] = cn
                    cert_status["issuer_ca"] = issuer_cn
                    cert_status["serial_number"] = str(leaf_cert.serial_number) if hasattr(leaf_cert, "serial_number") else None

                    if hasattr(leaf_cert, "valid_from") and leaf_cert.valid_from:
                        cert_status["valid_from"] = leaf_cert.valid_from.isoformat()
                    if hasattr(leaf_cert, "valid_to") and leaf_cert.valid_to:
                        cert_status["valid_to"] = leaf_cert.valid_to.isoformat()

                if signer_info and hasattr(signer_info, "digest_algorithm"):
                    cert_status["signature_algorithm"] = str(signer_info.digest_algorithm)

    except Exception:
        # File is not signed or cannot be parsed by signify
        cert_status["is_signed"] = False
        cert_status["verification_status"] = "UNSIGNED"

    # Run Counterfeit Clone Detection
    clone_detected, clone_reasons = check_counterfeit_clone(cert_status)
    cert_status["clone_mismatch_detected"] = clone_detected
    reasons.extend(clone_reasons)

    return cert_status, reasons

def check_counterfeit_clone(cert_status: Dict[str, Any], publishers_path: Optional[str] = None) -> Tuple[bool, List[str]]:
    """
    Cross-references claimed product/company names against data/known_publishers.json.
    Flags critical counterfeit warning if file claims to be a recognized commercial app
    but is unsigned or signed by an unauthorized certificate entity.
    """
    if publishers_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        publishers_path = os.path.join(base_dir, "data", "known_publishers.json")

    if not os.path.exists(publishers_path):
        return False, []

    claimed_product = (cert_status.get("claimed_product_name") or "").strip().lower()
    claimed_company = (cert_status.get("claimed_company_name") or "").strip().lower()
    signer_cn = (cert_status.get("signer_common_name") or "").strip().lower()
    is_signed = cert_status.get("is_signed", False)

    if not claimed_product and not claimed_company:
        return False, []

    try:
        with open(publishers_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False, []

    publishers = data.get("publishers", [])
    mismatch_detected = False
    reasons = []

    for pub in publishers:
        pub_company = pub.get("company_name", "").lower()
        pub_products = [p.lower() for p in pub.get("products", [])]
        allowed_cns = [c.lower() for c in pub.get("legitimate_signer_cns", [])]

        # Check if the binary claims to be this publisher's product or company
        company_match = claimed_company and (pub_company in claimed_company or claimed_company in pub_company)
        product_match = any(p in claimed_product or claimed_product in p for p in pub_products if len(p) > 2)

        if company_match or product_match:
            claimed_target = cert_status.get("claimed_product_name") or cert_status.get("claimed_company_name") or pub.get("company_name")
            if not is_signed:
                mismatch_detected = True
                reasons.append(
                    f"File claims to be {claimed_target} but lacks a valid {pub.get('company_name')} digital signature (CRITICAL: Counterfeit Clone Alert)"
                )
            else:
                # File is signed, but does the signer CN match legitimate authorized certificates?
                signer_legit = any(allowed in signer_cn for allowed in allowed_cns)
                if not signer_legit:
                    mismatch_detected = True
                    reasons.append(
                        f"Identity Spoofing Detected: File claims to be {claimed_target} ({pub.get('company_name')}), but is signed by an unauthorized entity ('{cert_status.get('signer_common_name')}')."
                    )

    return mismatch_detected, reasons
