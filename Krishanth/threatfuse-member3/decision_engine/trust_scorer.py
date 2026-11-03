"""
Module 3: Dynamic Weighted Risk & Final Trust Score Engine
Merges Member 1 (Static/Crypto), Member 2 (ML Probability), and Member 3 (Threat Intel)
into a unified Final Trust Score (0 to 100) with dynamic Zero-Day weight shifting.
"""

from typing import Dict, Any, List, Optional, Tuple

def extract_member1_static_risk(m1_json: Dict[str, Any]) -> Tuple[float, bool]:
    """
    Extracts or normalizes Member 1's static risk score into a 0.0 - 100.0 scale.
    Also returns whether a counterfeit clone mismatch was flagged.
    """
    if not m1_json:
        return 50.0, False

    # 1. Direct risk_score if available
    risk_assessment = m1_json.get("risk_assessment", {})
    if "risk_score" in risk_assessment:
        score = float(risk_assessment["risk_score"])
        cert = m1_json.get("certificate_status", {})
        clone_flag = bool(cert.get("clone_mismatch_detected", False))
        return min(100.0, max(0.0, score)), clone_flag

    # 2. Heuristic derivation if raw telemetry passed
    cert = m1_json.get("certificate_status", {})
    file_info = m1_json.get("file_info", {})
    pe_meta = m1_json.get("pe_metadata", {})

    score = 0.0
    clone_flag = bool(cert.get("clone_mismatch_detected", False))

    if clone_flag:
        score += 55.0
    if not cert.get("is_signed", False):
        score += 20.0
    if file_info.get("overall_shannon_entropy", 0.0) > 7.2 or file_info.get("is_likely_packed", False):
        score += 25.0
    if file_info.get("extension_masquerading", False):
        score += 40.0

    sections = pe_meta.get("sections", [])
    if any(s.get("wx_risk", False) for s in sections):
        score += 20.0

    suspicious_count = len(pe_meta.get("suspicious_imports", []))
    score += min(suspicious_count * 5.0, 25.0)

    return min(100.0, max(0.0, score)), clone_flag

def extract_member2_ml_risk(m2_json: Dict[str, Any]) -> float:
    """
    Extracts Member 2's ML malware probability score (0.0 to 100.0).
    """
    if not m2_json:
        return 50.0

    ml_pred = m2_json.get("ml_prediction", {})
    if "malware_probability_score" in ml_pred:
        return float(ml_pred["malware_probability_score"])

    # Fallback to direct key
    if "malware_probability_score" in m2_json:
        return float(m2_json["malware_probability_score"])

    return 50.0

def evaluate_threat_intel_risk(vt_data: Dict[str, Any], mb_data: Dict[str, Any]) -> Tuple[Optional[float], bool, List[str]]:
    """
    Calculates Member 3's Threat Intelligence risk score (0.0 to 100.0) and checks
    if the hash is Cloud-Known vs. Zero-Day.
    Returns (ti_risk_score, is_cloud_known, kill_switch_reasons).
    """
    vt_found = vt_data.get("found", False)
    mb_found = mb_data.get("found", False)

    kill_switch_reasons = []

    # Check Zero-Day: Not present in either feed
    if not vt_found and not mb_found:
        return None, False, []

    is_cloud_known = True
    mal_count = vt_data.get("malicious_count", 0)
    total_eng = vt_data.get("total_engines", 72)

    # Hard triggers for Threat Intel
    if mb_found:
        family = mb_data.get("signature_family") or "Known Malware"
        kill_switch_reasons.append(f"Confirmed malware in MalwareBazaar ({family})")

    if mal_count >= 5:
        kill_switch_reasons.append(f"Flagged by {mal_count}/{total_eng} vendors on VirusTotal")

    # Threat Intel Scoring logic
    if mb_found or mal_count >= 10:
        ti_score = 100.0
    elif mal_count >= 5:
        ti_score = 88.0
    elif mal_count >= 2:
        ti_score = 65.0
    elif mal_count == 1:
        ti_score = 40.0
    else:
        # File is known on VT with 0 malicious engines (Verified clean)
        ti_score = 0.0

    return ti_score, is_cloud_known, kill_switch_reasons

def compute_final_trust_score(
    member1_json: Dict[str, Any],
    member2_json: Dict[str, Any],
    threat_intel_json: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Main merging algorithm combining:
      - Member 1: Static Binary Analysis & Cryptographic Integrity
      - Member 2: Machine Learning Malware Probability
      - Member 3: VirusTotal & MalwareBazaar Threat Feeds
    Applies Dynamic Zero-Day Weight Shifting and Hard Kill-Switch Overrides to compute Final Trust Score (0-100).
    """
    sha256 = (
        member1_json.get("hashes", {}).get("sha256")
        or member1_json.get("sha256")
        or threat_intel_json.get("sha256")
        or "unknown_sha256"
    )

    vt_data = threat_intel_json.get("virustotal", {})
    mb_data = threat_intel_json.get("malwarebazaar", {})

    # Step 1: Component Risk Normalization (0-100)
    s_m1, clone_mismatch = extract_member1_static_risk(member1_json)
    s_m2 = extract_member2_ml_risk(member2_json)
    s_m3, is_cloud_known, ti_kill_switches = evaluate_threat_intel_risk(vt_data, mb_data)

    critical_overrides = list(ti_kill_switches)
    if clone_mismatch:
        claimed_prod = member1_json.get("certificate_status", {}).get("claimed_product_name") or "known application"
        critical_overrides.append(f"Counterfeit Publisher Identity Mismatch detected by Member 1 (Claims {claimed_prod} but unsigned)")

    # Step 2: Dynamic Weight Shifting
    if is_cloud_known and s_m3 is not None:
        # Mode A: Cloud-Verified Consensus
        # 50% Threat Intel, 30% ML Model, 20% Static Binary
        w_m1 = 0.20
        w_m2 = 0.30
        w_m3 = 0.50
        strategy_desc = "Cloud-Verified Weighted Consensus (50% TI / 30% ML / 20% Static)"
        active_weights = {"member1_static": w_m1, "member2_ml": w_m2, "member3_ti": w_m3}
        final_risk = (w_m1 * s_m1) + (w_m2 * s_m2) + (w_m3 * s_m3)
    else:
        # Mode B: Dynamic Zero-Day Weight Shift
        # When cloud intelligence has no record (404), do NOT lower risk!
        # Shift weights to 55% ML Model and 45% Static Analysis
        w_m1 = 0.45
        w_m2 = 0.55
        w_m3 = 0.00
        strategy_desc = "Dynamic Zero-Day Weight Shift (55% ML / 45% Static / 0% Cloud TI)"
        active_weights = {"member1_static": w_m1, "member2_ml": w_m2, "member3_ti": w_m3}
        final_risk = (w_m1 * s_m1) + (w_m2 * s_m2)

    # Step 3: Hard Kill-Switch Overrides
    # If confirmed malware or counterfeit clone, floor final risk at 90.0+ (Trust Score <= 10.0)
    if critical_overrides:
        final_risk = max(final_risk, 90.0)

    final_risk_score = round(max(0.0, min(100.0, final_risk)), 2)
    final_trust_score = round(max(0.0, min(100.0, 100.0 - final_risk_score)), 2)

    # Step 4: Decision Verdict & Recommended Action
    if final_trust_score >= 75.0:
        verdict = "TRUSTED / SAFE TO INSTALL"
        recommended_action = "ALLOW"
    elif final_trust_score >= 40.0:
        verdict = "SUSPICIOUS / PROCEED WITH CAUTION"
        recommended_action = "WARN_USER"
    else:
        verdict = "MALICIOUS OR COUNTERFEIT / DO NOT INSTALL"
        recommended_action = "BLOCK_AND_QUARANTINE"

    # Assemble Standardized Final JSON Schema
    return {
        "sha256": sha256,
        "threat_intelligence": {
            "virustotal": vt_data,
            "malwarebazaar": mb_data
        },
        "component_risk_breakdown": {
            "member1_static_risk_score": round(s_m1, 2),
            "member2_ml_probability_score": round(s_m2, 2),
            "member3_threat_intel_risk_score": round(s_m3, 2) if s_m3 is not None else "N/A (Zero-Day Unknown)",
            "weighting_strategy_used": strategy_desc,
            "active_weights": active_weights
        },
        "final_decision": {
            "final_risk_score": final_risk_score,
            "final_trust_score": final_trust_score,
            "verdict": verdict,
            "recommended_action": recommended_action,
            "critical_overrides_triggered": critical_overrides
        }
    }

def evaluate_sample_consensus(
    sha256: str,
    member1_json: Optional[Dict[str, Any]] = None,
    member2_json: Optional[Dict[str, Any]] = None,
    api_key_vt: Optional[str] = None,
    api_key_mb: Optional[str] = None
) -> Dict[str, Any]:
    """
    High-level evaluation function:
    Queries Threat Intelligence (live API with automatic cache fallback)
    and executes consensus scoring.
    """
    from threat_intel.vt_client import query_virustotal
    from threat_intel.mb_client import query_malwarebazaar

    m1 = member1_json or {}
    m2 = member2_json or {}

    imphash = m1.get("hashes", {}).get("imphash")

    vt_res = query_virustotal(sha256, api_key_vt)
    mb_res = query_malwarebazaar(sha256, imphash=imphash, api_key=api_key_mb)

    ti_bundle = {
        "sha256": sha256,
        "virustotal": vt_res,
        "malwarebazaar": mb_res
    }

    return compute_final_trust_score(m1, m2, ti_bundle)
