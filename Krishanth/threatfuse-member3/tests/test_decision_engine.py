"""
Unit Tests for Member 3 Decision Engine & Threat Intelligence Consensus
Validates:
1. Cloud-Verified Consensus vs. Dynamic Zero-Day Weight Shifting
2. Hard Kill-Switch Overrides (MalwareBazaar, VT >= 5, Clone Mismatch)
3. Final Trust Score thresholds and recommended actions (ALLOW, WARN, BLOCK)
"""

import os
import sys
import json

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from decision_engine.trust_scorer import compute_final_trust_score, evaluate_sample_consensus
from threat_intel.cache_manager import get_cached_threat_intel

# Load test inputs
INPUTS_PATH = os.path.join(PROJECT_ROOT, "data", "sample_m1_m2_inputs.json")
with open(INPUTS_PATH, "r", encoding="utf-8") as f:
    SAMPLE_INPUTS = json.load(f)

def test_scenario1_clean_vlc():
    data = SAMPLE_INPUTS["scenario_1_vlc_clean"]
    ti = get_cached_threat_intel(data["sha256"])
    res = compute_final_trust_score(data["member1_static"], data["member2_ml"], ti)

    decision = res["final_decision"]
    assert decision["final_trust_score"] >= 75.0, f"Expected Trust Score >= 75.0, got {decision['final_trust_score']}"
    assert decision["verdict"] == "TRUSTED / SAFE TO INSTALL"
    assert decision["recommended_action"] == "ALLOW"
    assert len(decision["critical_overrides_triggered"]) == 0

def test_scenario2_fake_chrome_killswitch():
    data = SAMPLE_INPUTS["scenario_2_fake_chrome_trojan"]
    ti = get_cached_threat_intel(data["sha256"])
    res = compute_final_trust_score(data["member1_static"], data["member2_ml"], ti)

    decision = res["final_decision"]
    breakdown = res["component_risk_breakdown"]

    assert decision["final_risk_score"] >= 90.0, f"Expected Risk >= 90.0, got {decision['final_risk_score']}"
    assert decision["final_trust_score"] <= 10.0, f"Expected Trust <= 10.0, got {decision['final_trust_score']}"
    assert decision["verdict"] == "MALICIOUS OR COUNTERFEIT / DO NOT INSTALL"
    assert decision["recommended_action"] == "BLOCK_AND_QUARANTINE"

    # Verify critical kill switch triggers
    overrides = decision["critical_overrides_triggered"]
    assert any("MalwareBazaar" in o for o in overrides)
    assert any("VirusTotal" in o for o in overrides)
    assert any("Counterfeit" in o for o in overrides)

def test_scenario3_zero_day_weight_shift():
    data = SAMPLE_INPUTS["scenario_3_zero_day_packed"]
    ti = get_cached_threat_intel(data["sha256"])
    res = compute_final_trust_score(data["member1_static"], data["member2_ml"], ti)

    decision = res["final_decision"]
    breakdown = res["component_risk_breakdown"]

    # Verify Dynamic Zero-Day Weight Shifting occurred
    assert breakdown["active_weights"]["member3_ti"] == 0.0, "Zero-day must assign 0% weight to missing cloud APIs"
    assert breakdown["active_weights"]["member2_ml"] == 0.55, "Zero-day must assign 55% weight to ML probability"
    assert breakdown["active_weights"]["member1_static"] == 0.45, "Zero-day must assign 45% weight to Static analysis"
    assert "Dynamic Zero-Day Weight Shift" in breakdown["weighting_strategy_used"]

    # Assert unknown hash did NOT cause malware to slip through with low risk
    assert decision["final_risk_score"] >= 80.0, "Zero-day packed malware must not receive artificially low risk"
    assert decision["final_trust_score"] <= 20.0
    assert decision["recommended_action"] == "BLOCK_AND_QUARANTINE"

def test_scenario4_grayware_adware():
    data = SAMPLE_INPUTS["scenario_4_grayware_adware"]
    ti = get_cached_threat_intel(data["sha256"])
    res = compute_final_trust_score(data["member1_static"], data["member2_ml"], ti)

    decision = res["final_decision"]
    assert 40.0 <= decision["final_trust_score"] < 75.0, f"Expected Trust in [40, 75), got {decision['final_trust_score']}"
    assert decision["verdict"] == "SUSPICIOUS / PROCEED WITH CAUTION"
    assert decision["recommended_action"] == "WARN_USER"

if __name__ == "__main__":
    print("Running Member 3 Decision Engine Tests...")
    test_scenario1_clean_vlc()
    print("  [PASSED] Scenario 1 (Clean VLC): Final Trust Score >= 75.0 -> ALLOW")
    test_scenario2_fake_chrome_killswitch()
    print("  [PASSED] Scenario 2 (Fake Chrome Trojan): Hard Kill-Switch Overrides -> BLOCK (Trust < 10.0)")
    test_scenario3_zero_day_weight_shift()
    print("  [PASSED] Scenario 3 (Zero-Day Packed): Dynamic Zero-Day Weight Shift Verified (55% ML / 45% Static)")
    test_scenario4_grayware_adware()
    print("  [PASSED] Scenario 4 (Grayware / Adware): Suspicious Score -> WARN_USER")
    print("\nALL MEMBER 3 TESTS PASSED SUCCESSFULLY! [OK]")
