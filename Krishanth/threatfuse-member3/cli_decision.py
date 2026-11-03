"""
TrustShield Member 3 CLI Decision Engine
Executes VirusTotal & MalwareBazaar threat lookups, combines Member 1 and Member 2 telemetry,
and outputs the standardized Final Trust Score JSON payload.
"""

import sys
import os
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from decision_engine.trust_scorer import compute_final_trust_score, evaluate_sample_consensus
from threat_intel.cache_manager import get_cached_threat_intel

INPUTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "sample_m1_m2_inputs.json")

def print_banner():
    banner = r"""
========================================================================
  ______                   __  ____  __     _        __     __ 
 /_  __/______  __________/ /_/ __/ / /    (_)___   / /____/ / 
  / / / ___/ / / / ___/ _  / / /_  / /    / / _ \  / / __  /  
 / / / /  / /_/ (__  ) // / / __/ / /___ / /  __/ / / // /   
/_/ /_/   \__,_/____/\_,_/ /_/   /_____//_/\___/ /_/\_,_/    
    Member 3: Threat Intelligence & Decision Engine Lead
========================================================================
"""
    print(banner)

def main():
    parser = argparse.ArgumentParser(
        description="TrustShield Member 3: Threat Intelligence & Consensus Decision Engine"
    )
    parser.add_argument("--scenario", "-s", type=int, choices=[1, 2, 3, 4], help="Run one of the 4 standard IA3 evaluation scenarios", default=None)
    parser.add_argument("--sha256", help="Query threat intelligence for a SHA-256 hash", default=None)
    parser.add_argument("--m1", help="Path to Member 1 static analysis JSON report", default=None)
    parser.add_argument("--m2", help="Path to Member 2 ML prediction JSON report", default=None)
    parser.add_argument("-o", "--output", help="Save final merged JSON payload to file", default=None)
    parser.add_argument("--raw", action="store_true", help="Print only raw JSON output")

    args = parser.parse_args()

    # Load sample inputs
    sample_inputs = {}
    if os.path.exists(INPUTS_PATH):
        try:
            with open(INPUTS_PATH, "r", encoding="utf-8") as f:
                sample_inputs = json.load(f)
        except Exception:
            pass

    scenario_map = {
        1: "scenario_1_vlc_clean",
        2: "scenario_2_fake_chrome_trojan",
        3: "scenario_3_zero_day_packed",
        4: "scenario_4_grayware_adware"
    }

    m1_data = {}
    m2_data = {}
    sha256 = None

    if args.scenario:
        sc_key = scenario_map[args.scenario]
        sc_data = sample_inputs.get(sc_key, {})
        m1_data = sc_data.get("member1_static", {})
        m2_data = sc_data.get("member2_ml", {})
        sha256 = sc_data.get("sha256")
    elif args.m1 or args.m2:
        if args.m1 and os.path.exists(args.m1):
            with open(args.m1, "r", encoding="utf-8") as f:
                m1_data = json.load(f)
        if args.m2 and os.path.exists(args.m2):
            with open(args.m2, "r", encoding="utf-8") as f:
                m2_data = json.load(f)
        sha256 = args.sha256 or m1_data.get("hashes", {}).get("sha256") or m1_data.get("sha256")
    elif args.sha256:
        sha256 = args.sha256
    else:
        # Default to Scenario 2 as requested in prompt Step 4
        sc_data = sample_inputs.get("scenario_2_fake_chrome_trojan", {})
        m1_data = sc_data.get("member1_static", {})
        m2_data = sc_data.get("member2_ml", {})
        sha256 = sc_data.get("sha256")

    if not sha256:
        sha256 = "unknown_sha256"

    # Execute Consensus Evaluation
    result = evaluate_sample_consensus(sha256, m1_data, m2_data)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            print(f"[+] Successfully wrote Merged Final Trust Score report to: {args.output}")
        except Exception as ex:
            print(f"Error saving file: {ex}", file=sys.stderr)

    if args.raw:
        print(json.dumps(result, indent=2))
    else:
        print_banner()
        breakdown = result["component_risk_breakdown"]
        decision = result["final_decision"]
        ti = result["threat_intelligence"]
        vt = ti.get("virustotal", {})
        mb = ti.get("malwarebazaar", {})

        print(f" SHA-256:             {result.get('sha256')}")
        print(f" FINAL TRUST SCORE:   {decision['final_trust_score']} / 100.0  (Risk: {decision['final_risk_score']}%)")
        print(f" VERDICT:             [ {decision['verdict']} ]")
        print(f" RECOMMENDED ACTION:  >>> {decision['recommended_action']} <<<")
        print("-" * 65)
        print(" 3-Pillar Component Risk Breakdown:")
        print(f"   * Member 1 (Static Analysis Risk):    {breakdown['member1_static_risk_score']}%")
        print(f"   * Member 2 (ML Malware Probability):  {breakdown['member2_ml_probability_score']}%")
        print(f"   * Member 3 (Threat Intel Cloud Risk): {breakdown['member3_threat_intel_risk_score']}%")
        print(f"   * Weighting Strategy:                 {breakdown['weighting_strategy_used']}")
        print("-" * 65)
        print(" Cloud Threat Intelligence:")
        print(f"   * VirusTotal:      {vt.get('malicious_count', 0)}/{vt.get('total_engines', 0)} vendors flagged ({vt.get('threat_label') or 'Clean'})")
        print(f"   * MalwareBazaar:   {'MATCH: ' + str(mb.get('signature_family')) if mb.get('found') else 'Not Listed'}")

        overrides = decision.get("critical_overrides_triggered", [])
        if overrides:
            print("-" * 65)
            print(" [!] CRITICAL KILL-SWITCH OVERRIDES TRIGGERED:")
            for o in overrides:
                print(f"     - {o}")
        print("-" * 65 + "\n")
        print(">>> STANDARDIZED MERGED FINAL TRUST SCORE JSON PAYLOAD <<<")
        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
