"""
CertiScan Studio // MalDetect-AI Unified CLI Tool
Group IA3: Fake Software & Malware Detection Suite
Command-Line Interface executing the full 4-stage Defense-in-Depth pipeline
with Dual-AI Engine integration (Member 2 XGBoost + AI Model 2 EMBER2024 LightGBM).
"""

import os
import sys
import json
import argparse
from typing import Optional

# Ensure standard output handles UTF-8 on Windows command lines
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Setup sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
MEMBER1_DIR = os.path.join(ROOT_DIR, "Daniel", "trustshield-member1")
MEMBER2_DIR = os.path.join(ROOT_DIR, "Jerom", "trustshield-member2")
MEMBER3_DIR = os.path.join(ROOT_DIR, "Krishanth", "threatfuse-member3")
MEMBER4_DIR = os.path.join(ROOT_DIR, "Rohith", "certiscan-maldetect-ai")
AI_MODEL2_DIR = os.path.join(ROOT_DIR, "AI model 2")

for path in [ROOT_DIR, MEMBER4_DIR, MEMBER1_DIR, MEMBER2_DIR, MEMBER3_DIR, AI_MODEL2_DIR]:
    if os.path.exists(path) and path not in sys.path:
        sys.path.insert(0, path)

from integration.pipeline_orchestrator import run_full_security_pipeline, load_scenario_preset
from integration.ai_model2_adapter import predict_binary_with_ai2, load_ai2_test_samples, get_ai_model2_predictor
from reporting.pdf_generator import generate_pdf_report

BANNER = r"""
========================================================================
  ______                   __  ____  __     _        __     __ 
 /_  __/______  __________/ /_/ __/ / /    (_)___   / /____/ / 
  / / / ___/ / / / ___/ _  / / /_  / /    / / _ \  / / __  /  
 / / / /  / /_/ (__  ) // / / __/ / /___ / /  __/ / / // /   
/_/ /_/   \__,_/____/\_,_/ /_/   /_____//_/\___/ /_/\_,_/    
    CertiScan Studio // MalDetect-AI Unified Defense-in-Depth
  [Dual-AI Engines: Jerom XGBoost v1.2 + EMBER2024 LightGBM 620D]
========================================================================
"""


def run_test_sample_benchmark(sample_idx: int):
    """Executes AI Model 2 on a specified held-out test sample from Weeks 53-64."""
    meta, X_test, y_test = load_ai2_test_samples()
    if not meta or X_test is None or y_test is None:
        print("[!] Error: Held-out test set files not found in 'AI model 2/processed'.")
        sys.exit(1)

    if sample_idx < 0 or sample_idx >= len(meta):
        print(f"[!] Error: Sample index must be between 0 and {len(meta) - 1}.")
        sys.exit(1)

    predictor = get_ai_model2_predictor()
    chosen_meta = meta[sample_idx]
    x_vec = X_test[sample_idx]
    true_label = int(y_test[sample_idx])

    res = predictor.predict_features(x_vec)
    pred_label = res["prediction"]
    is_correct = (pred_label == true_label)

    print(BANNER)
    print(f"--- AI MODEL 2: HELD-OUT TEST SAMPLE EVALUATION (INDEX #{sample_idx}) ---")
    print(f" SHA-256 HASH:     {chosen_meta.get('sha256')}")
    print(f" FILE TYPE:        {chosen_meta.get('file_type', 'ELF')}")
    print(f" VT DETECTION:     {chosen_meta.get('detection_ratio', 'N/A')}")
    print(f" GROUND TRUTH:     {'MALICIOUS (1)' if true_label == 1 else 'BENIGN (0)'}")
    print(f" MODEL PREDICTION: {'MALICIOUS (1)' if pred_label == 1 else 'BENIGN (0)'}")
    print(f" CONFIDENCE:       {res['confidence']*100:.2f}%")
    print(f" P(MALICIOUS):     {res['prob_malicious']*100:.2f}%")
    print(f" P(BENIGN):        {res['prob_benign']*100:.2f}%")
    print(f" VERDICT ACCURACY: {'[PASS] CORRECT PREDICTION' if is_correct else '[WARN] MISMATCH'}")
    print("========================================================================\n")


def main():
    parser = argparse.ArgumentParser(
        description="CertiScan Studio / MalDetect-AI Unified Master Security Scanner (Group IA3)"
    )
    parser.add_argument("binary_file", nargs="?", default=None, help="Path to executable or installer (.exe, .dll, .msi, .apk, .elf, .bin)")
    parser.add_argument("--scenario", "-s", choices=["1", "2", "3", "4"], help="Evaluate one of the 4 verified IA3 demo scenarios")
    parser.add_argument("--deep-ai", "--ai-model2", dest="deep_ai", action="store_true", help="Include AI Model 2 (EMBER2024 LightGBM 620-dim) deep binary evaluation")
    parser.add_argument("--test-ai2", type=int, default=None, help="Evaluate AI Model 2 on a specified held-out test sample index (0-11999)")
    parser.add_argument("--vt-key", help="VirusTotal v3 API Key (optional)")
    parser.add_argument("--mb-key", help="MalwareBazaar Auth Key (optional)")
    parser.add_argument("--json-out", "-o", help="Filepath to export merged IA3 JSON report")
    parser.add_argument("--pdf-out", help="Filepath to generate and export Forensic PDF report (.pdf)")
    parser.add_argument("--raw", action="store_true", help="Print only raw JSON output to stdout")

    args = parser.parse_args()

    # Handle dedicated test sample evaluation
    if args.test_ai2 is not None:
        run_test_sample_benchmark(args.test_ai2)
        sys.exit(0)

    if not args.binary_file and not args.scenario:
        parser.print_help()
        sys.exit(1)

    # 1. Fetch analysis report
    ai2_result = None
    if args.scenario:
        report = load_scenario_preset(f"scenario_{args.scenario}")
    else:
        if not os.path.exists(args.binary_file):
            print(f"[!] Error: Target file '{args.binary_file}' not found.")
            sys.exit(1)
        report = run_full_security_pipeline(
            args.binary_file,
            vt_api_key=args.vt_key,
            mb_api_key=args.mb_key
        )

        # Run AI Model 2 (Deep Binary 620-dim LightGBM)
        try:
            ai2_result = predict_binary_with_ai2(args.binary_file)
            report["ai_model_2"] = ai2_result
        except Exception as e:
            report["ai_model_2"] = {"status": "ERROR", "error": str(e)}

    # 2. Raw JSON mode
    if args.raw:
        print(json.dumps(report, indent=2))
        sys.exit(0)

    # 3. Formatted Terminal Display
    print(BANNER)
    m1 = report.get("member1_static", {})
    m2 = report.get("member2_ml", {})
    m3_ti = report.get("member3_threat_intel", {})
    m3_dec = report.get("member3_decision", {}).get("trust_decision", {})

    file_info = m1.get("file_info", {})
    cert = m1.get("certificate_status", {})
    hashes = m1.get("hashes", {})
    pe_meta = m1.get("pe_metadata", {})
    ml_pred = m2.get("ml_prediction", {})
    vt = m3_ti.get("virustotal", {})
    mb = m3_ti.get("malwarebazaar", {})

    filename = file_info.get("filename", "binary.exe")
    size_bytes = file_info.get("size_bytes", 0)
    trust_score = float(m3_dec.get("final_trust_score", 50.0))
    risk_score = float(m3_dec.get("final_risk_score", 50.0))
    verdict = m3_dec.get("verdict", "UNKNOWN")
    action = m3_dec.get("recommended_action", "INSPECT")
    kill_switches = m3_dec.get("kill_switch_overrides", [])

    print(f" TARGET FILE:       {filename} ({size_bytes:,} bytes)")
    print(f" DETECTED FORMAT:   {file_info.get('detected_format', 'PE32 Executable')}")
    print(f" SHANNON ENTROPY:   {file_info.get('overall_shannon_entropy', 0.0):.4f} / 8.0000 (Packed: {file_info.get('is_likely_packed', False)})")
    print(f" SHA-256 HASH:      {hashes.get('sha256', 'N/A')}")
    print(f" IMPHASH:           {pe_meta.get('imphash', 'N/A')}")
    print(f" AUTHENTICODE:      {'VALID SIGNED' if cert.get('is_signed') else 'UNSIGNED'} (Signer: {cert.get('subject_cn', 'None')})")
    print(f" CLONE ALERT:       {'[!] MISMATCH DETECTED' if cert.get('clone_mismatch_detected') else '[OK] NONE'}")
    print(f"-----------------------------------------------------------------")
    print(f" FINAL TRUST SCORE: {trust_score:.2f} / 100.0  (Risk: {risk_score:.2f}%)")
    print(f" VERDICT:           [ {verdict} ]")
    print(f" ACTION DIRECTIVE:  >>> {action} <<<")
    
    if kill_switches:
        print(f" [!] CRITICAL KILL-SWITCH OVERRIDES:")
        for ks in kill_switches:
            print(f"     * {ks}")

    print(f"-----------------------------------------------------------------")
    print(f" 3-Pillar Defense-in-Depth Breakdown:")
    pillar_scores = m3_dec.get("pillar_scores", {})
    weights = m3_dec.get("weight_distribution", {})
    print(f"   * Member 1 (Static Binary Risk):    {pillar_scores.get('member1_static_risk', 0.0):.1f}% (Weight: {weights.get('member1_static_weight', 0.0)*100:.0f}%)")
    print(f"   * Member 2 (ML Malware Prob):       {pillar_scores.get('member2_ml_probability', 0.0):.1f}% (Weight: {weights.get('member2_ml_weight', 0.0)*100:.0f}%)")
    ti_score = pillar_scores.get('member3_cloud_ti_risk')
    ti_str = f"{ti_score:.1f}%" if ti_score is not None else "N/A (Zero-Day)"
    print(f"   * Member 3 (Threat Intel Risk):     {ti_str} (Weight: {weights.get('member3_ti_weight', 0.0)*100:.0f}%)")
    print(f"   * Active Strategy:                  {weights.get('strategy', 'Consensus')}")

    print(f"-----------------------------------------------------------------")
    print(f" Machine Learning & Threat Intelligence Telemetry:")
    print(f"   * AI Engine 1 (Jerom XGBoost):      {ml_pred.get('malware_probability_score', 0.0):.1f}% | Risk Tier: {ml_pred.get('risk_tier', 'BENIGN')}")
    print(f"   * VirusTotal v3:                    {vt.get('detection_ratio', '0/72')} engines flagged")
    print(f"   * MalwareBazaar:                    {mb.get('signature', 'None')} ({mb.get('query_status', 'not_found')})")

    # Display AI Model 2 Telemetry if available
    if ai2_result and ai2_result.get("status") == "SUCCESS":
        print(f"-----------------------------------------------------------------")
        print(f" 🚀 AI Model 2: EMBER2024 Deep Binary Telemetry (LightGBM):")
        print(f"   * Classification Verdict:           [ {ai2_result['prediction_label']} ]")
        print(f"   * Malicious Risk Probability:       {ai2_result['prob_malicious_pct']:.2f}% (Confidence: {ai2_result['confidence_pct']:.2f}%)")
        print(f"   * Benign Probability:               {ai2_result['prob_benign_pct']:.2f}%")
        top_f = ai2_result.get("top_features", [])
        if top_f:
            print(f"   * Dominant Byte/Entropy Feature:    {top_f[0]['feature']} (raw: {top_f[0]['raw_value']:.4f})")

    print(f"=================================================================\n")

    # 4. Optional Exports
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[OK] Standardized IA3 JSON telemetry saved to: {args.json_out}")

    if args.pdf_out:
        pdf_bytes = generate_pdf_report(report)
        with open(args.pdf_out, "wb") as f:
            f.write(pdf_bytes)
        print(f"[OK] Multi-Section Forensic Audit PDF saved to: {args.pdf_out}")


if __name__ == "__main__":
    main()
