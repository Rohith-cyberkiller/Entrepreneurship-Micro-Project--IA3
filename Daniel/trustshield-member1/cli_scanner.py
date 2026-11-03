"""
TrustShield CLI Scanner
Member 1: Cryptographic & Static Binary Analysis Engine
Accepts a binary or APK file path, executes the complete IA3 static analysis pipeline,
and outputs the standardized JSON payload (to terminal or saved file).
"""

import sys
import os
import json
import argparse
from typing import Optional

# Ensure analyzer package can be resolved
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer.core_pipeline import analyze_binary

def print_banner():
    banner = r"""
========================================================================
  ______                   __  ____  __     _        __     __ 
 /_  __/______  __________/ /_/ __/ / /    (_)___   / /____/ / 
  / / / ___/ / / / ___/ _  / / /_  / /    / / _ \  / / __  /  
 / / / /  / /_/ (__  ) // / / __/ / /___ / /  __/ / / // /   
/_/ /_/   \__,_/____/\_,_/ /_/   /_____//_/\___/ /_/\_,_/    
   Member 1: Cryptographic & Static Binary Analysis Engine
========================================================================
"""
    print(banner)

def print_executive_summary(report: dict):
    file_info = report.get("file_info", {})
    cert = report.get("certificate_status", {})
    risk = report.get("risk_assessment", {})
    hashes = report.get("hashes", {})
    pe_meta = report.get("pe_metadata", {})

    verdict = risk.get("verdict", "UNKNOWN")
    score = risk.get("risk_score", 0)

    # Color highlights
    color_reset = "\033[0m"
    if "SAFE" in verdict:
        v_color = "\033[92m" # Green
    elif "SUSPICIOUS" in verdict:
        v_color = "\033[93m" # Yellow
    else:
        v_color = "\033[91m" # Red

    print(f"\n{'-'*65}")
    print(f" FILE:       {file_info.get('filename')} ({file_info.get('size_bytes', 0):,} bytes)")
    print(f" FORMAT:     {file_info.get('detected_format')} [Magic: {file_info.get('magic_bytes')}]")
    print(f" ENTROPY:    {file_info.get('overall_shannon_entropy', 0.0):.4f} / 8.0000 (Packed: {file_info.get('is_likely_packed')})")
    print(f" SHA-256:    {hashes.get('sha256')}")
    print(f" IMPHASH:    {hashes.get('imphash')}")
    print(f" SIGNATURE:  {cert.get('verification_status')} (Signer: {cert.get('signer_common_name') or 'None'})")
    print(f" CLONE ALERT:{' YES - Mismatch Detected!' if cert.get('clone_mismatch_detected') else ' No'}")
    print(f" VERDICT:    {v_color}[ {verdict} ]{color_reset} - Risk Score: {v_color}{score}/100{color_reset}")
    print(f"{'-'*65}")

    reasons = risk.get("reasons", [])
    if reasons:
        print(" [!] Key Risk Indicators & Anomalies:")
        for r in reasons:
            print(f"     * {r}")
    
    suspicious = pe_meta.get("suspicious_imports", [])
    if suspicious:
        print(f" [!] Suspicious IAT APIs Flagged: {', '.join(suspicious)}")
    print(f"{'-'*65}\n")

def main():
    parser = argparse.ArgumentParser(
        description="TrustShield Member 1: Cryptographic & Static Binary Analyzer CLI"
    )
    parser.add_argument("target", nargs="?", default=None, help="Path to executable (.exe, .dll, .msi) or APK file")
    parser.add_argument("-i", "--input", dest="input_target", default=None, help="Alternative flag for target file path")
    parser.add_argument("-o", "--output", help="Save JSON report to specified file path", default=None)
    parser.add_argument("--raw", action="store_true", help="Print only raw JSON output (clean for piping)")
    parser.add_argument("--compact", action="store_true", help="Compact JSON formatting without indentation")

    args = parser.parse_args()

    target_path = args.target or args.input_target
    if not target_path:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(target_path):
        print(f"Error: Target file not found: {target_path}", file=sys.stderr)
        sys.exit(1)

    try:
        report = analyze_binary(target_path)
    except Exception as ex:
        print(f"Analysis failed: {ex}", file=sys.stderr)
        sys.exit(1)

    # Save to file if requested
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"[+] Successfully wrote IA3 JSON report to: {args.output}")
        except Exception as ex:
            print(f"Error writing to output file: {ex}", file=sys.stderr)

    # Output to stdout
    if args.raw:
        indent = None if args.compact else 2
        print(json.dumps(report, indent=indent))
    else:
        print_banner()
        print_executive_summary(report)
        print(">>> IA3 STANDARDIZED JSON PAYLOAD <<<")
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
