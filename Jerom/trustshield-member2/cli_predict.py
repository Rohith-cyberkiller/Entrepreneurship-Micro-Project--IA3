"""
TrustShield Member 2 CLI Predictor
Accepts Member 1's static analysis JSON output and executes ML probability scoring.
"""

import sys
import os
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml_engine.model_inference import predict_risk

def print_banner():
    banner = r"""
========================================================================
  ______                   __  ____  __     _        __     __ 
 /_  __/______  __________/ /_/ __/ / /    (_)___   / /____/ / 
  / / / ___/ / / / ___/ _  / / /_  / /    / / _ \  / / __  /  
 / / / /  / /_/ (__  ) // / / __/ / /___ / /  __/ / / // /   
/_/ /_/   \__,_/____/\_,_/ /_/   /_____//_/\___/ /_/\_,_/    
    Member 2: Machine Learning Malware & Repacking Classifier
========================================================================
"""
    print(banner)

def main():
    parser = argparse.ArgumentParser(
        description="TrustShield Member 2: ML Malware Probability & Anomaly Classifier"
    )
    parser.add_argument("json_file", nargs="?", help="Path to Member 1 static analysis JSON report", default=None)
    parser.add_argument("-o", "--output", help="Save ML prediction JSON to specified file", default=None)
    parser.add_argument("--raw", action="store_true", help="Print only raw JSON payload")

    args = parser.parse_args()

    # Read from file or stdin
    if args.json_file:
        if not os.path.exists(args.json_file):
            print(f"Error: JSON report not found: {args.json_file}", file=sys.stderr)
            sys.exit(1)
        with open(args.json_file, "r", encoding="utf-8") as f:
            m1_data = json.load(f)
    elif not sys.stdin.isatty():
        m1_data = json.load(sys.stdin)
    else:
        print("Usage: py cli_predict.py <member1_report.json> [-o output.json]")
        print("Or pipe: py ..\\Daniel\\cli_scanner.py demo_samples\\sample2_fake_chrome_clone.exe --raw | py cli_predict.py")
        sys.exit(1)

    result = predict_risk(m1_data)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"[+] Successfully wrote ML inference payload to: {args.output}")

    if args.raw:
        print(json.dumps(result, indent=2))
    else:
        print_banner()
        pred = result["ml_prediction"]
        score = pred["malware_probability_score"]
        verdict = pred["classification_verdict"]

        print(f" TARGET FILE:       {result.get('filename')}")
        print(f" MODEL TYPE:        {pred.get('model_type')}")
        print(f" MALWARE PROBABILITY: {score:.1f}%")
        print(f" VERDICT:           [ {verdict} ] (Confidence: {pred.get('confidence_level')})")
        print("-" * 65)
        print(" Top Contributing Risk Features:")
        for feat in pred.get("top_contributing_features", []):
            print(f"   * {feat['feature']:25s} ({feat['impact']:>7s}) : {feat['description']}")
        print("-" * 65 + "\n")
        print(">>> STANDARDIZED MEMBER 2 ML JSON PAYLOAD <<<")
        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
