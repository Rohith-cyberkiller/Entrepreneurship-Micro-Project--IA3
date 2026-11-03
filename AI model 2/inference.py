"""
Production Inference Script for EMBER2024 Malware Classification
Loads champion model & preprocessor from models/ to classify binary files,
EMBER JSON feature records, or preprocessed arrays.
"""

import os
import sys
import json
import math
import argparse
from pathlib import Path
from typing import Dict, Any, Union, Tuple, List
import numpy as np
import joblib

# Add current workspace to path for preprocessor import
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from preprocess import extract_features_from_dict, EmberPreprocessor, FEATURE_NAMES

# Ensure pickle compatibility across scripts
setattr(sys.modules["__main__"], "EmberPreprocessor", EmberPreprocessor)


def extract_features_from_raw_binary(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Extracts raw EMBER-compatible features directly from any executable/binary file on disk:
    byte histogram, 256-bin entropy, printable strings, file size, and magic bytes.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    data = path.read_bytes()
    size = len(data)

    # 1. Byte Histogram
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    histogram = counts[:256].tolist()

    # 2. Byte Entropy (sliding window entropy estimation)
    window_size = 2048
    step_size = 1024
    byteentropy = [0.0] * 256

    if size > 0:
        # Approximate 256-bin entropy histogram
        num_windows = max(1, (size - window_size) // step_size + 1)
        for w in range(min(num_windows, 50)):
            start = w * step_size
            chunk = data[start : start + window_size]
            if len(chunk) == 0:
                break
            w_counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
            probs = w_counts / len(chunk)
            # Shannon entropy of window
            ent = -sum(p * math.log2(p) for p in probs if p > 0)
            bin_idx = min(255, int((ent / 8.0) * 256))
            byteentropy[bin_idx] += 1.0

    # 3. String statistics
    strings_list = []
    current = []
    for b in data:
        if 0x20 <= b <= 0x7E:
            current.append(chr(b))
        else:
            if len(current) >= 4:
                strings_list.append("".join(current))
            current = []
    if len(current) >= 4:
        strings_list.append("".join(current))

    numstrings = len(strings_list)
    avlength = float(np.mean([len(s) for s in strings_list])) if strings_list else 0.0
    printables = sum(len(s) for s in strings_list)

    # Printable ASCII distribution
    pdist = [0] * 96
    for s in strings_list:
        for ch in s:
            idx = ord(ch) - 0x20
            if 0 <= idx < 96:
                pdist[idx] += 1

    # String entropy
    if printables > 0:
        p_probs = [c / printables for c in pdist if c > 0]
        str_entropy = -sum(p * math.log2(p) for p in p_probs)
    else:
        str_entropy = 0.0

    # Overall file entropy
    if size > 0:
        probs = [c / size for c in counts if c > 0]
        gen_entropy = -sum(p * math.log2(p) for p in probs)
    else:
        gen_entropy = 0.0

    start_bytes = list(data[:4])

    return {
        "histogram": histogram,
        "byteentropy": byteentropy,
        "strings": {
            "numstrings": numstrings,
            "avlength": avlength,
            "printables": printables,
            "entropy": str_entropy,
            "printabledist": pdist
        },
        "general": {
            "size": size,
            "entropy": gen_entropy,
            "is_pe": 1 if data[:2] == b"MZ" else 0,
            "start_bytes": start_bytes
        }
    }


class MalwarePredictor:
    """Production Inference Engine."""

    def __init__(
        self,
        model_path: Union[str, Path] = CURRENT_DIR / "models" / "best_model.joblib",
        preprocessor_path: Union[str, Path] = CURRENT_DIR / "models" / "preprocessor.joblib"
    ):
        self.model_path = Path(model_path)
        self.preprocessor_path = Path(preprocessor_path)

        if not self.model_path.exists():
            raise FileNotFoundError(f"Model artifact missing: {self.model_path}")
        if not self.preprocessor_path.exists():
            raise FileNotFoundError(f"Preprocessor artifact missing: {self.preprocessor_path}")

        print(f"[Inference] Loading champion model from {self.model_path.name}...")
        self.model = joblib.load(self.model_path)
        print(f"[Inference] Loading preprocessor from {self.preprocessor_path.name}...")
        self.preprocessor = joblib.load(self.preprocessor_path)

        # Feature names
        self.feature_names = getattr(self.preprocessor, "feature_names", FEATURE_NAMES)

    def predict_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a single EMBER dictionary."""
        feat = extract_features_from_dict(record)
        return self.predict_features(feat)

    def predict_binary_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Classify any executable or binary file from disk."""
        record = extract_features_from_raw_binary(file_path)
        result = self.predict_record(record)
        result["file_path"] = str(file_path)
        result["file_size_bytes"] = record["general"]["size"]
        return result

    def predict_features(self, feat_vector: np.ndarray) -> Dict[str, Any]:
        """Classify a 1D raw feature vector."""
        if feat_vector.ndim == 1:
            X_raw = feat_vector.reshape(1, -1)
        else:
            X_raw = feat_vector

        # Transform features using trained preprocessor
        X_proc = self.preprocessor.transform(X_raw)

        # Predict probability & label
        probs = self.model.predict_proba(X_proc)[0]
        pred_label = int(np.argmax(probs))
        confidence = float(probs[pred_label])

        verdict = "MALICIOUS" if pred_label == 1 else "BENIGN"

        # Determine top 5 contributing features (based on feature value * model importance)
        top_features = []
        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
            weights = np.abs(X_proc[0]) * importances
            top_indices = np.argsort(weights)[::-1][:5]
            for idx in top_indices:
                top_features.append({
                    "feature": self.feature_names[idx],
                    "raw_value": float(X_raw[0, idx]),
                    "importance_weight": float(weights[idx])
                })

        return {
            "prediction": pred_label,
            "verdict": verdict,
            "confidence": confidence,
            "prob_benign": float(probs[0]),
            "prob_malicious": float(probs[1]),
            "top_features": top_features
        }


def run_test_sample_demonstration(predictor: MalwarePredictor, sample_idx: int = 0):
    """Pulls a genuine held-out test sample to demonstrate prediction."""
    proc_dir = CURRENT_DIR / "processed"
    x_test_file = proc_dir / "X_test_ELF.npy"
    y_test_file = proc_dir / "y_test_ELF.npy"
    meta_file = proc_dir / "test_meta_ELF.json"

    if not x_test_file.exists():
        print("Test data not found in processed/ directory. Generating mock sample.")
        mock_raw = np.zeros(620, dtype=np.float32)
        mock_raw[0:10] = 0.05
        result = predictor.predict_features(mock_raw)
        print(json.dumps(result, indent=2))
        return

    X_test_proc = np.load(x_test_file)
    y_test = np.load(y_test_file)
    metadata = []
    if meta_file.exists():
        with open(meta_file, "r") as f:
            metadata = json.load(f)

    # Pick samples: one Benign (label 0) and one Malicious (label 1)
    idx_benign = int(np.where(y_test == 0)[0][sample_idx % 1000])
    idx_malicious = int(np.where(y_test == 1)[0][sample_idx % 1000])

    print("\n" + "=" * 70)
    print("LIVE INFERENCE DEMONSTRATION ON UNSEEN HELD-OUT TEST SAMPLES")
    print("=" * 70)

    for case_name, sample_idx, true_lbl in [
        ("TEST CASE 1 (Ground Truth: BENIGN)", idx_benign, 0),
        ("TEST CASE 2 (Ground Truth: MALICIOUS)", idx_malicious, 1)
    ]:
        probs = predictor.model.predict_proba(X_test_proc[sample_idx:sample_idx+1])[0]
        pred_lbl = int(np.argmax(probs))
        meta = metadata[sample_idx] if sample_idx < len(metadata) else {}

        print(f"\n>>> {case_name}")
        if meta:
            print(f"  SHA256:          {meta.get('sha256', 'N/A')}")
            print(f"  File Type:       {meta.get('file_type', 'N/A')}")
            print(f"  VT Detection:    {meta.get('detection_ratio', 'N/A')}")
            print(f"  Week Uploaded:   Week {meta.get('week_id', 'N/A')}")

        print(f"  Model Verdict:   [{'MALICIOUS' if pred_lbl == 1 else 'BENIGN'}]")
        print(f"  Confidence:      {probs[pred_lbl]*100:.2f}%")
        print(f"  P(Benign):       {probs[0]*100:.2f}%")
        print(f"  P(Malicious):    {probs[1]*100:.2f}%")
        is_correct = "CORRECT [PASS]" if pred_lbl == true_lbl else "INCORRECT [FAIL]"
        print(f"  Prediction Test: {is_correct}")

    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Run Malware Classification Inference")
    parser.add_argument("--file", type=str, default=None, help="Path to raw binary file to inspect and classify")
    parser.add_argument("--json", type=str, default=None, help="JSON string of EMBER features")
    parser.add_argument("--test-sample", action="store_true", help="Run inference on real unseen test samples")
    parser.add_argument("--sample-idx", type=int, default=42, help="Sample index for test run")
    args = parser.parse_args()

    predictor = MalwarePredictor()

    if args.file:
        print(f"\nAnalyzing binary file: {args.file}")
        res = predictor.predict_binary_file(args.file)
        print(f"File Size:    {res.get('file_size_bytes', 0):,} bytes")
        print(f"Verdict:      [{res['verdict']}]")
        print(f"Confidence:   {res['confidence']*100:.2f}%")
        print(f"P(Malicious): {res['prob_malicious']*100:.2f}%")
        print(f"P(Benign):    {res['prob_benign']*100:.2f}%")
        print("\nTop Contributing Features:")
        for tf in res.get("top_features", []):
            print(f" - {tf['feature']:<25}: raw={tf['raw_value']:.4f}, weight={tf['importance_weight']:.4f}")

    elif args.json:
        record = json.loads(args.json)
        res = predictor.predict_record(record)
        print(json.dumps(res, indent=2))

    else:
        # Default: demonstrate on real held-out test data
        run_test_sample_demonstration(predictor, sample_idx=args.sample_idx)


if __name__ == "__main__":
    main()
