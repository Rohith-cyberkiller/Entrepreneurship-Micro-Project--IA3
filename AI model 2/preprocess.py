"""
Preprocess Pipeline for EMBER2024 Malware Classification Benchmark
Safe for Windows paths, streaming ZIP extraction, zero data leakage.
"""

import os
import sys
import json
import zipfile
import argparse
import numpy as np
from pathlib import Path
import joblib
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any, Tuple, List, Optional


FEATURE_NAMES: List[str] = (
    [f"byte_hist_{i:03d}" for i in range(256)] +
    [f"byte_entropy_{i:03d}" for i in range(256)] +
    [f"printable_ascii_{i:02d}" for i in range(96)] +
    [
        "strings_numstrings",
        "strings_avlength",
        "strings_printables",
        "strings_entropy",
        "general_size",
        "general_log_size",
        "general_entropy",
        "general_is_pe",
        "magic_byte_0",
        "magic_byte_1",
        "magic_byte_2",
        "magic_byte_3"
    ]
)


def extract_features_from_dict(d: Dict[str, Any]) -> np.ndarray:
    """
    Extracts the 620-dimensional universal feature vector from an EMBER JSON dictionary.
    Excludes all metadata and leaking identifiers (md5, sha256, dates, detection_ratio).
    """
    feat = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
    idx = 0

    # 1. Byte Histogram (256 dims) - normalized to probability distribution
    hist = d.get("histogram")
    if hist and len(hist) == 256:
        h_arr = np.array(hist, dtype=np.float32)
        total = np.sum(h_arr)
        if total > 0:
            feat[idx : idx + 256] = h_arr / total
        else:
            feat[idx : idx + 256] = 0.0
    idx += 256

    # 2. Byte Entropy (256 dims)
    be = d.get("byteentropy")
    if be and len(be) == 256:
        feat[idx : idx + 256] = np.array(be, dtype=np.float32)
    idx += 256

    # 3. Printable ASCII Character Distribution (96 dims)
    strings = d.get("strings") or {}
    pdist = strings.get("printabledist")
    if pdist and len(pdist) == 96:
        p_arr = np.array(pdist, dtype=np.float32)
        ptotal = np.sum(p_arr)
        if ptotal > 0:
            feat[idx : idx + 96] = p_arr / ptotal
        else:
            feat[idx : idx + 96] = 0.0
    idx += 96

    # 4. Strings Scalar Properties (4 dims)
    feat[idx] = float(strings.get("numstrings") or 0)
    feat[idx + 1] = float(strings.get("avlength") or 0.0)
    feat[idx + 2] = float(strings.get("printables") or 0)
    feat[idx + 3] = float(strings.get("entropy") or 0.0)
    idx += 4

    # 5. General Properties (4 dims)
    general = d.get("general") or {}
    size = float(general.get("size") or 0)
    feat[idx] = size
    feat[idx + 1] = np.log1p(max(0.0, size))
    feat[idx + 2] = float(general.get("entropy") or 0.0)
    feat[idx + 3] = float(1.0 if general.get("is_pe") else 0.0)
    idx += 4

    # 6. Magic / Start Bytes (4 dims)
    start_bytes = general.get("start_bytes") or []
    for i in range(4):
        if i < len(start_bytes):
            try:
                feat[idx + i] = float(start_bytes[i])
            except (ValueError, TypeError):
                feat[idx + i] = 0.0
        else:
            feat[idx + i] = 0.0

    return feat


class EmberPreprocessor:
    """
    Modular preprocessor pipeline that fits strictly on training data
    to prevent any data leakage.
    """
    __module__ = "preprocess"

    def __init__(self, with_scaling: bool = True):
        self.with_scaling = with_scaling
        self.imputer = SimpleImputer(strategy="median")
        self.scaler = StandardScaler() if with_scaling else None
        self.feature_names = FEATURE_NAMES
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> "EmberPreprocessor":
        """Fit imputer and scaler on training data only."""
        X_clean = np.where(np.isnan(X) | np.isinf(X), np.nan, X)
        X_imp = self.imputer.fit_transform(X_clean)
        if self.scaler:
            self.scaler.fit(X_imp)
        self.is_fitted = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transform features using fitted parameters."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before transforming.")
        X_clean = np.where(np.isnan(X) | np.isinf(X), np.nan, X)
        X_imp = self.imputer.transform(X_clean)
        if self.scaler:
            return self.scaler.transform(X_imp)
        return X_imp

    def fit_transform(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> np.ndarray:
        return self.fit(X, y).transform(X)

    def save(self, filepath: Path):
        """Save fitted preprocessor to disk."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, filepath)
        print(f"[Preprocessor] Saved to {filepath}")

    @staticmethod
    def load(filepath: Path) -> "EmberPreprocessor":
        """Load fitted preprocessor from disk."""
        return joblib.load(filepath)


def load_ember_split(
    archive_path: Path,
    max_samples: Optional[int] = None,
    max_weeks: Optional[int] = None
) -> Tuple[np.ndarray, np.ndarray, List[Dict[str, Any]]]:
    """
    Streams weekly jsonl files directly from the zip archive.
    Returns (X, y, metadata_list).
    """
    if not archive_path.exists():
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    X_list = []
    y_list = []
    meta_list = []

    print(f"[DataLoader] Reading from {archive_path.name}...")
    with zipfile.ZipFile(archive_path, "r") as z:
        file_list = sorted(z.namelist())
        if max_weeks:
            file_list = file_list[:max_weeks]

        total_files = len(file_list)
        for f_idx, fname in enumerate(file_list, 1):
            with z.open(fname) as f:
                for line in f:
                    try:
                        record = json.loads(line.decode("utf-8"))
                    except Exception:
                        continue

                    label = record.get("label")
                    if label is None or label not in (0, 1):
                        continue

                    feat = extract_features_from_dict(record)
                    X_list.append(feat)
                    y_list.append(label)

                    meta_list.append({
                        "sha256": record.get("sha256", ""),
                        "file_type": record.get("file_type", ""),
                        "detection_ratio": record.get("detection_ratio", ""),
                        "week_id": record.get("week_id", 0),
                        "label": label
                    })

                    if max_samples and len(X_list) >= max_samples:
                        break

            print(f"  Processed [{f_idx}/{total_files}] files | Samples collected: {len(X_list):,}", end="\r")
            if max_samples and len(X_list) >= max_samples:
                break

    print(f"\n[DataLoader] Completed: {len(X_list):,} samples from {archive_path.name}")
    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)
    return X, y, meta_list


def main():
    parser = argparse.ArgumentParser(description="Preprocess EMBER2024 Dataset")
    parser.add_argument("--data-dir", type=str, default=r"C:\ENTER", help="Path to raw dataset directory")
    parser.add_argument("--modality", type=str, default="ELF", help="Modality (ELF, PDF, APK, Dot_Net, Win32, Win64)")
    parser.add_argument("--max-train-samples", type=int, default=None, help="Max train samples to load")
    parser.add_argument("--max-test-samples", type=int, default=None, help="Max test samples to load")
    parser.add_argument("--output-dir", type=str, default="processed", help="Directory to save processed arrays")
    parser.add_argument("--models-dir", type=str, default="models", help="Directory to save preprocessor")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    models_dir = Path(args.models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)

    train_zip = data_dir / f"{args.modality}_train.zip"
    test_zip = data_dir / f"{args.modality}_test.zip"

    print(f"=== Preprocessing Modality: {args.modality} ===")
    X_train_raw, y_train, train_meta = load_ember_split(train_zip, max_samples=args.max_train_samples)
    X_test_raw, y_test, test_meta = load_ember_split(test_zip, max_samples=args.max_test_samples)

    print(f"Train Shape: {X_train_raw.shape}, Label Dist: {np.bincount(y_train)}")
    print(f"Test Shape:  {X_test_raw.shape}, Label Dist: {np.bincount(y_test)}")

    # Fit preprocessor strictly on training data
    print("\nFitting Preprocessor on Training Split (No Leakage)...")
    preprocessor = EmberPreprocessor(with_scaling=True)
    X_train_proc = preprocessor.fit_transform(X_train_raw)
    X_test_proc = preprocessor.transform(X_test_raw)

    # Save preprocessor
    prep_path = models_dir / f"preprocessor_{args.modality}.joblib"
    preprocessor.save(prep_path)

    # Also save standard default preprocessor
    default_prep_path = models_dir / "preprocessor.joblib"
    preprocessor.save(default_prep_path)

    # Save processed arrays
    np.save(out_dir / f"X_train_{args.modality}.npy", X_train_proc)
    np.save(out_dir / f"y_train_{args.modality}.npy", y_train)
    np.save(out_dir / f"X_test_{args.modality}.npy", X_test_proc)
    np.save(out_dir / f"y_test_{args.modality}.npy", y_test)

    # Save feature names and metadata sample
    with open(out_dir / "feature_names.json", "w") as f:
        json.dump(FEATURE_NAMES, f, indent=2)

    with open(out_dir / f"test_meta_{args.modality}.json", "w") as f:
        json.dump(test_meta[:500], f, indent=2)

    print(f"[Done] Processed data saved to {out_dir}/ and preprocessor saved to {prep_path}")


if __name__ == "__main__":
    main()
