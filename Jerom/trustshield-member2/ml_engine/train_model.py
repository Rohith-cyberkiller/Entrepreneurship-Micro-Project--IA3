"""
Module 1 & 2: Dataset Generator, Model Training & Evaluation Engine
Generates balanced synthetic PE feature training data, trains an ensemble
XGBoost/RandomForest classifier, reports performance metrics, and serializes the model.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
from typing import Dict, Any, Tuple

from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report
import xgboost as xgb

FEATURE_COLUMNS = [
    "overall_shannon_entropy",
    "file_size_bytes",
    "section_count",
    "max_section_entropy",
    "compile_timestamp_anomaly",
    "is_signed",
    "clone_mismatch_detected",
    "wx_permission_risk",
    "is_likely_packed",
    "suspicious_imports_count",
    "has_process_injection",
    "has_masquerading"
]

def generate_synthetic_dataset(output_path: str = "data/training_dataset.csv", n_samples: int = 5000, random_seed: int = 42) -> pd.DataFrame:
    """
    Generates a balanced dataset of clean vs malicious/counterfeit Windows PE executables
    reflecting real-world threat telemetry.
    """
    np.random.seed(random_seed)
    n_clean = n_samples // 2
    n_mal = n_samples - n_clean

    data = []

    # 1. Generate Clean/Benign Samples (n_clean)
    for _ in range(n_clean):
        entropy = float(np.clip(np.random.normal(5.2, 0.65), 2.5, 6.7))
        size = int(np.random.lognormal(mean=13.0, sigma=1.2)) # ~100KB to 50MB
        sec_count = int(np.random.choice([3, 4, 5, 6, 7], p=[0.15, 0.40, 0.30, 0.10, 0.05]))
        max_sec_ent = float(np.clip(entropy + np.random.uniform(0.1, 0.6), entropy, 6.95))
        ts_anomaly = int(np.random.choice([0, 1], p=[0.985, 0.015]))
        is_signed = int(np.random.choice([1, 0], p=[0.88, 0.12]))
        clone_mismatch = 0 # Clean files never spoof vendor identity
        wx_risk = int(np.random.choice([0, 1], p=[0.995, 0.005]))
        is_packed = int(np.random.choice([0, 1], p=[0.98, 0.02]))
        suspicious_count = int(np.random.choice([0, 1], p=[0.95, 0.05]))
        has_injection = 0
        has_masquerading = 0

        data.append([
            entropy, size, sec_count, max_sec_ent, ts_anomaly, is_signed,
            clone_mismatch, wx_risk, is_packed, suspicious_count, has_injection,
            has_masquerading, 0 # is_malware = 0
        ])

    # 2. Generate Malware / Counterfeit / Packed Samples (n_mal)
    for _ in range(n_mal):
        # 3 distinct threat archetypes
        archetype = np.random.choice(["counterfeit", "packed", "masquerade_injector"], p=[0.35, 0.35, 0.30])

        if archetype == "counterfeit":
            # Poses as popular app (Google Chrome, VLC) without legitimate signature
            entropy = float(np.clip(np.random.normal(5.5, 0.8), 2.8, 7.5))
            size = int(np.random.lognormal(12.5, 1.0))
            sec_count = int(np.random.choice([3, 4, 5]))
            max_sec_ent = float(np.clip(entropy + np.random.uniform(0.2, 0.8), entropy, 7.8))
            ts_anomaly = int(np.random.choice([0, 1], p=[0.75, 0.25]))
            is_signed = int(np.random.choice([0, 1], p=[0.85, 0.15])) # Usually unsigned or untrusted
            clone_mismatch = 1 # CRITICAL counterfeit indicator
            wx_risk = int(np.random.choice([0, 1], p=[0.80, 0.20]))
            is_packed = int(max_sec_ent > 7.2)
            suspicious_count = int(np.random.randint(1, 5))
            has_injection = int(np.random.choice([0, 1], p=[0.60, 0.40]))
            has_masquerading = int(np.random.choice([0, 1], p=[0.85, 0.15]))

        elif archetype == "packed":
            # Packed with UPX, Themida, ASPack, encrypted payload
            entropy = float(np.clip(np.random.normal(7.65, 0.25), 7.25, 7.99))
            size = int(np.random.lognormal(11.8, 1.1))
            sec_count = int(np.random.choice([2, 3, 4])) # Minimal sections like UPX0, UPX1
            max_sec_ent = float(np.clip(entropy + np.random.uniform(0.05, 0.25), 7.4, 7.995))
            ts_anomaly = int(np.random.choice([0, 1], p=[0.65, 0.35]))
            is_signed = int(np.random.choice([0, 1], p=[0.92, 0.08]))
            clone_mismatch = int(np.random.choice([0, 1], p=[0.75, 0.25]))
            wx_risk = int(np.random.choice([1, 0], p=[0.85, 0.15])) # W+X self-modifying code
            is_packed = 1
            suspicious_count = int(np.random.randint(0, 4))
            has_injection = int(np.random.choice([0, 1], p=[0.70, 0.30]))
            has_masquerading = 0

        else: # masquerade_injector
            # Double extension, process injection triad, downloader APIs
            entropy = float(np.clip(np.random.normal(5.8, 0.9), 3.2, 7.6))
            size = int(np.random.lognormal(11.0, 1.2))
            sec_count = int(np.random.choice([2, 3, 4, 5]))
            max_sec_ent = float(np.clip(entropy + np.random.uniform(0.2, 0.9), entropy, 7.7))
            ts_anomaly = int(np.random.choice([1, 0], p=[0.55, 0.45]))
            is_signed = 0
            clone_mismatch = int(np.random.choice([0, 1], p=[0.80, 0.20]))
            wx_risk = int(np.random.choice([0, 1], p=[0.60, 0.40]))
            is_packed = int(max_sec_ent > 7.2)
            suspicious_count = int(np.random.randint(3, 8))
            has_injection = 1 # VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
            has_masquerading = 1 # invoice.pdf.exe

        data.append([
            entropy, size, sec_count, max_sec_ent, ts_anomaly, is_signed,
            clone_mismatch, wx_risk, is_packed, suspicious_count, has_injection,
            has_masquerading, 1 # is_malware = 1
        ])

    df = pd.DataFrame(data, columns=FEATURE_COLUMNS + ["is_malware"])
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)

    # Save to CSV
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[+] Successfully generated balanced training dataset: {output_path} ({len(df)} samples)")
    return df

def train_model(
    data_path: str = "data/training_dataset.csv",
    model_output_path: str = "ml_engine/trained_model.pkl",
    random_seed: int = 42
) -> Dict[str, Any]:
    """
    Trains an XGBoost ensemble classifier on PE static telemetry,
    evaluates performance using 5-fold cross-validation, and saves the trained pipeline.
    """
    if not os.path.exists(data_path):
        print(f"Dataset '{data_path}' not found. Generating synthetic dataset...")
        df = generate_synthetic_dataset(data_path, n_samples=5000, random_seed=random_seed)
    else:
        df = pd.read_csv(data_path)

    X = df[FEATURE_COLUMNS]
    y = df["is_malware"]

    # 80/20 Train/Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=random_seed, stratify=y
    )

    print(f"Training XGBoost Classifier on {len(X_train)} samples, testing on {len(X_test)} samples...")

    # Configure robust XGBoost Classifier
    model = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        eval_metric="logloss",
        random_state=random_seed
    )

    model.fit(X_train, y_train)

    # Predictions & Probabilities
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    # Calculate metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)

    # 5-fold cross validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_seed)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="roc_auc")
    mean_cv_auc = float(np.mean(cv_scores))

    print("\n" + "="*50)
    print("      TRUSTSHIELD ML MODEL EVALUATION RESULTS     ")
    print("="*50)
    print(f"  Accuracy:            {acc * 100:.2f}%")
    print(f"  Precision:           {prec * 100:.2f}%")
    print(f"  Recall:              {rec * 100:.2f}%")
    print(f"  F1-Score:            {f1 * 100:.2f}%")
    print(f"  ROC-AUC Score:       {roc_auc:.4f}")
    print(f"  5-Fold Mean CV AUC:  {mean_cv_auc:.4f}")
    print("="*50 + "\n")

    # Feature Importance Mapping
    importances = model.feature_importances_
    feat_importance_dict = {
        col: round(float(imp) * 100, 2)
        for col, imp in sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True)
    }

    print("Top Feature Importances:")
    for f, imp in list(feat_importance_dict.items())[:6]:
        print(f"  - {f}: {imp}%")

    metrics_summary = {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
        "mean_cv_auc": round(mean_cv_auc, 4),
        "test_sample_count": len(X_test),
        "total_sample_count": len(df)
    }

    # Bundle artifact
    artifact = {
        "model": model,
        "feature_names": FEATURE_COLUMNS,
        "model_type": "XGBoost Classifier (v1.2)",
        "metrics": metrics_summary,
        "feature_importances": feat_importance_dict
    }

    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    joblib.dump(artifact, model_output_path)
    print(f"\n[+] Serialized model artifact saved to: {model_output_path}")

    return artifact

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ds_path = os.path.join(base_dir, "data", "training_dataset.csv")
    mdl_path = os.path.join(base_dir, "ml_engine", "trained_model.pkl")
    train_model(ds_path, mdl_path)
