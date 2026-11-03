"""
AI Model 2 Adapter for CertiScan Studio // MalDetect-AI Suite
Seamlessly bridges AI Model 2 (EMBER2024 LightGBM 620-dim Classifier)
into the unified IA3 ecosystem without path or module collisions.
"""

import os
import sys
import json
import importlib.util
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import numpy as np

# Cache singleton instances
_AI2_PREDICTOR = None
_AI2_METADATA = None
_AI2_TEST_SAMPLES = None

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
AI2_DIR = ROOT_DIR / "AI model 2"
MODELS_DIR = AI2_DIR / "models"
PROCESSED_DIR = AI2_DIR / "processed"


def get_ai_model2_predictor():
    """
    Dynamically loads and returns the singleton MalwarePredictor for AI Model 2.
    """
    global _AI2_PREDICTOR
    if _AI2_PREDICTOR is not None:
        return _AI2_PREDICTOR

    prep_path = AI2_DIR / "preprocess.py"
    inf_path = AI2_DIR / "inference.py"
    model_path = MODELS_DIR / "best_model.joblib"
    preprocessor_path = MODELS_DIR / "preprocessor.joblib"

    if not model_path.exists() or not preprocessor_path.exists():
        raise FileNotFoundError(f"AI Model 2 weights not found at {MODELS_DIR}")

    # Load preprocess module dynamically
    spec_prep = importlib.util.spec_from_file_location("ai2_preprocess", prep_path)
    prep_mod = importlib.util.module_from_spec(spec_prep)
    spec_prep.loader.exec_module(prep_mod)
    setattr(sys.modules["__main__"], "EmberPreprocessor", prep_mod.EmberPreprocessor)

    # Load inference module dynamically
    spec_inf = importlib.util.spec_from_file_location("ai2_inference", inf_path)
    inf_mod = importlib.util.module_from_spec(spec_inf)
    spec_inf.loader.exec_module(inf_mod)

    _AI2_PREDICTOR = inf_mod.MalwarePredictor(
        model_path=model_path,
        preprocessor_path=preprocessor_path
    )
    return _AI2_PREDICTOR


def predict_binary_with_ai2(file_path: str) -> Dict[str, Any]:
    """
    Executes AI Model 2 inference on any raw binary executable (.exe, .dll, .elf, .apk, .bin).
    Returns formatted prediction results with probabilities and top contributing features.
    """
    predictor = get_ai_model2_predictor()
    res = predictor.predict_binary_file(file_path)
    return {
        "model_name": "EMBER2024-LightGBM-620D",
        "modality": "Universal-Binary-ELF",
        "prediction_label": "MALICIOUS" if res["prediction"] == 1 else "BENIGN",
        "is_malicious": bool(res["prediction"] == 1),
        "confidence_pct": round(float(res["confidence"]) * 100, 2),
        "prob_malicious_pct": round(float(res["prob_malicious"]) * 100, 2),
        "prob_benign_pct": round(float(res["prob_benign"]) * 100, 2),
        "top_features": res.get("top_features", []),
        "status": "SUCCESS"
    }


def load_ai2_metadata() -> Dict[str, Any]:
    """
    Loads and caches model metadata and candidate benchmarks.
    """
    global _AI2_METADATA
    if _AI2_METADATA is not None:
        return _AI2_METADATA

    meta_path = MODELS_DIR / "model_metadata.json"
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            _AI2_METADATA = json.load(f)
    else:
        _AI2_METADATA = {}
    return _AI2_METADATA


def load_ai2_test_samples() -> Tuple[list, Optional[np.ndarray], Optional[np.ndarray]]:
    """
    Loads and caches the 12,000 held-out test sample metadata and preprocessed matrices.
    """
    global _AI2_TEST_SAMPLES
    if _AI2_TEST_SAMPLES is not None:
        return _AI2_TEST_SAMPLES

    meta_file = PROCESSED_DIR / "test_meta_ELF.json"
    x_test_file = PROCESSED_DIR / "X_test_ELF.npy"
    y_test_file = PROCESSED_DIR / "y_test_ELF.npy"

    if meta_file.exists() and x_test_file.exists() and y_test_file.exists():
        with open(meta_file, "r", encoding="utf-8") as f:
            metadata = json.load(f)
        X_test = np.load(x_test_file)
        y_test = np.load(y_test_file)
        _AI2_TEST_SAMPLES = (metadata, X_test, y_test)
    else:
        _AI2_TEST_SAMPLES = ([], None, None)

    return _AI2_TEST_SAMPLES

