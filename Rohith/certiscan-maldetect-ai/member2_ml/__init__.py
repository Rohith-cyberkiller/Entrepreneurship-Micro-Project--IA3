"""
Member 2 Machine Learning & Anomaly Classification Package
Exposes MalwarePredictor and inference functions from Jerom's trustshield-member2 module.
"""

import os
import sys

MEMBER4_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE_ROOT = os.path.dirname(os.path.dirname(MEMBER4_DIR))
MEMBER2_DIR = os.path.join(WORKSPACE_ROOT, "Jerom", "trustshield-member2")

if os.path.exists(MEMBER2_DIR) and MEMBER2_DIR not in sys.path:
    sys.path.insert(0, MEMBER2_DIR)

from ml_engine.model_inference import MalwarePredictor, predict_risk, FEATURE_COLUMNS

__all__ = [
    "MalwarePredictor",
    "predict_risk",
    "FEATURE_COLUMNS"
]
