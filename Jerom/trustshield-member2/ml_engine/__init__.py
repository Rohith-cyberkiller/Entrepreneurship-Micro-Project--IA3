"""
TrustShield ML Engine
Member 2: Machine Learning Engineer & Anomaly Classification Lead
Malware & Repacking Probability Classifier
"""

from .model_inference import MalwarePredictor, predict_risk
from .train_model import train_model, generate_synthetic_dataset

__all__ = [
    "MalwarePredictor",
    "predict_risk",
    "train_model",
    "generate_synthetic_dataset"
]
