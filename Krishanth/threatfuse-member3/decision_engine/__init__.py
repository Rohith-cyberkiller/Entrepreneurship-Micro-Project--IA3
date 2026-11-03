"""
Decision Engine Package
Member 3: Threat Intelligence & Decision Engine Lead
Dynamic Weighted Trust Score & Consensus Gateway
"""

from .trust_scorer import compute_final_trust_score, evaluate_sample_consensus

__all__ = [
    "compute_final_trust_score",
    "evaluate_sample_consensus"
]
