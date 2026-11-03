"""
TrustShield Analyzer Package
Member 1: Cryptographic & Static Binary Analysis Engine
"""

from .core_pipeline import analyze_binary, analyze_file
from .ingestion import inspect_file_header, detect_extension_masquerading
from .crypto_hash import calculate_hashes, check_known_bad_hash
from .entropy_math import calculate_shannon_entropy, calculate_file_entropy
from .cert_verifier import verify_authenticode, check_counterfeit_clone
from .pe_apk_parser import parse_pe_metadata, parse_apk_metadata

__all__ = [
    "analyze_binary",
    "analyze_file",
    "inspect_file_header",
    "detect_extension_masquerading",
    "calculate_hashes",
    "check_known_bad_hash",
    "calculate_shannon_entropy",
    "calculate_file_entropy",
    "verify_authenticode",
    "check_counterfeit_clone",
    "parse_pe_metadata",
    "parse_apk_metadata"
]
