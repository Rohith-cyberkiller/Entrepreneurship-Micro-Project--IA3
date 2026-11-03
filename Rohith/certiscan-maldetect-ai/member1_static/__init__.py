"""
Member 1 Static Binary & Cryptographic Package
Exposes core analysis functions from Daniel's trustshield-member1 module.
"""

import os
import sys

MEMBER4_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE_ROOT = os.path.dirname(os.path.dirname(MEMBER4_DIR))
MEMBER1_DIR = os.path.join(WORKSPACE_ROOT, "Daniel", "trustshield-member1")

if os.path.exists(MEMBER1_DIR) and MEMBER1_DIR not in sys.path:
    sys.path.insert(0, MEMBER1_DIR)

from analyzer.core_pipeline import analyze_binary
from analyzer.ingestion import inspect_file_header, detect_extension_masquerading
from analyzer.crypto_hash import calculate_hashes, check_known_bad_hash
from analyzer.cert_verifier import verify_authenticode
from analyzer.entropy_math import calculate_file_entropy, analyze_pe_sections_entropy
from analyzer.pe_apk_parser import parse_pe_metadata, parse_apk_metadata

__all__ = [
    "analyze_binary",
    "inspect_file_header",
    "detect_extension_masquerading",
    "calculate_hashes",
    "check_known_bad_hash",
    "verify_authenticode",
    "calculate_file_entropy",
    "analyze_pe_sections_entropy",
    "parse_pe_metadata",
    "parse_apk_metadata"
]
