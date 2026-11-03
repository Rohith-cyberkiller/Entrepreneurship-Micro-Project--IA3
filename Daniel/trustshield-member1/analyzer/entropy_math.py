"""
Module 4: Shannon Entropy & Packer Detection Engine
Computes byte-level Shannon Entropy using math.log2 from 0.0000 to 8.0000,
detects packed sections, and identifies known packer signatures.
"""

import math
import os
from collections import Counter
from typing import Dict, Any, List, Tuple, Optional
import pefile

PACKER_SECTION_SIGNATURES = {
    "UPX": ["UPX0", "UPX1", "UPX2", ".upx"],
    "ASPack": [".aspack", ".adata", "aspack"],
    "Themida": [".themida", "themida", ".boot"],
    "VMProtect": [".vmp0", ".vmp1", ".vmp2", "vmp0", "vmp1"],
    "PECompact": [".pec", "pec1", "pec2", "pecompact2"],
    "Enigma": [".enigma1", ".enigma2"],
    "Petite": [".petite"],
    "FSG": [".fsg"]
}

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Computes Shannon Entropy H(X) = -sum(P(x) * log2(P(x)))
    Returns float rounded to 4 decimal places (0.0000 to 8.0000).
    """
    if not data:
        return 0.0000

    length = len(data)
    byte_counts = Counter(data)
    entropy = 0.0

    for count in byte_counts.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)

def calculate_file_entropy(filepath: str) -> float:
    """
    Computes overall Shannon entropy of an entire file using streaming chunk counts
    to handle files of any size without loading entire file into memory.
    """
    if not os.path.exists(filepath):
        return 0.0000

    total_size = os.path.getsize(filepath)
    if total_size == 0:
        return 0.0000

    byte_counts = Counter()
    with open(filepath, "rb") as f:
        while chunk := f.read(64 * 1024):
            byte_counts.update(chunk)

    entropy = 0.0
    for count in byte_counts.values():
        p_x = count / total_size
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)

def detect_packers_by_section_names(section_names: List[str]) -> List[str]:
    """
    Checks section names against known packer fingerprints.
    """
    detected = []
    for s_name in section_names:
        clean_name = s_name.strip("\x00").strip().lower()
        for packer_name, signatures in PACKER_SECTION_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in clean_name and packer_name not in detected:
                    detected.append(packer_name)
    return detected

def analyze_pe_sections_entropy(pe_obj: pefile.PE) -> Tuple[List[Dict[str, Any]], bool, List[str]]:
    """
    Iterates through all PE sections, calculates entropy per section, checks W+X permissions,
    and determines if the binary is likely packed.
    """
    sections_info = []
    is_packed = False
    reasons = []

    all_section_names = []

    for section in pe_obj.sections:
        # Decode section name
        try:
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00").strip()
        except Exception:
            name = "UNKNOWN"

        all_section_names.append(name)
        raw_size = section.SizeOfRawData
        virtual_size = section.Misc_VirtualSize
        
        # Calculate section entropy
        section_data = section.get_data()
        entropy = calculate_shannon_entropy(section_data)

        # Check W+X: Writable (0x80000000) and Executable (0x20000000)
        chars = section.Characteristics
        is_writable = bool(chars & 0x80000000)
        is_executable = bool(chars & 0x20000000)
        wx_risk = is_writable and is_executable

        sec_entry = {
            "name": name,
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "entropy": entropy,
            "wx_risk": wx_risk
        }
        sections_info.append(sec_entry)

        # Packing Indicators:
        # 1. High entropy (> 7.2) in executable or non-resource section
        if entropy > 7.2:
            is_packed = True
            reasons.append(f"High Shannon entropy ({entropy:.4f}) in section '{name}' indicates packed/encrypted code")

        # 2. Section with raw_size == 0 but large virtual size (e.g. UPX0)
        if raw_size == 0 and virtual_size > 4096:
            is_packed = True
            reasons.append(f"Section '{name}' has raw size 0 but large virtual size ({virtual_size} bytes), characteristic of runtime unpacking")

        # 3. W+X permissions
        if wx_risk:
            reasons.append(f"Section '{name}' has both Writable and Executable (W+X) permissions")

    # Check for known packer section names
    packers_detected = detect_packers_by_section_names(all_section_names)
    if packers_detected:
        is_packed = True
        reasons.append(f"Known packer signature(s) detected in section names: {', '.join(packers_detected)}")

    return sections_info, is_packed, reasons
