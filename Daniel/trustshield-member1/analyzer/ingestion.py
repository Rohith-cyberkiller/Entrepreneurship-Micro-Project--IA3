"""
Module 1: Safe File Ingestion & Magic Byte Engine
Reads files in safe chunks, extracts magic bytes, identifies file formats,
and flags extension masquerading.
"""

import os
from typing import Dict, Any, Tuple

CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunk size

# Common signatures (hex strings uppercase without spaces)
SIGNATURES = {
    b"\x4D\x5A": "Windows PE Executable",
    b"\x50\x4B\x03\x04": "ZIP / Android APK Archive",
    b"\x7F\x45\x4C\x46": "Linux ELF Executable",
    b"\x25\x50\x44\x46": "PDF Document",
    b"\xFF\xD8\xFF": "JPEG Image",
    b"\x89\x50\x4E\x47": "PNG Image",
    b"\x52\x61\x72\x21": "RAR Archive",
    b"\x37\x7A\xBC\xAF\x27\x1C": "7-Zip Archive"
}

DISGUISE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".txt", ".csv", ".mp3", ".mp4"
}

def inspect_file_header(filepath: str) -> Dict[str, Any]:
    """
    Safely reads file header in binary mode ('rb') to extract magic bytes,
    file size, and determine the binary format.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    size_bytes = os.path.getsize(filepath)
    magic_bytes_raw = b""

    with open(filepath, "rb") as f:
        magic_bytes_raw = f.read(8)

    # Format first 4 bytes as uppercase space-separated hex: "4D 5A 90 00"
    first_4 = magic_bytes_raw[:4]
    magic_bytes_hex = " ".join(f"{b:02X}" for b in first_4)

    detected_format = "Unknown Binary Format"
    if magic_bytes_raw.startswith(b"\x4D\x5A"):
        # Check if it has a PE header offset at 0x3C
        detected_format = "Windows PE Executable"
    elif magic_bytes_raw.startswith(b"\x50\x4B\x03\x04"):
        if filepath.lower().endswith(".apk"):
            detected_format = "Android Package (APK)"
        else:
            detected_format = "ZIP / Android APK Archive"
    else:
        for sig, name in SIGNATURES.items():
            if magic_bytes_raw.startswith(sig):
                detected_format = name
                break

    filename = os.path.basename(filepath)
    is_masquerading, masquerade_reason = detect_extension_masquerading(filename, magic_bytes_raw)

    return {
        "filename": filename,
        "size_bytes": size_bytes,
        "magic_bytes": magic_bytes_hex,
        "detected_format": detected_format,
        "extension_masquerading": is_masquerading,
        "masquerading_reason": masquerade_reason
    }

def detect_extension_masquerading(filename: str, magic_bytes: bytes) -> Tuple[bool, str]:
    """
    Detects if an executable attempts to disguise itself using deceptive file extensions.
    Catches:
    1. Double extensions (e.g. invoice.pdf.exe, photo.jpg.exe)
    2. Document extension with MZ magic bytes (e.g. payload.pdf with MZ executable header)
    """
    name_lower = filename.lower()
    is_mz = magic_bytes.startswith(b"\x4D\x5A")

    # Check for double extensions like file.pdf.exe
    parts = name_lower.split(".")
    if len(parts) >= 3:
        second_to_last = f".{parts[-2]}"
        final_ext = f".{parts[-1]}"
        if second_to_last in DISGUISE_EXTENSIONS and final_ext in [".exe", ".scr", ".pif", ".com", ".bat", ".vbs"]:
            return True, f"Double extension masquerading detected: '{filename}' pretends to be a {second_to_last.upper()} document but executes as an executable ({final_ext})."

    # Check if file has document extension but starts with MZ header
    _, ext = os.path.splitext(name_lower)
    if ext in DISGUISE_EXTENSIONS and is_mz:
        return True, f"Critical masquerading detected: File has document extension '{ext}' but binary contains Windows PE executable header ('4D 5A')."

    return False, ""
