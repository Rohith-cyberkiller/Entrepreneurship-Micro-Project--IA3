"""
Threat Intelligence Package
Member 3: Threat Intelligence & Decision Engine Lead
External API Client (VirusTotal v3 & MalwareBazaar) + Offline Cache Manager
"""

from .vt_client import query_virustotal
from .mb_client import query_malwarebazaar, query_malwarebazaar_imphash
from .cache_manager import get_cached_threat_intel, save_to_cache

__all__ = [
    "query_virustotal",
    "query_malwarebazaar",
    "query_malwarebazaar_imphash",
    "get_cached_threat_intel",
    "save_to_cache"
]
