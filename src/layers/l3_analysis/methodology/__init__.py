"""
P6-06b: Business Logic Detection Methodology Module
P6-07d: WooYun Vulnerability Case Library

This module provides methodology documents and patterns for detecting
business logic vulnerabilities (D9 dimension) in code audits.

Business logic vulnerabilities are "missing security controls" rather than
"dangerous code patterns". They require Control-driven audit methodology:
  1. Enumerate operations/endpoints
  2. Verify security controls exist
  3. Missing control = Vulnerability

D9 Subtypes:
  - IDOR / Resource Ownership
  - Mass Assignment
  - State Machine Integrity
  - Race Conditions (TOCTOU, Lost Update)
  - Data Export / Bulk Operations
  - Multi-tenant Isolation

WooYun Case Library:
  - 88,636 real vulnerability cases from WooYun (2010-2016)
  - 8 vulnerability types with bypass techniques
  - Used as reference patterns for Agent audits
"""

from pathlib import Path

# Methodology document paths
METHODOLOGY_DIR = Path(__file__).parent

METHODOLOGY_FILES = {
    "general": METHODOLOGY_DIR / "business_logic.md",
    "python": METHODOLOGY_DIR / "python_business_logic.md",
    "java": METHODOLOGY_DIR / "java_business_logic.md",
    "go": METHODOLOGY_DIR / "go_business_logic.md",
}

# WooYun case library paths
WOOWYUN_DIR = METHODOLOGY_DIR / "wooyun"

WOOWYUN_FILES = {
    "index": WOOWYUN_DIR / "INDEX.md",
    "sql_injection": WOOWYUN_DIR / "sql-injection.md",
    "xss": WOOWYUN_DIR / "xss.md",
    "command_execution": WOOWYUN_DIR / "command-execution.md",
    "logic_flaws": WOOWYUN_DIR / "logic-flaws.md",
    "file_upload": WOOWYUN_DIR / "file-upload.md",
    "unauthorized_access": WOOWYUN_DIR / "unauthorized-access.md",
    "info_disclosure": WOOWYUN_DIR / "info-disclosure.md",
    "file_traversal": WOOWYUN_DIR / "file-traversal.md",
}

# Vulnerability type statistics from WooYun
WOOWYUN_STATS = {
    "sql_injection": 27732,
    "xss": 7532,
    "command_execution": 6826,
    "logic_flaws": 8292,
    "file_upload": 2711,
    "unauthorized_access": 14377,
    "info_disclosure": 7337,
    "file_traversal": 2854,
    "total": 88636,
}


def get_methodology_path(language: str | None = None) -> Path | None:
    """
    Get the path to a methodology document.

    Args:
        language: Language-specific methodology, or None for general.

    Returns:
        Path to the methodology document, or None if not found.
    """
    key = language if language else "general"
    return METHODOLOGY_FILES.get(key)


def list_available_methodologies() -> list[str]:
    """
    List available methodology languages.

    Returns:
        List of language codes with available methodologies.
    """
    return [k for k, v in METHODOLOGY_FILES.items() if v.exists()]


def get_wooyun_path(vuln_type: str | None = None) -> Path | None:
    """
    Get the path to a WooYun case library document.

    Args:
        vuln_type: Vulnerability type key, or None for index.
                   Valid keys: sql_injection, xss, command_execution,
                   logic_flaws, file_upload, unauthorized_access,
                   info_disclosure, file_traversal

    Returns:
        Path to the WooYun document, or None if not found.
    """
    key = vuln_type if vuln_type else "index"
    return WOOWYUN_FILES.get(key)


def list_available_wooyun_types() -> list[str]:
    """
    List available WooYun vulnerability types.

    Returns:
        List of vulnerability type keys with available documents.
    """
    return [k for k, v in WOOWYUN_FILES.items() if v.exists()]


def get_wooyun_stats() -> dict[str, int]:
    """
    Get WooYun case library statistics.

    Returns:
        Dict mapping vulnerability types to case counts.
    """
    return WOOWYUN_STATS.copy()


__all__ = [
    "METHODOLOGY_DIR",
    "METHODOLOGY_FILES",
    "WOOWYUN_DIR",
    "WOOWYUN_FILES",
    "WOOWYUN_STATS",
    "get_methodology_path",
    "list_available_methodologies",
    "get_wooyun_path",
    "list_available_wooyun_types",
    "get_wooyun_stats",
]
