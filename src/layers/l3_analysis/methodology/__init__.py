"""
P6-06b: Business Logic Detection Methodology Module

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


__all__ = [
    "METHODOLOGY_DIR",
    "METHODOLOGY_FILES",
    "get_methodology_path",
    "list_available_methodologies",
]
