"""Security analyzer module for automated vulnerability detection."""

from src.layers.l1_intelligence.security_analyzer.analyzer import (
    DependencyVuln,
    FrameworkVuln,
    SecurityAnalyzer,
    SecurityReport,
)

__all__ = [
    "SecurityAnalyzer",
    "SecurityReport",
    "DependencyVuln",
    "FrameworkVuln",
]
