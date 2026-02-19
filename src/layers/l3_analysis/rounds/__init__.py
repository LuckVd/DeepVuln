"""
L3 Analysis Rounds Module

Multi-round audit system for progressive vulnerability discovery.

- RoundController: Manages multi-round audit execution
- RoundOneExecutor: First round - Attack Surface Reconnaissance
- RoundResult: Result from a single audit round
- VulnerabilityCandidate: A potential vulnerability finding
- AuditSession: Complete audit session across all rounds
"""

from src.layers.l3_analysis.rounds.models import (
    AnalysisDepth,
    AuditSession,
    ConfidenceLevel,
    CoverageStats,
    EngineStats,
    RoundResult,
    RoundStatus,
    VulnerabilityCandidate,
)
from src.layers.l3_analysis.rounds.controller import RoundController
from src.layers.l3_analysis.rounds.round_one import RoundOneExecutor

__all__ = [
    # Models
    "AnalysisDepth",
    "AuditSession",
    "ConfidenceLevel",
    "CoverageStats",
    "EngineStats",
    "RoundResult",
    "RoundStatus",
    "VulnerabilityCandidate",
    # Controller
    "RoundController",
    # Executors
    "RoundOneExecutor",
]
