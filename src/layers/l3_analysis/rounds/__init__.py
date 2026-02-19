"""
L3 Analysis Rounds Module

Multi-round audit system for progressive vulnerability discovery.

- RoundController: Manages multi-round audit execution
- RoundOneExecutor: First round - Attack Surface Reconnaissance
- RoundTwoExecutor: Second round - Deep Tracking
- RoundResult: Result from a single audit round
- VulnerabilityCandidate: A potential vulnerability finding
- AuditSession: Complete audit session across all rounds
- DataFlow models: TaintSource, TaintSink, Sanitizer, PathNode, DataFlowPath
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
from src.layers.l3_analysis.rounds.round_two import RoundTwoExecutor
from src.layers.l3_analysis.rounds.dataflow import (
    DataFlowPath,
    DeepAnalysisResult,
    PathNode,
    Sanitizer,
    SanitizerType,
    SinkType,
    SourceType,
    TaintSink,
    TaintSource,
)

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
    "RoundTwoExecutor",
    # Dataflow models
    "SourceType",
    "SinkType",
    "SanitizerType",
    "TaintSource",
    "TaintSink",
    "Sanitizer",
    "PathNode",
    "DataFlowPath",
    "DeepAnalysisResult",
]
