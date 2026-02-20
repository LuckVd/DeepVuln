"""
L3 Analysis Rounds Module

Multi-round audit system for progressive vulnerability discovery.

- RoundController: Manages multi-round audit execution
- RoundOneExecutor: First round - Attack Surface Reconnaissance
- RoundTwoExecutor: Second round - Deep Tracking
- RoundThreeExecutor: Third round - Correlation Verification
- RoundResult: Result from a single audit round
- VulnerabilityCandidate: A potential vulnerability finding
- AuditSession: Complete audit session across all rounds
- DataFlow models: TaintSource, TaintSink, Sanitizer, PathNode, DataFlowPath
- Correlation models: EvidenceChain, CorrelationResult, VerificationStatus
- Termination models: TerminationDecider, TerminationDecision, TerminationReason
- Evidence Builder: EvidenceChainBuilder, ExploitScenario, ExportFormat
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
from src.layers.l3_analysis.rounds.round_three import RoundThreeExecutor
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
from src.layers.l3_analysis.rounds.correlation import (
    CorrelationResult,
    CorrelationRule,
    Evidence,
    EvidenceChain,
    EvidenceSource,
    EvidenceType,
    VerificationStatus,
)
from src.layers.l3_analysis.rounds.termination import (
    DecisionMetrics,
    DEFAULT_TERMINATION_CONFIG,
    FindingsTrend,
    TerminationConfig,
    TerminationDecision,
    TerminationDecider,
    TerminationReason,
)
from src.layers.l3_analysis.rounds.evidence_builder import (
    DEFAULT_EVIDENCE_CHAIN_CONFIG,
    EvidenceChainBuilder,
    EvidenceChainConfig,
    ExploitScenario,
    ExploitStep,
    ExportFormat,
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
    "RoundThreeExecutor",
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
    # Correlation models
    "VerificationStatus",
    "EvidenceSource",
    "EvidenceType",
    "Evidence",
    "EvidenceChain",
    "CorrelationRule",
    "CorrelationResult",
    # Termination models
    "TerminationReason",
    "FindingsTrend",
    "DecisionMetrics",
    "TerminationDecision",
    "TerminationConfig",
    "TerminationDecider",
    "DEFAULT_TERMINATION_CONFIG",
    # Evidence builder
    "EvidenceChainBuilder",
    "EvidenceChainConfig",
    "DEFAULT_EVIDENCE_CHAIN_CONFIG",
    "ExploitScenario",
    "ExploitStep",
    "ExportFormat",
]
