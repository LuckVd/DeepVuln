"""
L3 Analysis Layer - Static Code Analysis

This layer provides multi-engine static analysis capabilities:
- Semgrep: Fast pattern matching for known vulnerability patterns
- CodeQL: Deep dataflow analysis
- OpenCode Agent: AI-powered deep audit

Core components:
- Finding: Unified vulnerability finding model
- BaseEngine: Abstract base class for analysis engines
- SemgrepEngine: Semgrep integration
- CodeQLEngine: CodeQL integration
- OpenCodeAgent: AI-powered security audit
- SmartScanner: Intelligent scanner with auto rule selection
- StrategyEngine: Priority-based audit strategy generation
- TaskDispatcher: Agent task dispatch and execution
- RoundController: Multi-round audit management
- IncrementalScanner: Incremental analysis for 70%+ speedup
"""

from src.layers.l3_analysis.engines.base import BaseEngine, EngineRegistry
from src.layers.l3_analysis.engines.codeql import CodeQLEngine
from src.layers.l3_analysis.engines.opencode_agent import OpenCodeAgent
from src.layers.l3_analysis.engines.semgrep import SemgrepEngine
from src.layers.l3_analysis.incremental import (
    BaselineDiff,
    BaselineManager,
    ChangeDetector,
    ChangeInfo,
    ChangeType,
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
    DependencyType,
    DiffResult,
    ImpactAnalyzer,
    ImpactLevel,
    ImpactResult,
    IncrementalScanConfig,
    IncrementalScanner,
    IncrementalScanResult,
    VulnerabilityBaseline,
    VulnerabilityStatus,
)
from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    ScanResult,
    SeverityLevel,
)
from src.layers.l3_analysis.rounds import (
    AnalysisDepth,
    AuditSession,
    ConfidenceLevel,
    CoverageStats,
    EngineStats,
    RoundController,
    RoundOneExecutor,
    RoundResult,
    RoundStatus,
    VulnerabilityCandidate,
)
from src.layers.l3_analysis.smart_scanner import SmartScanner, create_smart_scanner
from src.layers.l3_analysis.strategy import (
    AuditPriority,
    AuditPriorityLevel,
    AuditStrategy,
    AuditTarget,
    EngineAllocation,
    PriorityCalculator,
    PriorityScore,
    StrategyEngine,
    TargetGroup,
)
from src.layers.l3_analysis.task import (
    AgentTask,
    ContextBuilder,
    TaskBatch,
    TaskContext,
    TaskDispatcher,
    TaskGenerator,
    TaskPriority,
    TaskResult,
    TaskStatus,
    TaskType,
)

__all__ = [
    # Models
    "Finding",
    "FindingType",
    "SeverityLevel",
    "CodeLocation",
    "ScanResult",
    # Engines
    "BaseEngine",
    "EngineRegistry",
    "SemgrepEngine",
    "CodeQLEngine",
    "OpenCodeAgent",
    # Scanner
    "SmartScanner",
    "create_smart_scanner",
    # Strategy
    "AuditPriority",
    "AuditPriorityLevel",
    "AuditTarget",
    "AuditStrategy",
    "EngineAllocation",
    "TargetGroup",
    "PriorityScore",
    "PriorityCalculator",
    "StrategyEngine",
    # Task
    "AgentTask",
    "TaskType",
    "TaskPriority",
    "TaskStatus",
    "TaskContext",
    "TaskResult",
    "TaskBatch",
    "TaskGenerator",
    "TaskDispatcher",
    "ContextBuilder",
    # Rounds
    "RoundStatus",
    "RoundResult",
    "RoundController",
    "RoundOneExecutor",
    "VulnerabilityCandidate",
    "ConfidenceLevel",
    "AnalysisDepth",
    "CoverageStats",
    "EngineStats",
    "AuditSession",
    # Incremental Analysis
    "ChangeDetector",
    "ChangeInfo",
    "ChangeType",
    "DiffResult",
    "ImpactAnalyzer",
    "ImpactResult",
    "ImpactLevel",
    "DependencyGraph",
    "DependencyNode",
    "DependencyEdge",
    "DependencyType",
    "BaselineManager",
    "VulnerabilityBaseline",
    "VulnerabilityStatus",
    "BaselineDiff",
    "IncrementalScanner",
    "IncrementalScanConfig",
    "IncrementalScanResult",
]
