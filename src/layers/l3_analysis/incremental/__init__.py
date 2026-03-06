"""
L3 Incremental Analysis Module

This module provides incremental analysis capabilities to speed up repeated scans
by only analyzing changed code and its dependencies.

Core components:
- ChangeDetector: Detect git changes between scans
- ImpactAnalyzer: Analyze impact scope of changes
- DependencyGraph: Build and query file dependency relationships
- BaselineManager: Manage historical vulnerability baselines
- IncrementalScanner: Coordinate incremental scanning workflow
"""

from src.layers.l3_analysis.incremental.baseline_manager import (
    BaselineDiff,
    BaselineManager,
    VulnerabilityBaseline,
    VulnerabilityStatus,
)
from src.layers.l3_analysis.incremental.change_detector import (
    ChangeDetector,
    ChangeInfo,
    ChangeType,
    DiffResult,
)
from src.layers.l3_analysis.incremental.dependency_graph import (
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
    DependencyType,
)
from src.layers.l3_analysis.incremental.impact_analyzer import (
    ImpactAnalyzer,
    ImpactLevel,
    ImpactResult,
)
from src.layers.l3_analysis.incremental.scanner import (
    IncrementalScanConfig,
    IncrementalScanner,
    IncrementalScanResult,
)

__all__ = [
    # Change Detection
    "ChangeDetector",
    "ChangeInfo",
    "ChangeType",
    "DiffResult",
    # Impact Analysis
    "ImpactAnalyzer",
    "ImpactResult",
    "ImpactLevel",
    # Dependency Graph
    "DependencyGraph",
    "DependencyNode",
    "DependencyEdge",
    "DependencyType",
    # Baseline Management
    "BaselineManager",
    "VulnerabilityBaseline",
    "VulnerabilityStatus",
    "BaselineDiff",
    # Incremental Scanner
    "IncrementalScanner",
    "IncrementalScanConfig",
    "IncrementalScanResult",
]
