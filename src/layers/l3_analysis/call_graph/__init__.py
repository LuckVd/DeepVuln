"""
Call Graph Analysis Module.

Provides call graph construction and reachability analysis for
determining if vulnerabilities are reachable from entry points.
"""

from src.layers.l3_analysis.call_graph.analyzer import CallGraphAnalyzer
from src.layers.l3_analysis.call_graph.models import (
    CallEdge,
    CallGraph,
    CallNode,
    CallType,
    FileCallGraph,
    NodeType,
    ReachabilityResult,
    SanitizerDetectionMethod,
    SanitizerMatchEx,
    SanitizerType,
    # P5-01c: Taint Tracking
    TaintTraceResult,
    TaintTrackerConfig,
    TransformScore,
    TypeBasedScore,
)
from src.layers.l3_analysis.call_graph.reachability import (
    ReachabilityChecker,
    ReachabilityConfig,
)
from src.layers.l3_analysis.call_graph.taint_tracker import TaintTracker

# P5-01c: Taint Tracking Components
from src.layers.l3_analysis.call_graph.transform_analyzer import TransformAnalyzer
from src.layers.l3_analysis.call_graph.type_analyzer import TypeAnalyzer

__all__ = [
    # Models
    "CallGraph",
    "CallNode",
    "CallEdge",
    "CallType",
    "NodeType",
    "FileCallGraph",
    "ReachabilityResult",
    # P5-01c: Taint Tracking Models
    "TaintTraceResult",
    "TaintTrackerConfig",
    "SanitizerMatchEx",
    "SanitizerDetectionMethod",
    "SanitizerType",
    "TransformScore",
    "TypeBasedScore",
    # Analyzer
    "CallGraphAnalyzer",
    # Reachability
    "ReachabilityChecker",
    "ReachabilityConfig",
    # P5-01c: Taint Tracking Components
    "TransformAnalyzer",
    "TypeAnalyzer",
    "TaintTracker",
]
