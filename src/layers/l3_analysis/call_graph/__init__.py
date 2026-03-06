"""
Call Graph Analysis Module.

Provides call graph construction and reachability analysis for
determining if vulnerabilities are reachable from entry points.
"""

from src.layers.l3_analysis.call_graph.models import (
    CallGraph,
    CallNode,
    CallEdge,
    CallType,
    NodeType,
    FileCallGraph,
    ReachabilityResult,
)
from src.layers.l3_analysis.call_graph.analyzer import CallGraphAnalyzer
from src.layers.l3_analysis.call_graph.reachability import (
    ReachabilityChecker,
    ReachabilityConfig,
)

__all__ = [
    # Models
    "CallGraph",
    "CallNode",
    "CallEdge",
    "CallType",
    "NodeType",
    "FileCallGraph",
    "ReachabilityResult",
    # Analyzer
    "CallGraphAnalyzer",
    # Reachability
    "ReachabilityChecker",
    "ReachabilityConfig",
]
