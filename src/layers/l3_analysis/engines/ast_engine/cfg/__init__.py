"""
Control Flow Graph (CFG) Module.

Provides CFG construction for multiple languages, enabling
reachability analysis and attack path verification.
"""

from src.layers.l3_analysis.engines.ast_engine.cfg.models import (
    CFGEdge,
    CFGEdgeType,
    CFGNode,
    ControlFlowGraph,
)
from src.layers.l3_analysis.engines.ast_engine.cfg.factory import (
    CFGBuilderFactory,
    get_cfg_builder,
)

__all__ = [
    "CFGNode",
    "CFGEdge",
    "CFGEdgeType",
    "ControlFlowGraph",
    "CFGBuilderFactory",
    "get_cfg_builder",
]
