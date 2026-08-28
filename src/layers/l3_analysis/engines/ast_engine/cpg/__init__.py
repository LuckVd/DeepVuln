"""
Code Property Graph (CPG) Module.

Provides unified code graph by merging AST Graph, Call Graph, and CFG.
"""

from src.layers.l3_analysis.engines.ast_engine.cpg.builder import CPGBuilder
from src.layers.l3_analysis.engines.ast_engine.cpg.models import (
    CodePropertyGraph,
    CPGEdge,
    CPGNode,
)

__all__ = [
    "CPGNode",
    "CPGEdge",
    "CodePropertyGraph",
    "CPGBuilder",
]
