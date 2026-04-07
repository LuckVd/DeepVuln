"""
Java CFG Builder - Control Flow Graph builder for Java.

Implements CFG construction for Java code.
"""

from src.layers.l3_analysis.engines.ast_engine.cfg.base import LanguageCFGBuilder
from src.layers.l3_analysis.engines.ast_engine.cfg.models import (
    BasicBlock,
    CFGEdge,
    CFGEdgeType,
)


class JavaCFGBuilder(LanguageCFGBuilder):
    """Control Flow Graph builder for Java."""

    def get_language(self) -> str:
        return "java"

    def get_control_flow_types(self) -> set[str]:
        return {
            "if_statement",
            "while_statement",
            "for_statement",
            "do_statement",
            "try_statement",
            "switch_expression",
            "switch_statement",
            "return_statement",
            "break_statement",
            "continue_statement",
            "throw_statement",
        }

    def get_edge_type_for_statement(self, stmt_type: str) -> CFGEdgeType | None:
        edge_mapping = {
            "if_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "while_statement": CFGEdgeType.LOOP_ENTER,
            "for_statement": CFGEdgeType.LOOP_ENTER,
            "do_statement": CFGEdgeType.LOOP_ENTER,
            "try_statement": CFGEdgeType.UNCONDITIONAL,
            "catch_clause": CFGEdgeType.EXCEPTION,
            "finally_clause": CFGEdgeType.UNCONDITIONAL,
            "switch_expression": CFGEdgeType.CONDITIONAL_TRUE,
            "switch_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "return_statement": CFGEdgeType.UNCONDITIONAL,
            "break_statement": CFGEdgeType.LOOP_EXIT,
            "continue_statement": CFGEdgeType.LOOP_BACK,
            "throw_statement": CFGEdgeType.EXCEPTION,
        }
        return edge_mapping.get(stmt_type)

    def identify_basic_blocks(
        self,
        function_body: list,
        file_path: str,
    ) -> list[BasicBlock]:
        """Identify basic blocks in Java function body."""
        blocks = []
        for stmt in function_body:
            blocks.append(
                BasicBlock(
                    start_line=getattr(stmt, "line", 0),
                    end_line=getattr(stmt, "line", 0),
                    statements=[stmt],
                    leader_type=getattr(stmt, "type", None),
                )
            )
        return blocks

    def build_cfg_edges(
        self,
        blocks: list[BasicBlock],
        function_id: str,
        file_path: str,
    ) -> list[CFGEdge]:
        """Build CFG edges for Java basic blocks."""
        edges = []
        for i in range(len(blocks) - 1):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.UNCONDITIONAL,
                    source=id(blocks[i]),
                    target=id(blocks[i + 1]),
                )
            )
        return edges
