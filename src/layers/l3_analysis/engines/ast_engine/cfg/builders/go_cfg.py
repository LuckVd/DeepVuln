"""
Go CFG Builder - Control Flow Graph builder for Go.

Implements CFG construction for Go code.
"""

from src.layers.l3_analysis.engines.ast_engine.cfg.base import LanguageCFGBuilder
from src.layers.l3_analysis.engines.ast_engine.cfg.models import (
    BasicBlock,
    CFGEdge,
    CFGEdgeType,
)


class GoCFGBuilder(LanguageCFGBuilder):
    """Control Flow Graph builder for Go."""

    def get_language(self) -> str:
        return "go"

    def get_control_flow_types(self) -> set[str]:
        return {
            "if_statement",
            "while_statement",  # Go doesn't have while, but for can act like it
            "for_statement",
            "switch_statement",
            "select_statement",
            "return_statement",
            "break_statement",
            "continue_statement",
            "go_statement",  # Goroutine spawn
            "defer_statement",  # Deferred execution
        }

    def get_edge_type_for_statement(self, stmt_type: str) -> CFGEdgeType | None:
        edge_mapping = {
            "if_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "else_clause": CFGEdgeType.CONDITIONAL_FALSE,
            "for_statement": CFGEdgeType.LOOP_ENTER,
            "switch_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "select_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "case_clause": CFGEdgeType.CONDITIONAL_TRUE,
            "default_clause": CFGEdgeType.CONDITIONAL_FALSE,
            "return_statement": CFGEdgeType.UNCONDITIONAL,
            "break_statement": CFGEdgeType.LOOP_EXIT,
            "continue_statement": CFGEdgeType.LOOP_BACK,
            "go_statement": CFGEdgeType.GO_SPAWN,
            "defer_statement": CFGEdgeType.UNCONDITIONAL,
        }
        return edge_mapping.get(stmt_type)

    def identify_basic_blocks(
        self,
        function_body: list,
        file_path: str,
    ) -> list[BasicBlock]:
        """Identify basic blocks in Go function body."""
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
        """Build CFG edges for Go basic blocks."""
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
