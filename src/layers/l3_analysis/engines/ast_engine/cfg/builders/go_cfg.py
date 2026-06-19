"""
Go CFG Builder - Control Flow Graph builder for Go.

Implements CFG construction for Go code, supporting:
- if/else statements
- for loops (including for-range)
- switch/case/default statements
- select/case statements
- defer statements
- go statements (goroutine spawn)
- break/continue/return
- panic/recover (exception-like control flow)
"""

from typing import Any

from src.layers.l3_analysis.engines.ast_engine.cfg.base import LanguageCFGBuilder
from src.layers.l3_analysis.engines.ast_engine.cfg.models import (
    BasicBlock,
    CFGEdge,
    CFGEdgeType,
)


class GoCFGBuilder(LanguageCFGBuilder):
    """
    Control Flow Graph builder for Go.

    Supports all Go control flow structures including for-range loops,
    select statements, goroutine spawning, defer, and panic/recover.
    """

    def get_language(self) -> str:
        """Return 'go'."""
        return "go"

    def get_control_flow_types(self) -> set[str]:
        """Return Go control flow node types."""
        return {
            "if_statement",
            "for_statement",
            "switch_statement",
            "type_switch_statement",
            "select_statement",
            "return_statement",
            "break_statement",
            "continue_statement",
            "go_statement",
            "defer_statement",
            "panic_expression",  # Go's exception-like mechanism
            "recover_expression",
        }

    def get_edge_type_for_statement(self, stmt_type: str) -> CFGEdgeType | None:
        """Get CFG edge type for a Go statement type."""
        edge_mapping = {
            "if_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "else_clause": CFGEdgeType.CONDITIONAL_FALSE,
            "for_statement": CFGEdgeType.LOOP_ENTER,
            "switch_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "type_switch_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "select_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "case_clause": CFGEdgeType.CONDITIONAL_TRUE,
            "default_clause": CFGEdgeType.CONDITIONAL_FALSE,
            "return_statement": CFGEdgeType.UNCONDITIONAL,
            "break_statement": CFGEdgeType.LOOP_EXIT,
            "continue_statement": CFGEdgeType.LOOP_BACK,
            "go_statement": CFGEdgeType.GO_SPAWN,
            "defer_statement": CFGEdgeType.UNCONDITIONAL,
            "panic_expression": CFGEdgeType.EXCEPTION,
        }
        return edge_mapping.get(stmt_type)

    def _extract_function_body(self, function_ast_node: Any, ast_graph: Any) -> list[Any]:
        """
        Extract Go function body statements.

        Tree-sitter Go wraps the body as ``function_declaration -> block ->
        statement_list -> [statements]``. The base implementation stops at the
        ``block`` and would return ``[statement_list]`` (a single grouping
        node), collapsing the whole body into one basic block. This unwraps the
        ``statement_list`` and returns the real statements.
        """
        for child_id in function_ast_node.children:
            child = ast_graph.get_node(child_id)
            if child and child.type == "block":
                for grand_id in child.children:
                    grand = ast_graph.get_node(grand_id)
                    if grand and grand.type == "statement_list":
                        return [
                            ast_graph.get_node(sid)
                            for sid in grand.children
                            if ast_graph.get_node(sid)
                        ]
                # Fallback: block's direct children.
                return [
                    ast_graph.get_node(cid)
                    for cid in child.children
                    if ast_graph.get_node(cid)
                ]
        return super()._extract_function_body(function_ast_node, ast_graph)

    # ------------------------------------------------------------------
    # Basic block identification
    # ------------------------------------------------------------------

    def identify_basic_blocks(
        self,
        function_body: list[Any],
        file_path: str,
    ) -> list[BasicBlock]:
        """
        Identify basic blocks in a Go function body.

        A basic block starts at:
        - Function entry
        - After a conditional branch point
        - After a loop back edge target
        - Exception handler entry (recover)

        A basic block ends at:
        - Before a conditional branch
        - Before a loop
        - At return/break/continue/panic
        """
        if not function_body:
            return []

        blocks: list[BasicBlock] = []
        current_block = BasicBlock(
            start_line=function_body[0].line if function_body else 0,
            end_line=0,
        )
        current_block.is_entry = True

        for i, stmt in enumerate(function_body):
            stmt_type = getattr(stmt, "type", "")

            if self._is_block_terminator(stmt_type):
                current_block.end_line = stmt.line
                current_block.statements.append(stmt)
                current_block.is_exit = stmt_type in (
                    "return_statement",
                    "panic_expression",
                )
                current_block.leader_type = stmt_type
                blocks.append(current_block)

                if i < len(function_body) - 1:
                    current_block = BasicBlock(
                        start_line=function_body[i + 1].line,
                        end_line=0,
                    )
            else:
                if not current_block.statements:
                    current_block.start_line = stmt.line
                current_block.statements.append(stmt)
                current_block.end_line = stmt.line

        if current_block.statements and current_block not in blocks:
            if not current_block.is_exit:
                blocks.append(current_block)

        return blocks

    def _is_block_terminator(self, stmt_type: str) -> bool:
        """Check if a statement type terminates a basic block in Go."""
        terminators = {
            "if_statement",
            "else_clause",
            "for_statement",
            "switch_statement",
            "type_switch_statement",
            "select_statement",
            "case_clause",
            "default_clause",
            "return_statement",
            "break_statement",
            "continue_statement",
            "go_statement",
            "defer_statement",
            "panic_expression",
        }
        return stmt_type in terminators

    # ------------------------------------------------------------------
    # Edge construction
    # ------------------------------------------------------------------

    def build_cfg_edges(
        self,
        blocks: list[BasicBlock],
        function_id: str,
        file_path: str,
    ) -> list[CFGEdge]:
        """
        Build CFG edges between Go basic blocks.

        Handles:
        - Sequential flow (fall-through)
        - Conditional branches (if/else)
        - Loops (for, for-range)
        - Switch/case/default (expression and type switches)
        - Select/case (channel operations)
        - Goroutine spawning (go statements)
        - Deferred execution (defer statements)
        - Panic/recover (exception-like flow)
        - Control transfers (break/continue/return)
        """
        edges: list[CFGEdge] = []

        for i, block in enumerate(blocks):
            leader_type = block.leader_type

            if leader_type == "if_statement":
                edges.extend(self._build_if_edges(block, blocks, i))
            elif leader_type == "for_statement":
                edges.extend(self._build_for_edges(block, blocks, i))
            elif leader_type in ("switch_statement", "type_switch_statement"):
                edges.extend(self._build_switch_edges(block, blocks, i))
            elif leader_type == "select_statement":
                edges.extend(self._build_select_edges(block, blocks, i))
            elif leader_type == "go_statement":
                edges.extend(self._build_go_edges(block, blocks, i))
            elif leader_type == "defer_statement":
                edges.extend(self._build_defer_edges(block, blocks, i))
            elif leader_type == "panic_expression":
                # Exception-like: no fall-through
                edges.extend(self._build_panic_edges(block, blocks, i))
            elif leader_type == "return_statement":
                # No outgoing edges from return
                pass
            elif leader_type in ("break_statement", "continue_statement"):
                # Handled by loop edge builders
                pass
            else:
                # Sequential fall-through to next block
                if i + 1 < len(blocks):
                    edges.append(
                        CFGEdge(
                            edge_type=CFGEdgeType.UNCONDITIONAL,
                            source=id(block),
                            target=id(blocks[i + 1]),
                        )
                    )

        return edges

    # -- if / else -------------------------------------------------------

    def _build_if_edges(
        self, if_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for if/else statements."""
        edges: list[CFGEdge] = []

        # True branch (if body)
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.CONDITIONAL_TRUE,
                    source=id(if_block),
                    target=id(blocks[index + 1]),
                    condition="if_condition",
                )
            )

        # False branch (else)
        else_index = self._find_else_block(blocks, index)
        if else_index is not None and else_index < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.CONDITIONAL_FALSE,
                    source=id(if_block),
                    target=id(blocks[else_index]),
                    condition="else_branch",
                )
            )

        return edges

    def _find_else_block(
        self, blocks: list[BasicBlock], if_index: int
    ) -> int | None:
        """Find the else block index after an if statement."""
        for i in range(if_index + 1, len(blocks)):
            if blocks[i].leader_type == "else_clause":
                return i
            if blocks[i].leader_type not in ("if_statement",):
                break
        return None

    # -- for loop (includes for-range) -----------------------------------

    def _build_for_edges(
        self, for_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for for loops (classic, condition-only, and for-range)."""
        edges: list[CFGEdge] = []

        # Entry to loop body
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.LOOP_ENTER,
                    source=id(for_block),
                    target=id(blocks[index + 1]),
                )
            )

        # Back edge from end of loop body to for statement
        loop_exit_index = self._find_loop_exit(blocks, index)
        if loop_exit_index is not None:
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.LOOP_BACK,
                    source=id(blocks[loop_exit_index]),
                    target=id(for_block),
                )
            )

            # Exit edge from loop when condition is false
            if loop_exit_index + 1 < len(blocks):
                edges.append(
                    CFGEdge(
                        edge_type=CFGEdgeType.LOOP_EXIT,
                        source=id(for_block),
                        target=id(blocks[loop_exit_index + 1]),
                        condition="loop_condition_false",
                    )
                )

        return edges

    # -- switch / case ---------------------------------------------------

    def _build_switch_edges(
        self, switch_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for switch and type-switch statements."""
        edges: list[CFGEdge] = []

        # Edge to each case/default clause
        case_index = index + 1
        while case_index < len(blocks) and blocks[case_index].leader_type in (
            "case_clause",
            "default_clause",
        ):
            edge_type = (
                CFGEdgeType.CONDITIONAL_TRUE
                if blocks[case_index].leader_type == "case_clause"
                else CFGEdgeType.CONDITIONAL_FALSE
            )
            edges.append(
                CFGEdge(
                    edge_type=edge_type,
                    source=id(switch_block),
                    target=id(blocks[case_index]),
                )
            )
            case_index += 1

        # All cases merge to the block after switch
        # Go switch cases don't fall through by default (no break needed)
        if case_index < len(blocks):
            for j in range(index + 1, case_index):
                edges.append(
                    CFGEdge(
                        edge_type=CFGEdgeType.UNCONDITIONAL,
                        source=id(blocks[j]),
                        target=id(blocks[case_index]),
                    )
                )

        return edges

    # -- select ----------------------------------------------------------

    def _build_select_edges(
        self, select_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for select statements (channel operations)."""
        edges: list[CFGEdge] = []

        # Edge to each case/default clause
        case_index = index + 1
        while case_index < len(blocks) and blocks[case_index].leader_type in (
            "case_clause",
            "default_clause",
        ):
            edge_type = (
                CFGEdgeType.CONDITIONAL_TRUE
                if blocks[case_index].leader_type == "case_clause"
                else CFGEdgeType.CONDITIONAL_FALSE
            )
            edges.append(
                CFGEdge(
                    edge_type=edge_type,
                    source=id(select_block),
                    target=id(blocks[case_index]),
                )
            )
            case_index += 1

        # All cases merge to block after select
        if case_index < len(blocks):
            for j in range(index + 1, case_index):
                edges.append(
                    CFGEdge(
                        edge_type=CFGEdgeType.UNCONDITIONAL,
                        source=id(blocks[j]),
                        target=id(blocks[case_index]),
                    )
                )

        return edges

    # -- go statement (goroutine) ----------------------------------------

    def _build_go_edges(
        self, go_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for go statements (goroutine spawn)."""
        edges: list[CFGEdge] = []

        # Spawn edge: the goroutine starts independently
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.GO_SPAWN,
                    source=id(go_block),
                    target=id(blocks[index + 1]),
                )
            )

        # Caller continues to next block (sequential fall-through)
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.UNCONDITIONAL,
                    source=id(go_block),
                    target=id(blocks[index + 1]),
                )
            )

        return edges

    # -- defer -----------------------------------------------------------

    def _build_defer_edges(
        self, defer_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for defer statements."""
        edges: list[CFGEdge] = []

        # Defer registers the call; execution continues to next block
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.UNCONDITIONAL,
                    source=id(defer_block),
                    target=id(blocks[index + 1]),
                )
            )

        return edges

    # -- panic -----------------------------------------------------------

    def _build_panic_edges(
        self, panic_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for panic expressions (exception-like)."""
        edges: list[CFGEdge] = []

        # Panic unwinds the stack; if there is a recover, it catches
        # Search forward for a deferred recover or treat as exit
        recover_index = self._find_recover_block(blocks, index)
        if recover_index is not None:
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.EXCEPTION,
                    source=id(panic_block),
                    target=id(blocks[recover_index]),
                )
            )

        return edges

    def _find_recover_block(
        self, blocks: list[BasicBlock], panic_index: int
    ) -> int | None:
        """Find a block containing recover after a panic."""
        for i in range(panic_index + 1, len(blocks)):
            if blocks[i].leader_type == "recover_expression":
                return i
        return None

    # -- helpers ---------------------------------------------------------

    def _find_loop_exit(
        self, blocks: list[BasicBlock], loop_index: int
    ) -> int | None:
        """Find the block where a loop exits (break or end of loop body)."""
        depth = 0
        for i in range(loop_index + 1, len(blocks)):
            leader_type = blocks[i].leader_type
            if leader_type == "for_statement":
                depth += 1
            elif leader_type == "break_statement" and depth == 0:
                return i
            elif depth == 0 and leader_type not in (
                "break_statement",
                "continue_statement",
            ):
                return i - 1
            elif leader_type == "for_statement" and depth > 0:
                depth -= 1
                if depth == 0:
                    return i - 1
        if loop_index + 1 < len(blocks):
            return loop_index + 1
        return None
