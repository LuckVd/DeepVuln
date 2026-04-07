"""
Python CFG Builder - Control Flow Graph builder for Python.

Implements CFG construction for Python code, supporting:
- if/elif/else statements
- while loops
- for loops
- try/except/finally
- match/case (Python 3.10+)
- async/await
- break/continue/return
"""

from typing import Any

from src.layers.l3_analysis.engines.ast_engine.cfg.base import LanguageCFGBuilder
from src.layers.l3_analysis.engines.ast_engine.cfg.models import (
    BasicBlock,
    CFGEdge,
    CFGEdgeType,
)


class PythonCFGBuilder(LanguageCFGBuilder):
    """
    Control Flow Graph builder for Python.

    Supports all Python control flow structures including
    match statements (3.10+) and async functions.
    """

    def get_language(self) -> str:
        """Return 'python'."""
        return "python"

    def get_control_flow_types(self) -> set[str]:
        """Return Python control flow node types."""
        return {
            "if_statement",
            "while_statement",
            "for_statement",
            "try_statement",
            "match_statement",  # Python 3.10+
            "with_statement",  # Context manager (creates implicit control flow)
            "return_statement",
            "break_statement",
            "continue_statement",
            "raise_statement",  # Exception raising
            "assert_statement",  # Assert (can raise AssertionError)
        }

    def get_edge_type_for_statement(self, stmt_type: str) -> CFGEdgeType | None:
        """Get CFG edge type for a Python statement type."""
        edge_mapping = {
            "if_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "elif_clause": CFGEdgeType.CONDITIONAL_TRUE,
            "else_clause": CFGEdgeType.CONDITIONAL_FALSE,
            "while_statement": CFGEdgeType.LOOP_ENTER,
            "for_statement": CFGEdgeType.LOOP_ENTER,
            "try_statement": CFGEdgeType.UNCONDITIONAL,  # Try body
            "except_clause": CFGEdgeType.EXCEPTION,
            "finally_clause": CFGEdgeType.UNCONDITIONAL,
            "match_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "case_clause": CFGEdgeType.CONDITIONAL_TRUE,
            "return_statement": CFGEdgeType.UNCONDITIONAL,  # To exit
            "break_statement": CFGEdgeType.LOOP_EXIT,
            "continue_statement": CFGEdgeType.LOOP_BACK,
            "raise_statement": CFGEdgeType.EXCEPTION,
            "with_statement": CFGEdgeType.UNCONDITIONAL,
        }
        return edge_mapping.get(stmt_type)

    def identify_basic_blocks(
        self,
        function_body: list[Any],
        file_path: str,
    ) -> list[BasicBlock]:
        """
        Identify basic blocks in a Python function body.

        A basic block starts at:
        - Function entry
        - After a conditional branch point
        - After a loop back edge target
        - Exception handler entry

        A basic block ends at:
        - Before a conditional branch
        - Before a loop
        - At return/break/continue
        """
        if not function_body:
            return []

        blocks = []
        current_block = BasicBlock(start_line=function_body[0].line if function_body else 0, end_line=0)
        current_block.is_entry = True

        for i, stmt in enumerate(function_body):
            stmt_type = getattr(stmt, "type", "")

            # Check if this statement ends the current block
            if self._is_block_terminator(stmt_type):
                current_block.end_line = stmt.line
                current_block.statements.append(stmt)
                current_block.is_exit = stmt_type in ("return_statement", "raise_statement")
                current_block.leader_type = stmt_type
                blocks.append(current_block)

                # Start new block (if not at end)
                if i < len(function_body) - 1:
                    current_block = BasicBlock(start_line=function_body[i + 1].line, end_line=0)
            else:
                # Add to current block
                if not current_block.statements:
                    current_block.start_line = stmt.line
                current_block.statements.append(stmt)
                current_block.end_line = stmt.line

        # Add final block if it has statements
        if current_block.statements and current_block not in blocks:
            if not current_block.is_exit:
                blocks.append(current_block)

        return blocks

    def _is_block_terminator(self, stmt_type: str) -> bool:
        """Check if a statement type terminates a basic block."""
        terminators = {
            "if_statement",
            "elif_clause",
            "else_clause",
            "while_statement",
            "for_statement",
            "try_statement",
            "except_clause",
            "finally_clause",
            "match_statement",
            "case_clause",
            "return_statement",
            "break_statement",
            "continue_statement",
            "raise_statement",
            "with_statement",  # Starts new context
        }
        return stmt_type in terminators

    def build_cfg_edges(
        self,
        blocks: list[BasicBlock],
        function_id: str,
        file_path: str,
    ) -> list[CFGEdge]:
        """
        Build CFG edges between Python basic blocks.

        Handles:
        - Sequential flow (fall-through)
        - Conditional branches (if/elif/else)
        - Loops (while/for)
        - Exception handling (try/except/finally)
        - Match statements
        - Control transfers (break/continue/return)
        """
        edges = []

        for i, block in enumerate(blocks):
            leader_type = block.leader_type

            if leader_type == "if_statement":
                edges.extend(self._build_if_edges(block, blocks, i))
            elif leader_type == "while_statement":
                edges.extend(self._build_while_edges(block, blocks, i))
            elif leader_type == "for_statement":
                edges.extend(self._build_for_edges(block, blocks, i))
            elif leader_type == "try_statement":
                edges.extend(self._build_try_edges(block, blocks, i))
            elif leader_type == "match_statement":
                edges.extend(self._build_match_edges(block, blocks, i))
            elif leader_type == "return_statement":
                # No outgoing edges from return
                pass
            elif leader_type in ("break_statement", "continue_statement"):
                # These create loop exit/back edges
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

    def _build_if_edges(
        self, if_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for if/elif/else statements."""
        edges = []

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

        # False branch (else if exists)
        # Find the else block (typically after elif blocks)
        # For simplicity, fall through to next block after if/elif chain
        else_block_index = self._find_else_block(blocks, index)
        if else_block_index is not None and else_block_index < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.CONDITIONAL_FALSE,
                    source=id(if_block),
                    target=id(blocks[else_block_index]),
                    condition="else_branch",
                )
            )
        elif index + 1 < len(blocks):
            # No else, fall through to next block
            # Actually, this is the merge point after if/else
            # We need to connect both branches to the merge point
            pass

        return edges

    def _find_else_block(self, blocks: list[BasicBlock], if_index: int) -> int | None:
        """Find the else block index after an if statement."""
        # Look for else_clause after if/elif blocks
        for i in range(if_index + 1, len(blocks)):
            if blocks[i].leader_type == "else_clause":
                return i
            # Stop if we hit a different control structure
            if blocks[i].leader_type not in ("elif_clause",):
                break
        return None

    def _build_while_edges(
        self, while_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for while loops."""
        edges = []

        # Entry to loop body
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.LOOP_ENTER,
                    source=id(while_block),
                    target=id(blocks[index + 1]),
                )
            )

        # Back edge from loop exit to while condition
        # Find the block after the loop body
        loop_exit_index = self._find_loop_exit(blocks, index)
        if loop_exit_index is not None:
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.LOOP_BACK,
                    source=id(blocks[loop_exit_index]),
                    target=id(while_block),
                )
            )

        return edges

    def _build_for_edges(
        self, for_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for for loops."""
        edges = []

        # Entry to loop body
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.LOOP_ENTER,
                    source=id(for_block),
                    target=id(blocks[index + 1]),
                )
            )

        # Back edge from loop exit to for statement
        loop_exit_index = self._find_loop_exit(blocks, index)
        if loop_exit_index is not None:
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.LOOP_BACK,
                    source=id(blocks[loop_exit_index]),
                    target=id(for_block),
                )
            )

        return edges

    def _find_loop_exit(self, blocks: list[BasicBlock], loop_index: int) -> int | None:
        """Find the block where a loop exits (break or end of loop)."""
        depth = 0
        for i in range(loop_index + 1, len(blocks)):
            leader_type = blocks[i].leader_type
            if leader_type in ("for_statement", "while_statement"):
                depth += 1
            elif leader_type == "break_statement" and depth == 0:
                return i
            elif leader_type in ("for_statement", "while_statement") and depth > 0:
                depth -= 1
                if depth == 0:
                    return i - 1  # Block before next loop
        # If no break found, the block after the loop is the exit
        if loop_index + 1 < len(blocks):
            return loop_index + 1
        return None

    def _build_try_edges(
        self, try_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for try/except/finally statements."""
        edges = []

        # Normal flow through try body
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.UNCONDITIONAL,
                    source=id(try_block),
                    target=id(blocks[index + 1]),
                )
            )

        # Exception edges to except clauses
        except_index = index + 1
        while except_index < len(blocks) and blocks[except_index].leader_type == "except_clause":
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.EXCEPTION,
                    source=id(try_block),
                    target=id(blocks[except_index]),
                )
            )
            except_index += 1

        # Finally clause always executes
        if except_index < len(blocks) and blocks[except_index].leader_type == "finally_clause":
            # All paths lead to finally
            for j in range(index, except_index):
                edges.append(
                    CFGEdge(
                        edge_type=CFGEdgeType.UNCONDITIONAL,
                        source=id(blocks[j]),
                        target=id(blocks[except_index]),
                    )
                )

        return edges

    def _build_match_edges(
        self, match_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for match/case statements (Python 3.10+)."""
        edges = []

        # Edge to each case clause
        case_index = index + 1
        while case_index < len(blocks) and blocks[case_index].leader_type == "case_clause":
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.CONDITIONAL_TRUE,
                    source=id(match_block),
                    target=id(blocks[case_index]),
                )
            )
            case_index += 1

        # Default case (wildcard) if exists
        if case_index < len(blocks) and blocks[case_index].leader_type == "case_clause":
            # Check for wildcard pattern in metadata
            if blocks[case_index].metadata.get("is_wildcard"):
                edges.append(
                    CFGEdge(
                        edge_type=CFGEdgeType.CONDITIONAL_FALSE,
                        source=id(match_block),
                        target=id(blocks[case_index]),
                    )
                )

        # All cases merge to the block after match
        if case_index < len(blocks):
            for j in range(index, case_index):
                edges.append(
                    CFGEdge(
                        edge_type=CFGEdgeType.UNCONDITIONAL,
                        source=id(blocks[j]),
                        target=id(blocks[case_index]),
                    )
                )

        return edges
