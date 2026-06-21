"""
JavaScript/TypeScript CFG Builder - Control Flow Graph builder for JS/TS.

Implements CFG construction for JavaScript/TypeScript code, supporting:
- if/else statements (including ternary expressions)
- for loops (classic, for-in, for-of)
- while loops
- do-while loops
- switch/case/default statements
- try/catch/finally statements
- async/await
- break/continue/return/throw
"""

from typing import Any

from src.layers.l3_analysis.engines.ast_engine.cfg.base import LanguageCFGBuilder
from src.layers.l3_analysis.engines.ast_engine.cfg.models import (
    BasicBlock,
    CFGEdge,
    CFGEdgeType,
)


class JSCFGBuilder(LanguageCFGBuilder):
    """
    Control Flow Graph builder for JavaScript/TypeScript.

    Supports all JS/TS control flow structures including for-in,
    for-of, do-while loops, async/await, and ternary expressions.
    """

    def get_language(self) -> str:
        """Return 'javascript'."""
        return "javascript"

    def get_control_flow_types(self) -> set[str]:
        """Return JavaScript/TypeScript control flow node types."""
        return {
            "if_statement",
            "ternary_expression",  # Conditional expression (a ? b : c)
            "while_statement",
            "do_statement",
            "for_statement",
            "for_in_statement",
            "for_of_statement",
            "switch_statement",
            "try_statement",
            "async_function_declaration",
            "async_function_expression",
            "async_arrow_function",
            "await_expression",
            "return_statement",
            "break_statement",
            "continue_statement",
            "throw_statement",
        }

    def get_edge_type_for_statement(self, stmt_type: str) -> CFGEdgeType | None:
        """Get CFG edge type for a JS/TS statement type."""
        edge_mapping = {
            "if_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "else_clause": CFGEdgeType.CONDITIONAL_FALSE,
            "ternary_expression": CFGEdgeType.CONDITIONAL_TRUE,
            "while_statement": CFGEdgeType.LOOP_ENTER,
            "do_statement": CFGEdgeType.LOOP_ENTER,
            "for_statement": CFGEdgeType.LOOP_ENTER,
            "for_in_statement": CFGEdgeType.LOOP_ENTER,
            "for_of_statement": CFGEdgeType.LOOP_ENTER,
            "try_statement": CFGEdgeType.UNCONDITIONAL,
            "catch_clause": CFGEdgeType.EXCEPTION,
            "finally_clause": CFGEdgeType.UNCONDITIONAL,
            "switch_statement": CFGEdgeType.CONDITIONAL_TRUE,
            "case_clause": CFGEdgeType.CONDITIONAL_TRUE,
            "default_clause": CFGEdgeType.CONDITIONAL_FALSE,
            "await_expression": CFGEdgeType.ASYNC_AWAIT,
            "return_statement": CFGEdgeType.UNCONDITIONAL,
            "break_statement": CFGEdgeType.LOOP_EXIT,
            "continue_statement": CFGEdgeType.LOOP_BACK,
            "throw_statement": CFGEdgeType.EXCEPTION,
        }
        return edge_mapping.get(stmt_type)

    # ------------------------------------------------------------------
    # Basic block identification
    # ------------------------------------------------------------------

    def identify_basic_blocks(
        self,
        function_body: list[Any],
        file_path: str,
    ) -> list[BasicBlock]:
        """
        Identify basic blocks in a JavaScript/TypeScript function body.

        A basic block starts at:
        - Function entry
        - After a conditional branch point
        - After a loop back edge target
        - Exception handler entry (catch)

        A basic block ends at:
        - Before a conditional branch
        - Before a loop
        - At return/break/continue/throw
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
                    "throw_statement",
                )
                current_block.leader_type = stmt_type
                blocks.append(current_block)

                # P3: recurse into the compound body (if/for/while/...) so
                # nested sinks get their own basic blocks for edge connection.
                blocks.extend(self._recurse_compound_body(stmt, file_path))

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
        """Check if a statement type terminates a basic block in JS/TS."""
        terminators = {
            "if_statement",
            "else_clause",
            "ternary_expression",
            "while_statement",
            "do_statement",
            "for_statement",
            "for_in_statement",
            "for_of_statement",
            "try_statement",
            "catch_clause",
            "finally_clause",
            "switch_statement",
            "case_clause",
            "default_clause",
            "await_expression",
            "return_statement",
            "break_statement",
            "continue_statement",
            "throw_statement",
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
        Build CFG edges between JavaScript/TypeScript basic blocks.

        Handles:
        - Sequential flow (fall-through)
        - Conditional branches (if/else, ternary)
        - Loops (for, for-in, for-of, while, do-while)
        - Exception handling (try/catch/finally)
        - Switch/case/default
        - Async/await
        - Control transfers (break/continue/return/throw)
        """
        edges: list[CFGEdge] = []

        for i, block in enumerate(blocks):
            leader_type = block.leader_type

            if leader_type == "if_statement":
                edges.extend(self._build_if_edges(block, blocks, i))
            elif leader_type == "ternary_expression":
                edges.extend(self._build_ternary_edges(block, blocks, i))
            elif leader_type == "while_statement":
                edges.extend(self._build_while_edges(block, blocks, i))
            elif leader_type == "do_statement":
                edges.extend(self._build_do_while_edges(block, blocks, i))
            elif leader_type in (
                "for_statement",
                "for_in_statement",
                "for_of_statement",
            ):
                edges.extend(self._build_for_edges(block, blocks, i))
            elif leader_type == "try_statement":
                edges.extend(self._build_try_edges(block, blocks, i))
            elif leader_type == "switch_statement":
                edges.extend(self._build_switch_edges(block, blocks, i))
            elif leader_type == "await_expression":
                edges.extend(self._build_await_edges(block, blocks, i))
            elif leader_type == "throw_statement":
                # Exception edges handled by try builder
                pass
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

    # -- ternary ---------------------------------------------------------

    def _build_ternary_edges(
        self, ternary_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for ternary conditional expressions."""
        edges: list[CFGEdge] = []

        # True branch
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.CONDITIONAL_TRUE,
                    source=id(ternary_block),
                    target=id(blocks[index + 1]),
                    condition="ternary_true_branch",
                )
            )

            # False branch
            if index + 2 < len(blocks):
                edges.append(
                    CFGEdge(
                        edge_type=CFGEdgeType.CONDITIONAL_FALSE,
                        source=id(ternary_block),
                        target=id(blocks[index + 2]),
                        condition="ternary_false_branch",
                    )
                )

        return edges

    # -- while loop ------------------------------------------------------

    def _build_while_edges(
        self, while_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for while loops."""
        edges: list[CFGEdge] = []

        # Entry to loop body
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.LOOP_ENTER,
                    source=id(while_block),
                    target=id(blocks[index + 1]),
                )
            )

        # Back edge from end of loop body to while condition
        loop_exit_index = self._find_loop_exit(blocks, index)
        if loop_exit_index is not None:
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.LOOP_BACK,
                    source=id(blocks[loop_exit_index]),
                    target=id(while_block),
                )
            )

            # Exit edge when condition is false
            if loop_exit_index + 1 < len(blocks):
                edges.append(
                    CFGEdge(
                        edge_type=CFGEdgeType.LOOP_EXIT,
                        source=id(while_block),
                        target=id(blocks[loop_exit_index + 1]),
                        condition="loop_condition_false",
                    )
                )

        return edges

    # -- do-while loop ---------------------------------------------------

    def _build_do_while_edges(
        self, do_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for do-while loops."""
        edges: list[CFGEdge] = []

        # Entry to loop body (always executes at least once)
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.LOOP_ENTER,
                    source=id(do_block),
                    target=id(blocks[index + 1]),
                )
            )

        # Back edge from end of loop body to do condition
        loop_exit_index = self._find_loop_exit(blocks, index)
        if loop_exit_index is not None:
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.LOOP_BACK,
                    source=id(blocks[loop_exit_index]),
                    target=id(do_block),
                    condition="do_while_condition_true",
                )
            )

            # Exit when condition is false
            if loop_exit_index + 1 < len(blocks):
                edges.append(
                    CFGEdge(
                        edge_type=CFGEdgeType.LOOP_EXIT,
                        source=id(blocks[loop_exit_index]),
                        target=id(blocks[loop_exit_index + 1]),
                        condition="do_while_condition_false",
                    )
                )

        return edges

    # -- for / for-in / for-of -------------------------------------------

    def _build_for_edges(
        self, for_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for for, for-in, and for-of loops."""
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

            # Exit edge when condition is false or iteration done
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

    # -- try / catch / finally -------------------------------------------

    def _build_try_edges(
        self, try_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for try/catch/finally statements."""
        edges: list[CFGEdge] = []

        # Normal flow through try body
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.UNCONDITIONAL,
                    source=id(try_block),
                    target=id(blocks[index + 1]),
                )
            )

        # Exception edges to catch clauses
        catch_index = index + 1
        while catch_index < len(blocks) and blocks[catch_index].leader_type == "catch_clause":
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.EXCEPTION,
                    source=id(try_block),
                    target=id(blocks[catch_index]),
                )
            )
            catch_index += 1

        # Finally clause always executes
        if catch_index < len(blocks) and blocks[catch_index].leader_type == "finally_clause":
            for j in range(index, catch_index):
                edges.append(
                    CFGEdge(
                        edge_type=CFGEdgeType.UNCONDITIONAL,
                        source=id(blocks[j]),
                        target=id(blocks[catch_index]),
                    )
                )

        return edges

    # -- switch / case ---------------------------------------------------

    def _build_switch_edges(
        self, switch_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for switch statements."""
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

        # All cases merge to the block after switch (via break or fall-through)
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

    # -- async / await ---------------------------------------------------

    def _build_await_edges(
        self, await_block: BasicBlock, blocks: list[BasicBlock], index: int
    ) -> list[CFGEdge]:
        """Build edges for await expressions."""
        edges: list[CFGEdge] = []

        # Await suspends and resumes execution
        if index + 1 < len(blocks):
            edges.append(
                CFGEdge(
                    edge_type=CFGEdgeType.ASYNC_AWAIT,
                    source=id(await_block),
                    target=id(blocks[index + 1]),
                    condition="await_resolved",
                )
            )

        return edges

    # -- helpers ---------------------------------------------------------

    def _find_loop_exit(
        self, blocks: list[BasicBlock], loop_index: int
    ) -> int | None:
        """Find the block where a loop exits (break or end of loop body)."""
        depth = 0
        for i in range(loop_index + 1, len(blocks)):
            leader_type = blocks[i].leader_type
            if leader_type in (
                "for_statement",
                "for_in_statement",
                "for_of_statement",
                "while_statement",
                "do_statement",
            ):
                depth += 1
            elif leader_type == "break_statement" and depth == 0:
                return i
            elif depth == 0 and leader_type not in (
                "break_statement",
                "continue_statement",
            ):
                return i - 1
            elif leader_type in (
                "for_statement",
                "for_in_statement",
                "for_of_statement",
                "while_statement",
                "do_statement",
            ) and depth > 0:
                depth -= 1
                if depth == 0:
                    return i - 1
        if loop_index + 1 < len(blocks):
            return loop_index + 1
        return None
