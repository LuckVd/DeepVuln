"""
CFG Builder Base - Abstract base class for language-specific CFG builders.

Provides the interface that all language CFG builders must implement.
"""

from abc import ABC, abstractmethod
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.ast_engine.cfg.models import (
    BasicBlock,
    CFGEdge,
    CFGEdgeType,
    CFGNode,
    ControlFlowGraph,
)


class LanguageCFGBuilder(ABC):
    """
    Abstract base class for language-specific Control Flow Graph builders.

    Each language (Python, JavaScript, Java, Go) should implement this
    interface to provide CFG construction for that language.
    """

    def __init__(self) -> None:
        """Initialize the language CFG builder."""
        self.logger = get_logger(__name__)
        # Bound per build_cfg() call so identify_basic_blocks can recurse
        # into compound-statement bodies (if/for/while/...). None when
        # identify_basic_blocks is called outside build_cfg (no recursion).
        self._ast_graph: Any = None

    @abstractmethod
    def get_language(self) -> str:
        """
        Return the language this builder handles.

        Returns:
            Language name (python, javascript, java, go, etc.)
        """
        pass

    @abstractmethod
    def get_control_flow_types(self) -> set[str]:
        """
        Return the set of tree-sitter node types that represent control flow.

        Returns:
            Set of tree-sitter node type strings
        """
        pass

    @abstractmethod
    def identify_basic_blocks(
        self,
        function_body: list[Any],
        file_path: str,
    ) -> list[BasicBlock]:
        """
        Identify basic blocks within a function body.

        A basic block is a maximal sequence of statements with a single
        entry point and no internal branches.

        Args:
            function_body: List of AST nodes representing the function body
            file_path: Path to the source file

        Returns:
            List of BasicBlock objects
        """
        pass

    @abstractmethod
    def build_cfg_edges(
        self,
        blocks: list[BasicBlock],
        function_id: str,
        file_path: str,
    ) -> list[CFGEdge]:
        """
        Build control flow edges between basic blocks.

        Args:
            blocks: List of basic blocks
            function_id: ID of the containing function
            file_path: Path to the source file

        Returns:
            List of CFGEdge objects
        """
        pass

    @abstractmethod
    def get_edge_type_for_statement(self, stmt_type: str) -> CFGEdgeType | None:
        """
        Get the CFG edge type for a given statement type.

        Args:
            stmt_type: tree-sitter node type

        Returns:
            CFGEdgeType if this statement creates control flow, None otherwise
        """
        pass

    def build_cfg(
        self,
        function_ast_node: Any,
        ast_graph: Any,
        function_id: str,
        file_path: str,
    ) -> ControlFlowGraph:
        """
        Build a complete CFG for a function.

        This is the main entry point for CFG construction.

        Args:
            function_ast_node: The function definition AST node
            ast_graph: The AST graph containing the function
            function_id: ID for the function
            file_path: Path to the source file

        Returns:
            Complete ControlFlowGraph for the function
        """
        self.logger.debug(f"Building CFG for function {function_id}")
        self._ast_graph = ast_graph  # P3: enable basic-block recursion

        cfg = ControlFlowGraph(
            function_id=function_id,
            function_name=function_ast_node.name if hasattr(function_ast_node, "name") else "unknown",
            file=file_path,
        )

        # 1. Extract function body
        function_body = self._extract_function_body(function_ast_node, ast_graph)

        if not function_body:
            self.logger.warning(f"Empty function body for {function_id}")
            return cfg

        # 2. Identify basic blocks
        blocks = self.identify_basic_blocks(function_body, file_path)

        if not blocks:
            self.logger.warning(f"No basic blocks found for {function_id}")
            return cfg

        # 3. Create CFG nodes from basic blocks
        block_id_map = {}
        for i, block in enumerate(blocks):
            node = CFGNode(
                id=f"cfg:{file_path}:{function_id}:block{i}",
                file=file_path,
                start_line=block.start_line,
                end_line=block.end_line,
                is_entry=block.is_entry,
                is_exit=block.is_exit,
                statements=[s.id for s in block.statements],
            )
            cfg.add_node(node)
            block_id_map[id(block)] = node.id

        # 4. Build control flow edges
        edges = self.build_cfg_edges(blocks, function_id, file_path)

        for edge in edges:
            # Map block object IDs to node IDs
            source_id = block_id_map.get(edge.source)
            target_id = block_id_map.get(edge.target)

            if source_id and target_id:
                cfg.add_edge(
                    CFGEdge(
                        edge_type=edge.edge_type,
                        source=source_id,
                        target=target_id,
                        condition=edge.condition,
                    )
                )

        # 5. Calculate loop depth
        self._calculate_loop_depth(cfg)

        return cfg

    def _extract_function_body(self, function_ast_node: Any, ast_graph: Any) -> list[Any]:
        """
        Extract the body statements of a function.

        In tree-sitter grammars the function body is nested under a
        body-wrapper child node (``block`` for Python/Java/Go,
        ``statement_block`` for JavaScript) rather than being a direct child
        of the function node. This descends into that wrapper and returns its
        statement children, falling back to direct ``*_statement`` children
        for grammars that lack such a wrapper.
        """
        body_wrappers = {"block", "statement_block"}

        for child_id in function_ast_node.children:
            child = ast_graph.get_node(child_id)
            if child and child.type in body_wrappers:
                body: list[Any] = []
                for stmt_id in child.children:
                    stmt = ast_graph.get_node(stmt_id)
                    if stmt:
                        body.append(stmt)
                return body

        # Fallback: direct children that look like statements.
        body = []
        for child_id in function_ast_node.children:
            child = ast_graph.get_node(child_id)
            if child and child.type.endswith("_statement"):
                body.append(child)
        return body

    def _collect_compound_body(self, stmt: Any) -> list[Any]:
        """Return the primary body statements of a compound statement.

        Phase 18/P3: lets identify_basic_blocks recurse so a sink nested in
        an if/for/while/try body gets its own basic block and goes through
        real CFG reachability, instead of being silently treated as
        reachable (the old ``_locate_block -> None -> continue`` fallback).
        Targets the first block/statement_block child (consequence / loop
        body / try body) — shared across python/java/js/go grammars. Returns
        [] when no AST graph is bound (behaviour unchanged).
        """
        if self._ast_graph is None:
            return []
        body_wrappers = {"block", "statement_block"}
        for child_id in stmt.children:
            child = self._ast_graph.get_node(child_id)
            if child and child.type in body_wrappers:
                body: list[Any] = []
                for stmt_id in child.children:
                    nested = self._ast_graph.get_node(stmt_id)
                    if nested:
                        body.append(nested)
                return body
        return []

    def _recurse_compound_body(
        self, stmt: Any, file_path: str
    ) -> list[BasicBlock]:
        """Recurse into a compound statement's body, returning its basic
        blocks. identify_basic_blocks nests these right after the compound's
        own block so build_cfg_edges (which targets ``blocks[index+1]``)
        connects them correctly.
        """
        body_stmts = self._collect_compound_body(stmt)
        if not body_stmts:
            return []
        return self.identify_basic_blocks(body_stmts, file_path)

    def _calculate_loop_depth(self, cfg: ControlFlowGraph) -> None:
        """Calculate loop nesting depth for each node."""
        loop_depths = {cfg.entry_node: 0} if cfg.entry_node else {}

        def visit(node_id: str, current_depth: int) -> None:
            if node_id in loop_depths:
                if loop_depths[node_id] < current_depth:
                    loop_depths[node_id] = current_depth
                else:
                    return  # Already visited with higher or equal depth
            else:
                loop_depths[node_id] = current_depth

            node = cfg.get_node(node_id)
            if node:
                node.loop_depth = current_depth

            for successor, edge_type in cfg.get_successors(node_id):
                new_depth = current_depth
                if edge_type == CFGEdgeType.LOOP_ENTER:
                    new_depth = current_depth + 1
                elif edge_type == CFGEdgeType.LOOP_EXIT:
                    new_depth = max(0, current_depth - 1)

                visit(successor, new_depth)

        if cfg.entry_node:
            visit(cfg.entry_node, 0)

        cfg.max_loop_depth = max(loop_depths.values()) if loop_depths else 0
