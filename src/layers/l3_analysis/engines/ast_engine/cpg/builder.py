"""
CPG Builder - Build Code Property Graph from source code.

Orchestrates the construction of AST Graph, Call Graph, and their
fusion into a unified Code Property Graph.
"""

from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.call_graph.analyzer import CallGraphAnalyzer
from src.layers.l3_analysis.engines.ast_engine.graph.builder import ASTGraphBuilder
from src.layers.l3_analysis.engines.ast_engine.graph.models import ASTGraph, ASTNode
from src.layers.l3_analysis.call_graph.models import CallGraph
from src.layers.l3_analysis.engines.ast_engine.cpg.models import (
    CPGEdge,
    CodePropertyGraph,
)


class CPGBuilder:
    """
    Builder for creating Code Property Graphs.

    Orchestrates:
    1. AST Graph construction
    2. Call Graph construction
    3. Fusion into unified CPG
    """

    # AST node types that represent a function/method definition across the
    # supported tree-sitter grammars.
    FUNCTION_TYPES = frozenset(
        {
            "function_definition",  # Python, Go
            "function_declaration",  # JavaScript
            "function",
            "method_definition",  # JavaScript methods
            "method_declaration",  # Java
        }
    )

    def __init__(self) -> None:
        """Initialize the CPG builder."""
        self.logger = get_logger(__name__)
        self._ast_builder = ASTGraphBuilder()
        self._call_analyzer = CallGraphAnalyzer()

    def build_from_file(self, file_path: str | Path) -> CodePropertyGraph:
        """
        Build a CPG from a single source file.

        Args:
            file_path: Path to the source file

        Returns:
            CodePropertyGraph containing the fused code graph
        """
        file_path = Path(file_path)

        if not file_path.exists():
            self.logger.warning(f"File not found: {file_path}")
            return CodePropertyGraph()

        self.logger.info(f"Building CPG for {file_path}")

        # 1. Build AST Graph
        self.logger.debug("Building AST Graph...")
        ast_graph = self._ast_builder.build_from_file(file_path)

        if ast_graph.size() == 0:
            self.logger.warning(f"AST Graph is empty for {file_path}")
            return CodePropertyGraph()

        # 2. Build Call Graph
        self.logger.debug("Building Call Graph...")
        call_graph = self._call_analyzer.build_graph(file_path.parent)

        # 3. Fuse into CPG
        cpg = self._fuse_graphs(ast_graph, call_graph)

        self.logger.info(
            f"CPG built: {cpg.size()} nodes, {len(cpg.edges)} edges"
        )

        return cpg

    def build_from_directory(
        self,
        source_path: str | Path,
        file_patterns: list[str] | None = None,
    ) -> CodePropertyGraph:
        """
        Build a CPG from a directory of source files.

        Args:
            source_path: Path to the source directory
            file_patterns: File patterns to include (default: ["*.py"])

        Returns:
            CodePropertyGraph containing the fused code graph
        """
        source_path = Path(source_path)

        if not source_path.exists() or not source_path.is_dir():
            self.logger.warning(f"Directory not found: {source_path}")
            return CodePropertyGraph()

        if file_patterns is None:
            file_patterns = ["*.py"]

        self.logger.info(f"Building CPG for directory {source_path}")

        # 1. Build AST Graph from all files
        self.logger.debug("Building AST Graph from directory...")
        ast_graph = ASTGraph()

        for pattern in file_patterns:
            for file_path in source_path.rglob(pattern):
                file_ast = self._ast_builder.build_from_file(file_path)
                # Merge graphs
                for node in file_ast.nodes.values():
                    ast_graph.add_node(node)

        self.logger.info(f"AST Graph: {ast_graph.size()} nodes")

        # 2. Build Call Graph
        self.logger.debug("Building Call Graph from directory...")
        call_graph = self._call_analyzer.build_graph(source_path, file_patterns)

        self.logger.info(
            f"Call Graph: {call_graph.node_count} nodes, {call_graph.edge_count} edges"
        )

        # 3. Fuse into CPG
        cpg = self._fuse_graphs(ast_graph, call_graph)

        self.logger.info(
            f"CPG built: {cpg.size()} nodes, {len(cpg.edges)} edges"
        )

        return cpg

    def _fuse_graphs(
        self,
        ast_graph: ASTGraph,
        call_graph: CallGraph,
        language: str | None = None,
    ) -> CodePropertyGraph:
        """
        Fuse AST Graph and Call Graph into a unified CPG.

        Args:
            ast_graph: The AST graph
            call_graph: The call graph
            language: Optional explicit language (e.g. when building from a
                code string). When ``None``, language is detected per function
                node from its source file extension.

        Returns:
            Unified CodePropertyGraph
        """
        cpg = CodePropertyGraph()

        # Merge AST Graph
        cpg.merge_ast_graph(ast_graph)

        # Merge Call Graph
        cpg.merge_call_graph(call_graph)

        # Create cross-graph edges (function -> body statements)
        self._create_function_body_edges(cpg, ast_graph)

        # Build and merge per-function CFGs (D6: CPG CFG reachability).
        self._build_and_merge_cfgs(cpg, ast_graph, default_language=language)

        # Link each function's call-level node to its definition-level node
        # (P9-01) so BFS can traverse entry -> body -> sink.
        self._link_call_to_definition(cpg)

        return cpg

    def _build_and_merge_cfgs(
        self,
        cpg: CodePropertyGraph,
        ast_graph: ASTGraph,
        default_language: str | None = None,
    ) -> None:
        """
        Build per-function CFGs and merge them into the CPG (D6).

        Registers each function's ControlFlowGraph on the CPG so that
        ``AttackPathFinder`` can verify real CFG reachability. Per-function
        failures are tolerated (logged) so one bad function cannot break the
        CPG; languages without a CFG builder are skipped silently.

        Args:
            cpg: CodePropertyGraph to merge CFGs into
            ast_graph: AST graph carrying function definition nodes
            default_language: Language override (used when building from code);
                otherwise detected per function from its file extension
        """
        from src.layers.l3_analysis.engines.ast_engine.cfg.factory import (
            CFGBuilderFactory,
        )

        factory = CFGBuilderFactory()
        builders: dict[str, Any] = {}  # language -> builder (cached, may be None)

        merged = 0
        for ast_node in ast_graph.nodes.values():
            if ast_node.type not in self.FUNCTION_TYPES:
                continue

            file_path = ast_node.file or "<unknown>"
            language = default_language or factory.detect_language_from_file(file_path)
            if not language:
                continue

            if language not in builders:
                builders[language] = factory.get_builder(language)
            builder = builders[language]
            if builder is None:
                continue

            try:
                cfg = builder.build_cfg(
                    function_ast_node=ast_node,
                    ast_graph=ast_graph,
                    function_id=ast_node.id,
                    file_path=file_path,
                )
                if cfg and cfg.nodes:
                    cpg.merge_cfg(cfg)
                    merged += 1
            except Exception as exc:  # noqa: BLE001 - tolerate per-function failure
                self.logger.warning(f"CFG build failed for {ast_node.id}: {exc}")

        if merged:
            self.logger.debug(f"Merged {merged} CFG(s) into CPG")

    def _create_function_body_edges(
        self,
        cpg: CodePropertyGraph,
        ast_graph: ASTGraph,
    ) -> None:
        """
        Create edges from function definitions to their body statements.

        This links the call graph (function-level) with the AST graph
        (statement-level) for complete traversal.
        """
        # Find all function definition AST nodes
        for ast_node in ast_graph.nodes.values():
            if ast_node.type in self.FUNCTION_TYPES:
                func_cpg = cpg.find_by_ast_id(ast_node.id)

                if not func_cpg:
                    continue

                # Find all AST nodes within this function
                # (children in the AST tree)
                body_nodes = self._get_function_body_nodes(ast_node, ast_graph)

                # Create "contains" edges
                for body_node in body_nodes:
                    body_cpg = cpg.find_by_ast_id(body_node.id)
                    if body_cpg:
                        cpg.add_edge(
                            CPGEdge(
                                edge_type="contains",
                                source=func_cpg.id,
                                target=body_cpg.id,
                            )
                        )

    def _get_function_body_nodes(
        self,
        function_node: ASTNode,
        ast_graph: ASTGraph,
    ) -> list[ASTNode]:
        """Get all AST nodes within a function's body."""
        body_nodes = []

        for child_id in function_node.children:
            child = ast_graph.get_node(child_id)
            if child:
                body_nodes.append(child)
                # Recursively get descendants
                body_nodes.extend(self._get_all_descendants(child, ast_graph))

        return body_nodes

    def _link_call_to_definition(self, cpg: CodePropertyGraph) -> None:
        """
        Link each function's call-level CPG node to its definition-level node.

        The call graph and AST graph represent the same function as two
        separate CPG nodes — a ``call_function`` node (call graph) and a
        ``function_definition`` ``ast_statement`` node (AST graph) — with no
        edge between them. Entry-point detection anchors on the call_function
        node, while the function body ("contains" edges) hangs off the
        function_definition node, so BFS started from an entry could never
        reach the body or any sink.

        This adds a ``defines`` edge from each call_function node to its
        matching function_definition node. Matching uses the definition line
        and a suffix-aware file comparison, which are stable across the two
        analyzers despite their relative-vs-absolute path inconsistency.
        """
        call_nodes = cpg.get_nodes_by_type("call_function")
        if not call_nodes:
            return

        ast_funcs = [
            n
            for n in cpg.nodes.values()
            if n.node_type == "ast_statement" and n.ast_type in self.FUNCTION_TYPES
        ]

        for ast_func in ast_funcs:
            for call_node in call_nodes:
                if call_node.line != ast_func.line:
                    continue
                if not self._files_match(call_node.file, ast_func.file):
                    continue
                cpg.add_edge(
                    CPGEdge(
                        edge_type="defines",
                        source=call_node.id,
                        target=ast_func.id,
                    )
                )
                break

    @staticmethod
    def _files_match(path_a: str, path_b: str) -> bool:
        """Compare two file paths, tolerating relative-vs-absolute differences."""
        if not path_a or not path_b:
            return False
        return path_a == path_b or path_a.endswith(path_b) or path_b.endswith(path_a)

    def _get_all_descendants(
        self,
        ancestor: ASTNode,
        ast_graph: ASTGraph,
    ) -> list[ASTNode]:
        """Get all descendant nodes of an AST node."""
        descendants = []

        for child_id in ancestor.children:
            child = ast_graph.get_node(child_id)
            if child:
                descendants.append(child)
                descendants.extend(self._get_all_descendants(child, ast_graph))

        return descendants

    def build_from_code(
        self,
        code: str,
        language: str,
        file_path: str = "<unknown>",
    ) -> CodePropertyGraph:
        """
        Build a CPG from source code string.

        Args:
            code: Source code content
            language: Programming language (python, javascript, etc.)
            file_path: Virtual file path for node IDs

        Returns:
            CodePropertyGraph containing the fused code graph
        """
        self.logger.info(f"Building CPG from code ({language})")

        # 1. Build AST Graph from code
        ast_graph = self._ast_builder.build_from_code(code, language, file_path)

        if ast_graph.size() == 0:
            self.logger.warning("AST Graph is empty")
            return CodePropertyGraph()

        # 2. Call graph from code is complex (requires full project context)
        # For now, create an empty call graph
        from src.layers.l3_analysis.call_graph.models import CallGraph

        call_graph = CallGraph()

        # 3. Fuse into CPG (language is known explicitly here)
        cpg = self._fuse_graphs(ast_graph, call_graph, language=language)

        self.logger.info(
            f"CPG built from code: {cpg.size()} nodes, {len(cpg.edges)} edges"
        )

        return cpg
