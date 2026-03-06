"""
Base class for language-specific call graph builders.

Provides the abstract interface and common utilities for building call graphs
from source code using Tree-sitter AST parsing.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from tree_sitter import Language, Parser

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.call_graph.models import (
    CallGraph,
    CallNode,
    CallEdge,
    CallType,
    NodeType,
    FileCallGraph,
)


class CallGraphBuilder(ABC):
    """
    Abstract base class for language-specific call graph builders.

    Subclasses must implement:
    - language_module: The tree-sitter language module
    - language_name: Human-readable language name
    - file_extensions: List of supported file extensions
    - _extract_functions(): Extract function definitions from AST
    - _extract_calls(): Extract function calls from AST
    """

    # Subclasses must define these
    language_module: Any = None
    language_name: str = "unknown"
    file_extensions: list[str] = []

    def __init__(self) -> None:
        """Initialize the call graph builder."""
        self.logger = get_logger(__name__)
        self._language: Language | None = None
        self._parser: Parser | None = None
        self._initialized = False

    def _ensure_initialized(self) -> None:
        """Lazily initialize the parser and language."""
        if self._initialized:
            return

        if self.language_module is None:
            self.logger.warning(f"Language module not set for {self.language_name}")
            self._initialized = True
            return

        try:
            self._language = Language(self.language_module.language())
            self._parser = Parser(self._language)
            self.logger.debug(f"Initialized {self.language_name} call graph builder")
        except Exception as e:
            self.logger.error(f"Failed to initialize {self.language_name} parser: {e}")

        self._initialized = True

    def can_parse(self, file_path: Path) -> bool:
        """Check if this builder can parse the given file.

        Args:
            file_path: Path to the source file.

        Returns:
            True if the file extension matches this builder.
        """
        return file_path.suffix in self.file_extensions

    def build_file_graph(
        self,
        content: str,
        file_path: Path,
        source_root: Path | None = None,
    ) -> FileCallGraph:
        """
        Build call graph for a single file.

        Args:
            content: Source code content.
            file_path: Path to the file.
            source_root: Root path of the project (for relative paths).

        Returns:
            FileCallGraph containing nodes and edges for this file.
        """
        self._ensure_initialized()

        rel_path = str(file_path)
        if source_root:
            try:
                rel_path = str(file_path.relative_to(source_root))
            except ValueError:
                pass

        file_graph = FileCallGraph(file_path=rel_path)

        if self._parser is None or self._language is None:
            self.logger.debug(f"Parser not available for {self.language_name}")
            return file_graph

        try:
            # Parse the source code into AST
            tree = self._parser.parse(content.encode("utf-8"))
            root = tree.root_node

            # Extract function definitions (nodes)
            functions = self._extract_functions(root, content, rel_path)
            file_graph.nodes.extend(functions)

            # Build function name -> node mapping
            func_map = {f.name: f for f in functions}

            # Extract calls (edges)
            for func in functions:
                calls = self._extract_calls(func, root, content, rel_path)
                for call_edge in calls:
                    # Check if call is internal or external
                    if call_edge.callee_id.split(":")[-1] in func_map:
                        file_graph.internal_calls.append(call_edge)
                    else:
                        file_graph.external_calls.append(call_edge)

        except Exception as e:
            self.logger.warning(f"Failed to build call graph for {file_path}: {e}")

        return file_graph

    def build_graph(
        self,
        files: list[tuple[Path, str]],
        source_root: Path | None = None,
    ) -> CallGraph:
        """
        Build complete call graph from multiple files.

        Args:
            files: List of (file_path, content) tuples.
            source_root: Root path of the project.

        Returns:
            Complete CallGraph with all nodes and edges.
        """
        graph = CallGraph()

        # First pass: extract all nodes
        file_graphs: list[FileCallGraph] = []
        for file_path, content in files:
            if not self.can_parse(file_path):
                continue

            file_graph = self.build_file_graph(content, file_path, source_root)
            file_graphs.append(file_graph)

            # Add nodes to main graph
            for node in file_graph.nodes:
                graph.add_node(node)

        # Second pass: add all edges
        for fg in file_graphs:
            for edge in fg.internal_calls + fg.external_calls:
                # Only add edge if callee exists (avoid dangling references)
                if edge.callee_id in graph.nodes:
                    graph.add_edge(edge)

        self.logger.info(
            f"Built {self.language_name} call graph: "
            f"{graph.node_count} nodes, {graph.edge_count} edges, "
            f"{graph.entry_point_count} entry points"
        )

        return graph

    @abstractmethod
    def _extract_functions(
        self,
        root: Any,
        content: str,
        file_path: str,
    ) -> list[CallNode]:
        """
        Extract function definitions from AST.

        Args:
            root: Root node of the AST.
            content: Source code content.
            file_path: File path for node IDs.

        Returns:
            List of CallNode for each function definition.
        """
        ...

    @abstractmethod
    def _extract_calls(
        self,
        func_node: CallNode,
        root: Any,
        content: str,
        file_path: str,
    ) -> list[CallEdge]:
        """
        Extract function calls from a function body.

        Args:
            func_node: The function node being analyzed.
            root: Root node of the AST.
            content: Source code content.
            file_path: File path for edge IDs.

        Returns:
            List of CallEdge for each call in the function.
        """
        ...

    def _get_line_number(self, node: Any) -> int:
        """Get line number from a tree-sitter node."""
        return node.start_point[0] + 1  # tree-sitter is 0-indexed

    def _get_text(self, node: Any, content: str) -> str:
        """Get text content of a tree-sitter node."""
        return content[node.start_byte : node.end_byte]

    def _create_node_id(self, file_path: str, func_name: str, class_name: str | None = None) -> str:
        """Create a unique node ID."""
        if class_name:
            return f"{file_path}:{class_name}.{func_name}"
        return f"{file_path}:{func_name}"

    def _create_callee_id(self, file_path: str, func_name: str) -> str:
        """Create a callee ID (may be resolved to actual node later)."""
        # Use Unknown as file path for unresolved calls
        return f"Unknown:{func_name}"
