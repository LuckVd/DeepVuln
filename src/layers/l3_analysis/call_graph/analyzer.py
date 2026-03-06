"""
Call Graph Analyzer.

Main orchestrator for building and analyzing call graphs across multiple languages.
"""

from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.call_graph.models import (
    CallGraph,
    CallNode,
    ReachabilityResult,
    FileCallGraph,
)
from src.layers.l3_analysis.call_graph.builders.base import CallGraphBuilder
from src.layers.l3_analysis.call_graph.builders.python_builder import PythonCallGraphBuilder
from src.layers.l3_analysis.call_graph.reachability import (
    ReachabilityChecker,
    ReachabilityConfig,
)


class CallGraphAnalyzer:
    """
    Main call graph analyzer.

    Orchestrates:
    1. Language-specific call graph builders
    2. Call graph construction from source files
    3. Reachability analysis from entry points to vulnerabilities
    """

    def __init__(
        self,
        reachability_config: ReachabilityConfig | None = None,
    ) -> None:
        """Initialize the call graph analyzer.

        Args:
            reachability_config: Configuration for reachability analysis.
        """
        self.logger = get_logger(__name__)
        self.reachability_checker = ReachabilityChecker(reachability_config)

        # Initialize language builders
        self._builders: dict[str, CallGraphBuilder] = {}
        self._register_builders()

        # Cache for built graphs
        self._graph_cache: dict[str, CallGraph] = {}

    def _register_builders(self) -> None:
        """Register all language-specific builders."""
        builders = [
            PythonCallGraphBuilder(),
            # Java and Go builders will be added later
        ]

        for builder in builders:
            for ext in builder.file_extensions:
                self._builders[ext] = builder
                self.logger.debug(f"Registered {builder.language_name} builder for {ext}")

    def register_builder(self, builder: CallGraphBuilder) -> None:
        """Register a custom builder.

        Args:
            builder: The builder to register.
        """
        for ext in builder.file_extensions:
            self._builders[ext] = builder
            self.logger.info(f"Registered custom {builder.language_name} builder for {ext}")

    def build_graph(
        self,
        source_path: Path,
        file_patterns: list[str] | None = None,
        max_files: int = 1000,
    ) -> CallGraph:
        """
        Build call graph from source directory.

        Args:
            source_path: Root directory of source code.
            file_patterns: Glob patterns for files to include.
            max_files: Maximum number of files to process.

        Returns:
            Complete call graph.
        """
        self.logger.info(f"Building call graph from {source_path}")

        # Collect files
        files = self._collect_files(source_path, file_patterns, max_files)

        # Group files by language
        files_by_ext: dict[str, list[tuple[Path, str]]] = {}
        for file_path in files:
            ext = file_path.suffix
            if ext not in self._builders:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                if ext not in files_by_ext:
                    files_by_ext[ext] = []
                files_by_ext[ext].append((file_path, content))
            except Exception as e:
                self.logger.debug(f"Failed to read {file_path}: {e}")

        # Build graph for each language
        combined_graph = CallGraph()

        for ext, file_list in files_by_ext.items():
            builder = self._builders.get(ext)
            if not builder:
                continue

            self.logger.info(f"Building {builder.language_name} call graph ({len(file_list)} files)")
            graph = builder.build_graph(file_list, source_path)

            # Merge into combined graph
            for node in graph.nodes.values():
                combined_graph.add_node(node)
            for edge in graph.edges:
                combined_graph.add_edge(edge)

        self.logger.info(
            f"Built combined call graph: {combined_graph.node_count} nodes, "
            f"{combined_graph.edge_count} edges, {combined_graph.entry_point_count} entry points"
        )

        return combined_graph

    def build_file_graph(
        self,
        file_path: Path,
        content: str | None = None,
        source_root: Path | None = None,
    ) -> FileCallGraph | None:
        """
        Build call graph for a single file.

        Args:
            file_path: Path to the file.
            content: File content (read from disk if None).
            source_root: Root path for relative paths.

        Returns:
            FileCallGraph or None if language not supported.
        """
        ext = file_path.suffix
        builder = self._builders.get(ext)

        if not builder:
            return None

        if content is None:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                self.logger.warning(f"Failed to read {file_path}: {e}")
                return None

        return builder.build_file_graph(content, file_path, source_root)

    def check_reachability(
        self,
        graph: CallGraph,
        target_file: str,
        target_function: str | None = None,
        target_line: int | None = None,
    ) -> ReachabilityResult | None:
        """
        Check if a target is reachable from entry points.

        Args:
            graph: The call graph.
            target_file: Target file path.
            target_function: Target function name.
            target_line: Target line number.

        Returns:
            ReachabilityResult if target found, None otherwise.
        """
        return self.reachability_checker.check_reachability(
            graph=graph,
            target_file=target_file,
            target_function=target_function,
            target_line=target_line,
        )

    def find_callers(
        self,
        graph: CallGraph,
        target_file: str,
        target_function: str,
        max_depth: int = 5,
    ) -> list[CallNode]:
        """
        Find all callers of a target function.

        Args:
            graph: The call graph.
            target_file: Target file path.
            target_function: Target function name.
            max_depth: Maximum depth to search.

        Returns:
            List of caller nodes.
        """
        # Find target node
        target_nodes = [
            n for n in graph.nodes.values()
            if n.name == target_function and target_file in n.file_path
        ]

        if not target_nodes:
            return []

        callers = []
        for target in target_nodes:
            caller_ids = self.reachability_checker.find_callers_of(
                graph, target.id, max_depth
            )
            for caller_id in caller_ids:
                if caller_id in graph.nodes:
                    callers.append(graph.nodes[caller_id])

        return callers

    def is_entry_point(
        self,
        graph: CallGraph,
        file_path: str,
        function_name: str,
    ) -> tuple[bool, str | None]:
        """
        Check if a function is an entry point.

        Args:
            graph: The call graph.
            file_path: File path.
            function_name: Function name.

        Returns:
            Tuple of (is_entry_point, entry_point_type).
        """
        for node in graph.nodes.values():
            if node.name == function_name and file_path in node.file_path:
                return node.is_entry_point, node.entry_point_type

        return False, None

    def get_entry_point_path(
        self,
        graph: CallGraph,
        target_file: str,
        target_function: str,
    ) -> list[str] | None:
        """
        Get the call path from entry point to target.

        Args:
            graph: The call graph.
            target_file: Target file path.
            target_function: Target function name.

        Returns:
            List of function names in the call chain, or None if not reachable.
        """
        result = self.check_reachability(
            graph=graph,
            target_file=target_file,
            target_function=target_function,
        )

        if result and result.is_reachable:
            return result.call_chain

        return None

    def _collect_files(
        self,
        source_path: Path,
        file_patterns: list[str] | None,
        max_files: int,
    ) -> list[Path]:
        """Collect source files from directory."""
        files = []

        # Default patterns for supported languages
        if file_patterns is None:
            file_patterns = ["**/*.py", "**/*.java", "**/*.go"]

        for pattern in file_patterns:
            for file_path in source_path.glob(pattern):
                if file_path.is_file():
                    # Skip common non-source directories
                    if any(part in file_path.parts for part in [
                        "node_modules", ".git", "__pycache__",
                        "venv", ".venv", "build", "dist",
                    ]):
                        continue

                    files.append(file_path)

                    if len(files) >= max_files:
                        self.logger.warning(f"Reached max file limit ({max_files})")
                        return files

        return files

    def clear_cache(self) -> None:
        """Clear the graph cache."""
        self._graph_cache.clear()
        self.logger.debug("Cleared graph cache")
