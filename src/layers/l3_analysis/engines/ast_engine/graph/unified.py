"""
Unified Graph Query - High-level interface for cross-graph queries.

Provides simplified APIs that combine AST Graph and Call Graph for
complete code analysis scenarios.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.call_graph.models import CallGraph, CallNode
from src.layers.l3_analysis.engines.ast_engine.graph.bridge import (
    GraphBridge,
    TracedPath,
)
from src.layers.l3_analysis.engines.ast_engine.graph.builder import ASTGraphBuilder
from src.layers.l3_analysis.engines.ast_engine.graph.models import (
    ASTGraph,
    ASTNode,
)


# ============================================================================
# Common dangerous sink patterns
# ============================================================================

DANGEROUS_SINKS: dict[str, list[str]] = {
    "code_injection": ["eval", "exec", "compile", "__import__"],
    "command_injection": ["system", "popen", "subprocess.call", "subprocess.Popen"],
    "sql_injection": ["execute", "executemany", "executescript"],
    "path_traversal": ["open", "Path.open", "file"],
    "deserialization": ["pickle.load", "yaml.load", "marshal.load"],
    "weak_crypto": ["md5", "sha1", "DES", "ARC4", "blowfish"],
}


@dataclass
class SinkMatch:
    """
    A matched sink with context information.

    Attributes:
        ast_node: The AST node representing the sink
        sink_type: Type of vulnerability (e.g., "code_injection")
        confidence: Confidence score (0-1)
        containing_function: CallNode of the function containing the sink
    """

    ast_node: ASTNode
    sink_type: str
    confidence: float
    containing_function: CallNode | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ast_node": {
                "id": self.ast_node.id,
                "type": self.ast_node.type,
                "name": self.ast_node.name,
                "file": self.ast_node.file,
                "line": self.ast_node.line,
            },
            "sink_type": self.sink_type,
            "confidence": self.confidence,
            "containing_function": (
                {
                    "id": self.containing_function.id,
                    "name": self.containing_function.name,
                    "file": self.containing_function.file_path,
                    "line": self.containing_function.line,
                }
                if self.containing_function
                else None
            ),
        }


@dataclass
class FunctionContext:
    """
    Complete context for a function or code location.

    Combines information from both Call Graph and AST Graph.
    """

    # Call Graph info
    call_node: CallNode | None

    # AST Graph info
    ast_nodes: list[ASTNode]

    # Reachability
    is_entry_point: bool = False
    entry_point_type: str | None = None

    # Sinks found in this function
    sinks: list[SinkMatch] = field(default_factory=list)

    # Callers and callees
    callers: list[CallNode] = field(default_factory=list)
    callees: list[CallNode] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "call_node": (
                {
                    "id": self.call_node.id,
                    "name": self.call_node.name,
                    "file": self.call_node.file_path,
                    "line": self.call_node.line,
                }
                if self.call_node
                else None
            ),
            "ast_nodes_count": len(self.ast_nodes),
            "is_entry_point": self.is_entry_point,
            "entry_point_type": self.entry_point_type,
            "sinks": [s.to_dict() for s in self.sinks],
            "callers_count": len(self.callers),
            "callees_count": len(self.callees),
        }


# ============================================================================
# Unified Query Interface
# ============================================================================


class UnifiedGraphQuery:
    """
    Unified query interface for AST + Call Graph.

    Provides high-level APIs that combine both graphs for common
    analysis scenarios.
    """

    def __init__(
        self,
        call_graph: CallGraph,
        ast_graph: ASTGraph,
    ) -> None:
        """
        Initialize the unified query interface.

        Args:
            call_graph: The call graph
            ast_graph: The AST graph
        """
        self.call_graph = call_graph
        self.ast_graph = ast_graph
        self.bridge = GraphBridge()
        self.logger = get_logger(__name__)

    # ========================================================================
    # Sink discovery
    # ========================================================================

    def find_all_sinks(
        self,
        sink_types: list[str] | None = None,
        custom_patterns: dict[str, list[str]] | None = None,
    ) -> list[SinkMatch]:
        """
        Find all dangerous sinks in the AST graph.

        Args:
            sink_types: Types of sinks to find (default: all)
            custom_patterns: Custom sink patterns to add

        Returns:
            List of SinkMatch objects
        """
        patterns = DANGEROUS_SINKS.copy()
        if custom_patterns:
            patterns.update(custom_patterns)

        if sink_types:
            patterns = {k: v for k, v in patterns.items() if k in sink_types}

        matches = []

        # Search for call nodes matching dangerous patterns
        call_nodes = self.ast_graph.get_nodes_by_type("call")
        call_nodes.extend(self.ast_graph.get_nodes_by_type("call_expression"))

        for node in call_nodes:
            for sink_type, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if self._matches_pattern(node, pattern):
                        # Find containing function
                        containing = self.bridge.find_containing_function(
                            node, self.ast_graph, self.call_graph
                        )

                        match = SinkMatch(
                            ast_node=node,
                            sink_type=sink_type,
                            confidence=0.8,
                            containing_function=containing,
                        )
                        matches.append(match)
                        break

        self.logger.info(f"Found {len(matches)} sinks")
        return matches

    def _matches_pattern(self, node: ASTNode, pattern: str) -> bool:
        """Check if a node matches a dangerous pattern."""
        # Simple name matching
        if pattern.lower() in node.name.lower():
            return True

        # Attribute access matching (e.g., "subprocess.call")
        if "." in pattern:
            parts = pattern.split(".")
            if len(parts) == 2:
                # Check if node name is the last part
                if parts[1].lower() in node.name.lower():
                    return True

        return False

    # ========================================================================
    # Reachability analysis
    # ========================================================================

    def find_reachable_sinks(
        self,
        entry_point: CallNode | None = None,
        sink_types: list[str] | None = None,
        max_path_length: int = 10,
    ) -> list[TracedPath]:
        """
        Find all reachable dangerous sinks from entry points.

        Args:
            entry_point: Specific entry point (None = use all entry points)
            sink_types: Types of sinks to find
            max_path_length: Maximum path length to consider

        Returns:
            List of TracedPath objects
        """
        # Get entry points
        if entry_point:
            entry_points = [entry_point]
        else:
            entry_points = self.call_graph.get_entry_points()

        if not entry_points:
            self.logger.warning("No entry points found")
            return []

        # Find all sinks
        all_sinks = self.find_all_sinks(sink_types=sink_types)

        if not all_sinks:
            self.logger.info("No sinks found")
            return []

        # Check reachability for each sink
        paths = []

        for entry in entry_points:
            for sink_match in all_sinks:
                if not sink_match.containing_function:
                    # Global sink - check if in same file
                    if sink_match.ast_node.file == entry.file_path:
                        # Create a simple path
                        path = TracedPath(
                            entry_point=entry,
                            sink_ast_node=sink_match.ast_node,
                            containing_function=None,
                            full_path=[entry.id, sink_match.ast_node.id],
                            confidence=0.5,
                            path_length=1,
                        )
                        paths.append(path)
                    continue

                # Use bridge to trace
                path = self.bridge.trace_to_sink(
                    entry_point=entry,
                    sink_ast_node=sink_match.ast_node,
                    call_graph=self.call_graph,
                    ast_graph=self.ast_graph,
                )

                if path and path.path_length <= max_path_length:
                    # Add sink type info
                    path.sink_type = sink_match.sink_type  # type: ignore
                    paths.append(path)

        self.logger.info(f"Found {len(paths)} reachable sinks")
        return paths

    # ========================================================================
    # Context queries
    # ========================================================================

    def get_function_context(
        self,
        file_path: str,
        line: int,
    ) -> FunctionContext:
        """
        Get complete context for a code location.

        Args:
            file_path: File path
            line: Line number

        Returns:
            FunctionContext with combined information
        """
        # Find AST nodes at this location
        file_nodes = self.ast_graph.get_nodes_by_file(file_path)
        nearby_nodes = [n for n in file_nodes if abs(n.line - line) <= 5]

        # Check if we're at a function definition itself
        function_defs = [
            n for n in nearby_nodes
            if n.type in ("function_definition", "function_declaration", "function")
            and abs(n.line - line) <= 1
        ]

        containing_func: CallNode | None = None

        if function_defs:
            # Direct lookup for function definition line
            func_def = function_defs[0]
            # Find matching CallNode
            file_call_nodes = self.call_graph.get_node_by_file(file_path)
            for call_node in file_call_nodes:
                if call_node.name == func_def.name and abs(call_node.line - func_def.line) <= 5:
                    containing_func = call_node
                    break
        else:
            # Find containing function for non-definition lines
            for node in nearby_nodes:
                func = self.bridge.find_containing_function(
                    node, self.ast_graph, self.call_graph
                )
                if func:
                    containing_func = func
                    break

        # Check if entry point
        is_entry = False
        entry_type = None
        if containing_func:
            is_entry = containing_func.is_entry_point
            entry_type = containing_func.entry_point_type

        # Find sinks in this function
        sinks = []
        if containing_func:
            func_nodes = self.bridge.find_ast_nodes_in_function(
                containing_func, self.ast_graph
            )
            for node in func_nodes:
                for sink_type, patterns in DANGEROUS_SINKS.items():
                    for pattern in patterns:
                        if self._matches_pattern(node, pattern):
                            sinks.append(
                                SinkMatch(
                                    ast_node=node,
                                    sink_type=sink_type,
                                    confidence=0.8,
                                    containing_function=containing_func,
                                )
                            )

        # Get callers and callees
        callers = []
        callees = []
        if containing_func:
            callers = [
                self.call_graph.nodes[cid]
                for cid in self.call_graph.get_callers(containing_func.id)
                if cid in self.call_graph.nodes
            ]
            callees = [
                self.call_graph.nodes[cid]
                for cid in self.call_graph.get_callees(containing_func.id)
                if cid in self.call_graph.nodes
            ]

        return FunctionContext(
            call_node=containing_func,
            ast_nodes=nearby_nodes,
            is_entry_point=is_entry,
            entry_point_type=entry_type,
            sinks=sinks,
            callers=callers,
            callees=callees,
        )

    # ========================================================================
    # Attack path analysis
    # ========================================================================

    def get_attack_paths(
        self,
        target_file: str,
        target_line: int,
    ) -> list[dict[str, Any]]:
        """
        Get all attack paths to a specific target location.

        Args:
            target_file: Target file path
            target_line: Target line number

        Returns:
            List of attack path dictionaries
        """
        paths = []

        # Get entry points
        entry_points = self.call_graph.get_entry_points()

        # Find target AST node
        target_node = None
        for node in self.ast_graph.get_nodes_by_file(target_file):
            if node.line == target_line:
                target_node = node
                break

        if not target_node:
            self.logger.warning(f"No AST node found at {target_file}:{target_line}")
            return []

        # Find paths from each entry point
        for entry in entry_points:
            path = self.bridge.trace_to_sink(
                entry_point=entry,
                sink_ast_node=target_node,
                call_graph=self.call_graph,
                ast_graph=self.ast_graph,
            )

            if path:
                paths.append(path.to_dict())

        return paths

    # ========================================================================
    # Factory method
    # ========================================================================

    @classmethod
    def from_source_files(
        cls,
        source_path: Path,
        file_patterns: list[str] | None = None,
    ) -> "UnifiedGraphQuery":
        """
        Create a UnifiedGraphQuery from source files.

        Builds both Call Graph and AST Graph from source.

        Args:
            source_path: Path to source code
            file_patterns: File patterns to include

        Returns:
            UnifiedGraphQuery instance
        """
        # Import here to avoid circular dependency
        from src.layers.l3_analysis.call_graph.analyzer import CallGraphAnalyzer

        # Build call graph
        call_analyzer = CallGraphAnalyzer()
        call_graph = call_analyzer.build_graph(source_path, file_patterns)

        # Build AST graph
        ast_builder = ASTGraphBuilder()
        ast_graph = ASTGraph()

        files = list(source_path.rglob("*.py"))  # TODO: support more languages
        for file_path in files:
            graph = ast_builder.build_from_file(file_path)
            # Merge graphs
            for node in graph.nodes.values():
                ast_graph.add_node(node)

        return cls(call_graph=call_graph, ast_graph=ast_graph)
