"""
Graph Bridge - Bridge AST Graph and Call Graph for unified analysis.

Provides accurate cross-graph navigation using tree-sitter's parent-child
relationships, ensuring no false positives in function attribution.
"""

from dataclasses import dataclass, field
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.ast_engine.graph.models import ASTGraph, ASTNode
from src.layers.l3_analysis.call_graph.models import CallGraph, CallNode


@dataclass
class TracedPath:
    """
    Result of tracing from entry point to a sink.

    Combines Call Graph (function-level) and AST Graph (statement-level)
    for complete attack path representation.
    """

    # Entry point
    entry_point: CallNode

    # Call path (function-level)
    call_chain: list[CallNode] = field(default_factory=list)

    # AST sink (statement-level)
    sink_ast_node: ASTNode | None = None

    # Containing function of the sink
    containing_function: CallNode | None = None

    # Full path (mixing function IDs and AST node IDs)
    full_path: list[str] = field(default_factory=list)

    # Metadata
    confidence: float = 0.0
    path_length: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "entry_point": {
                "id": self.entry_point.id,
                "name": self.entry_point.name,
                "file": self.entry_point.file_path,
                "line": self.entry_point.line,
            },
            "call_chain": [
                {"id": n.id, "name": n.name, "file": n.file_path, "line": n.line}
                for n in self.call_chain
            ],
            "sink": {
                "id": self.sink_ast_node.id if self.sink_ast_node else None,
                "type": self.sink_ast_node.type if self.sink_ast_node else None,
                "name": self.sink_ast_node.name if self.sink_ast_node else None,
                "file": self.sink_ast_node.file if self.sink_ast_node else None,
                "line": self.sink_ast_node.line if self.sink_ast_node else None,
            },
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
            "full_path": self.full_path,
            "confidence": self.confidence,
            "path_length": self.path_length,
        }


class GraphBridge:
    """
    Bridge between AST Graph and Call Graph.

    Enables navigation from function-level (Call Graph) to statement-level
    (AST Graph) and vice versa, using tree-sitter's accurate parent-child
    relationships to ensure precision.
    """

    # Node types that represent function/class definitions
    FUNCTION_TYPES = {
        "function_definition",  # Python
        "function_declaration",  # JavaScript/TypeScript
        "function",  # Go
        "method_definition",  # Python methods in class
        "class_definition",  # Python class
        "class_declaration",  # JavaScript class
    }

    # Node types that represent lambda/anonymous functions
    LAMBDA_TYPES = {
        "lambda",  # Python lambda
        "arrow_function",  # JavaScript arrow function
        "function_expression",  # JavaScript function expression
    }

    def __init__(self) -> None:
        """Initialize the graph bridge."""
        self.logger = get_logger(__name__)

    # ========================================================================
    # AST Graph → Call Graph (find containing function)
    # ========================================================================

    def find_containing_function(
        self,
        ast_node: ASTNode,
        ast_graph: ASTGraph,
        call_graph: CallGraph,
    ) -> CallNode | None:
        """
        Find the CallGraph function that contains this AST node.

        Uses accurate upward traversal through parent_id, following
        tree-sitter's real AST structure.

        Args:
            ast_node: The AST node to locate.
            ast_graph: The AST graph containing the node.
            call_graph: The call graph to search for the function.

        Returns:
            CallNode of the containing function, or None if global code.
        """
        # Walk up the AST to find the containing function definition
        function_ast_node = self._find_function_by_ancestor(ast_node, ast_graph)

        if not function_ast_node:
            # Global code, not in any function
            self.logger.debug(
                f"AST node {ast_node.id} is not in a function (global code)"
            )
            return None

        # Now find the corresponding CallNode
        # Match by file path and function name
        func_name = function_ast_node.name

        # Get all functions in the same file
        file_functions = call_graph.get_node_by_file(function_ast_node.file)

        # Find matching function by name
        for call_node in file_functions:
            if call_node.name == func_name:
                self.logger.debug(
                    f"AST node {ast_node.id} is in function {call_node.id}"
                )
                return call_node

        self.logger.debug(
            f"No CallNode found for function '{func_name}' in {function_ast_node.file}"
        )
        return None

    def _find_function_by_ancestor(
        self, ast_node: ASTNode, ast_graph: ASTGraph
    ) -> ASTNode | None:
        """
        Walk up the AST tree to find the containing function definition.

        This is completely accurate because it follows tree-sitter's
        real parent-child relationships.

        Args:
            ast_node: Starting AST node.
            ast_graph: The AST graph.

        Returns:
            ASTNode of the containing function, or None.
        """
        current = ast_node

        while current.parent_id:
            parent = ast_graph.get_node(current.parent_id)
            if not parent:
                break

            # Check if parent is a function definition
            if parent.type in self.FUNCTION_TYPES:
                return parent

            current = parent

        # No function definition found
        return None

    # ========================================================================
    # Call Graph → AST Graph (find AST nodes in function)
    # ========================================================================

    def find_ast_nodes_in_function(
        self,
        call_node: CallNode,
        ast_graph: ASTGraph,
    ) -> list[ASTNode]:
        """
        Find all AST nodes within a function's body.

        Uses accurate downward traversal through the function's
        AST subtree.

        Args:
            call_node: The CallNode representing the function.
            ast_graph: The AST graph.

        Returns:
            List of AST nodes in the function's body.
        """
        # First, find the function definition AST node
        func_ast_node = self._find_function_ast_node(call_node, ast_graph)

        if not func_ast_node:
            self.logger.debug(f"No AST node found for function {call_node.id}")
            return []

        # Get all descendants of this function
        descendants = self._get_all_descendants(func_ast_node, ast_graph)

        self.logger.debug(
            f"Found {len(descendants)} AST nodes in function {call_node.id}"
        )
        return descendants

    def _find_function_ast_node(
        self, call_node: CallNode, ast_graph: ASTGraph
    ) -> ASTNode | None:
        """Find the AST node for a CallNode's function definition."""
        # Get all AST nodes in the file
        file_nodes = ast_graph.get_nodes_by_file(call_node.file_path)

        # Find matching function definition
        for node in file_nodes:
            if node.type in self.FUNCTION_TYPES and node.name == call_node.name:
                # Additional check: line numbers should be close
                if abs(node.line - call_node.line) <= 5:  # Allow small offset
                    return node

        return None

    def _get_all_descendants(
        self, ancestor: ASTNode, ast_graph: ASTGraph
    ) -> list[ASTNode]:
        """Get all descendant nodes of an AST node."""
        descendants = []

        for child_id in ancestor.children:
            child = ast_graph.get_node(child_id)
            if child:
                descendants.append(child)
                descendants.extend(self._get_all_descendants(child, ast_graph))

        return descendants

    # ========================================================================
    # End-to-end tracing
    # ========================================================================

    def trace_to_sink(
        self,
        entry_point: CallNode,
        sink_ast_node: ASTNode,
        call_graph: CallGraph,
        ast_graph: ASTGraph,
    ) -> TracedPath | None:
        """
        Trace from entry point to sink, combining both graphs.

        Args:
            entry_point: Entry point CallNode.
            sink_ast_node: Sink AST node (e.g., dangerous API call).
            call_graph: The call graph.
            ast_graph: The AST graph.

        Returns:
            TracedPath with complete attack path, or None.
        """
        # Find containing function of the sink
        containing_func = self.find_containing_function(
            sink_ast_node, ast_graph, call_graph
        )

        if not containing_func:
            # Sink is in global code, no call chain needed
            return TracedPath(
                entry_point=entry_point,
                sink_ast_node=sink_ast_node,
                containing_function=None,
                full_path=[entry_point.id, sink_ast_node.id],
                confidence=1.0,
                path_length=1,
            )

        # Check if entry point can reach the containing function
        from src.layers.l3_analysis.call_graph.reachability import ReachabilityChecker

        checker = ReachabilityChecker()
        reachability = checker.check_reachability_from_node(
            call_graph,
            entry_point.id,
            containing_func.file_path,
            containing_func.name,
        )

        if not reachability or not reachability.is_reachable:
            # Sink is not reachable from entry point
            return None

        # Build call chain
        call_chain = []
        for node_id in reachability.path:
            node = call_graph.nodes.get(node_id)
            if node:
                call_chain.append(node)

        return TracedPath(
            entry_point=entry_point,
            call_chain=call_chain,
            sink_ast_node=sink_ast_node,
            containing_function=containing_func,
            full_path=reachability.path + [sink_ast_node.id],
            confidence=reachability.confidence,
            path_length=reachability.path_length + 1,
        )
