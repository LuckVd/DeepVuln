"""
CFG Models - Control Flow Graph data structures.

Provides nodes and edges for representing control flow within functions,
supporting multiple languages and control structures.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CFGEdgeType(str, Enum):
    """Types of control flow edges."""

    # Unconditional flow
    UNCONDITIONAL = "unconditional"

    # Conditional branches
    CONDITIONAL_TRUE = "conditional_true"
    CONDITIONAL_FALSE = "conditional_false"

    # Loop control
    LOOP_ENTER = "loop_enter"
    LOOP_BACK = "loop_back"
    LOOP_EXIT = "loop_exit"

    # Exception handling
    EXCEPTION = "exception"

    # Async control
    ASYNC_AWAIT = "async_await"

    # Go routine
    GO_SPAWN = "go_spawn"


@dataclass
class CFGNode:
    """
    Control Flow Graph node representing a basic block.

    A basic block is a sequence of statements with a single entry point
    and single exit point (no internal branches).
    """

    # Unique identifier (format: "cfg:file:function:block")
    id: str

    # Location
    file: str
    start_line: int
    end_line: int

    # Basic block content
    statements: list[str] = field(default_factory=list)  # AST node IDs

    # Basic block attributes
    is_entry: bool = False  # Is this the function entry block?
    is_exit: bool = False  # Is this a function exit block?
    has_call: bool = False  # Does this block contain a function call?
    has_sink: bool = False  # Does this block contain a dangerous sink?

    # Loop context
    in_loop: bool = False  # Is this block inside a loop?
    loop_depth: int = 0  # Nesting depth of loops

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CFGNode):
            return False
        return self.id == other.id


@dataclass
class CFGEdge:
    """
    Control Flow Graph edge representing transfer of control.

    Connects basic blocks and indicates the type of control flow.
    """

    edge_type: CFGEdgeType
    source: str  # CFGNode id
    target: str  # CFGNode id

    # Edge attributes
    condition: str | None = None  # Condition expression (if applicable)
    probability: float = 1.0  # Estimated probability of taking this edge

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.edge_type, self.source, self.target))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CFGEdge):
            return False
        return (
            self.edge_type == other.edge_type
            and self.source == other.source
            and self.target == other.target
        )


@dataclass
class ControlFlowGraph:
    """
    Control Flow Graph for a single function.

    Represents all possible execution paths through a function
    using basic blocks and control flow edges.
    """

    # Function identification
    function_id: str  # Corresponding CallNode or function definition
    function_name: str
    file: str

    # Graph structure
    nodes: dict[str, CFGNode] = field(default_factory=dict)
    edges: list[CFGEdge] = field(default_factory=list)

    # Entry and exit points
    entry_node: str | None = None  # ID of entry block
    exit_nodes: list[str] = field(default_factory=list)  # IDs of exit blocks

    # CFG properties
    has_loops: bool = False
    has_exceptions: bool = False
    max_loop_depth: int = 0

    def add_node(self, node: CFGNode) -> None:
        """Add a node to the CFG."""
        self.nodes[node.id] = node

        if node.is_entry:
            self.entry_node = node.id

        if node.is_exit:
            if node.id not in self.exit_nodes:
                self.exit_nodes.append(node.id)

    def add_edge(self, edge: CFGEdge) -> None:
        """Add an edge to the CFG."""
        self.edges.append(edge)

        # Track loop depth
        if edge.edge_type in (CFGEdgeType.LOOP_ENTER, CFGEdgeType.LOOP_BACK):
            self.has_loops = True

        # Track exceptions
        if edge.edge_type == CFGEdgeType.EXCEPTION:
            self.has_exceptions = True

    def get_successors(self, node_id: str) -> list[tuple[str, CFGEdgeType]]:
        """
        Get successor nodes with edge types.

        Returns:
            List of (node_id, edge_type) tuples
        """
        successors = []
        for edge in self.edges:
            if edge.source == node_id:
                successors.append((edge.target, edge.edge_type))
        return successors

    def get_predecessors(self, node_id: str) -> list[tuple[str, CFGEdgeType]]:
        """
        Get predecessor nodes with edge types.

        Returns:
            List of (node_id, edge_type) tuples
        """
        predecessors = []
        for edge in self.edges:
            if edge.target == node_id:
                predecessors.append((edge.source, edge.edge_type))
        return predecessors

    def is_reachable(self, from_node: str, to_node: str) -> bool:
        """
        Check if to_node is reachable from from_node using DFS.

        Args:
            from_node: Source node ID
            to_node: Target node ID

        Returns:
            True if reachable, False otherwise
        """
        if from_node == to_node:
            return True

        if from_node not in self.nodes:
            return False

        visited = set()

        def dfs(current: str) -> bool:
            if current == to_node:
                return True

            if current in visited:
                return False

            visited.add(current)

            for successor, _ in self.get_successors(current):
                if dfs(successor):
                    return True

            return False

        return dfs(from_node)

    def get_node(self, node_id: str) -> CFGNode | None:
        """Get a node by ID."""
        return self.nodes.get(node_id)

    def size(self) -> int:
        """Return total number of nodes."""
        return len(self.nodes)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "function_id": self.function_id,
            "function_name": self.function_name,
            "file": self.file,
            "nodes": [
                {
                    "id": n.id,
                    "file": n.file,
                    "start_line": n.start_line,
                    "end_line": n.end_line,
                    "is_entry": n.is_entry,
                    "is_exit": n.is_exit,
                    "has_call": n.has_call,
                    "has_sink": n.has_sink,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "type": e.edge_type.value,
                    "source": e.source,
                    "target": e.target,
                }
                for e in self.edges
            ],
            "entry_node": self.entry_node,
            "exit_nodes": self.exit_nodes,
            "has_loops": self.has_loops,
            "has_exceptions": self.has_exceptions,
            "size": self.size(),
        }


@dataclass
class BasicBlock:
    """
    Temporary representation of a basic block during construction.

    Used by CFG builders before creating final CFGNodes.
    """

    start_line: int
    end_line: int
    statements: list[Any] = field(default_factory=list)  # AST nodes
    is_entry: bool = False
    is_exit: bool = False
    leader_type: str | None = None  # Type of statement that starts this block
