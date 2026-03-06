"""
Call Graph Models.

Data structures for representing call graphs, nodes, edges, and reachability results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    """Type of call graph node."""

    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    ENTRY_POINT = "entry_point"
    LAMBDA = "lambda"


@dataclass
class CallNode:
    """A node in the call graph representing a function/method."""

    id: str  # Unique identifier: "file_path:function_name"
    name: str  # Function/method name
    file_path: str  # Relative file path
    line: int  # Line number of definition
    node_type: NodeType = NodeType.FUNCTION
    is_entry_point: bool = False  # Is this externally callable?
    entry_point_type: str | None = None  # HTTP, RPC, MQ, etc.
    class_name: str | None = None  # For methods, the containing class
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CallNode):
            return False
        return self.id == other.id


class CallType(str, Enum):
    """Type of call relationship."""

    DIRECT = "direct"  # Direct function call: foo()
    VIRTUAL = "virtual"  # Virtual method call: obj.method()
    CONDITIONAL = "conditional"  # Conditional call: if x: foo()
    DYNAMIC = "dynamic"  # Dynamic call: getattr(obj, name)()


@dataclass
class CallEdge:
    """An edge in the call graph representing a call relationship."""

    caller_id: str  # ID of the calling function
    callee_id: str  # ID of the called function
    call_site: str  # Location of call: "file_path:line"
    call_type: CallType = CallType.DIRECT
    line_number: int = 0  # Line number of the call
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.caller_id, self.callee_id, self.call_site))


@dataclass
class CallGraph:
    """
    Call graph representing function call relationships.

    Supports both forward (callers -> callees) and reverse (callees -> callers)
    traversal for reachability analysis.
    """

    nodes: dict[str, CallNode] = field(default_factory=dict)
    edges: list[CallEdge] = field(default_factory=list)

    # Indexes for fast lookup
    _caller_index: dict[str, list[str]] = field(default_factory=dict)  # callee_id -> [caller_ids]
    _callee_index: dict[str, list[str]] = field(default_factory=dict)  # caller_id -> [callee_ids]
    _file_index: dict[str, list[str]] = field(default_factory=dict)  # file_path -> [node_ids]
    _entry_points: list[str] = field(default_factory=list)  # Entry point node IDs

    def add_node(self, node: CallNode) -> None:
        """Add a node to the graph."""
        self.nodes[node.id] = node

        # Update file index
        if node.file_path not in self._file_index:
            self._file_index[node.file_path] = []
        self._file_index[node.file_path].append(node.id)

        # Track entry points
        if node.is_entry_point:
            self._entry_points.append(node.id)

    def add_edge(self, edge: CallEdge) -> None:
        """Add an edge to the graph."""
        self.edges.append(edge)

        # Update caller index (reverse: who calls this function?)
        if edge.callee_id not in self._caller_index:
            self._caller_index[edge.callee_id] = []
        if edge.caller_id not in self._caller_index[edge.callee_id]:
            self._caller_index[edge.callee_id].append(edge.caller_id)

        # Update callee index (forward: what does this function call?)
        if edge.caller_id not in self._callee_index:
            self._callee_index[edge.caller_id] = []
        if edge.callee_id not in self._callee_index[edge.caller_id]:
            self._callee_index[edge.caller_id].append(edge.callee_id)

    def get_callers(self, node_id: str) -> list[str]:
        """Get all functions that call this node (reverse traversal)."""
        return self._caller_index.get(node_id, [])

    def get_callees(self, node_id: str) -> list[str]:
        """Get all functions called by this node (forward traversal)."""
        return self._callee_index.get(node_id, [])

    def get_node_by_file(self, file_path: str) -> list[CallNode]:
        """Get all nodes defined in a file."""
        node_ids = self._file_index.get(file_path, [])
        return [self.nodes[nid] for nid in node_ids if nid in self.nodes]

    def get_entry_points(self) -> list[CallNode]:
        """Get all entry point nodes."""
        return [self.nodes[nid] for nid in self._entry_points if nid in self.nodes]

    def find_node(self, name: str, file_path: str | None = None) -> CallNode | None:
        """Find a node by name and optionally by file."""
        for node in self.nodes.values():
            if node.name == name:
                if file_path is None or node.file_path == file_path:
                    return node
        return None

    def find_nodes_by_name(self, name: str) -> list[CallNode]:
        """Find all nodes with a given name."""
        return [n for n in self.nodes.values() if n.name == name]

    @property
    def node_count(self) -> int:
        """Total number of nodes."""
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        """Total number of edges."""
        return len(self.edges)

    @property
    def entry_point_count(self) -> int:
        """Number of entry points."""
        return len(self._entry_points)


@dataclass
class ReachabilityResult:
    """Result of reachability analysis from source to target."""

    source_id: str  # Source node ID (entry point)
    target_id: str  # Target node ID (vulnerability point)
    is_reachable: bool  # Is there a path from source to target?
    path: list[str] = field(default_factory=list)  # Path of node IDs
    path_length: int = 0  # Number of edges in path
    confidence: float = 0.0  # Confidence of reachability (0-1)

    # Additional info
    entry_point_type: str | None = None  # Type of entry point
    call_chain: list[str] = field(default_factory=list)  # Human-readable call chain

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "is_reachable": self.is_reachable,
            "path": self.path,
            "path_length": self.path_length,
            "confidence": self.confidence,
            "entry_point_type": self.entry_point_type,
            "call_chain": self.call_chain,
        }


@dataclass
class FileCallGraph:
    """Call graph for a single file."""

    file_path: str
    nodes: list[CallNode] = field(default_factory=list)
    internal_calls: list[CallEdge] = field(default_factory=list)  # Calls within file
    external_calls: list[CallEdge] = field(default_factory=list)  # Calls to other files
    incoming_calls: list[CallEdge] = field(default_factory=list)  # Calls from other files
