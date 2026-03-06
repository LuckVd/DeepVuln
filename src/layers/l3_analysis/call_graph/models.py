"""
Call Graph Models.

Data structures for representing call graphs, nodes, edges, and reachability results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.layers.l3_analysis.codeql.sanitizer_detector import (
    SanitizerEffectiveness,
    SanitizerMatch,
)


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


# ============================================================================
# P5-01c: Taint Tracking Models
# ============================================================================


class SanitizerDetectionMethod(str, Enum):
    """Method used to detect a sanitizer."""

    TRANSFORM_ANALYSIS = "transform_analysis"  # AST-based transform detection
    TYPE_BASED = "type_based"  # Type annotation/ decorator detection
    SEMANTIC = "semantic"  # Known library function name
    CODEQL = "codeql"  # CodeQL native sanitizer predicate


@dataclass
class TransformScore:
    """Score from transform analysis for sanitizer detection."""

    has_replace_ops: bool = False  # Has string replace operations
    has_encode_calls: bool = False  # Has encoding function calls
    dangerous_char_coverage: float = 0.0  # Coverage of dangerous chars (0-1)
    is_sanitizer: bool = False  # Combined judgment
    confidence: float = 0.0  # Confidence score (0-1)
    details: dict[str, Any] = field(default_factory=dict)  # Detailed analysis

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "has_replace_ops": self.has_replace_ops,
            "has_encode_calls": self.has_encode_calls,
            "dangerous_char_coverage": self.dangerous_char_coverage,
            "is_sanitizer": self.is_sanitizer,
            "confidence": self.confidence,
            "details": self.details,
        }


@dataclass
class TypeBasedScore:
    """Score from type-based sanitizer detection."""

    has_safe_return_type: bool = False  # Returns SafeHtml, SafeSql, etc.
    has_sanitizer_decorator: bool = False  # Has @sanitizer, @escape decorator
    has_type_guard: bool = False  # Has type guard pattern
    is_sanitizer: bool = False  # Combined judgment
    confidence: float = 0.0  # Confidence score (0-1)
    safe_types: list[str] = field(default_factory=list)  # Detected safe types
    decorators: list[str] = field(default_factory=list)  # Detected decorators

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "has_safe_return_type": self.has_safe_return_type,
            "has_sanitizer_decorator": self.has_sanitizer_decorator,
            "has_type_guard": self.has_type_guard,
            "is_sanitizer": self.is_sanitizer,
            "confidence": self.confidence,
            "safe_types": self.safe_types,
            "decorators": self.decorators,
        }


@dataclass
class SanitizerMatchEx(SanitizerMatch):
    """
    Extended sanitizer match with multi-dimensional detection info.

    Extends SanitizerMatch with additional fields for P5-01c.
    """

    detection_method: SanitizerDetectionMethod = SanitizerDetectionMethod.SEMANTIC
    transform_score: TransformScore | None = None
    type_score: TypeBasedScore | None = None
    combined_confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update({
            "detection_method": self.detection_method.value,
            "transform_score": self.transform_score.to_dict() if self.transform_score else None,
            "type_score": self.type_score.to_dict() if self.type_score else None,
            "combined_confidence": self.combined_confidence,
        })
        return base


@dataclass
class TaintTraceResult:
    """
    Result of backward taint tracking from sink to source.

    Represents the complete trace analysis including sanitizer detection
    along the path.
    """

    # Source and sink identification
    source_id: str | None = None  # Entry point ID (if found)
    sink_id: str = ""  # Vulnerability point ID

    # Reachability status
    is_reachable: bool = False  # Is there a path from source to sink?
    is_sanitized: bool = False  # Is there an effective sanitizer on the path?

    # Path information
    path: list[str] = field(default_factory=list)  # Node IDs in the path
    path_length: int = 0  # Number of edges

    # Sanitizer information
    sanitizers: list[SanitizerMatchEx] = field(default_factory=list)  # Sanitizers found
    effective_sanitizer: SanitizerMatchEx | None = None  # The sanitizer that blocks the path

    # Confidence scoring
    confidence: float = 0.0  # Overall confidence in the result (0-1)
    distance_decay: float = 1.0  # Decay factor based on path length

    # Additional info
    entry_point_type: str | None = None  # Type of entry point (HTTP, RPC, etc.)
    call_chain: list[str] = field(default_factory=list)  # Human-readable call chain
    trace_direction: str = "backward"  # Direction of tracing

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "source_id": self.source_id,
            "sink_id": self.sink_id,
            "is_reachable": self.is_reachable,
            "is_sanitized": self.is_sanitized,
            "path": self.path,
            "path_length": self.path_length,
            "sanitizers": [s.to_dict() for s in self.sanitizers],
            "effective_sanitizer": self.effective_sanitizer.to_dict() if self.effective_sanitizer else None,
            "confidence": self.confidence,
            "distance_decay": self.distance_decay,
            "entry_point_type": self.entry_point_type,
            "call_chain": self.call_chain,
            "trace_direction": self.trace_direction,
        }

    @property
    def is_exploitable(self) -> bool:
        """Check if the vulnerability is exploitable (reachable and not sanitized)."""
        return self.is_reachable and not self.is_sanitized


@dataclass
class TaintTrackerConfig:
    """Configuration for taint tracking."""

    # Path limits
    max_path_length: int = 15  # Maximum path length to trace
    max_nodes_visited: int = 1000  # Maximum nodes to visit in BFS

    # Confidence thresholds
    min_confidence: float = 0.3  # Minimum confidence threshold
    sanitizer_confidence_threshold: float = 0.6  # Threshold to consider sanitizer effective
    full_sanitizer_threshold: float = 0.8  # Threshold for FULL effectiveness

    # Decay factors
    distance_decay_factor: float = 0.9  # Decay per hop in path

    # Detection weights
    transform_weight: float = 0.5  # Weight for transform analysis
    type_weight: float = 0.3  # Weight for type-based detection
    semantic_weight: float = 0.2  # Weight for semantic (known library) detection


# Dangerous character patterns by vulnerability type
DANGEROUS_CHARS: dict[str, list[str]] = {
    "xss": ["<", ">", "&", '"', "'", "/", "="],
    "sqli": ["'", '"', ";", "--", "/*", "*/", "=", "OR", "AND"],
    "cmdi": ["|", ";", "&", "$", "`", "(", ")", "\n", "\r"],
    "path_traversal": ["/", "\\", "..", "~", "\x00"],
    "ldap": ["(", ")", "\\", "*", "\x00"],
}
