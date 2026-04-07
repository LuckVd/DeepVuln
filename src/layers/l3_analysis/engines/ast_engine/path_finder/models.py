"""
Path Finder Models - Data structures for attack path representation.

Defines AttackPath and related configuration for path finding.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PathType(str, Enum):
    """Types of attack paths."""

    DATAFLOW = "dataflow"  # Taint flow path
    EXECUTION = "execution"  # Execution flow path
    REACHABILITY = "reachability"  # Simple reachability path


@dataclass
class AttackPath:
    """
    Complete attack path from entry point to vulnerable sink.

    Combines information from CPG nodes, CFG edges, and sanitizers
    to represent a exploitable attack path.
    """

    # Path identification
    entry_point: str  # Entry point CPGNode id
    sink: str  # Sink CPGNode id (dangerous function)
    path_type: PathType  # Type of path

    # Complete path (ordered list of CPG node IDs)
    path: list[str] = field(default_factory=list)

    # Vulnerability info
    sink_type: str = ""  # e.g., "sql_injection", "command_injection"
    confidence: float = 0.0  # Confidence in exploitability (0-1)

    # Sanitization info
    is_sanitized: bool = False  # Is there an effective sanitizer?
    sanitizers: list[str] = field(default_factory=list)  # Sanitizer function IDs
    effective_sanitizer: str | None = None  # The sanitizer that blocks exploitation

    # CFG reachability
    reaches_sink: bool = True  # Can the sink actually be reached?
    condition_paths: dict[str, bool] = field(default_factory=dict)  # Branch conditions

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_exploitable(self) -> bool:
        """Check if this path is exploitable."""
        return self.reaches_sink and not self.is_sanitized and self.confidence > 0.5

    def path_length(self) -> int:
        """Return the length of the path."""
        return len(self.path)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "entry_point": self.entry_point,
            "sink": self.sink,
            "path_type": self.path_type.value,
            "path": self.path,
            "sink_type": self.sink_type,
            "confidence": self.confidence,
            "is_sanitized": self.is_sanitized,
            "sanitizers": self.sanitizers,
            "effective_sanitizer": self.effective_sanitizer,
            "is_exploitable": self.is_exploitable,
            "reaches_sink": self.reaches_sink,
            "path_length": self.path_length(),
        }


@dataclass
class PathFinderConfig:
    """Configuration for path finding algorithms."""

    # Search limits
    max_path_length: int = 15  # Maximum path length to search
    max_nodes_visited: int = 1000  # Maximum nodes to visit in BFS
    search_timeout: float = 30.0  # Maximum search time in seconds

    # Confidence thresholds
    min_confidence: float = 0.3  # Minimum confidence to include a path
    sanitizer_confidence_threshold: float = 0.7  # Threshold for effective sanitizer

    # Path scoring
    distance_decay_factor: float = 0.9  # Confidence decay per hop
    sink_bonus: float = 0.5  # Confidence bonus for reaching a sink

    # Sanitizer patterns
    sanitizer_patterns: list[str] = field(
        default_factory=lambda: [
            "sanitize",
            "escape",
            "encode",
            "validate",
            "filter",
            "clean",
        ]
    )


@dataclass
class PathFinder:
    """Base interface for path finding algorithms."""

    config: PathFinderConfig = field(default_factory=PathFinderConfig)

    def find_paths(
        self,
        cpg: Any,
        sink_pattern: str,
        entry_points: list[str] | None = None,
    ) -> list[AttackPath]:
        """
        Find attack paths in the CPG.

        Args:
            cpg: CodePropertyGraph to search
            sink_pattern: Pattern to identify dangerous sinks
            entry_points: Specific entry points to start from (None = all)

        Returns:
            List of AttackPath objects
        """
        pass
