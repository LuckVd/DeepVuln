"""
Path Finder Unit Tests.

Test AttackPathFinder and related models.
"""

import pytest

from src.layers.l3_analysis.engines.ast_engine.path_finder.models import (
    AttackPath,
    PathFinderConfig,
    PathType,
)
from src.layers.l3_analysis.engines.ast_engine.cpg.models import (
    CPGEdge,
    CPGNode,
    CodePropertyGraph,
)


class TestPathFinderConfig:
    """Test PathFinderConfig dataclass."""

    def test_defaults(self):
        """Test default configuration values."""
        config = PathFinderConfig()

        assert config.max_path_length == 15
        assert config.max_nodes_visited == 1000
        assert config.min_confidence == 0.3
        assert config.sanitizer_confidence_threshold == 0.7
        assert config.distance_decay_factor == 0.9

    def test_sanitizer_patterns(self):
        """Test default sanitizer patterns."""
        config = PathFinderConfig()

        assert "sanitize" in config.sanitizer_patterns
        assert "escape" in config.sanitizer_patterns
        assert "validate" in config.sanitizer_patterns


class TestAttackPath:
    """Test AttackPath dataclass."""

    def test_init(self):
        """Test AttackPath initialization."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.EXECUTION,
            path=["entry", "mid", "sink"],
            sink_type="sql_injection",
            confidence=0.8,
        )

        assert path.entry_point == "entry"
        assert path.sink == "sink"
        assert path.path_type == PathType.EXECUTION
        assert path.path == ["entry", "mid", "sink"]
        assert path.sink_type == "sql_injection"
        assert path.confidence == 0.8

    def test_is_exploitable_true(self):
        """Test is_exploitable when conditions are met."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.DATAFLOW,
            confidence=0.8,
            reaches_sink=True,
            is_sanitized=False,
        )

        assert path.is_exploitable

    def test_is_exploitable_false_low_confidence(self):
        """Test is_exploitable with low confidence."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.DATAFLOW,
            confidence=0.3,
            reaches_sink=True,
            is_sanitized=False,
        )

        assert not path.is_exploitable

    def test_is_exploitable_false_sanitized(self):
        """Test is_exploitable when sanitized."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.DATAFLOW,
            confidence=0.8,
            reaches_sink=True,
            is_sanitized=True,
        )

        assert not path.is_exploitable

    def test_is_exploitable_false_not_reachable(self):
        """Test is_exploitable when not reachable."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.DATAFLOW,
            confidence=0.8,
            reaches_sink=False,
            is_sanitized=False,
        )

        assert not path.is_exploitable

    def test_path_length(self):
        """Test path_length property."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.EXECUTION,
            path=["a", "b", "c", "d"],
        )

        assert path.path_length() == 4

    def test_to_dict(self):
        """Test serialization to dictionary."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.EXECUTION,
            path=["entry", "sink"],
            sink_type="command_injection",
            confidence=0.9,
            is_sanitized=False,
            reaches_sink=True,
        )

        result = path.to_dict()

        assert result["entry_point"] == "entry"
        assert result["sink"] == "sink"
        assert result["path_type"] == "execution"
        assert result["sink_type"] == "command_injection"
        assert result["confidence"] == 0.9
        assert result["is_exploitable"]
        assert not result["is_sanitized"]
        assert result["reaches_sink"]
        assert result["path_length"] == 2


class TestAttackPathFinder:
    """Test AttackPathFinder class."""

    def test_init(self):
        """Test AttackPathFinder initialization."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        finder = AttackPathFinder()
        assert finder.config.max_path_length == 15

    def test_init_with_config(self):
        """Test AttackPathFinder with custom config."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        config = PathFinderConfig(max_path_length=20)
        finder = AttackPathFinder(config)

        assert finder.config.max_path_length == 20

    def test_find_paths_empty_cpg(self):
        """Test find_paths with empty CPG."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        finder = AttackPathFinder()
        cpg = CodePropertyGraph()

        paths = finder.find_paths(cpg, "eval")

        assert paths == []

    def test_find_paths_with_entry_and_sink(self):
        """Test find_paths with entry point and sink."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        # Create a simple CPG with entry and sink
        cpg = CodePropertyGraph()

        # Create entry node
        entry = CPGNode(
            id="entry",
            node_type="call_function",
            call_name="handler",
            file="test.py",
            line=5,
            metadata={"is_entry_point": True},
        )

        # Create middle node
        mid = CPGNode(
            id="mid",
            node_type="call_function",
            call_name="process",
            file="test.py",
            line=10,
        )

        # Create sink node
        sink = CPGNode(
            id="sink",
            node_type="ast_statement",
            ast_type="call_expression",
            file="test.py",
            line=15,
            metadata={"ast_name": "eval"},
        )

        cpg.add_node(entry)
        cpg.add_node(mid)
        cpg.add_node(sink)

        # Connect them
        cpg.add_edge(CPGEdge(edge_type="calls", source="entry", target="mid"))
        cpg.add_edge(CPGEdge(edge_type="calls", source="mid", target="sink"))

        # Find paths
        finder = AttackPathFinder()
        paths = finder.find_paths(cpg, "eval", entry_points=["entry"])

        assert len(paths) == 1
        assert paths[0].entry_point == "entry"
        assert paths[0].sink == "sink"
        assert paths[0].path == ["entry", "mid", "sink"]
        assert paths[0].is_exploitable

    def test_find_paths_sanitized(self):
        """Test find_paths with sanitizer in path."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        cpg = CodePropertyGraph()

        # Create entry
        entry = CPGNode(
            id="entry",
            node_type="call_function",
            call_name="handler",
            file="test.py",
            line=5,
            metadata={"is_entry_point": True},
        )

        # Create sanitizer
        sanitizer = CPGNode(
            id="sanitizer",
            node_type="call_function",
            call_name="sanitize_input",
            file="test.py",
            line=10,
        )

        # Create sink
        sink = CPGNode(
            id="sink",
            node_type="ast_statement",
            ast_type="call_expression",
            file="test.py",
            line=15,
            metadata={"ast_name": "eval"},
        )

        cpg.add_node(entry)
        cpg.add_node(sanitizer)
        cpg.add_node(sink)

        cpg.add_edge(CPGEdge(edge_type="calls", source="entry", target="sanitizer"))
        cpg.add_edge(CPGEdge(edge_type="calls", source="sanitizer", target="sink"))

        finder = AttackPathFinder()
        paths = finder.find_paths(cpg, "eval", entry_points=["entry"])

        assert len(paths) == 1
        assert paths[0].is_sanitized
        assert "sanitizer" in paths[0].sanitizers
        assert not paths[0].is_exploitable  # Sanitized paths are not exploitable
