"""
CFG Models Unit Tests.

Test CFGNode, CFGEdge, ControlFlowGraph data structures.
"""

import pytest

from src.layers.l3_analysis.engines.ast_engine.cfg.models import (
    BasicBlock,
    CFGEdge,
    CFGEdgeType,
    CFGNode,
    ControlFlowGraph,
)


class TestCFGEdgeType:
    """Test CFGEdgeType enum."""

    def test_values(self):
        """Test that all expected edge types exist."""
        assert CFGEdgeType.UNCONDITIONAL == "unconditional"
        assert CFGEdgeType.CONDITIONAL_TRUE == "conditional_true"
        assert CFGEdgeType.CONDITIONAL_FALSE == "conditional_false"
        assert CFGEdgeType.LOOP_ENTER == "loop_enter"
        assert CFGEdgeType.LOOP_BACK == "loop_back"
        assert CFGEdgeType.LOOP_EXIT == "loop_exit"
        assert CFGEdgeType.EXCEPTION == "exception"
        assert CFGEdgeType.ASYNC_AWAIT == "async_await"
        assert CFGEdgeType.GO_SPAWN == "go_spawn"


class TestCFGNode:
    """Test CFGNode dataclass."""

    def test_init_minimal(self):
        """Test CFGNode initialization with minimal fields."""
        node = CFGNode(
            id="cfg:test.py:func:block0",
            file="test.py",
            start_line=10,
            end_line=20,
        )
        assert node.id == "cfg:test.py:func:block0"
        assert node.file == "test.py"
        assert node.start_line == 10
        assert node.end_line == 20
        assert not node.is_entry
        assert not node.is_exit

    def test_init_with_attributes(self):
        """Test CFGNode with various attributes."""
        node = CFGNode(
            id="cfg:test.py:func:block1",
            file="test.py",
            start_line=15,
            end_line=25,
            is_entry=True,
            is_exit=False,
            has_call=True,
            has_sink=False,
            in_loop=True,
            loop_depth=2,
        )
        assert node.is_entry
        assert node.has_call
        assert node.in_loop
        assert node.loop_depth == 2

    def test_hash_and_equality(self):
        """Test CFGNode hash and equality based on id."""
        node1 = CFGNode(id="cfg:a", file="test.py", start_line=1, end_line=5)
        node2 = CFGNode(id="cfg:a", file="other.py", start_line=10, end_line=15)
        node3 = CFGNode(id="cfg:b", file="test.py", start_line=1, end_line=5)

        assert node1 == node2  # Same ID
        assert node1 != node3  # Different ID
        assert hash(node1) == hash(node2)


class TestCFGEdge:
    """Test CFGEdge dataclass."""

    def test_init(self):
        """Test CFGEdge initialization."""
        edge = CFGEdge(
            edge_type=CFGEdgeType.CONDITIONAL_TRUE,
            source="block1",
            target="block2",
            condition="x > 0",
        )
        assert edge.edge_type == CFGEdgeType.CONDITIONAL_TRUE
        assert edge.source == "block1"
        assert edge.target == "block2"
        assert edge.condition == "x > 0"
        assert edge.probability == 1.0

    def test_hash_and_equality(self):
        """Test CFGEdge hash and equality."""
        edge1 = CFGEdge(
            edge_type=CFGEdgeType.UNCONDITIONAL,
            source="a",
            target="b",
        )
        edge2 = CFGEdge(
            edge_type=CFGEdgeType.UNCONDITIONAL,
            source="a",
            target="b",
        )
        edge3 = CFGEdge(
            edge_type=CFGEdgeType.UNCONDITIONAL,
            source="a",
            target="c",
        )

        assert edge1 == edge2
        assert edge1 != edge3
        assert hash(edge1) == hash(edge2)


class TestControlFlowGraph:
    """Test ControlFlowGraph class."""

    def test_init(self):
        """Test ControlFlowGraph initialization."""
        cfg = ControlFlowGraph(
            function_id="test.py:func",
            function_name="func",
            file="test.py",
        )
        assert cfg.function_id == "test.py:func"
        assert cfg.function_name == "func"
        assert cfg.file == "test.py"
        assert cfg.size() == 0
        assert len(cfg.edges) == 0

    def test_add_node(self):
        """Test adding a node to the CFG."""
        cfg = ControlFlowGraph(
            function_id="test.py:func",
            function_name="func",
            file="test.py",
        )
        node = CFGNode(
            id="cfg:block0",
            file="test.py",
            start_line=10,
            end_line=20,
        )

        cfg.add_node(node)

        assert cfg.size() == 1
        assert cfg.get_node("cfg:block0") == node

    def test_entry_node(self):
        """Test setting entry node."""
        cfg = ControlFlowGraph(
            function_id="test.py:func",
            function_name="func",
            file="test.py",
        )
        entry_node = CFGNode(
            id="cfg:entry",
            file="test.py",
            start_line=5,
            end_line=10,
            is_entry=True,
        )

        cfg.add_node(entry_node)

        assert cfg.entry_node == "cfg:entry"

    def test_exit_nodes(self):
        """Test setting exit nodes."""
        cfg = ControlFlowGraph(
            function_id="test.py:func",
            function_name="func",
            file="test.py",
        )
        exit_node = CFGNode(
            id="cfg:exit",
            file="test.py",
            start_line=50,
            end_line=55,
            is_exit=True,
        )

        cfg.add_node(exit_node)

        assert "cfg:exit" in cfg.exit_nodes

    def test_add_edge(self):
        """Test adding an edge to the CFG."""
        cfg = ControlFlowGraph(
            function_id="test.py:func",
            function_name="func",
            file="test.py",
        )
        node1 = CFGNode(id="a", file="test.py", start_line=1, end_line=5)
        node2 = CFGNode(id="b", file="test.py", start_line=6, end_line=10)

        cfg.add_node(node1)
        cfg.add_node(node2)
        cfg.add_edge(
            CFGEdge(
                edge_type=CFGEdgeType.UNCONDITIONAL,
                source="a",
                target="b",
            )
        )

        assert len(cfg.edges) == 1

    def test_has_loops_tracking(self):
        """Test loop tracking."""
        cfg = ControlFlowGraph(
            function_id="test.py:func",
            function_name="func",
            file="test.py",
        )

        assert not cfg.has_loops

        cfg.add_edge(
            CFGEdge(
                edge_type=CFGEdgeType.LOOP_ENTER,
                source="a",
                target="b",
            )
        )

        assert cfg.has_loops

    def test_has_exceptions_tracking(self):
        """Test exception tracking."""
        cfg = ControlFlowGraph(
            function_id="test.py:func",
            function_name="func",
            file="test.py",
        )

        assert not cfg.has_exceptions

        cfg.add_edge(
            CFGEdge(
                edge_type=CFGEdgeType.EXCEPTION,
                source="a",
                target="b",
            )
        )

        assert cfg.has_exceptions

    def test_get_successors(self):
        """Test getting successor nodes."""
        cfg = ControlFlowGraph(
            function_id="test.py:func",
            function_name="func",
            file="test.py",
        )
        node1 = CFGNode(id="a", file="test.py", start_line=1, end_line=5)
        node2 = CFGNode(id="b", file="test.py", start_line=6, end_line=10)
        node3 = CFGNode(id="c", file="test.py", start_line=11, end_line=15)

        cfg.add_node(node1)
        cfg.add_node(node2)
        cfg.add_node(node3)
        cfg.add_edge(CFGEdge(edge_type=CFGEdgeType.UNCONDITIONAL, source="a", target="b"))
        cfg.add_edge(CFGEdge(edge_type=CFGEdgeType.CONDITIONAL_TRUE, source="a", target="c"))

        successors = cfg.get_successors("a")
        assert len(successors) == 2
        assert ("b", CFGEdgeType.UNCONDITIONAL) in successors
        assert ("c", CFGEdgeType.CONDITIONAL_TRUE) in successors

    def test_get_predecessors(self):
        """Test getting predecessor nodes."""
        cfg = ControlFlowGraph(
            function_id="test.py:func",
            function_name="func",
            file="test.py",
        )
        node1 = CFGNode(id="a", file="test.py", start_line=1, end_line=5)
        node2 = CFGNode(id="b", file="test.py", start_line=6, end_line=10)
        node3 = CFGNode(id="c", file="test.py", start_line=11, end_line=15)

        cfg.add_node(node1)
        cfg.add_node(node2)
        cfg.add_node(node3)
        cfg.add_edge(CFGEdge(edge_type=CFGEdgeType.UNCONDITIONAL, source="a", target="b"))
        cfg.add_edge(CFGEdge(edge_type=CFGEdgeType.UNCONDITIONAL, source="c", target="b"))

        predecessors = cfg.get_predecessors("b")
        assert len(predecessors) == 2
        assert ("a", CFGEdgeType.UNCONDITIONAL) in predecessors
        assert ("c", CFGEdgeType.UNCONDITIONAL) in predecessors

    def test_is_reachable(self):
        """Test reachability checking."""
        cfg = ControlFlowGraph(
            function_id="test.py:func",
            function_name="func",
            file="test.py",
        )
        entry = CFGNode(id="entry", file="test.py", start_line=1, end_line=5, is_entry=True)
        node1 = CFGNode(id="mid1", file="test.py", start_line=6, end_line=10)
        node2 = CFGNode(id="mid2", file="test.py", start_line=11, end_line=15)
        exit_node = CFGNode(id="exit", file="test.py", start_line=16, end_line=20, is_exit=True)

        cfg.add_node(entry)
        cfg.add_node(node1)
        cfg.add_node(node2)
        cfg.add_node(exit_node)

        cfg.entry_node = "entry"

        # Create a path: entry -> mid1 -> mid2 -> exit
        cfg.add_edge(CFGEdge(edge_type=CFGEdgeType.UNCONDITIONAL, source="entry", target="mid1"))
        cfg.add_edge(CFGEdge(edge_type=CFGEdgeType.UNCONDITIONAL, source="mid1", target="mid2"))
        cfg.add_edge(CFGEdge(edge_type=CFGEdgeType.UNCONDITIONAL, source="mid2", target="exit"))

        assert cfg.is_reachable("entry", "exit")
        assert cfg.is_reachable("entry", "mid1")
        assert not cfg.is_reachable("mid2", "entry")  # No backward path

    def test_to_dict(self):
        """Test serialization to dictionary."""
        cfg = ControlFlowGraph(
            function_id="test.py:func",
            function_name="func",
            file="test.py",
        )
        node = CFGNode(
            id="cfg:block0",
            file="test.py",
            start_line=10,
            end_line=20,
            is_entry=True,
            has_call=True,
        )

        cfg.add_node(node)
        cfg.add_edge(
            CFGEdge(
                edge_type=CFGEdgeType.UNCONDITIONAL,
                source="a",
                target="b",
            )
        )

        result = cfg.to_dict()

        assert result["function_id"] == "test.py:func"
        assert result["function_name"] == "func"
        assert result["file"] == "test.py"
        assert result["size"] == 1
        assert len(result["nodes"]) == 1
        assert result["nodes"][0]["id"] == "cfg:block0"
        assert result["nodes"][0]["is_entry"]
        assert result["nodes"][0]["has_call"]
        assert len(result["edges"]) == 1


class TestBasicBlock:
    """Test BasicBlock dataclass."""

    def test_init(self):
        """Test BasicBlock initialization."""
        block = BasicBlock(
            start_line=10,
            end_line=20,
            leader_type="if_statement",
        )
        assert block.start_line == 10
        assert block.end_line == 20
        assert block.leader_type == "if_statement"
        assert not block.is_entry
        assert not block.is_exit
