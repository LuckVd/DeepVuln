"""Tests for AST Graph models."""

import pytest

from src.layers.l3_analysis.engines.ast_engine.graph.models import ASTGraph, ASTNode


@pytest.mark.asyncio
class TestASTNode:
    """Test ASTNode dataclass."""

    def test_node_creation(self) -> None:
        """Test creating an ASTNode."""
        node = ASTNode(
            id="test.py:1:1",
            type="call_expression",
            name="eval",
            file="test.py",
            line=1,
        )

        assert node.id == "test.py:1:1"
        assert node.type == "call_expression"
        assert node.name == "eval"
        assert node.file == "test.py"
        assert node.line == 1
        assert node.parent_id is None
        assert node.children == []

    def test_node_with_parent(self) -> None:
        """Test node with parent reference."""
        node = ASTNode(
            id="test.py:1:2",
            type="identifier",
            name="x",
            file="test.py",
            line=1,
            parent_id="test.py:1:1",
        )

        assert node.parent_id == "test.py:1:1"

    def test_node_equality(self) -> None:
        """Test node equality by ID."""
        node1 = ASTNode(
            id="same", type="call", name="test", file="test.py", line=1
        )
        node2 = ASTNode(
            id="same", type="different", name="other", file="other.py", line=2
        )

        assert node1 == node2

    def test_node_inequality(self) -> None:
        """Test node inequality."""
        node1 = ASTNode(
            id="first", type="call", name="test", file="test.py", line=1
        )
        node2 = ASTNode(
            id="second", type="call", name="test", file="test.py", line=1
        )

        assert node1 != node2


@pytest.mark.asyncio
class TestASTGraph:
    """Test ASTGraph functionality."""

    def test_empty_graph(self) -> None:
        """Test creating an empty graph."""
        graph = ASTGraph()

        assert graph.size() == 0
        assert len(graph.nodes) == 0
        assert len(graph.file_index) == 0
        assert len(graph.type_index) == 0

    def test_add_node(self) -> None:
        """Test adding a node to the graph."""
        graph = ASTGraph()
        node = ASTNode(
            id="test.py:1:1",
            type="call_expression",
            name="eval",
            file="test.py",
            line=1,
        )

        graph.add_node(node)

        assert graph.size() == 1
        assert graph.get_node("test.py:1:1") == node

    def test_file_index(self) -> None:
        """Test file-based indexing."""
        graph = ASTGraph()

        node1 = ASTNode(
            id="test.py:1:1", type="call", name="f1", file="test.py", line=1
        )
        node2 = ASTNode(
            id="test.py:2:1", type="call", name="f2", file="test.py", line=2
        )

        graph.add_node(node1)
        graph.add_node(node2)

        nodes = graph.get_nodes_by_file("test.py")
        assert len(nodes) == 2
        assert node1 in nodes
        assert node2 in nodes

    def test_type_index(self) -> None:
        """Test type-based indexing."""
        graph = ASTGraph()

        node1 = ASTNode(
            id="test.py:1:1",
            type="call_expression",
            name="eval",
            file="test.py",
            line=1,
        )
        node2 = ASTNode(
            id="test.py:2:1",
            type="call_expression",
            name="exec",
            file="test.py",
            line=2,
        )
        node3 = ASTNode(
            id="test.py:3:1", type="identifier", name="x", file="test.py", line=3
        )

        graph.add_node(node1)
        graph.add_node(node2)
        graph.add_node(node3)

        calls = graph.get_nodes_by_type("call_expression")
        assert len(calls) == 2
        assert node1 in calls
        assert node2 in calls
        assert node3 not in calls

    def test_parent_child_relationship(self) -> None:
        """Test parent-child relationships."""
        graph = ASTGraph()

        parent = ASTNode(
            id="test.py:1:1",
            type="function_definition",
            name="func",
            file="test.py",
            line=1,
        )
        child = ASTNode(
            id="test.py:2:1",
            type="call_expression",
            name="eval",
            file="test.py",
            line=2,
            parent_id="test.py:1:1",
        )

        graph.add_node(parent)
        graph.add_node(child)

        # Check child is in parent's children list
        assert child.id in parent.children

        # Check get_children
        children = graph.get_children(parent.id)
        assert len(children) == 1
        assert child in children

    def test_get_children_nonexistent(self) -> None:
        """Test get_children with non-existent node."""
        graph = ASTGraph()
        children = graph.get_children("nonexistent")
        assert children == []

    def test_find_by_name(self) -> None:
        """Test finding nodes by name."""
        graph = ASTGraph()

        node1 = ASTNode(
            id="test.py:1:1",
            type="identifier",
            name="eval",
            file="test.py",
            line=1,
        )
        node2 = ASTNode(
            id="test.py:2:1",
            type="identifier",
            name="exec",
            file="test.py",
            line=2,
        )

        graph.add_node(node1)
        graph.add_node(node2)

        results = graph.find_by_name("eval")
        assert len(results) == 1
        assert results[0] == node1

    def test_get_files(self) -> None:
        """Test getting list of files."""
        graph = ASTGraph()

        node1 = ASTNode(
            id="test.py:1:1", type="call", name="f1", file="test.py", line=1
        )
        node2 = ASTNode(
            id="other.py:1:1", type="call", name="f2", file="other.py", line=1
        )

        graph.add_node(node1)
        graph.add_node(node2)

        files = graph.get_files()
        assert len(files) == 2
        assert "test.py" in files
        assert "other.py" in files

    def test_get_types(self) -> None:
        """Test getting list of node types."""
        graph = ASTGraph()

        node1 = ASTNode(
            id="test.py:1:1",
            type="call_expression",
            name="f1",
            file="test.py",
            line=1,
        )
        node2 = ASTNode(
            id="test.py:2:1",
            type="identifier",
            name="x",
            file="test.py",
            line=2,
        )

        graph.add_node(node1)
        graph.add_node(node2)

        types = graph.get_types()
        assert len(types) == 2
        assert "call_expression" in types
        assert "identifier" in types

    def test_to_dict(self) -> None:
        """Test graph serialization to dict."""
        graph = ASTGraph()

        node = ASTNode(
            id="test.py:1:1",
            type="call_expression",
            name="eval",
            file="test.py",
            line=1,
        )

        graph.add_node(node)

        result = graph.to_dict()

        assert "nodes" in result
        assert "files" in result
        assert "types" in result
        assert "size" in result
        assert result["size"] == 1
