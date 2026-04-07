"""
CPG Models Unit Tests.

Test CPGNode, CPGEdge, and CodePropertyGraph data structures.
"""

import pytest

from src.layers.l3_analysis.engines.ast_engine.cpg.models import (
    CPGEdge,
    CPGNode,
    CodePropertyGraph,
)
from src.layers.l3_analysis.engines.ast_engine.graph.models import (
    ASTGraph,
    ASTNode,
)
from src.layers.l3_analysis.call_graph.models import (
    CallGraph,
    CallNode,
    NodeType,
)


class TestCPGNode:
    """Test CPGNode dataclass."""

    def test_init_minimal(self):
        """Test CPGNode initialization with minimal fields."""
        node = CPGNode(id="cpg:test:1", node_type="ast_statement")
        assert node.id == "cpg:test:1"
        assert node.node_type == "ast_statement"
        assert node.ast_node_id is None
        assert node.call_node_id is None

    def test_init_with_ast_info(self):
        """Test CPGNode with AST information."""
        node = CPGNode(
            id="cpg:test:1",
            node_type="ast_statement",
            ast_node_id="ast:test.py:10:call",
            ast_type="call_expression",
            file="test.py",
            line=10,
        )
        assert node.ast_node_id == "ast:test.py:10:call"
        assert node.ast_type == "call_expression"
        assert node.file == "test.py"
        assert node.line == 10

    def test_init_with_call_info(self):
        """Test CPGNode with Call Graph information."""
        node = CPGNode(
            id="cpg:call:test.py:5:func",
            node_type="call_function",
            call_node_id="test.py:func",
            call_name="func",
            file="test.py",
            line=5,
        )
        assert node.call_node_id == "test.py:func"
        assert node.call_name == "func"

    def test_hash_and_equality(self):
        """Test CPGNode hash and equality based on id."""
        node1 = CPGNode(id="cpg:test:1", node_type="ast_statement")
        node2 = CPGNode(id="cpg:test:1", node_type="call_function")
        node3 = CPGNode(id="cpg:test:2", node_type="ast_statement")

        assert node1 == node2  # Same ID
        assert node1 != node3  # Different ID
        assert hash(node1) == hash(node2)


class TestCPGEdge:
    """Test CPGEdge dataclass."""

    def test_init(self):
        """Test CPGEdge initialization."""
        edge = CPGEdge(
            edge_type="calls",
            source="node1",
            target="node2",
        )
        assert edge.edge_type == "calls"
        assert edge.source == "node1"
        assert edge.target == "node2"

    def test_hash_and_equality(self):
        """Test CPGEdge hash and equality."""
        edge1 = CPGEdge(edge_type="calls", source="a", target="b")
        edge2 = CPGEdge(edge_type="calls", source="a", target="b")
        edge3 = CPGEdge(edge_type="calls", source="a", target="c")
        edge4 = CPGEdge(edge_type="cfg", source="a", target="b")

        assert edge1 == edge2  # Same attributes
        assert edge1 != edge3  # Different target
        assert edge1 != edge4  # Different edge type
        assert hash(edge1) == hash(edge2)


class TestCodePropertyGraph:
    """Test CodePropertyGraph class."""

    def test_init(self):
        """Test CodePropertyGraph initialization."""
        cpg = CodePropertyGraph()
        assert cpg.size() == 0
        assert len(cpg.edges) == 0
        assert cpg.ast_graph is None
        assert cpg.call_graph is None

    def test_add_node(self):
        """Test adding a node to the CPG."""
        cpg = CodePropertyGraph()
        node = CPGNode(id="cpg:test:1", node_type="ast_statement", file="test.py")

        cpg.add_node(node)

        assert cpg.size() == 1
        assert cpg.get_node("cpg:test:1") == node

    def test_add_edge(self):
        """Test adding an edge to the CPG."""
        cpg = CodePropertyGraph()
        node1 = CPGNode(id="a", node_type="ast_statement")
        node2 = CPGNode(id="b", node_type="ast_statement")

        cpg.add_node(node1)
        cpg.add_node(node2)
        cpg.add_edge(CPGEdge(edge_type="calls", source="a", target="b"))

        assert len(cpg.edges) == 1
        assert "b" in node1.successors
        assert "a" in node2.predecessors

    def test_file_index(self):
        """Test file index."""
        cpg = CodePropertyGraph()
        node1 = CPGNode(id="a", node_type="ast_statement", file="test.py")
        node2 = CPGNode(id="b", node_type="ast_statement", file="other.py")

        cpg.add_node(node1)
        cpg.add_node(node2)

        files = cpg.get_files()
        assert "test.py" in files
        assert "other.py" in files

        test_py_nodes = cpg.get_nodes_by_file("test.py")
        assert len(test_py_nodes) == 1
        assert test_py_nodes[0] == node1

    def test_type_index(self):
        """Test node type index."""
        cpg = CodePropertyGraph()
        node1 = CPGNode(id="a", node_type="ast_statement")
        node2 = CPGNode(id="b", node_type="call_function")

        cpg.add_node(node1)
        cpg.add_node(node2)

        ast_nodes = cpg.get_nodes_by_type("ast_statement")
        call_nodes = cpg.get_nodes_by_type("call_function")

        assert len(ast_nodes) == 1
        assert len(call_nodes) == 1
        assert ast_nodes[0] == node1
        assert call_nodes[0] == node2

    def test_merge_ast_graph(self):
        """Test merging an AST Graph into the CPG."""
        cpg = CodePropertyGraph()
        ast_graph = ASTGraph()

        # Add some AST nodes
        ast_node1 = ASTNode(
            id="ast:test.py:1:call",
            type="call_expression",
            name="eval",
            file="test.py",
            line=1,
        )
        ast_node2 = ASTNode(
            id="ast:test.py:2:if",
            type="if_statement",
            name="if",
            file="test.py",
            line=2,
            parent_id=ast_node1.id,
        )

        ast_graph.add_node(ast_node1)
        ast_graph.add_node(ast_node2)

        # Merge
        cpg.merge_ast_graph(ast_graph)

        # Verify
        assert cpg.size() == 2
        assert cpg.ast_graph == ast_graph

        cpg_node1 = cpg.find_by_ast_id("ast:test.py:1:call")
        assert cpg_node1 is not None
        assert cpg_node1.ast_type == "call_expression"
        assert cpg_node1.file == "test.py"

        # Check AST parent edge
        parent_edges = [e for e in cpg.edges if e.edge_type == "ast_parent"]
        assert len(parent_edges) == 1
        assert parent_edges[0].source == cpg.find_by_ast_id(ast_node1.id).id
        assert parent_edges[0].target == cpg.find_by_ast_id(ast_node2.id).id

    def test_merge_call_graph(self):
        """Test merging a Call Graph into the CPG."""
        cpg = CodePropertyGraph()
        call_graph = CallGraph()

        # Add some call nodes
        call_node1 = CallNode(
            id="test.py:func1",
            name="func1",
            file_path="test.py",
            line=5,
            node_type=NodeType.FUNCTION,
        )
        call_node2 = CallNode(
            id="test.py:func2",
            name="func2",
            file_path="test.py",
            line=10,
            node_type=NodeType.FUNCTION,
        )

        call_graph.add_node(call_node1)
        call_graph.add_node(call_node2)

        # Add an edge
        from src.layers.l3_analysis.call_graph.models import CallEdge, CallType

        call_graph.add_edge(
            CallEdge(
                caller_id=call_node1.id,
                callee_id=call_node2.id,
                call_site="test.py:7",
                call_type=CallType.DIRECT,
            )
        )

        # Merge
        cpg.merge_call_graph(call_graph)

        # Verify
        func_nodes = cpg.get_nodes_by_type("call_function")
        assert len(func_nodes) == 2
        assert cpg.call_graph == call_graph

        cpg_func1 = cpg.find_by_call_id("test.py:func1")
        assert cpg_func1 is not None
        assert cpg_func1.call_name == "func1"

        # Check calls edge
        call_edges = [e for e in cpg.edges if e.edge_type == "calls"]
        assert len(call_edges) == 1
        assert call_edges[0].source == cpg_func1.id
        assert call_edges[0].target == cpg.find_by_call_id(call_node2.id).id

    def test_get_successors_predecessors(self):
        """Test getting successors and predecessors."""
        cpg = CodePropertyGraph()
        node1 = CPGNode(id="a", node_type="ast_statement")
        node2 = CPGNode(id="b", node_type="ast_statement")
        node3 = CPGNode(id="c", node_type="ast_statement")

        cpg.add_node(node1)
        cpg.add_node(node2)
        cpg.add_node(node3)
        cpg.add_edge(CPGEdge(edge_type="cfg", source="a", target="b"))
        cpg.add_edge(CPGEdge(edge_type="cfg", source="a", target="c"))

        assert set(cpg.get_successors("a")) == {"b", "c"}
        assert cpg.get_predecessors("b") == ["a"]
        assert cpg.get_predecessors("c") == ["a"]

    def test_to_dict(self):
        """Test serialization to dictionary."""
        cpg = CodePropertyGraph()
        node = CPGNode(
            id="cpg:test:1",
            node_type="ast_statement",
            file="test.py",
            line=10,
            ast_type="call_expression",
        )

        cpg.add_node(node)
        cpg.add_edge(CPGEdge(edge_type="calls", source="a", target="b"))

        result = cpg.to_dict()

        assert result["size"] == 1
        assert result["files"] == ["test.py"]
        assert len(result["nodes"]) == 1
        assert result["nodes"][0]["id"] == "cpg:test:1"
        assert result["nodes"][0]["ast_type"] == "call_expression"
        assert len(result["edges"]) == 1
