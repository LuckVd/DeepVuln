"""
Unit tests for GraphBridge.

Tests the bridge between AST Graph and Call Graph, ensuring accurate
function attribution and cross-graph navigation.
"""

import pytest

from src.layers.l3_analysis.engines.ast_engine.graph import (
    ASTGraph,
    ASTGraphBuilder,
    ASTNode,
    GraphBridge,
    TracedPath,
)
from src.layers.l3_analysis.call_graph.models import (
    CallEdge,
    CallGraph,
    CallNode,
    CallType,
    NodeType,
)


@pytest.fixture
def sample_ast_graph() -> ASTGraph:
    """
    Create a sample AST graph with nested functions.

    Structure:
    line 1:  def outer_handler():
    line 2:      user_input = get_input()
    line 3:
    line 4:      def inner_helper():
    line 5:          data = process()
    line 6:
    line 7:      def another_inner():
    line 8:          return eval(danger)
    line 9:
    line 10:     inner_helper()
    line 11:
    line 12: eval(global_danger)  # Global scope
    """
    graph = ASTGraph()

    # Function definitions
    outer_func = ASTNode(
        id="test.py:1:1",
        type="function_definition",
        name="outer_handler",
        file="test.py",
        line=1,
    )
    inner_func = ASTNode(
        id="test.py:4:2",
        type="function_definition",
        name="inner_helper",
        file="test.py",
        line=4,
        parent_id=outer_func.id,
    )
    another_func = ASTNode(
        id="test.py:7:3",
        type="function_definition",
        name="another_inner",
        file="test.py",
        line=7,
        parent_id=outer_func.id,
    )

    # Add nodes and establish parent-child
    for node in [outer_func, inner_func, another_func]:
        graph.add_node(node)

    # AST nodes in different scopes
    eval_in_inner = ASTNode(
        id="test.py:5:10",
        type="call",
        name="process",
        file="test.py",
        line=5,
        parent_id=inner_func.id,
    )

    eval_in_another = ASTNode(
        id="test.py:8:15",
        type="call",
        name="eval",
        file="test.py",
        line=8,
        parent_id=another_func.id,
    )

    eval_in_outer = ASTNode(
        id="test.py:2:10",
        type="call",
        name="get_input",
        file="test.py",
        line=2,
        parent_id=outer_func.id,
    )

    global_eval = ASTNode(
        id="test.py:12:5",
        type="call",
        name="eval",
        file="test.py",
        line=12,
        parent_id=None,  # Global scope
    )

    for node in [eval_in_inner, eval_in_another, eval_in_outer, global_eval]:
        graph.add_node(node)

    return graph


@pytest.fixture
def sample_call_graph() -> CallGraph:
    """Create a sample call graph."""
    graph = CallGraph()

    outer_node = CallNode(
        id="test.py:outer_handler",
        name="outer_handler",
        file_path="test.py",
        line=1,
        node_type=NodeType.FUNCTION,
        is_entry_point=True,
        entry_point_type="HTTP",
    )

    inner_node = CallNode(
        id="test.py:inner_helper",
        name="inner_helper",
        file_path="test.py",
        line=4,
        node_type=NodeType.FUNCTION,
    )

    another_node = CallNode(
        id="test.py:another_inner",
        name="another_inner",
        file_path="test.py",
        line=7,
        node_type=NodeType.FUNCTION,
    )

    for node in [outer_node, inner_node, another_node]:
        graph.add_node(node)

    # Add edges
    graph.add_edge(
        CallEdge(
            caller_id=outer_node.id,
            callee_id=inner_node.id,
            call_site="test.py:10",
            call_type=CallType.DIRECT,
            line_number=10,
        )
    )

    graph.add_edge(
        CallEdge(
            caller_id=outer_node.id,
            callee_id=another_node.id,
            call_site="test.py:7",
            call_type=CallType.DIRECT,
            line_number=7,
        )
    )

    return graph


@pytest.fixture
def bridge() -> GraphBridge:
    """Create a GraphBridge instance."""
    return GraphBridge()


class TestFindContainingFunction:
    """Test find_containing_function method."""

    def test_finds_containing_function_simple(
        self, bridge, sample_ast_graph, sample_call_graph
    ):
        """Test finding the containing function for a simple case."""
        node = sample_ast_graph.get_node("test.py:2:10")  # get_input in outer
        result = bridge.find_containing_function(node, sample_ast_graph, sample_call_graph)

        assert result is not None
        assert result.name == "outer_handler"

    def test_finds_containing_function_nested(
        self, bridge, sample_ast_graph, sample_call_graph
    ):
        """Test finding the containing function for nested functions."""
        node = sample_ast_graph.get_node("test.py:8:15")  # eval in another_inner
        result = bridge.find_containing_function(node, sample_ast_graph, sample_call_graph)

        assert result is not None
        assert result.name == "another_inner"

    def test_returns_none_for_global_code(
        self, bridge, sample_ast_graph, sample_call_graph
    ):
        """Test that global code returns None."""
        node = sample_ast_graph.get_node("test.py:12:5")  # global eval
        result = bridge.find_containing_function(node, sample_ast_graph, sample_call_graph)

        assert result is None

    def test_returns_none_when_no_matching_call_node(
        self, bridge, sample_ast_graph, sample_call_graph
    ):
        """Test when AST function has no corresponding CallNode."""
        # Create a node for a function not in call graph
        orphan_func = ASTNode(
            id="test.py:100:1",
            type="function_definition",
            name="orphan_function",
            file="test.py",
            line=100,
        )
        sample_ast_graph.add_node(orphan_func)

        orphan_call = ASTNode(
            id="test.py:101:10",
            type="call",
            name="some_call",
            file="test.py",
            line=101,
            parent_id=orphan_func.id,
        )
        sample_ast_graph.add_node(orphan_call)

        result = bridge.find_containing_function(
            orphan_call, sample_ast_graph, sample_call_graph
        )

        assert result is None


class TestFindASTNodesInFunction:
    """Test find_ast_nodes_in_function method."""

    def test_finds_nodes_in_function(
        self, bridge, sample_ast_graph, sample_call_graph
    ):
        """Test finding all AST nodes within a function."""
        call_node = sample_call_graph.nodes["test.py:outer_handler"]
        result = bridge.find_ast_nodes_in_function(call_node, sample_ast_graph)

        # Should find all nodes in outer_handler's subtree
        node_ids = [n.id for n in result]
        assert "test.py:2:10" in node_ids  # get_input
        assert "test.py:4:2" in node_ids  # inner_helper
        assert "test.py:5:10" in node_ids  # process in inner
        assert "test.py:7:3" in node_ids  # another_inner
        assert "test.py:8:15" in node_ids  # eval in another

    def test_excludes_global_nodes(
        self, bridge, sample_ast_graph, sample_call_graph
    ):
        """Test that global nodes are excluded."""
        call_node = sample_call_graph.nodes["test.py:outer_handler"]
        result = bridge.find_ast_nodes_in_function(call_node, sample_ast_graph)

        node_ids = [n.id for n in result]
        assert "test.py:12:5" not in node_ids  # global eval

    def test_returns_empty_for_unknown_function(
        self, bridge, sample_ast_graph, sample_call_graph
    ):
        """Test when function has no corresponding AST node."""
        unknown_node = CallNode(
            id="test.py:unknown_func",
            name="unknown_func",
            file_path="test.py",
            line=999,
            node_type=NodeType.FUNCTION,
        )

        result = bridge.find_ast_nodes_in_function(unknown_node, sample_ast_graph)

        assert result == []


class TestTraceToSink:
    """Test trace_to_sink method."""

    def test_traces_from_entry_to_sink(
        self, bridge, sample_ast_graph, sample_call_graph
    ):
        """Test tracing from entry point to sink."""
        entry = sample_call_graph.nodes["test.py:outer_handler"]
        sink = sample_ast_graph.get_node("test.py:8:15")  # eval in another_inner

        result = bridge.trace_to_sink(entry, sink, sample_call_graph, sample_ast_graph)

        assert result is not None
        assert result.entry_point.id == entry.id
        assert result.sink_ast_node.id == sink.id
        assert result.containing_function is not None
        assert result.containing_function.name == "another_inner"
        assert len(result.call_chain) > 0

    def test_returns_none_for_unreachable_sink(
        self, bridge, sample_ast_graph, sample_call_graph
    ):
        """Test when sink is not reachable from entry point."""
        # Create an unreachable entry point
        isolated_entry = CallNode(
            id="test.py:isolated",
            name="isolated",
            file_path="other.py",
            line=1,
            node_type=NodeType.FUNCTION,
            is_entry_point=True,
        )
        sample_call_graph.add_node(isolated_entry)

        sink = sample_ast_graph.get_node("test.py:8:15")

        result = bridge.trace_to_sink(
            isolated_entry, sink, sample_call_graph, sample_ast_graph
        )

        assert result is None

    def test_handles_global_sink(
        self, bridge, sample_ast_graph, sample_call_graph
    ):
        """Test tracing to a global (non-function) sink."""
        entry = sample_call_graph.nodes["test.py:outer_handler"]
        global_sink = sample_ast_graph.get_node("test.py:12:5")  # global eval

        result = bridge.trace_to_sink(
            entry, global_sink, sample_call_graph, sample_ast_graph
        )

        # Global sink should still return a path
        assert result is not None
        assert result.containing_function is None


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_lambda_handling(self, bridge):
        """Test handling of lambda functions."""
        graph = ASTGraph()

        # Create a lambda structure
        outer_func = ASTNode(
            id="test.py:1:1",
            type="function_definition",
            name="outer",
            file="test.py",
            line=1,
        )

        lambda_node = ASTNode(
            id="test.py:3:10",
            type="lambda",
            name="lambda",
            file="test.py",
            line=3,
            parent_id=outer_func.id,
        )

        eval_in_lambda = ASTNode(
            id="test.py:3:20",
            type="call",
            name="eval",
            file="test.py",
            line=3,
            parent_id=lambda_node.id,
        )

        for node in [outer_func, lambda_node, eval_in_lambda]:
            graph.add_node(node)

        # The containing function should be outer, not lambda
        # (since lambda is not in FUNCTION_TYPES)
        containing = bridge._find_function_by_ancestor(eval_in_lambda, graph)

        assert containing is not None
        assert containing.name == "outer"

    def test_deeply_nested_structure(self, bridge):
        """Test deeply nested function/lambda structure."""
        graph = ASTGraph()

        # level1 -> level2 -> level3 -> eval
        level1 = ASTNode(
            id="test.py:1:1",
            type="function_definition",
            name="level1",
            file="test.py",
            line=1,
        )

        level2 = ASTNode(
            id="test.py:3:1",
            type="function_definition",
            name="level2",
            file="test.py",
            line=3,
            parent_id=level1.id,
        )

        level3 = ASTNode(
            id="test.py:5:1",
            type="function_definition",
            name="level3",
            file="test.py",
            line=5,
            parent_id=level2.id,
        )

        eval_node = ASTNode(
            id="test.py:6:10",
            type="call",
            name="eval",
            file="test.py",
            line=6,
            parent_id=level3.id,
        )

        for node in [level1, level2, level3, eval_node]:
            graph.add_node(node)

        containing = bridge._find_function_by_ancestor(eval_node, graph)

        assert containing is not None
        assert containing.name == "level3"

    def test_class_method(self, bridge):
        """Test class method handling."""
        graph = ASTGraph()

        class_def = ASTNode(
            id="test.py:1:1",
            type="class_definition",
            name="MyClass",
            file="test.py",
            line=1,
        )

        method_def = ASTNode(
            id="test.py:3:1",
            type="function_definition",
            name="my_method",
            file="test.py",
            line=3,
            parent_id=class_def.id,
        )

        eval_node = ASTNode(
            id="test.py:4:10",
            type="call",
            name="eval",
            file="test.py",
            line=4,
            parent_id=method_def.id,
        )

        for node in [class_def, method_def, eval_node]:
            graph.add_node(node)

        containing = bridge._find_function_by_ancestor(eval_node, graph)

        assert containing is not None
        assert containing.name == "my_method"


class TestTracedPath:
    """Test TracedPath dataclass."""

    def test_to_dict(self):
        """Test TracedPath serialization."""
        from src.layers.l3_analysis.call_graph.models import CallNode, NodeType

        entry = CallNode(
            id="test.py:main",
            name="main",
            file_path="test.py",
            line=1,
            node_type=NodeType.FUNCTION,
            is_entry_point=True,
        )

        sink = ASTNode(
            id="test.py:10:5",
            type="call",
            name="eval",
            file="test.py",
            line=10,
        )

        containing = CallNode(
            id="test.py:handler",
            name="handler",
            file_path="test.py",
            line=5,
            node_type=NodeType.FUNCTION,
        )

        path = TracedPath(
            entry_point=entry,
            call_chain=[containing],
            sink_ast_node=sink,
            containing_function=containing,
            full_path=[entry.id, containing.id, sink.id],
            confidence=0.9,
            path_length=2,
        )

        result = path.to_dict()

        assert result["entry_point"]["name"] == "main"
        assert result["sink"]["type"] == "call"
        assert result["confidence"] == 0.9
        assert len(result["call_chain"]) == 1
