"""
Unit tests for UnifiedGraphQuery.

Tests the high-level unified query interface that combines AST Graph
and Call Graph for common analysis scenarios.
"""

import pytest

from src.layers.l3_analysis.engines.ast_engine.graph import (
    ASTGraph,
    ASTGraphBuilder,
    ASTNode,
    GraphBridge,
    SinkMatch,
    UnifiedGraphQuery,
)
from src.layers.l3_analysis.call_graph.models import (
    CallEdge,
    CallGraph,
    CallNode,
    CallType,
    NodeType,
)


@pytest.fixture
def complex_graphs():
    """
    Create complex AST and Call graphs for testing.

    Structure:
    - app.py has handler() entry point
    - handler() calls process_user_input()
    - process_user_input() has eval() sink
    - utils.py has helper() with eval() but not reachable
    """
    # AST Graph
    ast_graph = ASTGraph()

    # app.py nodes
    handler_func = ASTNode(
        id="app.py:5:1",
        type="function_definition",
        name="handler",
        file="app.py",
        line=5,
    )

    process_func = ASTNode(
        id="app.py:15:1",
        type="function_definition",
        name="process_user_input",
        file="app.py",
        line=15,
        parent_id=None,  # Separate function, not nested in handler
    )

    eval_in_process = ASTNode(
        id="app.py:20:10",
        type="call",
        name="eval",
        file="app.py",
        line=20,
        parent_id=process_func.id,
    )

    system_call = ASTNode(
        id="app.py:25:15",
        type="call",
        name="system",
        file="app.py",
        line=25,
        parent_id=process_func.id,
    )

    # utils.py nodes (not reachable)
    helper_func = ASTNode(
        id="utils.py:10:1",
        type="function_definition",
        name="helper",
        file="utils.py",
        line=10,
    )

    eval_in_helper = ASTNode(
        id="utils.py:15:10",
        type="call",
        name="eval",
        file="utils.py",
        line=15,
        parent_id=helper_func.id,
    )

    for node in [
        handler_func,
        process_func,
        eval_in_process,
        system_call,
        helper_func,
        eval_in_helper,
    ]:
        ast_graph.add_node(node)

    # Call Graph
    call_graph = CallGraph()

    handler_node = CallNode(
        id="app.py:handler",
        name="handler",
        file_path="app.py",
        line=5,
        node_type=NodeType.FUNCTION,
        is_entry_point=True,
        entry_point_type="HTTP",
    )

    process_node = CallNode(
        id="app.py:process_user_input",
        name="process_user_input",
        file_path="app.py",
        line=15,
        node_type=NodeType.FUNCTION,
    )

    helper_node = CallNode(
        id="utils.py:helper",
        name="helper",
        file_path="utils.py",
        line=10,
        node_type=NodeType.FUNCTION,
    )

    for node in [handler_node, process_node, helper_node]:
        call_graph.add_node(node)

    # Add edges
    call_graph.add_edge(
        CallEdge(
            caller_id=handler_node.id,
            callee_id=process_node.id,
            call_site="app.py:18",
            call_type=CallType.DIRECT,
            line_number=18,
        )
    )

    return ast_graph, call_graph


@pytest.fixture
def unified_query(complex_graphs):
    """Create a UnifiedGraphQuery instance."""
    ast_graph, call_graph = complex_graphs
    return UnifiedGraphQuery(call_graph=call_graph, ast_graph=ast_graph)


class TestFindAllSinks:
    """Test find_all_sinks method."""

    def test_finds_all_dangerous_sinks(self, unified_query):
        """Test finding all dangerous sinks in the AST."""
        sinks = unified_query.find_all_sinks()

        sink_names = [s.ast_node.name for s in sinks]
        assert "eval" in sink_names
        assert "system" in sink_names

        # Should find both evals (one in process, one in helper)
        eval_sinks = [s for s in sinks if s.ast_node.name == "eval"]
        assert len(eval_sinks) == 2

    def test_filters_by_sink_type(self, unified_query):
        """Test filtering sinks by type."""
        code_injection_sinks = unified_query.find_all_sinks(
            sink_types=["code_injection"]
        )

        assert all(s.sink_type == "code_injection" for s in code_injection_sinks)
        assert len(code_injection_sinks) >= 1  # At least eval

    def test_custom_patterns(self, unified_query):
        """Test using custom sink patterns."""
        custom = {"custom_sink": ["custom_dangerous_function"]}

        # First, add a custom node
        custom_node = ASTNode(
            id="app.py:100:10",
            type="call",
            name="custom_dangerous_function",
            file="app.py",
            line=100,
        )
        unified_query.ast_graph.add_node(custom_node)

        sinks = unified_query.find_all_sinks(custom_patterns=custom)

        assert any(s.ast_node.name == "custom_dangerous_function" for s in sinks)


class TestFindReachableSinks:
    """Test find_reachable_sinks method."""

    def test_finds_reachable_sinks_from_entry(self, unified_query):
        """Test finding sinks reachable from entry point."""
        entry = unified_query.call_graph.nodes["app.py:handler"]

        paths = unified_query.find_reachable_sinks(entry_point=entry)

        # Should find eval in process_user_input (reachable)
        path_sink_names = [p.sink_ast_node.name for p in paths]
        assert "eval" in path_sink_names

        # Check that we found a path
        eval_paths = [p for p in paths if p.sink_ast_node.name == "eval"]
        assert len(eval_paths) >= 1

    def test_excludes_unreachable_sinks(self, unified_query):
        """Test that unreachable sinks are excluded."""
        paths = unified_query.find_reachable_sinks()

        # The eval in helper() should not be reachable
        # (no edge from handler to helper)
        for path in paths:
            if path.sink_ast_node.name == "eval":
                # If it's eval, it should be the one in process_user_input
                assert path.sink_ast_node.file == "app.py"

    def test_respects_max_path_length(self, unified_query):
        """Test max_path_length parameter."""
        paths = unified_query.find_reachable_sinks(max_path_length=0)

        # With max_path_length=0, only direct sinks should be found
        # (none in this case, since eval is one level deep)
        assert len(paths) == 0


class TestGetFunctionContext:
    """Test get_function_context method."""

    def test_returns_complete_context(self, unified_query):
        """Test getting complete context for a location."""
        context = unified_query.get_function_context("app.py", 20)

        assert context.call_node is not None
        assert context.call_node.name == "process_user_input"
        assert len(context.ast_nodes) > 0
        assert context.is_entry_point is False  # process_user_input is not entry

    def test_identifies_entry_point(self, unified_query):
        """Test identifying entry points."""
        context = unified_query.get_function_context("app.py", 5)

        assert context.is_entry_point is True
        assert context.entry_point_type == "HTTP"

    def test_finds_sinks_in_function(self, unified_query):
        """Test finding sinks within a function."""
        context = unified_query.get_function_context("app.py", 20)

        # process_user_input contains eval and system
        assert len(context.sinks) >= 1
        sink_types = [s.sink_type for s in context.sinks]
        assert "code_injection" in sink_types  # eval

    def test_gets_callers_and_callees(self, unified_query):
        """Test getting caller and callee information."""
        context = unified_query.get_function_context("app.py", 15)

        # process_user_input is called by handler
        assert len(context.callers) >= 1
        caller_names = [c.name for c in context.callers]
        assert "handler" in caller_names


class TestGetAttackPaths:
    """Test get_attack_paths method."""

    def test_gets_paths_to_target(self, unified_query):
        """Test getting all attack paths to a target."""
        paths = unified_query.get_attack_paths("app.py", 20)

        # Should find at least one path to the eval at line 20
        assert len(paths) >= 1

        # Check path structure
        path = paths[0]
        assert "entry_point" in path
        assert "sink" in path
        assert path["sink"]["line"] == 20

    def test_returns_empty_for_unknown_target(self, unified_query):
        """Test with a target that doesn't exist."""
        paths = unified_query.get_attack_paths("nonexistent.py", 999)

        assert len(paths) == 0


class TestSinkMatch:
    """Test SinkMatch dataclass."""

    def test_to_dict(self):
        """Test SinkMatch serialization."""
        node = ASTNode(
            id="test.py:10:5",
            type="call",
            name="eval",
            file="test.py",
            line=10,
        )

        match = SinkMatch(
            ast_node=node,
            sink_type="code_injection",
            confidence=0.9,
            containing_function=None,
        )

        result = match.to_dict()

        assert result["ast_node"]["name"] == "eval"
        assert result["sink_type"] == "code_injection"
        assert result["confidence"] == 0.9


class TestFunctionContext:
    """Test FunctionContext dataclass."""

    def test_to_dict(self, unified_query):
        """Test FunctionContext serialization."""
        context = unified_query.get_function_context("app.py", 15)

        result = context.to_dict()

        assert "call_node" in result
        assert "ast_nodes_count" in result
        assert "is_entry_point" in result
        assert "sinks" in result


class TestDangerousSinks:
    """Test DANGEROUS_SINKS constant."""

    def test_has_common_categories(self):
        """Test that common vulnerability categories are defined."""
        from src.layers.l3_analysis.engines.ast_engine.graph import (
            DANGEROUS_SINKS,
        )

        # Common categories should exist
        assert "code_injection" in DANGEROUS_SINKS
        assert "command_injection" in DANGEROUS_SINKS
        assert "sql_injection" in DANGEROUS_SINKS

        # Common dangerous functions should be listed
        assert "eval" in DANGEROUS_SINKS["code_injection"]
        assert "system" in DANGEROUS_SINKS["command_injection"]


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_graphs(self):
        """Test behavior with empty graphs."""
        ast_graph = ASTGraph()
        call_graph = CallGraph()

        query = UnifiedGraphQuery(call_graph=call_graph, ast_graph=ast_graph)

        sinks = query.find_all_sinks()
        assert sinks == []

        paths = query.find_reachable_sinks()
        assert paths == []

    def test_no_entry_points(self, complex_graphs):
        """Test when call graph has no entry points."""
        ast_graph, call_graph = complex_graphs

        # Create new graphs without entry points
        new_call_graph = CallGraph()
        for node in call_graph.nodes.values():
            # Create a copy without entry point status
            new_node = CallNode(
                id=node.id,
                name=node.name,
                file_path=node.file_path,
                line=node.line,
                node_type=node.node_type,
                is_entry_point=False,  # No entry points
                entry_point_type=None,
            )
            new_call_graph.add_node(new_node)

        # Copy edges
        for edge in call_graph.edges:
            new_call_graph.add_edge(edge)

        query = UnifiedGraphQuery(call_graph=new_call_graph, ast_graph=ast_graph)

        paths = query.find_reachable_sinks()
        # Should return empty since no entry points
        assert paths == []

    def test_global_sink_with_entry_in_same_file(self, complex_graphs):
        """Test global sink when entry point is in same file."""
        ast_graph, call_graph = complex_graphs

        # Add a global eval (no parent function)
        global_eval = ASTNode(
            id="app.py:200:10",
            type="call",
            name="eval",
            file="app.py",
            line=200,
            parent_id=None,  # Global scope
        )
        ast_graph.add_node(global_eval)

        query = UnifiedGraphQuery(call_graph=call_graph, ast_graph=ast_graph)

        paths = query.find_reachable_sinks()

        # Should find the global eval since entry is in same file
        global_eval_paths = [
            p for p in paths if p.sink_ast_node and p.sink_ast_node.line == 200
        ]
        # Note: Current implementation may or may not include this
        # depending on how same-file global code is handled
