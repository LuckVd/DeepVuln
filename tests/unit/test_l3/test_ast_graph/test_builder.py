"""Tests for ASTGraphBuilder."""

from pathlib import Path

import pytest

from src.layers.l3_analysis.engines.ast_engine.graph.builder import ASTGraphBuilder
from src.layers.l3_analysis.engines.ast_engine.graph.models import ASTGraph


@pytest.mark.asyncio
class TestASTGraphBuilder:
    """Test ASTGraphBuilder functionality."""

    async def test_build_from_code_python(self) -> None:
        """Test building graph from Python code."""
        builder = ASTGraphBuilder()

        code = """
def dangerous(user_input):
    return eval(user_input)
"""

        graph = builder.build_from_code(code, "python", "test.py")

        # Should have nodes
        assert graph.size() > 0

        # Should have eval call
        eval_nodes = graph.find_by_name("eval")
        assert len(eval_nodes) > 0

        # Should have function definition
        func_nodes = graph.get_nodes_by_type("function_definition")
        assert len(func_nodes) > 0

    async def test_build_from_file(self, tmp_path) -> None:
        """Test building graph from a file."""
        builder = ASTGraphBuilder()

        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("x = eval(user_input)")

        graph = builder.build_from_file(test_file)

        assert graph.size() > 0
        assert str(test_file) in graph.get_files()

    async def test_build_from_nonexistent_file(self) -> None:
        """Test building from nonexistent file returns empty graph."""
        builder = ASTGraphBuilder()

        graph = builder.build_from_file("/nonexistent/file.py")

        assert graph.size() == 0

    async def test_parent_child_relationships(self) -> None:
        """Test that parent-child relationships are preserved."""
        builder = ASTGraphBuilder()

        code = "eval(user_input)"
        graph = builder.build_from_code(code, "python", "test.py")

        # Find root nodes (no parent)
        root_nodes = [
            n for n in graph.nodes.values() if n.parent_id is None
        ]
        assert len(root_nodes) > 0

        # Check that children have correct parent
        for node in graph.nodes.values():
            if node.parent_id:
                parent = graph.get_node(node.parent_id)
                assert parent is not None
                assert node.id in parent.children

    async def test_type_indexing(self) -> None:
        """Test that nodes are indexed by type."""
        builder = ASTGraphBuilder()

        code = """
def func():
    x = eval(a)
    y = exec(b)
"""

        graph = builder.build_from_code(code, "python", "test.py")

        # Should have different node types
        types = graph.get_types()
        assert len(types) > 1

        # Python tree-sitter uses "call" not "call_expression"
        call_nodes = graph.get_nodes_by_type("call")
        assert len(call_nodes) > 0

    async def test_file_indexing(self) -> None:
        """Test that nodes are indexed by file."""
        builder = ASTGraphBuilder()

        graph1 = builder.build_from_code(
            "x = 1", "python", "file1.py"
        )
        graph2 = builder.build_from_code(
            "y = 2", "python", "file2.py"
        )

        # Check each graph has its file
        assert "file1.py" in graph1.get_files()
        assert "file2.py" in graph2.get_files()

    async def test_unknown_language(self) -> None:
        """Test building with unknown language."""
        builder = ASTGraphBuilder()

        graph = builder.build_from_code("code", "unknown_lang", "test.xyz")

        # Should return empty graph for unsupported language
        assert graph.size() == 0

    async def test_node_ids_are_unique(self) -> None:
        """Test that all node IDs are unique."""
        builder = ASTGraphBuilder()

        code = "x = eval(a) + exec(b)"
        graph = builder.build_from_code(code, "python", "test.py")

        # All node IDs should be unique
        node_ids = list(graph.nodes.keys())
        assert len(node_ids) == len(set(node_ids))

    async def test_graph_serialization(self) -> None:
        """Test that graph can be serialized to dict."""
        builder = ASTGraphBuilder()

        code = "eval(user_input)"
        graph = builder.build_from_code(code, "python", "test.py")

        result = graph.to_dict()

        assert "nodes" in result
        assert "size" in result
        assert isinstance(result["nodes"], list)
        assert result["size"] == graph.size()
