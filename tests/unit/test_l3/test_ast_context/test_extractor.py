"""
Unit tests for ASTContextExtractor.

Tests the extraction of structured AST context for AI Agent.
"""

import pytest

from src.layers.l3_analysis.engines.ast_engine.context import (
    ASTContext,
    ASTContextExtractor,
)
from src.layers.l3_analysis.engines.ast_engine.graph import (
    ASTGraph,
    ASTGraphBuilder,
    ASTNode,
)


@pytest.fixture
def sample_ast_graph() -> ASTGraph:
    """Create a sample AST graph for testing."""
    graph = ASTGraph()

    # Function definition
    func_node = ASTNode(
        id="test.py:5:1",
        type="function_definition",
        name="vulnerable_handler",
        file="test.py",
        line=5,
    )

    # Call expression (eval)
    eval_call = ASTNode(
        id="test.py:10:5",
        type="call",
        name="eval",
        file="test.py",
        line=10,
        parent_id=func_node.id,
    )

    # Identifier (argument)
    arg_node = ASTNode(
        id="test.py:10:10",
        type="identifier",
        name="user_input",
        file="test.py",
        line=10,
        parent_id=eval_call.id,
    )

    for node in [func_node, eval_call, arg_node]:
        graph.add_node(node)

    return graph


@pytest.fixture
def extractor(sample_ast_graph) -> ASTContextExtractor:
    """Create an ASTContextExtractor with sample graph."""
    return ASTContextExtractor(ast_graph=sample_ast_graph)


class TestASTContextExtractor:
    """Test ASTContextExtractor class."""

    def test_extract_for_location(self, extractor):
        """Test extracting context for a specific location."""
        context = extractor.extract_for_location(
            file_path="test.py",
            line=10,
            code_snippet="eval(user_input)",
        )

        assert context.code_snippet == "eval(user_input)"
        assert context.ast_structure is not None
        assert context.ast_structure["type"] == "call"
        assert context.ast_structure["name"] == "eval"

    def test_parent_context_extraction(self, extractor):
        """Test parent context extraction."""
        context = extractor.extract_for_location(
            file_path="test.py",
            line=10,
        )

        assert context.parent_context is not None
        assert context.parent_context["type"] == "function_definition"
        assert context.parent_context["name"] == "vulnerable_handler"

    def test_risk_analysis_for_dangerous_function(self, extractor):
        """Test risk analysis identifies dangerous functions."""
        context = extractor.extract_for_location(
            file_path="test.py",
            line=10,
        )

        assert context.risk_analysis is not None
        assert context.risk_analysis["sink_type"] == "code_injection"
        assert context.risk_analysis["dangerous_function"] == "eval"

    def test_extract_for_sinks(self, extractor, sample_ast_graph):
        """Test extracting context for multiple sink nodes."""
        sink_nodes = [
            sample_ast_graph.get_node("test.py:10:5"),
            sample_ast_graph.get_node("test.py:5:1"),
        ]

        contexts = extractor.extract_for_sinks(sink_nodes)

        assert len(contexts) == 2

        # First context (eval call)
        eval_ctx = contexts[0]
        assert eval_ctx.ast_structure["name"] == "eval"
        assert eval_ctx.risk_analysis is not None

    def test_to_prompt_section(self, extractor):
        """Test converting context to prompt section."""
        context = extractor.extract_for_location(
            file_path="test.py",
            line=10,
            code_snippet="eval(user_input)",
        )

        prompt_section = context.to_prompt_section()

        assert "## AST Structure Analysis" in prompt_section
        assert "Code Snippet" in prompt_section
        assert "AST Structure" in prompt_section
        assert "Parent Context" in prompt_section
        assert "Risk Assessment" in prompt_section

    def test_no_graph_fallback(self):
        """Test behavior when AST graph is not available."""
        extractor = ASTContextExtractor(ast_graph=None)

        context = extractor.extract_for_location(
            file_path="test.py",
            line=10,
            code_snippet="eval(user_input)",
        )

        assert context.code_snippet == "eval(user_input)"
        assert context.ast_structure["type"] == "unknown"
        assert context.parent_context is None
        assert context.risk_analysis is None


class TestASTContext:
    """Test ASTContext dataclass."""

    def test_to_prompt_section_complete(self):
        """Test prompt section generation with all fields."""
        context = ASTContext(
            code_snippet="eval(user_input)",
            ast_structure={
                "type": "call",
                "name": "eval",
                "line": 10,
            },
            parent_context={
                "type": "function_definition",
                "name": "handler",
            },
            risk_analysis={
                "sink_type": "code_injection",
                "confidence": 0.9,
            },
        )

        prompt = context.to_prompt_section()

        assert "## AST Structure Analysis" in prompt
        assert "eval" in prompt
        assert "code_injection" in prompt
        assert "handler" in prompt

    def test_to_prompt_section_minimal(self):
        """Test prompt section generation with minimal fields."""
        context = ASTContext(
            code_snippet="x = 1",
            ast_structure={"type": "assignment"},
            parent_context=None,
            risk_analysis=None,
        )

        prompt = context.to_prompt_section()

        assert "## AST Structure Analysis" in prompt
        assert "x = 1" in prompt
        assert "assignment" in prompt


class TestRiskAnalysis:
    """Test risk analysis functionality."""

    def test_dangerous_function_detection(self, sample_ast_graph):
        """Test detection of dangerous functions."""
        extractor = ASTContextExtractor(ast_graph=sample_ast_graph)

        context = extractor.extract_for_location("test.py", 10)

        assert context.risk_analysis is not None
        assert context.risk_analysis["sink_type"] == "code_injection"

    def test_various_dangerous_functions(self):
        """Test detection of various dangerous function types."""
        graph = ASTGraph()

        dangerous_calls = [
            ("system", "command_injection"),
            ("pickle.load", "deserialization"),
            ("md5", "weak_crypto"),
            ("open", "path_traversal"),
        ]

        for func_name, expected_type in dangerous_calls:
            node = ASTNode(
                id=f"test.py:1:1",
                type="call",
                name=func_name,
                file="test.py",
                line=1,
            )
            graph.add_node(node)

            extractor = ASTContextExtractor(ast_graph=graph)
            context = extractor.extract_for_location("test.py", 1)

            assert context.risk_analysis is not None
            assert context.risk_analysis["sink_type"] == expected_type

    def test_safe_function_no_risk(self):
        """Test that safe functions don't get flagged."""
        graph = ASTGraph()

        node = ASTNode(
            id="test.py:1:1",
            type="call",
            name="print",
            file="test.py",
            line=1,
        )
        graph.add_node(node)

        extractor = ASTContextExtractor(ast_graph=graph)
        context = extractor.extract_for_location("test.py", 1)

        # Should either have no risk analysis or low confidence
        if context.risk_analysis:
            assert context.risk_analysis["confidence"] < 0.8
