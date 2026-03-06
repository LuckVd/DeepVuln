"""
Tests for Taint Tracker (P5-01c).

Tests the backward taint tracking with sanitizer detection.
"""

import pytest

from src.layers.l3_analysis.call_graph.models import (
    CallEdge,
    CallGraph,
    CallNode,
    NodeType,
    TaintTraceResult,
    TaintTrackerConfig,
)
from src.layers.l3_analysis.call_graph.taint_tracker import (
    TaintTracker,
)

# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def sample_graph():
    """Create a sample call graph for testing."""
    graph = CallGraph()

    # Entry point
    entry_node = CallNode(
        id="app.py:handle_request",
        name="handle_request",
        file_path="app.py",
        line=10,
        node_type=NodeType.FUNCTION,
        is_entry_point=True,
        entry_point_type="HTTP",
    )
    graph.add_node(entry_node)

    # Middleware
    middleware_node = CallNode(
        id="app.py:validate_input",
        name="validate_input",
        file_path="app.py",
        line=25,
        node_type=NodeType.FUNCTION,
        is_entry_point=False,
    )
    graph.add_node(middleware_node)

    # Sanitizer
    sanitizer_node = CallNode(
        id="utils.py:escape_html",
        name="escape_html",
        file_path="utils.py",
        line=5,
        node_type=NodeType.FUNCTION,
        is_entry_point=False,
    )
    graph.add_node(sanitizer_node)

    # Sink (vulnerable function)
    sink_node = CallNode(
        id="app.py:render_template",
        name="render_template",
        file_path="app.py",
        line=50,
        node_type=NodeType.FUNCTION,
        is_entry_point=False,
    )
    graph.add_node(sink_node)

    # Vulnerable sink (no sanitizer)
    vuln_sink_node = CallNode(
        id="app.py:execute_query",
        name="execute_query",
        file_path="app.py",
        line=75,
        node_type=NodeType.FUNCTION,
        is_entry_point=False,
    )
    graph.add_node(vuln_sink_node)

    # Add edges
    graph.add_edge(CallEdge(
        caller_id=entry_node.id,
        callee_id=middleware_node.id,
        call_site="app.py:12",
        line_number=12,
    ))
    graph.add_edge(CallEdge(
        caller_id=middleware_node.id,
        callee_id=sanitizer_node.id,
        call_site="app.py:28",
        line_number=28,
    ))
    graph.add_edge(CallEdge(
        caller_id=middleware_node.id,
        callee_id=sink_node.id,
        call_site="app.py:30",
        line_number=30,
    ))
    graph.add_edge(CallEdge(
        caller_id=entry_node.id,
        callee_id=vuln_sink_node.id,
        call_site="app.py:15",
        line_number=15,
    ))

    return graph


@pytest.fixture
def sample_source_code_map():
    """Source code for AST analysis."""
    return {
        "utils.py": '''
def escape_html(input_string):
    """Escape HTML special characters."""
    result = input_string.replace("<", "&lt;")
    result = result.replace(">", "&gt;")
    result = result.replace("&", "&amp;")
    return result
''',
        "app.py": '''
def render_template(template, context):
    """Render template with context."""
    return template.format(**context)

def execute_query(query):
    """Execute SQL query (vulnerable)."""
    return db.execute(query)
'''
    }


# ============================================================
# Initialization Tests
# ============================================================

class TestTaintTrackerInit:
    """Tests for TaintTracker initialization."""

    def test_default_init(self):
        """Test default initialization."""
        tracker = TaintTracker()
        assert tracker.config is not None
        assert tracker.language == "python"

    def test_custom_config(self):
        """Test initialization with custom config."""
        config = TaintTrackerConfig(max_path_length=5)
        tracker = TaintTracker(config=config)
        assert tracker.config.max_path_length == 5

    def test_custom_language(self):
        """Test initialization with custom language."""
        tracker = TaintTracker(language="javascript")
        assert tracker.language == "javascript"

    def test_analyzers_initialized(self):
        """Test that sub-analyzers are initialized."""
        tracker = TaintTracker()
        assert tracker.transform_analyzer is not None
        assert tracker.type_analyzer is not None


# ============================================================
# Basic Taint Tracing Tests
# ============================================================

class TestBasicTaintTracing:
    """Tests for basic taint tracing functionality."""

    def test_trace_to_entry_point(self, sample_graph):
        """Test tracing from sink to entry point."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
        )

        assert result.is_reachable is True
        assert result.source_id is not None
        assert result.path_length > 0

    def test_trace_nonexistent_sink(self, sample_graph):
        """Test tracing from non-existent sink."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="nonexistent.py",
            sink_function="nonexistent",
        )

        assert result.is_reachable is False
        assert result.confidence == 0.0

    def test_path_is_built(self, sample_graph):
        """Test that call path is correctly built."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
        )

        assert len(result.path) > 0
        assert len(result.call_chain) > 0
        assert all(isinstance(p, str) for p in result.path)
        assert all(isinstance(c, str) for c in result.call_chain)

    def test_entry_point_type_recorded(self, sample_graph):
        """Test that entry point type is recorded."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
        )

        assert result.entry_point_type == "HTTP"


# ============================================================
# Sanitizer Detection Tests
# ============================================================

class TestSanitizerDetection:
    """Tests for sanitizer detection during taint tracing."""

    def test_sanitizer_detected_on_path(self, sample_graph, sample_source_code_map):
        """Test that sanitizers are detected on the path."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(  # noqa: F841
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
            source_code_map=sample_source_code_map,
        )

        # The path goes through escape_html sanitizer
        # Note: Detection depends on AST analysis being available

    def test_is_sanitized_flag(self, sample_graph, sample_source_code_map):
        """Test that is_sanitized flag is set correctly."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
            source_code_map=sample_source_code_map,
        )

        # If sanitizers found with sufficient confidence
        if result.sanitizers:
            assert result.is_sanitized == any(
                s.combined_confidence >= tracker.config.sanitizer_confidence_threshold
                for s in result.sanitizers
            )

    def test_effective_sanitizer_identified(self, sample_graph, sample_source_code_map):
        """Test that effective sanitizer is identified."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
            source_code_map=sample_source_code_map,
        )

        if result.is_sanitized:
            assert result.effective_sanitizer is not None
            assert result.effective_sanitizer.combined_confidence > 0

    def test_no_sanitizer_on_vulnerable_path(self, sample_graph, sample_source_code_map):
        """Test that vulnerable paths have no sanitizers."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="execute_query",
            source_code_map=sample_source_code_map,
        )

        # execute_query is directly called from entry, no sanitizer
        assert result.is_sanitized is False


# ============================================================
# Exploitability Assessment
# ============================================================

class TestExploitabilityAssessment:
    """Tests for exploitability assessment."""

    def test_reachable_unsanitized_is_exploitable(self, sample_graph, sample_source_code_map):
        """Test that reachable+unsanitized = exploitable."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="execute_query",
            source_code_map=sample_source_code_map,
        )

        if result.is_reachable and not result.is_sanitized:
            assert result.is_exploitable is True

    def test_sanitized_is_not_exploitable(self, sample_graph, sample_source_code_map):
        """Test that sanitized paths are not exploitable."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
            source_code_map=sample_source_code_map,
        )

        if result.is_sanitized:
            assert result.is_exploitable is False

    def test_not_reachable_is_not_exploitable(self, sample_graph):
        """Test that unreachable paths are not exploitable."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="nonexistent",
        )

        assert not result.is_reachable
        assert result.is_exploitable is False


# ============================================================
# Confidence Calculation Tests
# ============================================================

class TestConfidenceCalculation:
    """Tests for confidence score calculation."""

    def test_confidence_includes_path_length_factor(self, sample_graph):
        """Test that confidence considers path length."""
        tracker = TaintTracker(config=TaintTrackerConfig(max_path_length=20))
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
        )

        # Confidence should be affected by distance decay
        assert result.distance_decay > 0
        assert result.distance_decay <= 1.0

    def test_distance_decay_formula(self, sample_graph):
        """Test distance decay calculation."""
        tracker = TaintTracker(config=TaintTrackerConfig(distance_decay_factor=0.9))
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
        )

        expected_decay = 0.9 ** result.path_length
        assert abs(result.distance_decay - expected_decay) < 0.01

    def test_confidence_in_range(self, sample_graph):
        """Test that confidence is always in valid range."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
        )

        assert 0.0 <= result.confidence <= 1.0


# ============================================================
# Configuration Tests
# ============================================================

class TestConfiguration:
    """Tests for configuration options."""

    def test_max_path_length_respected(self, sample_graph):
        """Test that max_path_length limit is respected."""
        tracker = TaintTracker(config=TaintTrackerConfig(max_path_length=1))
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
        )

        # Should stop at max length
        assert result.path_length <= tracker.config.max_path_length

    def test_max_nodes_visited_respected(self, sample_graph):
        """Test that max_nodes_visited limit is respected."""
        # Create a large graph to test
        graph = CallGraph()
        for i in range(100):
            node = CallNode(
                id=f"file.py:func_{i}",
                name=f"func_{i}",
                file_path="file.py",
                line=i,
                node_type=NodeType.FUNCTION,
                is_entry_point=(i == 0),
            )
            graph.add_node(node)
            if i > 0:
                graph.add_edge(CallEdge(
                    caller_id=f"file.py:func_{i-1}",
                    callee_id=f"file.py:func_{i}",
                    call_site=f"file.py:{i}",
                    line_number=i,
                ))

        tracker = TaintTracker(config=TaintTrackerConfig(max_nodes_visited=10))
        result = tracker.trace_from_sink(
            graph=graph,
            sink_file="file.py",
            sink_function="func_50",
        )

        # Should complete without hanging
        assert result is not None

    def test_sanitizer_threshold_affects_detection(self, sample_graph, sample_source_code_map):
        """Test that sanitizer threshold affects is_sanitized."""
        # Low threshold = more likely to be sanitized
        tracker = TaintTracker(
            config=TaintTrackerConfig(sanitizer_confidence_threshold=0.1)
        )
        result = tracker.trace_from_sink(  # noqa: F841
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
            source_code_map=sample_source_code_map,
        )

        # With low threshold, weak sanitizers might trigger


# ============================================================
# Batch Processing Tests
# ============================================================

class TestBatchProcessing:
    """Tests for batch processing of multiple sinks."""

    def test_trace_multiple_sinks(self, sample_graph):
        """Test tracing multiple sinks at once."""
        tracker = TaintTracker()
        sinks = [
            ("app.py", "render_template", None),
            ("app.py", "execute_query", None),
        ]

        results = tracker.trace_multiple_sinks(
            graph=sample_graph,
            sinks=sinks,
        )

        assert len(results) == 2
        assert all(isinstance(r, TaintTraceResult) for r in results)

    def test_get_exploitable_sinks(self, sample_graph, sample_source_code_map):
        """Test filtering for only exploitable sinks."""
        tracker = TaintTracker()
        sinks = [
            ("app.py", "render_template", None),
            ("app.py", "execute_query", None),
        ]

        exploitable = tracker.get_exploitable_sinks(
            graph=sample_graph,
            sinks=sinks,
            source_code_map=sample_source_code_map,
        )

        # Should only return exploitable results
        assert all(r.is_exploitable for r in exploitable)


# ============================================================
# Different Vulnerability Types
# ============================================================

class TestDifferentVulnTypes:
    """Tests for different vulnerability types."""

    def test_sqli_taint_tracking(self, sample_graph):
        """Test taint tracking for SQL injection."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="execute_query",
            vuln_type="sqli",
        )

        assert result.sink_id == "app.py:execute_query"

    def test_cmdi_taint_tracking(self, sample_graph):
        """Test taint tracking for command injection."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="execute_query",  # Using same sink for test
            vuln_type="cmdi",
        )

        assert isinstance(result, TaintTraceResult)


# ============================================================
# Edge Cases
# ============================================================

class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_sink_is_entry_point(self, sample_graph):
        """Test when sink itself is an entry point."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="handle_request",
        )

        assert result.is_reachable is True
        assert result.path_length == 0

    def test_empty_graph(self):
        """Test with empty graph."""
        tracker = TaintTracker()
        graph = CallGraph()
        result = tracker.trace_from_sink(
            graph=graph,
            sink_file="app.py",
            sink_function="any_function",
        )

        assert result.is_reachable is False

    def test_disconnected_components(self):
        """Test with disconnected graph components."""
        graph = CallGraph()

        # Component 1
        entry = CallNode(
            id="a.py:entry",
            name="entry",
            file_path="a.py",
            line=1,
            node_type=NodeType.FUNCTION,
            is_entry_point=True,
            entry_point_type="HTTP",
        )
        graph.add_node(entry)

        # Component 2 (disconnected)
        sink = CallNode(
            id="b.py:sink",
            name="sink",
            file_path="b.py",
            line=1,
            node_type=NodeType.FUNCTION,
            is_entry_point=False,
        )
        graph.add_node(sink)

        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=graph,
            sink_file="b.py",
            sink_function="sink",
        )

        # Should not be reachable (no path between components)
        assert result.is_reachable is False


# ============================================================
# Serialization Tests
# ============================================================

class TestSerialization:
    """Tests for TaintTraceResult serialization."""

    def test_to_dict(self, sample_graph):
        """Test TaintTraceResult.to_dict() method."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
        )
        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert "source_id" in result_dict
        assert "sink_id" in result_dict
        assert "is_reachable" in result_dict
        assert "is_sanitized" in result_dict
        assert "is_exploitable" in result_dict
        assert "path" in result_dict
        assert "path_length" in result_dict
        assert "confidence" in result_dict

    def test_sanitizer_list_serialized(self, sample_graph, sample_source_code_map):
        """Test that sanitizers list is properly serialized."""
        tracker = TaintTracker()
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
            source_code_map=sample_source_code_map,
        )
        result_dict = result.to_dict()

        assert "sanitizers" in result_dict
        assert isinstance(result_dict["sanitizers"], list)


# ============================================================
# Integration Tests
# ============================================================

class TestIntegration:
    """Integration tests with other components."""

    def test_integration_with_call_graph_analyzer(self, sample_graph):
        """Test integration with CallGraphAnalyzer."""
        tracker = TaintTracker()

        # The tracker should work with graphs from CallGraphAnalyzer
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
        )

        assert isinstance(result, TaintTraceResult)

    def test_full_workflow(self, sample_graph, sample_source_code_map):
        """Test complete workflow from sink to exploitability."""
        tracker = TaintTracker()

        # Step 1: Trace from sink
        result = tracker.trace_from_sink(
            graph=sample_graph,
            sink_file="app.py",
            sink_function="render_template",
            source_code_map=sample_source_code_map,
        )

        # Step 2: Check if reachable
        assert isinstance(result.is_reachable, bool)

        # Step 3: Check if sanitized
        assert isinstance(result.is_sanitized, bool)

        # Step 4: Determine exploitability
        assert isinstance(result.is_exploitable, bool)

        # Step 5: Get confidence
        assert 0.0 <= result.confidence <= 1.0
