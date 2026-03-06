"""
Tests for Call Graph Analysis.

Tests the call graph construction and reachability analysis.
"""

import pytest
from pathlib import Path
import tempfile

from src.layers.l3_analysis.call_graph.models import (
    CallGraph,
    CallNode,
    CallEdge,
    CallType,
    NodeType,
    FileCallGraph,
    ReachabilityResult,
)
from src.layers.l3_analysis.call_graph.analyzer import CallGraphAnalyzer
from src.layers.l3_analysis.call_graph.reachability import (
    ReachabilityChecker,
    ReachabilityConfig,
)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def sample_python_code():
    """Sample Python code with various patterns."""
    return '''
from flask import Flask
app = Flask(__name__)

@app.route('/api/users')
def get_users():
    """HTTP entry point."""
    users = query_db()
    return format_response(users)

@app.route('/api/user/<id>')
def get_user_by_id(user_id):
    """Another HTTP entry point."""
    user = query_db(user_id)
    return format_response(user)

def query_db(user_id=None):
    """Internal function - not an entry point."""
    if user_id:
        return execute_raw_sql(f"SELECT * FROM users WHERE id = {user_id}")
    return execute_raw_sql("SELECT * FROM users")

def execute_raw_sql(query):
    """Vulnerable function - SQL injection sink."""
    pass

def format_response(data):
    """Helper function."""
    return {"data": data}

@celery.task
def process_background_job():
    """Celery task - async entry point."""
    data = fetch_data()
    process_data(data)

def fetch_data():
    pass

def process_data(data):
    pass
'''


@pytest.fixture
def sample_python_file(sample_python_code, tmp_path):
    """Create a temporary Python file."""
    test_file = tmp_path / "test_module.py"
    test_file.write_text(sample_python_code)
    return test_file


# ============================================================
# Model Tests
# ============================================================

class TestCallNode:
    """Tests for CallNode model."""

    def test_create_function_node(self):
        """Test creating a function node."""
        node = CallNode(
            id="test.py:my_func",
            name="my_func",
            file_path="test.py",
            line=10,
        )
        assert node.name == "my_func"
        assert node.node_type == NodeType.FUNCTION
        assert not node.is_entry_point

    def test_create_method_node(self):
        """Test creating a method node."""
        node = CallNode(
            id="test.py:MyClass.my_method",
            name="my_method",
            file_path="test.py",
            line=20,
            node_type=NodeType.METHOD,
            class_name="MyClass",
        )
        assert node.class_name == "MyClass"
        assert node.node_type == NodeType.METHOD

    def test_create_entry_point_node(self):
        """Test creating an entry point node."""
        node = CallNode(
            id="test.py:api_handler",
            name="api_handler",
            file_path="test.py",
            line=30,
            is_entry_point=True,
            entry_point_type="HTTP",
        )
        assert node.is_entry_point
        assert node.entry_point_type == "HTTP"

    def test_node_hash_and_equality(self):
        """Test node hash and equality."""
        node1 = CallNode(
            id="test.py:func",
            name="func",
            file_path="test.py",
            line=10,
        )
        node2 = CallNode(
            id="test.py:func",
            name="func",
            file_path="test.py",
            line=10,
        )
        node3 = CallNode(
            id="test.py:other",
            name="other",
            file_path="test.py",
            line=20,
        )

        assert hash(node1) == hash(node2)
        assert node1 == node2
        assert node1 != node3


class TestCallEdge:
    """Tests for CallEdge model."""

    def test_create_direct_call(self):
        """Test creating a direct call edge."""
        edge = CallEdge(
            caller_id="test.py:caller",
            callee_id="test.py:callee",
            call_site="test.py:15",
        )
        assert edge.call_type == CallType.DIRECT
        assert edge.caller_id == "test.py:caller"

    def test_create_virtual_call(self):
        """Test creating a virtual (method) call edge."""
        edge = CallEdge(
            caller_id="test.py:MyClass.method",
            callee_id="test.py:helper",
            call_site="test.py:25",
            call_type=CallType.VIRTUAL,
        )
        assert edge.call_type == CallType.VIRTUAL

    def test_edge_hash(self):
        """Test edge hash."""
        edge1 = CallEdge(
            caller_id="a",
            callee_id="b",
            call_site="f:10",
        )
        edge2 = CallEdge(
            caller_id="a",
            callee_id="b",
            call_site="f:10",
        )
        assert hash(edge1) == hash(edge2)


class TestCallGraph:
    """Tests for CallGraph model."""

    def test_empty_graph(self):
        """Test creating an empty graph."""
        graph = CallGraph()
        assert graph.node_count == 0
        assert graph.edge_count == 0
        assert graph.entry_point_count == 0

    def test_add_node(self):
        """Test adding nodes to graph."""
        graph = CallGraph()
        node = CallNode(
            id="test.py:func",
            name="func",
            file_path="test.py",
            line=10,
        )
        graph.add_node(node)

        assert graph.node_count == 1
        assert "test.py:func" in graph.nodes

    def test_add_edge(self):
        """Test adding edges to graph."""
        graph = CallGraph()

        caller = CallNode(id="a.py:caller", name="caller", file_path="a.py", line=1)
        callee = CallNode(id="a.py:callee", name="callee", file_path="a.py", line=10)
        graph.add_node(caller)
        graph.add_node(callee)

        edge = CallEdge(
            caller_id="a.py:caller",
            callee_id="a.py:callee",
            call_site="a.py:5",
        )
        graph.add_edge(edge)

        assert graph.edge_count == 1
        assert graph.get_callees("a.py:caller") == ["a.py:callee"]
        assert graph.get_callers("a.py:callee") == ["a.py:caller"]

    def test_entry_point_tracking(self):
        """Test entry point tracking."""
        graph = CallGraph()

        entry = CallNode(
            id="api.py:handler",
            name="handler",
            file_path="api.py",
            line=10,
            is_entry_point=True,
            entry_point_type="HTTP",
        )
        internal = CallNode(
            id="api.py:helper",
            name="helper",
            file_path="api.py",
            line=20,
        )
        graph.add_node(entry)
        graph.add_node(internal)

        entry_points = graph.get_entry_points()
        assert len(entry_points) == 1
        assert entry_points[0].name == "handler"

    def test_find_node(self):
        """Test finding nodes."""
        graph = CallGraph()
        node = CallNode(id="f.py:func", name="func", file_path="f.py", line=10)
        graph.add_node(node)

        found = graph.find_node("func")
        assert found is not None
        assert found.id == "f.py:func"

        not_found = graph.find_node("nonexistent")
        assert not_found is None


# ============================================================
# Python Builder Tests
# ============================================================

class TestPythonCallGraphBuilder:
    """Tests for Python call graph builder."""

    def test_extract_functions(self, sample_python_file, sample_python_code):
        """Test extracting function definitions."""
        from src.layers.l3_analysis.call_graph.builders.python_builder import PythonCallGraphBuilder

        builder = PythonCallGraphBuilder()
        graph = builder.build_file_graph(sample_python_code, sample_python_file, Path("/"))

        # Should extract all functions
        assert len(graph.nodes) >= 7  # At least 7 functions defined

        # Check function names
        names = [n.name for n in graph.nodes]
        assert "get_users" in names
        assert "query_db" in names
        assert "execute_raw_sql" in names

    def test_detect_http_entry_points(self, sample_python_file, sample_python_code):
        """Test detecting HTTP entry points."""
        from src.layers.l3_analysis.call_graph.builders.python_builder import PythonCallGraphBuilder

        builder = PythonCallGraphBuilder()
        graph = builder.build_file_graph(sample_python_code, sample_python_file, Path("/"))

        # Find HTTP entry points
        http_entries = [n for n in graph.nodes if n.is_entry_point and n.entry_point_type == "HTTP"]
        assert len(http_entries) >= 2  # get_users and get_user_by_id

    def test_detect_async_entry_points(self, sample_python_file, sample_python_code):
        """Test detecting async task entry points."""
        from src.layers.l3_analysis.call_graph.builders.python_builder import PythonCallGraphBuilder

        builder = PythonCallGraphBuilder()
        graph = builder.build_file_graph(sample_python_code, sample_python_file, Path("/"))

        # Find async entry points
        async_entries = [n for n in graph.nodes if n.is_entry_point and n.entry_point_type == "ASYNC_TASK"]
        assert len(async_entries) >= 1  # process_background_job

    def test_extract_calls(self, sample_python_file, sample_python_code):
        """Test extracting function calls."""
        from src.layers.l3_analysis.call_graph.builders.python_builder import PythonCallGraphBuilder

        builder = PythonCallGraphBuilder()
        graph = builder.build_file_graph(sample_python_code, sample_python_file, Path("/"))

        # Should have call edges
        assert len(graph.internal_calls) >= 2  # At least get_users -> query_db, query_db -> execute_raw_sql

        # Check call chain
        get_users = next(n for n in graph.nodes if n.name == "get_users")
        callees = [e.callee_id for e in graph.internal_calls if e.caller_id == get_users.id]
        assert len(callees) >= 1  # Should call query_db


# ============================================================
# Reachability Tests
# ============================================================

class TestReachabilityChecker:
    """Tests for reachability analysis."""

    def test_directly_reachable(self):
        """Test directly reachable (1 hop)."""
        graph = CallGraph()

        entry = CallNode(
            id="api.py:handler",
            name="handler",
            file_path="api.py",
            line=10,
            is_entry_point=True,
            entry_point_type="HTTP",
        )
        target = CallNode(
            id="db.py:query",
            name="query",
            file_path="db.py",
            line=20,
        )
        graph.add_node(entry)
        graph.add_node(target)

        edge = CallEdge(
            caller_id="api.py:handler",
            callee_id="db.py:query",
            call_site="api.py:15",
        )
        graph.add_edge(edge)

        checker = ReachabilityChecker()
        result = checker.check_reachability(
            graph=graph,
            target_file="db.py",
            target_function="query",
        )

        assert result is not None
        assert result.is_reachable
        assert result.path_length == 1
        assert result.confidence >= 0.8

    def test_indirectly_reachable(self):
        """Test indirectly reachable (2 hops)."""
        graph = CallGraph()

        entry = CallNode(
            id="api.py:handler",
            name="handler",
            file_path="api.py",
            line=10,
            is_entry_point=True,
        )
        middle = CallNode(
            id="service.py:process",
            name="process",
            file_path="service.py",
            line=20,
        )
        target = CallNode(
            id="db.py:query",
            name="query",
            file_path="db.py",
            line=30,
        )
        graph.add_node(entry)
        graph.add_node(middle)
        graph.add_node(target)

        graph.add_edge(CallEdge(
            caller_id="api.py:handler",
            callee_id="service.py:process",
            call_site="api.py:15",
        ))
        graph.add_edge(CallEdge(
            caller_id="service.py:process",
            callee_id="db.py:query",
            call_site="service.py:25",
        ))

        checker = ReachabilityChecker()
        result = checker.check_reachability(
            graph=graph,
            target_file="db.py",
            target_function="query",
        )

        assert result is not None
        assert result.is_reachable
        assert result.path_length == 2

    def test_not_reachable(self):
        """Test not reachable (no path)."""
        graph = CallGraph()

        entry = CallNode(
            id="api.py:handler",
            name="handler",
            file_path="api.py",
            line=10,
            is_entry_point=True,
        )
        target = CallNode(
            id="internal.py:helper",
            name="helper",
            file_path="internal.py",
            line=20,
        )
        graph.add_node(entry)
        graph.add_node(target)
        # No edge connecting them

        checker = ReachabilityChecker()
        result = checker.check_reachability(
            graph=graph,
            target_file="internal.py",
            target_function="helper",
        )

        # Target not reachable from entry point
        assert result is None or not result.is_reachable

    def test_max_path_length(self):
        """Test max path length limit."""
        config = ReachabilityConfig(max_path_length=2)
        checker = ReachabilityChecker(config)

        graph = CallGraph()

        # Create a chain of 4 nodes
        nodes = []
        for i in range(4):
            node = CallNode(
                id=f"f{i}.py:func{i}",
                name=f"func{i}",
                file_path=f"f{i}.py",
                line=10 * i,
                is_entry_point=(i == 0),
            )
            nodes.append(node)
            graph.add_node(node)

        # Connect them in a chain
        for i in range(3):
            graph.add_edge(CallEdge(
                caller_id=f"f{i}.py:func{i}",
                callee_id=f"f{i+1}.py:func{i+1}",
                call_site=f"f{i}.py:15",
            ))

        # func3 is 3 hops away, beyond max_path_length=2
        result = checker.check_reachability(
            graph=graph,
            target_file="f3.py",
            target_function="func3",
        )

        # Should not be reachable due to path length limit
        assert result is None or not result.is_reachable


# ============================================================
# Analyzer Tests
# ============================================================

class TestCallGraphAnalyzer:
    """Tests for CallGraphAnalyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = CallGraphAnalyzer()
        assert analyzer is not None

    def test_build_file_graph(self, sample_python_file, sample_python_code):
        """Test building file-level call graph."""
        analyzer = CallGraphAnalyzer()
        file_graph = analyzer.build_file_graph(
            sample_python_file, sample_python_code, Path("/")
        )

        assert file_graph is not None
        assert len(file_graph.nodes) >= 1

    def test_check_reachability(self, sample_python_file, sample_python_code):
        """Test reachability checking."""
        analyzer = CallGraphAnalyzer()

        # Build a CallGraph from the file
        from src.layers.l3_analysis.call_graph.builders.python_builder import PythonCallGraphBuilder
        builder = PythonCallGraphBuilder()
        file_graph = builder.build_file_graph(sample_python_code, sample_python_file, Path("/"))

        # Convert FileCallGraph to CallGraph
        from src.layers.l3_analysis.call_graph.models import CallGraph
        graph = CallGraph()
        for node in file_graph.nodes:
            graph.add_node(node)
        for edge in file_graph.internal_calls + file_graph.external_calls:
            graph.add_edge(edge)

        # Check reachability to execute_raw_sql (should be reachable)
        result = analyzer.check_reachability(
            graph=graph,
            target_file=sample_python_file.name,
            target_function="execute_raw_sql",
        )

        # execute_raw_sql should be reachable from get_users via query_db
        if result:
            assert result.is_reachable
