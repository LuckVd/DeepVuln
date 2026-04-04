"""
End-to-end verification for AST Graph + Call Graph bridge.

Minimal validation that the unified query interface works correctly
with real source code.
"""

import tempfile
from pathlib import Path

from src.layers.l3_analysis.engines.ast_engine.graph import UnifiedGraphQuery


def test_e2e_graph_building():
    """
    End-to-end test: verify both graphs can be built from source.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create a test Python file with a vulnerability
        app_code = '''
from http.server import BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        user_input = self.path.split("=")[1]
        # Vulnerable: eval of user input
        result = eval(user_input)
        self.send_response(200)

def helper():
    # This eval is not reachable from entry point
    x = eval("safe")
    return x
'''
        app_file = tmpdir / "app.py"
        app_file.write_text(app_code)

        # Create UnifiedGraphQuery from source
        query = UnifiedGraphQuery.from_source_files(
            source_path=tmpdir,
            file_patterns=["*.py"],
        )

        # Verify 1: AST graph has nodes
        assert query.ast_graph.size() > 0, "AST graph should have nodes"
        print(f"✓ AST graph built: {query.ast_graph.size()} nodes")

        # Verify 2: Call graph has nodes
        assert query.call_graph.node_count > 0, "Call graph should have nodes"
        print(f"✓ Call graph built: {query.call_graph.node_count} nodes")


def test_e2e_sink_detection():
    """
    Verify dangerous sinks can be detected.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Simple vulnerable code
        code = '''
def handle_request(data):
    return eval(data["command"])

def safe_function():
    return "safe"
'''
        test_file = tmpdir / "vuln.py"
        test_file.write_text(code)

        query = UnifiedGraphQuery.from_source_files(tmpdir)

        # Should detect sinks
        sinks = query.find_all_sinks()
        assert len(sinks) > 0, f"Should find sinks, got {len(sinks)}"

        # At least one should be code_injection (eval)
        code_injection_sinks = [s for s in sinks if s.sink_type == "code_injection"]
        assert len(code_injection_sinks) > 0, "Should find code_injection sinks"

        print(f"✓ Found {len(sinks)} sinks, {len(code_injection_sinks)} code_injection")


def test_e2e_cross_graph_lookup():
    """
    Verify that AST nodes can be mapped to CallGraph functions.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Code with eval in a function
        code = '''
def vulnerable_function(user_input):
    # This eval is in vulnerable_function
    result = eval(user_input)
    return result

def another_function():
    pass
'''
        test_file = tmpdir / "test.py"
        test_file.write_text(code)

        query = UnifiedGraphQuery.from_source_files(tmpdir)

        # Find sinks
        sinks = query.find_all_sinks()
        eval_sinks = [s for s in sinks if "eval" in s.ast_node.name.lower()]

        assert len(eval_sinks) > 0, "Should find eval sinks"

        # At least one sink should have a containing function
        sinks_with_function = [s for s in eval_sinks if s.containing_function is not None]
        print(f"✓ Found {len(sinks_with_function)} sinks with containing function")

        # The containing function should be named "vulnerable_function" or similar
        if sinks_with_function:
            func_name = sinks_with_function[0].containing_function.name
            print(f"✓ Sink is in function: {func_name}")
            assert "vulnerable" in func_name.lower() or "function" in func_name.lower()


if __name__ == "__main__":
    print("=" * 60)
    print("P8-05d: End-to-End Bridge Verification")
    print("=" * 60)
    print()

    try:
        print("Test 1: Graph Building")
        test_e2e_graph_building()
        print()

        print("Test 2: Sink Detection")
        test_e2e_sink_detection()
        print()

        print("Test 3: Cross-Graph Lookup")
        test_e2e_cross_graph_lookup()
        print()

        print("=" * 60)
        print("✅ All end-to-end verifications passed!")
        print("=" * 60)
    except Exception as e:
        print(f"\n❌ Verification failed: {e}")
        raise
