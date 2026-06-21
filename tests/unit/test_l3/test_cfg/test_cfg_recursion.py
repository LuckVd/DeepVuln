"""Phase 18/P3 — CFG basic-block recursion into compound bodies.

Verifies identify_basic_blocks recurses into if/for/while bodies so a sink
nested in a branch gets its own basic block (and thus goes through real CFG
reachability), instead of being silently treated as reachable via the old
``_locate_block -> None -> continue`` fallback.
"""

from src.layers.l3_analysis.engines.ast_engine.cfg.builders.python_cfg import (
    PythonCFGBuilder,
)
from src.layers.l3_analysis.engines.ast_engine.graph.models import (
    ASTGraph,
    ASTNode,
)


def _graph_with_nested_sink():
    """Build: def f(): A; if cond: B (sink); C

    B sits inside the if body block. Returns (graph, function_node).
    """
    g = ASTGraph()
    func = ASTNode(
        id="fn", type="function_definition", name="f", file="t.py", line=1
    )
    body = ASTNode(id="blk", type="block", name="", file="t.py", line=1)
    a = ASTNode(
        id="a", type="expression_statement", name="", file="t.py", line=2
    )
    ifs = ASTNode(id="ifs", type="if_statement", name="", file="t.py", line=3)
    cons = ASTNode(id="cons", type="block", name="", file="t.py", line=3)
    b = ASTNode(
        id="b", type="expression_statement", name="", file="t.py", line=4
    )
    c = ASTNode(
        id="c", type="expression_statement", name="", file="t.py", line=5
    )
    func.children = ["blk"]
    body.children = ["a", "ifs", "c"]
    ifs.children = ["cons"]
    cons.children = ["b"]
    for n in (func, body, a, ifs, cons, b, c):
        g.add_node(n)
    return g, func


class TestCFGCompoundRecursion:
    """P3: identify_basic_blocks recurses into compound bodies."""

    def test_nested_sink_in_if_body_gets_block(self):
        g, func = _graph_with_nested_sink()
        builder = PythonCFGBuilder()
        builder._ast_graph = g  # bind graph so recursion resolves children

        fn_body = builder._extract_function_body(func, g)
        blocks = builder.identify_basic_blocks(fn_body, "t.py")

        # The if-body sink (line 4) must be covered by some block's range.
        covered = {
            ln
            for blk in blocks
            for ln in range(blk.start_line, blk.end_line + 1)
        }
        assert 4 in covered, (
            f"if-body sink not in any block: "
            f"{[(b.start_line, b.end_line) for b in blocks]}"
        )

    def test_no_recursion_without_ast_graph(self):
        """When _ast_graph is None (called outside build_cfg), recursion is
        skipped — backward compatible with the pre-P3 behaviour."""
        g, func = _graph_with_nested_sink()
        builder = PythonCFGBuilder()
        # _ast_graph left None
        fn_body = builder._extract_function_body(func, g)
        blocks = builder.identify_basic_blocks(fn_body, "t.py")

        covered = {
            ln
            for blk in blocks
            for ln in range(blk.start_line, blk.end_line + 1)
        }
        # Without recursion the if-body sink (line 4) is NOT covered.
        assert 4 not in covered

    def test_collect_compound_body_returns_if_body(self):
        g, _ = _graph_with_nested_sink()
        builder = PythonCFGBuilder()
        builder._ast_graph = g
        ifs = g.get_node("ifs")

        body_stmts = builder._collect_compound_body(ifs)

        assert len(body_stmts) == 1
        assert body_stmts[0].line == 4  # the nested sink
