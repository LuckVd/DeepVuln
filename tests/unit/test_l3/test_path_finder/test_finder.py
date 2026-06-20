"""
Path Finder Unit Tests.

Test AttackPathFinder and related models.
"""

import pytest

from src.layers.l3_analysis.engines.ast_engine.path_finder.models import (
    AttackPath,
    PathFinderConfig,
    PathType,
)
from src.layers.l3_analysis.engines.ast_engine.cpg.models import (
    CPGEdge,
    CPGNode,
    CodePropertyGraph,
)


class TestPathFinderConfig:
    """Test PathFinderConfig dataclass."""

    def test_defaults(self):
        """Test default configuration values."""
        config = PathFinderConfig()

        assert config.max_path_length == 15
        assert config.max_nodes_visited == 1000
        assert config.min_confidence == 0.3
        assert config.sanitizer_confidence_threshold == 0.7
        assert config.distance_decay_factor == 0.9

    def test_sanitizer_patterns(self):
        """Test default sanitizer patterns."""
        config = PathFinderConfig()

        assert "sanitize" in config.sanitizer_patterns
        assert "escape" in config.sanitizer_patterns
        assert "validate" in config.sanitizer_patterns


class TestAttackPath:
    """Test AttackPath dataclass."""

    def test_init(self):
        """Test AttackPath initialization."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.EXECUTION,
            path=["entry", "mid", "sink"],
            sink_type="sql_injection",
            confidence=0.8,
        )

        assert path.entry_point == "entry"
        assert path.sink == "sink"
        assert path.path_type == PathType.EXECUTION
        assert path.path == ["entry", "mid", "sink"]
        assert path.sink_type == "sql_injection"
        assert path.confidence == 0.8

    def test_is_exploitable_true(self):
        """Test is_exploitable when conditions are met."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.DATAFLOW,
            confidence=0.8,
            reaches_sink=True,
            is_sanitized=False,
        )

        assert path.is_exploitable

    def test_is_exploitable_false_low_confidence(self):
        """Test is_exploitable with low confidence."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.DATAFLOW,
            confidence=0.3,
            reaches_sink=True,
            is_sanitized=False,
        )

        assert not path.is_exploitable

    def test_is_exploitable_false_sanitized(self):
        """Test is_exploitable when sanitized."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.DATAFLOW,
            confidence=0.8,
            reaches_sink=True,
            is_sanitized=True,
        )

        assert not path.is_exploitable

    def test_is_exploitable_false_not_reachable(self):
        """Test is_exploitable when not reachable."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.DATAFLOW,
            confidence=0.8,
            reaches_sink=False,
            is_sanitized=False,
        )

        assert not path.is_exploitable

    def test_path_length(self):
        """Test path_length property."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.EXECUTION,
            path=["a", "b", "c", "d"],
        )

        assert path.path_length() == 4

    def test_to_dict(self):
        """Test serialization to dictionary."""
        path = AttackPath(
            entry_point="entry",
            sink="sink",
            path_type=PathType.EXECUTION,
            path=["entry", "sink"],
            sink_type="command_injection",
            confidence=0.9,
            is_sanitized=False,
            reaches_sink=True,
        )

        result = path.to_dict()

        assert result["entry_point"] == "entry"
        assert result["sink"] == "sink"
        assert result["path_type"] == "execution"
        assert result["sink_type"] == "command_injection"
        assert result["confidence"] == 0.9
        assert result["is_exploitable"]
        assert not result["is_sanitized"]
        assert result["reaches_sink"]
        assert result["path_length"] == 2


class TestAttackPathFinder:
    """Test AttackPathFinder class."""

    def test_init(self):
        """Test AttackPathFinder initialization."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        finder = AttackPathFinder()
        assert finder.config.max_path_length == 15

    def test_init_with_config(self):
        """Test AttackPathFinder with custom config."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        config = PathFinderConfig(max_path_length=20)
        finder = AttackPathFinder(config)

        assert finder.config.max_path_length == 20

    def test_find_paths_empty_cpg(self):
        """Test find_paths with empty CPG."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        finder = AttackPathFinder()
        cpg = CodePropertyGraph()

        paths = finder.find_paths(cpg, "eval")

        assert paths == []

    def test_find_paths_with_entry_and_sink(self):
        """Test find_paths with entry point and sink."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        # Create a simple CPG with entry and sink
        cpg = CodePropertyGraph()

        # Create entry node
        entry = CPGNode(
            id="entry",
            node_type="call_function",
            call_name="handler",
            file="test.py",
            line=5,
            metadata={"is_entry_point": True},
        )

        # Create middle node
        mid = CPGNode(
            id="mid",
            node_type="call_function",
            call_name="process",
            file="test.py",
            line=10,
        )

        # Create sink node
        sink = CPGNode(
            id="sink",
            node_type="ast_statement",
            ast_type="call_expression",
            file="test.py",
            line=15,
            metadata={"ast_name": "eval"},
        )

        cpg.add_node(entry)
        cpg.add_node(mid)
        cpg.add_node(sink)

        # Connect them
        cpg.add_edge(CPGEdge(edge_type="calls", source="entry", target="mid"))
        cpg.add_edge(CPGEdge(edge_type="calls", source="mid", target="sink"))

        # Find paths
        finder = AttackPathFinder()
        paths = finder.find_paths(cpg, "eval", entry_points=["entry"])

        assert len(paths) == 1
        assert paths[0].entry_point == "entry"
        assert paths[0].sink == "sink"
        assert paths[0].path == ["entry", "mid", "sink"]
        assert paths[0].is_exploitable

    def test_find_paths_sanitized(self):
        """Test find_paths with sanitizer in path."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        cpg = CodePropertyGraph()

        # Create entry
        entry = CPGNode(
            id="entry",
            node_type="call_function",
            call_name="handler",
            file="test.py",
            line=5,
            metadata={"is_entry_point": True},
        )

        # Create sanitizer
        sanitizer = CPGNode(
            id="sanitizer",
            node_type="call_function",
            call_name="sanitize_input",
            file="test.py",
            line=10,
        )

        # Create sink
        sink = CPGNode(
            id="sink",
            node_type="ast_statement",
            ast_type="call_expression",
            file="test.py",
            line=15,
            metadata={"ast_name": "eval"},
        )

        cpg.add_node(entry)
        cpg.add_node(sanitizer)
        cpg.add_node(sink)

        cpg.add_edge(CPGEdge(edge_type="calls", source="entry", target="sanitizer"))
        cpg.add_edge(CPGEdge(edge_type="calls", source="sanitizer", target="sink"))

        finder = AttackPathFinder()
        paths = finder.find_paths(cpg, "eval", entry_points=["entry"])

        assert len(paths) == 1
        assert paths[0].is_sanitized
        assert "sanitizer" in paths[0].sanitizers
        assert not paths[0].is_exploitable  # Sanitized paths are not exploitable


class TestCFGReachability:
    """Test CFG-based reaches_sink verification (D6: CPG CFG reachability)."""

    def _build_cpg_with_cfg(self, cfg_reachable: bool) -> CodePropertyGraph:
        """Build a CPG (entry -> sink) with a CFG whose sink block is either
        reachable from the function entry or orphaned (dead code)."""
        from src.layers.l3_analysis.engines.ast_engine.cfg.models import (
            CFGEdge,
            CFGEdgeType,
            CFGNode,
            ControlFlowGraph,
        )

        cpg = CodePropertyGraph()
        entry = CPGNode(
            id="entry",
            node_type="call_function",
            call_name="handler",
            file="test.py",
            line=5,
            metadata={"is_entry_point": True},
        )
        sink = CPGNode(
            id="sink",
            node_type="ast_statement",
            ast_type="call_expression",
            file="test.py",
            line=10,
            metadata={"ast_name": "eval"},
        )
        cpg.add_node(entry)
        cpg.add_node(sink)
        cpg.add_edge(CPGEdge(edge_type="calls", source="entry", target="sink"))

        cfg = ControlFlowGraph(
            function_id="handler",
            function_name="handler",
            file="test.py",
        )
        b0 = CFGNode(
            id="cfg:test.py:handler:block0",
            file="test.py",
            start_line=1,
            end_line=7,
            is_entry=True,
        )
        b1 = CFGNode(
            id="cfg:test.py:handler:block1",
            file="test.py",
            start_line=8,
            end_line=15,
        )
        cfg.add_node(b0)
        cfg.add_node(b1)
        if cfg_reachable:
            cfg.add_edge(
                CFGEdge(
                    edge_type=CFGEdgeType.UNCONDITIONAL,
                    source=b0.id,
                    target=b1.id,
                )
            )
        # When cfg_reachable is False, b1 is an orphan (dead) block.
        cpg.merge_cfg(cfg)
        return cpg

    def test_reaches_sink_true_when_cfg_reachable(self):
        """reaches_sink is True when the sink block is CFG-reachable from entry."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        finder = AttackPathFinder()
        cpg = self._build_cpg_with_cfg(cfg_reachable=True)

        paths = finder.find_paths(cpg, "eval", entry_points=["entry"])

        assert len(paths) == 1
        assert paths[0].reaches_sink is True
        assert paths[0].is_exploitable

    def test_reaches_sink_false_when_sink_in_dead_branch(self):
        """reaches_sink is False when the sink sits in an unreachable (dead) block."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        finder = AttackPathFinder()
        cpg = self._build_cpg_with_cfg(cfg_reachable=False)

        paths = finder.find_paths(cpg, "eval", entry_points=["entry"])

        assert len(paths) == 1
        assert paths[0].reaches_sink is False
        assert not paths[0].is_exploitable

    def test_reaches_sink_true_when_no_cfg(self):
        """reaches_sink falls back to True when the CPG carries no CFG (no regression)."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        cpg = CodePropertyGraph()
        entry = CPGNode(
            id="entry",
            node_type="call_function",
            call_name="handler",
            file="test.py",
            line=5,
            metadata={"is_entry_point": True},
        )
        sink = CPGNode(
            id="sink",
            node_type="ast_statement",
            ast_type="call_expression",
            file="test.py",
            line=10,
            metadata={"ast_name": "eval"},
        )
        cpg.add_node(entry)
        cpg.add_node(sink)
        cpg.add_edge(CPGEdge(edge_type="calls", source="entry", target="sink"))

        finder = AttackPathFinder()
        paths = finder.find_paths(cpg, "eval", entry_points=["entry"])

        assert len(paths) == 1
        assert paths[0].reaches_sink is True


class TestConditionPaths:
    """Test _extract_condition_paths (D6: real branch conditions)."""

    def _build_cpg_with_conditional(self, true_branch: bool) -> CodePropertyGraph:
        """entry -> mid -> sink, with a conditional CFG edge entry_block -> mid_block."""
        from src.layers.l3_analysis.engines.ast_engine.cfg.models import (
            CFGEdge,
            CFGEdgeType,
            CFGNode,
            ControlFlowGraph,
        )

        cpg = CodePropertyGraph()
        entry = CPGNode(
            id="entry",
            node_type="call_function",
            call_name="handler",
            file="test.py",
            line=5,
            metadata={"is_entry_point": True},
        )
        mid = CPGNode(
            id="mid",
            node_type="call_function",
            call_name="step",
            file="test.py",
            line=10,
        )
        sink = CPGNode(
            id="sink",
            node_type="ast_statement",
            ast_type="call_expression",
            file="test.py",
            line=15,
            metadata={"ast_name": "eval"},
        )
        cpg.add_node(entry)
        cpg.add_node(mid)
        cpg.add_node(sink)
        cpg.add_edge(CPGEdge(edge_type="calls", source="entry", target="mid"))
        cpg.add_edge(CPGEdge(edge_type="calls", source="mid", target="sink"))

        cfg = ControlFlowGraph(
            function_id="handler",
            function_name="handler",
            file="test.py",
        )
        b0 = CFGNode(
            id="cfg:test.py:handler:block0",
            file="test.py",
            start_line=1,
            end_line=7,
            is_entry=True,
        )
        b1 = CFGNode(
            id="cfg:test.py:handler:block1",
            file="test.py",
            start_line=8,
            end_line=12,
        )
        b2 = CFGNode(
            id="cfg:test.py:handler:block2",
            file="test.py",
            start_line=13,
            end_line=20,
        )
        cfg.add_node(b0)
        cfg.add_node(b1)
        cfg.add_node(b2)
        cfg.add_edge(
            CFGEdge(
                edge_type=(
                    CFGEdgeType.CONDITIONAL_TRUE
                    if true_branch
                    else CFGEdgeType.CONDITIONAL_FALSE
                ),
                source=b0.id,
                target=b1.id,
                condition="user == 'admin'",
            )
        )
        cfg.add_edge(
            CFGEdge(
                edge_type=CFGEdgeType.UNCONDITIONAL,
                source=b1.id,
                target=b2.id,
            )
        )
        cpg.merge_cfg(cfg)
        return cpg

    def test_condition_paths_true_branch(self):
        """A taken true-branch condition is recorded as {condition: True}."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        finder = AttackPathFinder()
        cpg = self._build_cpg_with_conditional(true_branch=True)

        paths = finder.find_paths(cpg, "eval", entry_points=["entry"])

        assert len(paths) == 1
        assert paths[0].condition_paths == {"user == 'admin'": True}

    def test_condition_paths_false_branch(self):
        """A taken false-branch condition is recorded as {condition: False}."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        finder = AttackPathFinder()
        cpg = self._build_cpg_with_conditional(true_branch=False)

        paths = finder.find_paths(cpg, "eval", entry_points=["entry"])

        assert len(paths) == 1
        assert paths[0].condition_paths == {"user == 'admin'": False}

    def test_condition_paths_empty_when_no_cfg(self):
        """condition_paths is empty when the CPG carries no CFG (no regression)."""
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        cpg = CodePropertyGraph()
        entry = CPGNode(
            id="entry",
            node_type="call_function",
            call_name="handler",
            file="test.py",
            line=5,
            metadata={"is_entry_point": True},
        )
        sink = CPGNode(
            id="sink",
            node_type="ast_statement",
            ast_type="call_expression",
            file="test.py",
            line=10,
            metadata={"ast_name": "eval"},
        )
        cpg.add_node(entry)
        cpg.add_node(sink)
        cpg.add_edge(CPGEdge(edge_type="calls", source="entry", target="sink"))

        finder = AttackPathFinder()
        paths = finder.find_paths(cpg, "eval", entry_points=["entry"])

        assert len(paths) == 1
        assert paths[0].condition_paths == {}


class TestPythonEndToEnd:
    """Integration: real Python source -> CPG (with CFG) -> reachability (D6).

    These validate D6's contribution (CFG build + merge + real reachability)
    on real source. The full ``PythonCPGProvider.get_paths`` round-trip is
    blocked by a separate, pre-existing P9-01 bug (the entry ``call_function``
    CPG node is not linked to the function-body ``function_definition`` CPG
    node, so BFS cannot traverse entry -> sink); see the xfail test below.
    """

    def test_function_cfgs_populated_from_real_source(self, tmp_path):
        """Building a CPG from real Python source merges per-function CFGs."""
        from src.layers.l3_analysis.engines.ast_engine.cpg.builder import CPGBuilder

        src = tmp_path / "app.py"
        src.write_text("def handler(request):\n    return eval(request)\n")

        cpg = CPGBuilder().build_from_file(str(src))

        assert len(cpg.function_cfgs) >= 1

    def test_verify_reachability_true_on_real_reachable_source(self, tmp_path):
        """_verify_cfg_reachability returns True for a reachable sink in real code."""
        from src.layers.l3_analysis.engines.ast_engine.cpg.builder import CPGBuilder
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        src = tmp_path / "app.py"
        src.write_text("def handler(request):\n    return eval(request)\n")

        cpg = CPGBuilder().build_from_file(str(src))
        func_id, eval_id = _locate_func_and_call(cpg)
        assert func_id and eval_id

        finder = AttackPathFinder()
        assert finder._verify_cfg_reachability(cpg, [func_id, eval_id]) is True

    def test_verify_reachability_false_on_real_dead_source(self, tmp_path):
        """_verify_cfg_reachability returns False for a post-return (dead) sink."""
        from src.layers.l3_analysis.engines.ast_engine.cpg.builder import CPGBuilder
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        src = tmp_path / "dead.py"
        src.write_text(
            "def handler(request):\n    return None\n    result = eval(request)\n"
        )

        cpg = CPGBuilder().build_from_file(str(src))
        func_id, eval_id = _locate_func_and_call(cpg)
        assert func_id and eval_id

        finder = AttackPathFinder()
        assert finder._verify_cfg_reachability(cpg, [func_id, eval_id]) is False

    def test_provider_finds_reachable_sink(self, tmp_path):
        """Provider e2e: a reachable eval sink is found with reaches_sink=True."""
        from pathlib import Path

        from src.layers.l3_analysis.engines.ast_engine.cpg.providers.python_provider import (
            PythonCPGProvider,
        )

        src = tmp_path / "app.py"
        src.write_text("def handler(request):\n    return eval(request)\n")

        paths = PythonCPGProvider().get_paths(Path(src), "eval")

        assert len(paths) >= 1
        assert any(p.reaches_sink for p in paths)

    def test_provider_marks_dead_sink_unreachable(self, tmp_path):
        """Provider e2e: a post-return (dead) sink reports reaches_sink=False."""
        from pathlib import Path

        from src.layers.l3_analysis.engines.ast_engine.cpg.providers.python_provider import (
            PythonCPGProvider,
        )

        src = tmp_path / "dead.py"
        src.write_text(
            "def handler(request):\n    return None\n    x = eval(request)\n"
        )

        paths = PythonCPGProvider().get_paths(Path(src), "eval")

        assert len(paths) >= 1
        assert all(not p.reaches_sink for p in paths)


class TestJavaEndToEnd:
    """Phase 18/P2-pre: Java CPG attack-path end-to-end (was always 0 paths).

    Requires the P2-pre fixes to all hold together:
    - Java call-graph builder registered (P1)
    - entry-point detection propagated onto CPG call_function nodes
      (cpg/models.py merge_call_graph writes metadata["is_entry_point"])
    - callee_id resolved to real node ids so calls edges exist
      (call_graph/builders/base.py build_file_graph)
    - sink matching via regex, not substring (path_finder/finder.py _find_sinks)
    """

    def test_provider_finds_reachable_sink(self, tmp_path):
        from pathlib import Path

        from src.layers.l3_analysis.engines.ast_engine.cpg.providers.java_provider import (
            JavaCPGProvider,
        )

        src = tmp_path / "Vuln.java"
        src.write_text(
            'import org.springframework.web.bind.annotation.*;\n'
            '@RestController\n'
            'class Vuln {\n'
            '    @GetMapping("/e")\n'
            '    public String exec(String cmd) { return doExec(cmd); }\n'
            '    public String doExec(String s) {\n'
            '        Runtime.getRuntime().exec(s); return s;\n'
            '    }\n'
            '}\n'
        )

        paths = JavaCPGProvider().get_paths(Path(src), "exec|getRuntime")

        assert len(paths) >= 1
        assert any(p.reaches_sink for p in paths)


def _locate_func_and_call(cpg) -> tuple[str | None, str | None]:
    """Return (function_definition CPG id, eval call CPG id) from a built CPG."""
    func_id = None
    eval_id = None
    for nid, node in cpg.nodes.items():
        if node.node_type == "ast_statement" and node.ast_type == "function_definition":
            func_id = func_id or nid
        if node.node_type == "ast_statement" and node.ast_type == "call":
            ast_node = node.metadata.get("ast_node")
            name = getattr(ast_node, "name", "") if ast_node else ""
            if "eval" in (name or "").lower():
                eval_id = nid
    return func_id, eval_id


class TestMultiLanguageCFGBuild:
    """D6: per-function CFGs build & merge from real source across languages.

    All four languages (python/js/java/go) build CFGs, split basic blocks on
    ``if``, and produce control-flow edges. Go required unwrapping its
    ``block -> statement_list`` body wrapper; the others expose statements
    directly under the body ``block``.
    """

    @pytest.mark.parametrize(
        "lang,filename,code",
        [
            (
                "python",
                "app.py",
                "def h(r):\n    if r:\n        eval(r)\n    return 1\n",
            ),
            (
                "javascript",
                "app.js",
                "function h(r){\n if(r){ eval(r); }\n return 1;\n}\n",
            ),
            (
                "java",
                "App.java",
                "class App{\n void h(int r){\n  if(r>0){ System.exit(0); }\n  return;\n }\n}\n",
            ),
            (
                "go",
                "app.go",
                "package main\nfunc h(r int){\n if r>0 { print(r) }\n return\n}\n",
            ),
        ],
    )
    def test_cfg_built_from_real_source(self, lang, filename, code):
        """Every supported language builds and merges at least one CFG."""
        from src.layers.l3_analysis.engines.ast_engine.cpg.builder import CPGBuilder

        cpg = CPGBuilder().build_from_code(code, lang, filename)

        assert len(cpg.function_cfgs) >= 1, f"no CFG built for {lang}"

    @pytest.mark.parametrize(
        "lang,filename,code",
        [
            (
                "python",
                "app.py",
                "def h(r):\n    if r:\n        eval(r)\n    return 1\n",
            ),
            (
                "javascript",
                "app.js",
                "function h(r){\n if(r){ eval(r); }\n return 1;\n}\n",
            ),
            (
                "java",
                "App.java",
                "class App{\n void h(int r){\n  if(r>0){ System.exit(0); }\n  return;\n }\n}\n",
            ),
            (
                "go",
                "app.go",
                "package main\nfunc h(r int){\n if r>0 { print(r) }\n return\n}\n",
            ),
        ],
    )
    def test_all_languages_split_blocks_on_if(self, lang, filename, code):
        """Every language splits basic blocks on an ``if`` (>=2 blocks, >=1 edge)."""
        from src.layers.l3_analysis.engines.ast_engine.cpg.builder import CPGBuilder

        cpg = CPGBuilder().build_from_code(code, lang, filename)
        blocks = sum(len(c.nodes) for c in cpg.function_cfgs.values())
        edges = sum(len(c.edges) for c in cpg.function_cfgs.values())

        assert blocks >= 2, f"{lang} did not split basic blocks on `if`"
        assert edges >= 1, f"{lang} produced no control-flow edges"
