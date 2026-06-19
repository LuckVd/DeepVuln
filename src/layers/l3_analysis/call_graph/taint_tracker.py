"""
Taint Tracker for backward taint analysis with sanitizer detection.

This module provides functionality to trace taint flow from vulnerability sinks
back to entry points, detecting sanitizers along the path to determine exploitability.
"""

from collections import deque
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.call_graph.models import (
    CallGraph,
    CallNode,
    SanitizerDetectionMethod,
    SanitizerMatchEx,
    SanitizerType,
    TaintTraceResult,
    TaintTrackerConfig,
    TransformScore,
    TypeBasedScore,
)
from src.layers.l3_analysis.call_graph.transform_analyzer import TransformAnalyzer
from src.layers.l3_analysis.call_graph.type_analyzer import TypeAnalyzer
from src.layers.l3_analysis.codeql.sanitizer_detector import (
    SanitizerEffectiveness,
)


class TaintTracker:
    """
    Tracks taint flow from vulnerability sinks to entry points.

    Uses backward BFS to trace from a vulnerability point (sink) back to
    entry points (sources), detecting sanitizers along the path to determine
    if the vulnerability is exploitable.

    Integrates:
    - TransformAnalyzer: AST-based sanitizer detection
    - TypeAnalyzer: Type-based sanitizer detection
    - Semantic sanitizer detection from known library functions
    """

    def __init__(
        self,
        config: TaintTrackerConfig | None = None,
        language: str = "python",
    ) -> None:
        """
        Initialize the taint tracker.

        Args:
            config: Configuration for taint tracking
            language: Programming language for analysis
        """
        self.logger = get_logger(__name__)
        self.config = config or TaintTrackerConfig()
        self.language = language

        # Initialize analyzers
        self.transform_analyzer = TransformAnalyzer(
            vuln_type="xss", language=language
        )
        self.type_analyzer = TypeAnalyzer(
            vuln_type="xss", language=language
        )

    def trace_from_sink(
        self,
        graph: CallGraph,
        sink_file: str,
        sink_function: str,
        sink_line: int | None = None,
        vuln_type: str = "xss",
        source_code_map: dict[str, str] | None = None,
        source_path: str | None = None,
    ) -> TaintTraceResult:
        """
        Perform backward taint tracking from sink to entry points.

        Args:
            graph: The call graph to analyze
            sink_file: File path of the vulnerability
            sink_function: Function name where vulnerability occurs
            sink_line: Line number of vulnerability (optional)
            vuln_type: Type of vulnerability (xss, sqli, cmdi, etc.)
            source_code_map: Map of file paths to source code for AST analysis

        Returns:
            TaintTraceResult with trace information and exploitability assessment
        """
        # Update analyzers for the specific vulnerability type
        self.transform_analyzer.vuln_type = vuln_type
        self.type_analyzer.vuln_type = vuln_type

        # Find sink node
        sink_node = self._find_sink_node(graph, sink_file, sink_function, sink_line)
        if not sink_node:
            # The graph has no node for this function (CallGraphBuilder may
            # have failed to parse it). Still try intra-function taint straight
            # from source — source→sink within one function is exploitable
            # regardless of the call graph.
            intra = self._trace_intra_function_raw(
                sink_file, sink_function, source_code_map or {}, vuln_type, source_path
            )
            if intra is not None:
                return intra
            return TaintTraceResult(
                sink_id=f"{sink_file}:{sink_function}",
                is_reachable=False,
                is_sanitized=False,
                confidence=0.0,
            )

        # 1. Intra-procedural: detect source→sink WITHIN the same function.
        #    The call-graph BFS below is inter-procedural only and misses the
        #    common case where source and sink share a function
        #    (e.g. ``x = request.args.get(...); eval(x)``).
        intra = self._trace_intra_function(sink_node, source_code_map or {}, vuln_type, source_path)
        if intra is not None:
            return intra

        # 2. Inter-procedural: backward BFS over the call graph
        return self._backward_bfs(
            graph,
            sink_node,
            vuln_type,
            source_code_map or {},
        )

    def _find_sink_node(
        self,
        graph: CallGraph,
        sink_file: str,
        sink_function: str,
        sink_line: int | None = None,
    ) -> CallNode | None:
        """Find the sink node in the graph.

        Matches by file + function name. ``sink_line`` (the line of the sink
        *call* inside the function) is used only as a tiebreaker among
        multiple same-name functions — a graph node's line is the function's
        def line, which is not expected to equal the sink call line.
        """
        candidates = [
            node
            for node in graph.nodes.values()
            if self._path_match(node.file_path, sink_file) and node.name == sink_function
        ]
        if not candidates:
            return None
        if sink_line and len(candidates) > 1:
            candidates.sort(key=lambda n: abs((n.line or 0) - sink_line))
        return candidates[0]

    def _path_match(self, node_path: str, target_path: str) -> bool:
        """Check if two paths match (handles relative/absolute differences)."""
        # Exact match
        if node_path == target_path:
            return True

        # Suffix match (for relative paths)
        if node_path.endswith(target_path) or target_path.endswith(node_path):
            return True

        # Basename match
        if Path(node_path).name == Path(target_path).name:
            return True

        return False

    # --- Intra-procedural taint analysis (source→sink within one function) ---
    # The inter-procedural BFS only traces cross-function edges; it misses the
    # very common case where taint source and sink live in the SAME function.
    # This pass parses the sink function's body and tracks single-level
    # variable propagation: ``var = <source>; <sink>(... var ...)``.

    _PY_SOURCE_PATTERNS = [
        r"request\.args\.get", r"request\.args\[", r"request\.form\.get", r"request\.form\[",
        r"request\.values", r"request\.cookies", r"request\.headers", r"request\.GET",
        r"request\.POST", r"request\.data", r"request\.json", r"flask\.request",
        r"os\.environ", r"os\.getenv", r"sys\.argv", r"\binput\(", r"raw_input\(",
    ]
    _PY_SINK_PATTERNS: dict[str, list[str]] = {
        "cmdi": [r"\beval\(", r"\bexec\(", r"os\.system\(", r"os\.popen\(",
                 r"subprocess\.[\w.]*\(.*shell\s*=\s*True", r"commands\.\w+\("],
        "sqli": [r"\.execute\(", r"\.executemany\(", r"\.executescript\("],
        "path_traversal": [r"\bopen\(", r"\.read\(", r"\.readlines\("],
        "ldap": [r"ldap\.\w+\(", r"\.search_s\(", r"\.search_ext\("],
        "xss": [],  # XSS sinks are output calls; intra flow not modeled here
    }
    # Normalize vuln_type aliases (e.g. rule_id prefixes) to canonical sink keys
    _VULN_TYPE_ALIASES = {
        "rce": "cmdi", "command": "cmdi", "os_command": "cmdi", "code_exec": "cmdi",
        "sql": "sqli", "sql_injection": "sqli",
        "path": "path_traversal", "lfi": "path_traversal", "rfi": "path_traversal",
    }
    # JavaScript taint sources/sinks (intra-procedural). Extend per language
    # by adding a _<LANG>_SOURCE_PATTERNS / _<LANG>_SINK_PATTERNS and wiring it
    # into _source_patterns() / _sink_patterns() below.
    _JS_SOURCE_PATTERNS = [
        r"req\.query", r"req\.body", r"req\.params", r"req\.cookies",
        r"request\.body", r"request\.query", r"request\.params",
        r"process\.env", r"require\(.readline",
    ]
    _JS_SINK_PATTERNS: dict[str, list[str]] = {
        "cmdi": [r"\beval\(", r"child_process\.(exec|execSync|spawn)\(", r"new\s+Function\("],
        "sqli": [r"\.query\(", r"\.execute\("],
        "path_traversal": [r"fs\.(readFile|writeFile|readFileSync|writeFileSync|createReadStream|readdir)\("],
        "xss": [],
    }

    def _source_patterns(self) -> list[str]:
        return {
            "python": self._PY_SOURCE_PATTERNS,
            "javascript": self._JS_SOURCE_PATTERNS,
        }.get(self.language, [])

    def _sink_patterns(self, vuln_type: str) -> list[str]:
        per_lang = {
            "python": self._PY_SINK_PATTERNS,
            "javascript": self._JS_SINK_PATTERNS,
        }.get(self.language, {})
        return per_lang.get(vuln_type, [])

    def _extract_function(self, file_source: str, func_name: str) -> str | None:
        """Extract a function body by name, dispatching by language."""
        if self.language == "python":
            return self._extract_python_function(file_source, func_name)
        if self.language == "javascript":
            return self._extract_js_function(file_source, func_name)
        return None

    def _extract_js_function(self, file_source: str, func_name: str) -> str | None:
        """Heuristic JS function extraction via brace matching.

        Less precise than the Python indent-based extractor (string/regex
        braces can confuse it); accurate extraction needs tree-sitter-javascript,
        which is not currently installed.
        """
        import re

        lines = file_source.splitlines()
        pat = re.compile(
            rf"(function\s+{re.escape(func_name)}\s*\(|"
            rf"{re.escape(func_name)}\s*[:=]\s*(async\s+)?(\([^)]*\)\s*=>|function)|"
            rf"\b{re.escape(func_name)}\s*\([^)]*\)\s*\{{)"
        )
        start = None
        for i, line in enumerate(lines):
            if pat.search(line):
                start = i
                break
        if start is None:
            return None
        body = [lines[start]]
        depth = lines[start].count("{") - lines[start].count("}")
        for line in lines[start + 1:]:
            if pat.search(line):
                break  # next function definition
            body.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0 and "{" in "".join(body):
                break
        return "\n".join(body)

    def _trace_intra_function(self, sink_node, source_code_map, vuln_type, source_path=None):
        """Detect source→sink dataflow WITHIN the sink function.

        Returns a TaintTraceResult (reachable) if a same-function source→sink
        flow is found, otherwise None (caller falls back to inter-procedural BFS).
        """
        source = self._get_node_source(sink_node, source_code_map, source_path)
        if not source:
            return None
        func_body = self._extract_function(source, sink_node.name)
        if not func_body:
            return None
        reachable, evidence = self._find_intra_taint(func_body, vuln_type)
        if not reachable:
            return None
        chain = evidence.get("chain") or [sink_node.id]
        return TaintTraceResult(
            sink_id=sink_node.id,
            source_id=evidence.get("source"),
            is_reachable=True,
            is_sanitized=False,
            path=[sink_node.id],
            call_chain=chain,
            confidence=0.7,
            entry_point_type=sink_node.entry_point_type,
        )

    def _trace_intra_function_raw(self, sink_file, sink_function, source_code_map, vuln_type, source_path=None):
        """Intra-function taint WITHOUT a graph node (reads source directly).

        Fallback used when CallGraphBuilder failed to produce a node for the
        sink function — source→sink within one function is exploitable
        independent of the call graph.
        """
        source = source_code_map.get(sink_file) if source_code_map else None
        if not source:
            candidates = [sink_file]
            if source_path:
                candidates.append(str(Path(source_path) / sink_file))
            for c in candidates:
                try:
                    p = Path(c)
                    if p.exists():
                        source = p.read_text(encoding="utf-8", errors="replace")
                        break
                except Exception:
                    continue
        if not source:
            return None
        func_body = self._extract_function(source, sink_function)
        if not func_body:
            return None
        reachable, evidence = self._find_intra_taint(func_body, vuln_type)
        if not reachable:
            return None
        return TaintTraceResult(
            sink_id=f"{sink_file}:{sink_function}",
            source_id=evidence.get("source"),
            is_reachable=True,
            is_sanitized=False,
            path=[f"{sink_file}:{sink_function}"],
            call_chain=evidence.get("chain", []),
            confidence=0.7,
        )

    def _get_node_source(self, node, source_code_map, source_path=None):
        """Get source code for a node's file.

        Tries the source_code map, then the raw file_path, then
        ``source_path / file_path`` (call-graph nodes often store relative paths).
        """
        src = source_code_map.get(node.file_path) if source_code_map else None
        if src:
            return src
        candidates = [node.file_path]
        if source_path:
            candidates.append(str(Path(source_path) / node.file_path))
        for c in candidates:
            try:
                p = Path(c)
                if p.exists():
                    return p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
        return None

    def _extract_python_function(self, file_source, func_name):
        """Extract a Python function body by name (def + indent heuristic)."""
        import re

        lines = file_source.splitlines()
        start = None
        for i, line in enumerate(lines):
            if re.match(rf"\s*(async\s+)?def\s+{re.escape(func_name)}\s*\(", line):
                start = i
                break
        if start is None:
            return None
        body = [lines[start]]
        for line in lines[start + 1:]:
            if line.strip() == "":
                body.append(line)
                continue
            stripped = line.lstrip()
            # Stop at ANY nested def (any indent) so an inner function's body
            # is NOT merged into this scope (would cause scope-confusion false
            # positives). Also stop at a top-level class / decorator.
            if re.match(r"(def |async def )", stripped):
                break
            if re.match(r"\S", line) and re.match(r"(class |@)", line):
                break
            body.append(line)
        return "\n".join(body)

    def _find_intra_taint(self, func_body, vuln_type):
        """Find source→sink taint within a function body.

        Tracks single-level variable propagation (``var = <source>``) and also
        catches the direct case (``sink(<source>)`` on one line). Returns
        (reachable, evidence).
        """
        import re

        # Intra-procedural taint is Python-only: the source/sink patterns below
        # are Python syntax. Running them on JS/Java/Go would false-positive on
        # coincidental matches (e.g. `.execute(` exists in many languages).
        # Intra-procedural taint runs per-language patterns. Unsupported
        # languages/vuln_types get empty patterns → safe no-op (no false positive).
        if len(func_body.splitlines()) > 500:
            return False, {}
        vuln_type = self._VULN_TYPE_ALIASES.get(vuln_type, vuln_type)
        src_pats = self._source_patterns()
        sink_pats = self._sink_patterns(vuln_type)
        if not src_pats or not sink_pats:
            return False, {}
        src_re = [re.compile(p) for p in src_pats]
        sink_re = [re.compile(p) for p in sink_pats]

        # 1. Collect variables assigned from a source call
        tainted_vars: dict[str, str] = {}
        # Match ``var = <source>`` (Python) and ``var|let|const x = <source>`` (JS)
        assign_re = re.compile(r"^\s*(?:(?:var|let|const)\s+)?(\w+)\s*=\s*(.+)$")
        for line in func_body.splitlines():
            for r in src_re:
                if r.search(line):
                    m = assign_re.match(line)
                    if m:
                        tainted_vars[m.group(1)] = r.pattern

        # 2. For each sink call, check whether a tainted var or a source
        #    appears on the same statement
        for line in func_body.splitlines():
            for r in sink_re:
                if not r.search(line):
                    continue
                for var, pat in tainted_vars.items():
                    if re.search(r"\b" + re.escape(var) + r"\b", line):
                        return True, {
                            "source": pat,
                            "chain": [f"source({pat}) -> var({var}) -> sink"],
                        }
                for sr in src_re:
                    if sr.search(line):
                        return True, {
                            "source": sr.pattern,
                            "chain": [f"source({sr.pattern}) -> sink"],
                        }
        return False, {}

    def _backward_bfs(
        self,
        graph: CallGraph,
        sink_node: CallNode,
        vuln_type: str,
        source_code_map: dict[str, str],
    ) -> TaintTraceResult:
        """
        Perform backward BFS from sink to entry points.

        Args:
            graph: The call graph
            sink_node: The vulnerability node
            vuln_type: Type of vulnerability
            source_code_map: Source code for AST analysis

        Returns:
            TaintTraceResult with trace information
        """
        result = TaintTraceResult(
            sink_id=sink_node.id,
            confidence=0.0,
        )

        # BFS queue: (node_id, path, visited_sanitizers)
        queue: deque[tuple[str, list[str], list[SanitizerMatchEx]]] = deque([
            (sink_node.id, [sink_node.id], [])
        ])
        visited: set[str] = set()
        all_sanitizers: list[SanitizerMatchEx] = []

        # Track best path to an entry point
        best_entry_path: list[str] | None = None
        best_entry_type: str | None = None

        while queue:
            current_id, path, path_sanitizers = queue.popleft()

            if current_id in visited:
                continue
            visited.add(current_id)

            current_node = graph.nodes.get(current_id)
            if not current_node:
                continue

            # Check if this node is an entry point
            if current_node.is_entry_point:
                best_entry_path = path
                best_entry_type = current_node.entry_point_type
                result.source_id = current_id
                result.is_reachable = True
                break

            # Check depth limit
            if len(path) > self.config.max_path_length:
                continue

            # Check for sanitizers at this node
            node_sanitizers = self._check_node_for_sanitizer(
                current_node, source_code_map, vuln_type
            )

            if node_sanitizers:
                path_sanitizers.extend(node_sanitizers)
                all_sanitizers.extend(node_sanitizers)

            # Add callers to queue (reverse traversal)
            callers = graph.get_callers(current_id)
            if not callers:
                # No callers found - check if this is actually an entry point
                current_node = graph.nodes.get(current_id)
                if current_node and current_node.is_entry_point:
                    # Found an actual entry point
                    result.source_id = current_id
                    result.is_reachable = True
                    best_entry_path = path
                    best_entry_type = current_node.entry_point_type
                    break
                # Otherwise, continue - this is a dead end (not an entry point)

            for caller_id in callers:
                if caller_id not in visited:
                    queue.append((
                        caller_id,
                        path + [caller_id],
                        path_sanitizers.copy(),
                    ))

            # Check visitation limit
            if len(visited) > self.config.max_nodes_visited:
                self.logger.warning(f"Reached max nodes visited ({self.config.max_nodes_visited})")
                break

        # Populate result
        result.path = best_entry_path or path
        result.path_length = len(result.path) - 1
        result.entry_point_type = best_entry_type
        result.sanitizers = all_sanitizers

        # Build human-readable call chain
        result.call_chain = self._build_call_chain(graph, result.path)

        # Determine if sanitized
        result.is_sanitized = self._is_sanitized(all_sanitizers)

        # Find effective sanitizer (the one that blocks the path)
        if result.is_sanitized:
            result.effective_sanitizer = self._find_effective_sanitizer(all_sanitizers)

        # Calculate confidence
        result.confidence = self._calculate_confidence(result)

        # Apply distance decay
        result.distance_decay = self.config.distance_decay_factor ** result.path_length
        result.confidence *= result.distance_decay

        return result

    def _check_node_for_sanitizer(
        self,
        node: CallNode,
        source_code_map: dict[str, str],
        vuln_type: str,
    ) -> list[SanitizerMatchEx]:
        """
        Check if a node is a sanitizer using multiple detection methods.

        Returns:
            List of SanitizerMatchEx detected at this node
        """
        sanitizers = []

        # Get source code for this node if available
        source_code = source_code_map.get(node.file_path, "")

        if not source_code:
            return sanitizers

        # Method 1: Transform analysis (AST-based)
        transform_score = self.transform_analyzer.analyze_from_source(
            source_code, node.name
        )
        if transform_score.is_sanitizer:
            sanitizers.append(self._create_sanitizer_match(
                node, transform_score, SanitizerDetectionMethod.TRANSFORM_ANALYSIS
            ))

        # Method 2: Type-based detection
        type_score = self.type_analyzer.analyze_from_source(
            source_code, node.name
        )
        if type_score.is_sanitizer:
            sanitizers.append(self._create_sanitizer_match_from_type(
                node, type_score, SanitizerDetectionMethod.TYPE_BASED
            ))

        # Method 3: Semantic detection (known library functions)
        if self._is_semantic_sanitizer(node):
            sanitizers.append(self._create_semantic_sanitizer_match(node))

        return sanitizers

    def _create_sanitizer_match(
        self,
        node: CallNode,
        transform_score: TransformScore,
        method: SanitizerDetectionMethod,
    ) -> SanitizerMatchEx:
        """Create a SanitizerMatchEx from TransformScore."""
        return SanitizerMatchEx(
            function_name=node.name,
            function_id=node.id,
            location=f"{node.file_path}:{node.line}",
            sanitizer_type=SanitizerType.ESCAPE,
            effectiveness=SanitizerEffectiveness.PARTIAL
            if transform_score.confidence < self.config.full_sanitizer_threshold
            else SanitizerEffectiveness.FULL,
            detection_method=method,
            transform_score=transform_score,
            combined_confidence=transform_score.confidence,
        )

    def _create_sanitizer_match_from_type(
        self,
        node: CallNode,
        type_score: TypeBasedScore,
        method: SanitizerDetectionMethod,
    ) -> SanitizerMatchEx:
        """Create a SanitizerMatchEx from TypeBasedScore."""
        return SanitizerMatchEx(
            function_name=node.name,
            function_id=node.id,
            location=f"{node.file_path}:{node.line}",
            sanitizer_type=SanitizerType.ESCAPE,
            effectiveness=SanitizerEffectiveness.PARTIAL
            if type_score.confidence < self.config.full_sanitizer_threshold
            else SanitizerEffectiveness.FULL,
            detection_method=method,
            type_score=type_score,
            combined_confidence=type_score.confidence,
        )

    def _create_semantic_sanitizer_match(
        self, node: CallNode
    ) -> SanitizerMatchEx:
        """Create a SanitizerMatchEx for semantic detection."""
        return SanitizerMatchEx(
            function_name=node.name,
            function_id=node.id,
            location=f"{node.file_path}:{node.line}",
            sanitizer_type=SanitizerType.ESCAPE,
            effectiveness=SanitizerEffectiveness.FULL,
            detection_method=SanitizerDetectionMethod.SEMANTIC,
            combined_confidence=0.9,  # High confidence for known functions
        )

    def _is_semantic_sanitizer(self, node: CallNode) -> bool:
        """Check if node is a known semantic sanitizer."""
        known_sanitizers = {
            # Python
            "html.escape",
            "urllib.parse.quote",
            "urllib.parse.quote_plus",
            "cgi.escape",
            "xml.sax.saxutils.escape",
            "markupsafe.escape",
            "flask.escape",
            "django.utils.html.escape",
            # JavaScript
            "encodeURIComponent",
            "encodeURI",
            "DOMPurify.sanitize",
            # Java
            "StringEscapeUtils.escapeHtml4",
            "StringEscapeUtils.escapeEcmaScript",
            "URLEncoder.encode",
            # Go
            "html.EscapeString",
            "url.QueryEscape",
        }

        for name in known_sanitizers:
            if name in node.name or node.name.endswith(name.split(".")[-1]):
                return True

        return False

    def _is_sanitized(self, sanitizers: list[SanitizerMatchEx]) -> bool:
        """
        Determine if the path is sanitized.

        A path is considered sanitized if there's at least one sanitizer
        with confidence above the threshold.
        """
        for sanitizer in sanitizers:
            if sanitizer.combined_confidence >= self.config.sanitizer_confidence_threshold:
                return True
        return False

    def _find_effective_sanitizer(
        self, sanitizers: list[SanitizerMatchEx]
    ) -> SanitizerMatchEx | None:
        """
        Find the most effective sanitizer on the path.

        Returns the sanitizer with the highest confidence.
        """
        if not sanitizers:
            return None

        return max(sanitizers, key=lambda s: s.combined_confidence)

    def _calculate_confidence(self, result: TaintTraceResult) -> float:
        """
        Calculate overall confidence for the trace result.

        Considers:
        - Path length (shorter = higher confidence)
        - Sanitizer effectiveness
        - Entry point type
        """
        if not result.is_reachable:
            return 0.0

        # Base confidence from reachability
        confidence = 0.7

        # Adjust based on path length
        length_penalty = 0.05 * result.path_length
        confidence -= length_penalty

        # Adjust based on entry point type
        if result.entry_point_type == "HTTP":
            confidence += 0.2  # HTTP entry points are high confidence
        elif result.entry_point_type == "CLI":
            confidence += 0.1
        elif result.entry_point_type == "UNKNOWN":
            confidence -= 0.1

        return max(0.0, min(confidence, 1.0))

    def _build_call_chain(self, graph: CallGraph, path: list[str]) -> list[str]:
        """Build human-readable call chain from node IDs."""
        chain = []
        for node_id in path:
            node = graph.nodes.get(node_id)
            if node:
                chain.append(node.name)
            else:
                # Extract function name from ID
                chain.append(node_id.split(":")[-1])
        return chain

    def trace_multiple_sinks(
        self,
        graph: CallGraph,
        sinks: list[tuple[str, str, int | None]],
        vuln_type: str = "xss",
        source_code_map: dict[str, str] | None = None,
    ) -> list[TaintTraceResult]:
        """
        Trace multiple sinks in batch.

        Args:
            graph: The call graph
            sinks: List of (file, function, line) tuples
            vuln_type: Type of vulnerability
            source_code_map: Source code map

        Returns:
            List of TaintTraceResult for each sink
        """
        results = []
        for sink_file, sink_func, sink_line in sinks:
            result = self.trace_from_sink(
                graph=graph,
                sink_file=sink_file,
                sink_function=sink_func,
                sink_line=sink_line,
                vuln_type=vuln_type,
                source_code_map=source_code_map,
            )
            results.append(result)

        return results

    def get_exploitable_sinks(
        self,
        graph: CallGraph,
        sinks: list[tuple[str, str, int | None]],
        vuln_type: str = "xss",
        source_code_map: dict[str, str] | None = None,
    ) -> list[TaintTraceResult]:
        """
        Get only exploitable sinks (reachable and not sanitized).

        Args:
            graph: The call graph
            sinks: List of (file, function, line) tuples
            vuln_type: Type of vulnerability
            source_code_map: Source code map

        Returns:
            List of exploitable TaintTraceResult
        """
        results = self.trace_multiple_sinks(
            graph=graph,
            sinks=sinks,
            vuln_type=vuln_type,
            source_code_map=source_code_map,
        )

        return [r for r in results if r.is_exploitable]
