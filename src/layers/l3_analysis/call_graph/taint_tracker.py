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
            return TaintTraceResult(
                sink_id=f"{sink_file}:{sink_function}",
                is_reachable=False,
                is_sanitized=False,
                confidence=0.0,
            )

        # Perform backward BFS to find entry points and sanitizers
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
        """Find the sink node in the graph."""
        for node in graph.nodes.values():
            # Check file match (allow partial match for relative paths)
            if not self._path_match(node.file_path, sink_file):
                continue

            # Check function match
            if node.name != sink_function:
                continue

            # Check line match if specified
            if sink_line and node.line != sink_line:
                continue

            return node

        return None

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
