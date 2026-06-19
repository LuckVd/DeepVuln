"""
Attack Path Finder - Find attack paths in Code Property Graph.

Implements BFS-based path search from entry points to vulnerable sinks,
with CFG reachability verification and sanitizer detection.
"""

from collections import deque
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.ast_engine.path_finder.models import (
    AttackPath,
    PathFinder,
    PathFinderConfig,
    PathType,
)


class AttackPathFinder(PathFinder):
    """
    Finds attack paths in a Code Property Graph.

    Uses BFS to search from entry points to dangerous sinks,
    verifying reachability using CFG information and detecting
    sanitizers along the path.
    """

    def __init__(self, config: PathFinderConfig | None = None) -> None:
        """Initialize the path finder."""
        self.config = config or PathFinderConfig()
        self.logger = get_logger(__name__)

    def find_paths(
        self,
        cpg: Any,
        sink_pattern: str,
        entry_points: list[str] | None = None,
    ) -> list[AttackPath]:
        """
        Find all attack paths from entry points to matching sinks.

        Args:
            cpg: CodePropertyGraph to search
            sink_pattern: Pattern to identify dangerous sinks (e.g., "eval", "system")
            entry_points: Specific entry points (None = use all entry points)

        Returns:
            List of AttackPath objects, sorted by confidence
        """
        self.logger.info(f"Finding attack paths for sink pattern: {sink_pattern}")

        # 1. Get entry points
        if not entry_points:
            entry_points = self._get_entry_points(cpg)

        if not entry_points:
            self.logger.warning("No entry points found in CPG")
            return []

        self.logger.debug(f"Found {len(entry_points)} entry points")

        # 2. Get all sinks matching the pattern
        sinks = self._find_sinks(cpg, sink_pattern)

        if not sinks:
            self.logger.info(f"No sinks found matching pattern: {sink_pattern}")
            return []

        self.logger.debug(f"Found {len(sinks)} sinks")

        # 3. Find paths from each entry point to each sink
        paths = []

        for entry in entry_points:
            for sink in sinks:
                path = self._find_path_bfs(cpg, entry, sink)
                if path:
                    paths.append(path)

        # 4. Filter and sort by confidence
        valid_paths = [p for p in paths if p.confidence >= self.config.min_confidence]
        valid_paths.sort(key=lambda p: p.confidence, reverse=True)

        self.logger.info(f"Found {len(valid_paths)} attack paths")

        return valid_paths

    def _get_entry_points(self, cpg: Any) -> list[str]:
        """
        Get all entry point node IDs from the CPG.

        Entry points are nodes that are externally callable,
        typically HTTP endpoints, RPC handlers, or public functions.
        """
        entry_points = []

        for node_id, node in cpg.nodes.items():
            # Check if this is an entry point
            if node.node_type == "call_function":
                # Check metadata for entry point flag
                if node.metadata.get("is_entry_point", False):
                    entry_points.append(node_id)
                # Or check common entry point patterns
                elif any(
                    pattern in node.call_name.lower()
                    for pattern in ["handler", "endpoint", "route", "controller", "serve"]
                ):
                    entry_points.append(node_id)

        return entry_points

    def _find_sinks(self, cpg: Any, pattern: str) -> list[str]:
        """
        Find all sink node IDs matching the given pattern.

        Sinks are dangerous function calls or operations.
        """
        sinks = []
        pattern_lower = pattern.lower()

        for node_id, node in cpg.nodes.items():
            # Check AST node for dangerous function calls
            if node.node_type == "ast_statement":
                if node.ast_type in ("call_expression", "call"):
                    name = node.metadata.get("ast_name", "")
                    # merge_ast_graph stores the source ASTNode under
                    # metadata["ast_node"]; fall back to its name when the
                    # legacy "ast_name" key is absent.
                    if not name:
                        ast_node = node.metadata.get("ast_node")
                        if ast_node is not None:
                            name = getattr(ast_node, "name", "") or ""
                    if pattern_lower in name.lower():
                        sinks.append(node_id)

            # Check call node for dangerous functions
            elif node.node_type == "call_function":
                if pattern_lower in node.call_name.lower():
                    sinks.append(node_id)

        return sinks

    def _find_path_bfs(
        self,
        cpg: Any,
        start: str,
        target: str,
    ) -> AttackPath | None:
        """
        Use BFS to find a path from start to target.

        Args:
            cpg: CodePropertyGraph
            start: Starting node ID
            target: Target node ID

        Returns:
            AttackPath if found, None otherwise
        """
        queue = deque([(start, [start])])
        visited = set()
        nodes_visited = 0

        while queue and nodes_visited < self.config.max_nodes_visited:
            current, path = queue.popleft()
            nodes_visited += 1

            if current == target:
                # Found target, build the attack path
                return self._build_attack_path(cpg, path, start, target)

            if current in visited:
                continue
            visited.add(current)

            # Get successors
            for successor in cpg.get_successors(current):
                if successor not in visited:
                    queue.append((successor, path + [successor]))

        return None

    def _build_attack_path(
        self,
        cpg: Any,
        path: list[str],
        start: str,
        target: str,
    ) -> AttackPath:
        """
        Build an AttackPath object from a found path.

        Calculates confidence, detects sanitizers, and verifies
        CFG reachability.
        """
        # Calculate confidence based on path length
        base_confidence = 1.0
        for i in range(len(path) - 1):
            base_confidence *= self.config.distance_decay_factor

        confidence = min(1.0, base_confidence + self.config.sink_bonus)

        # Detect sanitizers along the path
        sanitizers = []
        for node_id in path:
            node = cpg.get_node(node_id)
            if node:
                if self._is_sanitizer(cpg, node_id):
                    sanitizers.append(node_id)

        is_sanitized = len(sanitizers) > 0

        # Verify CFG reachability (D6): real value when the CPG carries CFGs,
        # otherwise falls back to True (no regression).
        reaches_sink = self._verify_cfg_reachability(cpg, path)
        condition_paths = self._extract_condition_paths(cpg, path)

        return AttackPath(
            entry_point=start,
            sink=target,
            path_type=PathType.EXECUTION,
            path=path,
            confidence=confidence,
            is_sanitized=is_sanitized,
            sanitizers=sanitizers,
            reaches_sink=reaches_sink,
            condition_paths=condition_paths,
        )

    def _is_sanitizer(self, cpg: Any, node_id: str) -> bool:
        """Check if a node represents a sanitizer function."""
        node = cpg.get_node(node_id)
        if not node:
            return False

        # Check call name for sanitizer patterns
        if node.node_type == "call_function":
            name = node.call_name.lower()
            for pattern in self.config.sanitizer_patterns:
                if pattern in name:
                    return True

        # Check AST node
        if node.node_type == "ast_statement":
            name = node.metadata.get("ast_name", "")
            for pattern in self.config.sanitizer_patterns:
                if pattern in name:
                    return True

        return False

    def _verify_cfg_reachability(self, cpg: Any, path: list[str]) -> bool:
        """
        Verify whether the path is CFG-reachable.

        For each path node that maps to a CFG basic block, that block must be
        reachable from its function's CFG entry node. A sink that lives in a
        dead / unreachable block (e.g. inside an always-false branch) makes the
        whole path fail to reach the sink.

        Falls back to True when the CPG carries no CFG data (no regression).
        """
        function_cfgs = getattr(cpg, "function_cfgs", None)
        if not path or not function_cfgs:
            return True

        for node_id in path:
            node = cpg.get_node(node_id)
            if not node:
                continue
            located = self._locate_block(cpg, node)
            if located is None:
                continue
            cfg, block = located
            # No entry node → cannot verify; treat as reachable.
            if not cfg.entry_node:
                continue
            if block.id == cfg.entry_node:
                continue
            if not cfg.is_reachable(cfg.entry_node, block.id):
                return False
        return True

    def _locate_block(
        self,
        cpg: Any,
        node: Any,
    ) -> tuple[Any, Any] | None:
        """
        Map a CPG node to the ``(ControlFlowGraph, CFGNode)`` whose basic-block
        line range contains the node's line, within the same file.

        Returns ``None`` when the node has no usable location or no matching
        block is found.
        """
        if not node.line or not node.file:
            return None
        for cfg in cpg.get_cfgs_for_file(node.file):
            for block in cfg.nodes.values():
                if block.start_line <= node.line <= block.end_line:
                    return (cfg, block)
        return None

    def _extract_condition_paths(self, cpg: Any, path: list[str]) -> dict[str, bool]:
        """
        Extract branch conditions required along the path.

        For each consecutive pair of path nodes that map to CFG blocks within
        the same function, the CFG edge between them is inspected: a conditional
        edge carrying a condition expression is recorded as
        ``{condition: <taken-as-true?>}`` (``True`` for a true-branch,
        ``False`` for a false-branch). Unconditional / loop / exception edges
        carry no branch truth value and are skipped.

        Returns an empty dict when the CPG carries no CFG data (no regression).
        """
        from src.layers.l3_analysis.engines.ast_engine.cfg.models import CFGEdgeType

        function_cfgs = getattr(cpg, "function_cfgs", None)
        if not path or not function_cfgs:
            return {}

        # Locate (cfg, block) for each path node; None where unmappable.
        located: list[tuple[Any, Any] | None] = []
        for node_id in path:
            node = cpg.get_node(node_id)
            located.append(self._locate_block(cpg, node) if node else None)

        conditions: dict[str, bool] = {}
        for prev, cur in zip(located, located[1:]):
            if prev is None or cur is None:
                continue
            prev_cfg, prev_block = prev
            cur_cfg, cur_block = cur
            # CFG is intra-function; skip cross-function transitions.
            if prev_cfg is not cur_cfg:
                continue
            if prev_block.id == cur_block.id:
                continue
            edge = self._find_cfg_edge(prev_cfg, prev_block.id, cur_block.id)
            if edge is None or not edge.condition:
                continue
            if edge.edge_type == CFGEdgeType.CONDITIONAL_TRUE:
                conditions[edge.condition] = True
            elif edge.edge_type == CFGEdgeType.CONDITIONAL_FALSE:
                conditions[edge.condition] = False
            # Other edge types carry no branch truth value.
        return conditions

    def _find_cfg_edge(self, cfg: Any, source_id: str, target_id: str) -> Any:
        """Return the CFGEdge directly connecting two block ids, if any."""
        for edge in cfg.edges:
            if edge.source == source_id and edge.target == target_id:
                return edge
        return None
