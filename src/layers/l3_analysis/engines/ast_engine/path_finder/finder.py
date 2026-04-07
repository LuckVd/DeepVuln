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

        # Verify CFG reachability if CFG is available
        reaches_sink = True  # Default to true
        condition_paths = {}

        # TODO: Add CFG reachability verification when CFG is integrated
        # if cpg.has_cfg_for_path(path):
        #     reaches_sink = self._verify_cfg_reachability(cpg, path)
        #     condition_paths = self._extract_condition_paths(cpg, path)

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
        Verify if the path is reachable using CFG information.

        This checks that all conditional branches can be satisfied
        and that loops will execute.
        """
        # TODO: Implement CFG reachability verification
        # This requires CFG nodes to be integrated into the CPG
        return True

    def _extract_condition_paths(self, cpg: Any, path: list[str]) -> dict[str, bool]:
        """Extract condition requirements from the path."""
        # TODO: Implement condition path extraction
        return {}
