"""
Reachability Analyzer.

Performs reachability analysis on call graphs to determine if a vulnerability
is reachable from an entry point.
"""

from collections import deque
from dataclasses import dataclass
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.call_graph.models import (
    CallGraph,
    CallNode,
    ReachabilityResult,
)


@dataclass
class ReachabilityConfig:
    """Configuration for reachability analysis."""

    max_path_length: int = 10  # Maximum path length to consider
    confidence_decay: float = 0.1  # Confidence decay per hop
    min_confidence: float = 0.3  # Minimum confidence threshold


class ReachabilityChecker:
    """
    Checks reachability from entry points to target nodes.

    Uses BFS (Breadth-First Search) to find the shortest path from
    entry points to the target vulnerability location.
    """

    def __init__(self, config: ReachabilityConfig | None = None) -> None:
        """Initialize the reachability checker.

        Args:
            config: Configuration options.
        """
        self.logger = get_logger(__name__)
        self.config = config or ReachabilityConfig()

    def check_reachability(
        self,
        graph: CallGraph,
        target_file: str,
        target_function: str | None = None,
        target_line: int | None = None,
    ) -> ReachabilityResult | None:
        """
        Check if the target is reachable from any entry point.

        Args:
            graph: The call graph to analyze.
            target_file: Target file path.
            target_function: Target function name (optional).
            target_line: Target line number (optional).

        Returns:
            ReachabilityResult if target found, None otherwise.
        """
        # Find target node(s)
        target_nodes = self._find_target_nodes(
            graph, target_file, target_function, target_line
        )

        if not target_nodes:
            self.logger.debug(f"Target not found in graph: {target_file}:{target_function}")
            return None

        # Get all entry points
        entry_points = graph.get_entry_points()

        if not entry_points:
            self.logger.debug("No entry points found in graph")
            return None

        # Try to find path from any entry point to any target node
        best_result: ReachabilityResult | None = None

        for entry in entry_points:
            for target in target_nodes:
                result = self._bfs_search(graph, entry, target)

                if result and result.is_reachable:
                    if best_result is None or result.path_length < best_result.path_length:
                        best_result = result

        return best_result

    def check_reachability_from_node(
        self,
        graph: CallGraph,
        source_node_id: str,
        target_file: str,
        target_function: str | None = None,
    ) -> ReachabilityResult | None:
        """
        Check reachability from a specific source node.

        Args:
            graph: The call graph to analyze.
            source_node_id: ID of the source node.
            target_file: Target file path.
            target_function: Target function name.

        Returns:
            ReachabilityResult if reachable, None otherwise.
        """
        source_node = graph.nodes.get(source_node_id)
        if not source_node:
            return None

        target_nodes = self._find_target_nodes(graph, target_file, target_function)

        for target in target_nodes:
            result = self._bfs_search(graph, source_node, target)
            if result and result.is_reachable:
                return result

        return None

    def find_all_reachable_from(
        self,
        graph: CallGraph,
        source_node_id: str,
        max_depth: int | None = None,
    ) -> list[str]:
        """
        Find all nodes reachable from a source node.

        Args:
            graph: The call graph.
            source_node_id: ID of the source node.
            max_depth: Maximum depth to search.

        Returns:
            List of reachable node IDs.
        """
        max_depth = max_depth or self.config.max_path_length
        visited: set[str] = set()
        reachable: list[str] = []

        queue: deque[tuple[str, int]] = deque([(source_node_id, 0)])

        while queue:
            node_id, depth = queue.popleft()

            if node_id in visited:
                continue
            visited.add(node_id)

            if depth > 0:  # Don't include source node
                reachable.append(node_id)

            if depth >= max_depth:
                continue

            # Add callees to queue
            for callee_id in graph.get_callees(node_id):
                if callee_id not in visited:
                    queue.append((callee_id, depth + 1))

        return reachable

    def find_callers_of(
        self,
        graph: CallGraph,
        target_node_id: str,
        max_depth: int | None = None,
    ) -> list[str]:
        """
        Find all nodes that can reach the target (reverse reachability).

        Args:
            graph: The call graph.
            target_node_id: ID of the target node.
            max_depth: Maximum depth to search.

        Returns:
            List of caller node IDs.
        """
        max_depth = max_depth or self.config.max_path_length
        visited: set[str] = set()
        callers: list[str] = []

        queue: deque[tuple[str, int]] = deque([(target_node_id, 0)])

        while queue:
            node_id, depth = queue.popleft()

            if node_id in visited:
                continue
            visited.add(node_id)

            if depth > 0:  # Don't include target node
                callers.append(node_id)

            if depth >= max_depth:
                continue

            # Add callers to queue (reverse direction)
            for caller_id in graph.get_callers(node_id):
                if caller_id not in visited:
                    queue.append((caller_id, depth + 1))

        return callers

    def _bfs_search(
        self,
        graph: CallGraph,
        source: CallNode,
        target: CallNode,
    ) -> ReachabilityResult | None:
        """
        BFS search from source to target.

        Args:
            graph: The call graph.
            source: Source node (entry point).
            target: Target node (vulnerability).

        Returns:
            ReachabilityResult with path information.
        """
        if source.id == target.id:
            # Direct match
            return ReachabilityResult(
                source_id=source.id,
                target_id=target.id,
                is_reachable=True,
                path=[source.id],
                path_length=0,
                confidence=1.0,
                entry_point_type=source.entry_point_type,
                call_chain=[source.name],
            )

        visited: set[str] = set()
        # Queue: (current_node_id, path, depth)
        queue: deque[tuple[str, list[str], int]] = deque([(source.id, [source.id], 0)])

        while queue:
            current_id, path, depth = queue.popleft()

            if current_id in visited:
                continue
            visited.add(current_id)

            # Check if we found the target
            if current_id == target.id:
                return self._create_result(
                    graph, source, target, path, depth
                )

            # Check depth limit
            if depth >= self.config.max_path_length:
                continue

            # Add callees to queue
            for callee_id in graph.get_callees(current_id):
                if callee_id not in visited:
                    queue.append((callee_id, path + [callee_id], depth + 1))

        # Target not reachable
        return ReachabilityResult(
            source_id=source.id,
            target_id=target.id,
            is_reachable=False,
            path=[],
            path_length=0,
            confidence=0.0,
            entry_point_type=source.entry_point_type,
            call_chain=[],
        )

    def _create_result(
        self,
        graph: CallGraph,
        source: CallNode,
        target: CallNode,
        path: list[str],
        depth: int,
    ) -> ReachabilityResult:
        """Create a ReachabilityResult from the search result."""
        # Calculate confidence based on path length
        confidence = 1.0 - (depth * self.config.confidence_decay)
        confidence = max(confidence, self.config.min_confidence)

        # Build human-readable call chain
        call_chain = []
        for node_id in path:
            node = graph.nodes.get(node_id)
            if node:
                call_chain.append(node.name)
            else:
                call_chain.append(node_id.split(":")[-1])

        return ReachabilityResult(
            source_id=source.id,
            target_id=target.id,
            is_reachable=True,
            path=path,
            path_length=depth,
            confidence=confidence,
            entry_point_type=source.entry_point_type,
            call_chain=call_chain,
        )

    def _find_target_nodes(
        self,
        graph: CallGraph,
        target_file: str,
        target_function: str | None,
        target_line: int | None = None,
    ) -> list[CallNode]:
        """Find target nodes matching the given criteria."""
        targets = []

        for node in graph.nodes.values():
            # Check file match
            if node.file_path != target_file and not node.file_path.endswith(target_file):
                continue

            # Check function match if specified
            if target_function and node.name != target_function:
                continue

            # Check line match if specified
            if target_line and node.line != target_line:
                continue

            targets.append(node)

        return targets
