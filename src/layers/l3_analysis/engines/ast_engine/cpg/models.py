"""
CPG Models - Code Property Graph data structures.

Provides unified nodes and edges that combine information from AST Graph,
Call Graph, and (future) Control Flow Graph.
"""

from dataclasses import dataclass, field
from typing import Any

from src.layers.l3_analysis.call_graph.models import CallGraph
from src.layers.l3_analysis.engines.ast_engine.cfg.models import ControlFlowGraph
from src.layers.l3_analysis.engines.ast_engine.graph.models import ASTGraph


@dataclass
class CPGNode:
    """
    Code Property Graph unified node.

    Represents a code element that can be either an AST statement or a
    call graph function, providing a unified view for querying.
    """

    # Unique identifier (format: "cpg:file:line:type")
    id: str

    # Node type classification
    node_type: str  # "ast_statement" | "call_function" | "cfg_block"

    # AST information (if this represents an AST node)
    ast_node_id: str | None = None
    ast_type: str | None = None  # if_statement, call_expression, etc.

    # Call Graph information (if this represents a function)
    call_node_id: str | None = None
    call_name: str | None = None

    # Location information
    file: str = ""
    line: int = 0
    column: int = 0

    # Graph relationships
    predecessors: list[str] = field(default_factory=list)  # Incoming edges
    successors: list[str] = field(default_factory=list)  # Outgoing edges

    # Additional metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CPGNode):
            return False
        return self.id == other.id


@dataclass
class CPGEdge:
    """
    Code Property Graph edge.

    Represents relationships between CPG nodes, supporting multiple
    edge types for different analysis needs.
    """

    edge_type: str  # "ast_parent" | "calls" | "cfg" | "dataflow" | "reaches"
    source: str  # Source CPGNode id
    target: str  # Target CPGNode id

    # Edge attributes
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.edge_type, self.source, self.target))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CPGEdge):
            return False
        return (
            self.edge_type == other.edge_type
            and self.source == other.source
            and self.target == other.target
        )


@dataclass
class CodePropertyGraph:
    """
    Complete Code Property Graph.

    Fuses AST Graph (statement-level), Call Graph (function-level),
    and CFG (control flow) into a unified query interface.
    """

    # Core graph data
    nodes: dict[str, CPGNode] = field(default_factory=dict)
    edges: list[CPGEdge] = field(default_factory=list)

    # References to original graphs
    ast_graph: ASTGraph | None = None
    call_graph: CallGraph | None = None

    # Per-function Control Flow Graphs (function_id -> CFG).
    # Used for intra-function CFG reachability verification of attack paths.
    function_cfgs: dict[str, ControlFlowGraph] = field(default_factory=dict)

    # Indexes for fast lookup
    _ast_index: dict[str, str] = field(default_factory=dict)  # ast_id -> cpg_id
    _call_index: dict[str, str] = field(default_factory=dict)  # call_id -> cpg_id
    _file_index: dict[str, list[str]] = field(default_factory=dict)  # file -> [cpg_ids]
    _type_index: dict[str, list[str]] = field(default_factory=dict)  # type -> [cpg_ids]

    def add_node(self, node: CPGNode) -> None:
        """Add a node to the CPG."""
        self.nodes[node.id] = node

        # Update indexes
        if node.ast_node_id:
            self._ast_index[node.ast_node_id] = node.id

        if node.call_node_id:
            self._call_index[node.call_node_id] = node.id

        if node.file:
            if node.file not in self._file_index:
                self._file_index[node.file] = []
            self._file_index[node.file].append(node.id)

        if node.node_type:
            if node.node_type not in self._type_index:
                self._type_index[node.node_type] = []
            self._type_index[node.node_type].append(node.id)

    def add_edge(self, edge: CPGEdge) -> None:
        """Add an edge to the CPG."""
        self.edges.append(edge)

        # Update node relationships
        if edge.source in self.nodes:
            if edge.target not in self.nodes[edge.source].successors:
                self.nodes[edge.source].successors.append(edge.target)

        if edge.target in self.nodes:
            if edge.source not in self.nodes[edge.target].predecessors:
                self.nodes[edge.target].predecessors.append(edge.source)

    def merge_ast_graph(self, ast_graph: ASTGraph) -> None:
        """
        Merge an AST Graph into the CPG.

        Creates CPG nodes for all AST nodes and establishes
        AST parent-child relationships.
        """
        self.ast_graph = ast_graph

        for ast_node in ast_graph.nodes.values():
            # Create CPG node from AST node
            cpg_node = CPGNode(
                id=f"cpg:ast:{ast_node.file}:{ast_node.line}:{ast_node.type}",
                node_type="ast_statement",
                ast_node_id=ast_node.id,
                ast_type=ast_node.type,
                file=ast_node.file,
                line=ast_node.line,
                column=ast_node.column,
                metadata={"ast_node": ast_node},
            )
            self.add_node(cpg_node)

            # Add AST parent edges
            if ast_node.parent_id:
                parent_cpg_id = self._ast_index.get(ast_node.parent_id)
                if parent_cpg_id:
                    self.add_edge(
                        CPGEdge(
                            edge_type="ast_parent",
                            source=parent_cpg_id,
                            target=cpg_node.id,
                        )
                    )

    def merge_call_graph(self, call_graph: CallGraph) -> None:
        """
        Merge a Call Graph into the CPG.

        Creates CPG nodes for all function definitions and
        establishes call relationships.
        """
        self.call_graph = call_graph

        for call_node in call_graph.nodes.values():
            # Create CPG node from Call node
            cpg_node = CPGNode(
                id=f"cpg:call:{call_node.file_path}:{call_node.line}:{call_node.name}",
                node_type="call_function",
                call_node_id=call_node.id,
                call_name=call_node.name,
                file=call_node.file_path,
                line=call_node.line,
                metadata={
                    "call_node": call_node,
                    # Phase 18/P2-pre: propagate entry-point detection from the
                    # call graph so AttackPathFinder._get_entry_points (which
                    # reads metadata["is_entry_point"]) finds real HTTP/RPC/main
                    # entries instead of relying on fragile call_name matching.
                    "is_entry_point": call_node.is_entry_point,
                    "entry_point_type": call_node.entry_point_type,
                },
            )
            self.add_node(cpg_node)

        # Add call edges
        for edge in call_graph.edges:
            caller_cpg_id = self._call_index.get(edge.caller_id)
            callee_cpg_id = self._call_index.get(edge.callee_id)

            if caller_cpg_id and callee_cpg_id:
                self.add_edge(
                    CPGEdge(
                        edge_type="calls",
                        source=caller_cpg_id,
                        target=callee_cpg_id,
                        metadata={
                            "call_type": edge.call_type.value,
                            "call_site": edge.call_site,
                        },
                    )
                )

    def merge_cfg(self, cfg: ControlFlowGraph) -> None:
        """
        Merge a per-function Control Flow Graph into the CPG.

        Registers the CFG by ``function_id`` for reachability queries, and
        creates ``cfg_block`` CPGNodes plus ``cfg`` CPGEdges so control flow
        is queryable alongside AST/call edges.

        Args:
            cfg: ControlFlowGraph for a single function
        """
        # Register for reachability queries (function_id -> CFG).
        self.function_cfgs[cfg.function_id] = cfg

        # Map CFG block id -> CPG node id (block ids already encode
        # file + function + index, so prefixing with "cpg:" keeps them unique).
        block_id_to_cpg_id = {block.id: f"cpg:{block.id}" for block in cfg.nodes.values()}

        for block_id, block in cfg.nodes.items():
            cpg_node = CPGNode(
                id=block_id_to_cpg_id[block_id],
                node_type="cfg_block",
                file=block.file or cfg.file,
                line=block.start_line,
                metadata={
                    "cfg_function_id": cfg.function_id,
                    "cfg_block_id": block_id,
                    "start_line": block.start_line,
                    "end_line": block.end_line,
                    "is_entry": block.is_entry,
                    "is_exit": block.is_exit,
                },
            )
            self.add_node(cpg_node)

        for edge in cfg.edges:
            source_cpg_id = block_id_to_cpg_id.get(edge.source)
            target_cpg_id = block_id_to_cpg_id.get(edge.target)
            if source_cpg_id and target_cpg_id:
                self.add_edge(
                    CPGEdge(
                        edge_type="cfg",
                        source=source_cpg_id,
                        target=target_cpg_id,
                        metadata={
                            "cfg_function_id": cfg.function_id,
                            "cfg_edge_type": edge.edge_type.value,
                            "condition": edge.condition,
                        },
                    )
                )

    def get_node(self, node_id: str) -> CPGNode | None:
        """Get a node by ID."""
        return self.nodes.get(node_id)

    def get_nodes_by_file(self, file_path: str) -> list[CPGNode]:
        """Get all nodes from a specific file."""
        node_ids = self._file_index.get(file_path, [])
        return [self.nodes.get(nid) for nid in node_ids if nid in self.nodes]

    def get_nodes_by_type(self, node_type: str) -> list[CPGNode]:
        """Get all nodes of a specific type."""
        node_ids = self._type_index.get(node_type, [])
        return [self.nodes.get(nid) for nid in node_ids if nid in self.nodes]

    def get_successors(
        self,
        node_id: str,
        edge_types: set[str] | None = None,
    ) -> list[str]:
        """
        Get successor node IDs, optionally filtered by edge type.

        Args:
            node_id: Source node ID
            edge_types: Optional set of edge types to include
                (e.g. {"calls"}, {"cfg"}). ``None`` returns successors of all
                edge types (backward compatible).

        Returns:
            List of successor node IDs
        """
        node = self.get_node(node_id)
        if not node:
            return []
        if edge_types is None:
            return node.successors
        # Filtered view: scan the edge list to honor the requested types.
        result: list[str] = []
        seen: set[str] = set()
        for edge in self.edges:
            if edge.source == node_id and edge.edge_type in edge_types:
                if edge.target not in seen:
                    seen.add(edge.target)
                    result.append(edge.target)
        return result

    def get_predecessors(self, node_id: str) -> list[str]:
        """Get predecessor node IDs."""
        node = self.get_node(node_id)
        return node.predecessors if node else []

    def get_cfgs_for_file(self, file_path: str) -> list[ControlFlowGraph]:
        """
        Return all per-function CFGs whose source file matches.

        Args:
            file_path: Source file to match against ``ControlFlowGraph.file``

        Returns:
            List of matching ControlFlowGraphs (may be empty)
        """
        return [cfg for cfg in self.function_cfgs.values() if cfg.file == file_path]

    def find_by_ast_id(self, ast_id: str) -> CPGNode | None:
        """Find CPG node by AST node ID."""
        cpg_id = self._ast_index.get(ast_id)
        return self.get_node(cpg_id) if cpg_id else None

    def find_by_call_id(self, call_id: str) -> CPGNode | None:
        """Find CPG node by Call node ID."""
        cpg_id = self._call_index.get(call_id)
        return self.get_node(cpg_id) if cpg_id else None

    def size(self) -> int:
        """Return total number of nodes."""
        return len(self.nodes)

    def get_files(self) -> list[str]:
        """Return list of files in the graph."""
        return list(self._file_index.keys())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "node_type": n.node_type,
                    "file": n.file,
                    "line": n.line,
                    "ast_type": n.ast_type,
                    "call_name": n.call_name,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {"type": e.edge_type, "source": e.source, "target": e.target}
                for e in self.edges
            ],
            "files": self.get_files(),
            "size": self.size(),
        }
