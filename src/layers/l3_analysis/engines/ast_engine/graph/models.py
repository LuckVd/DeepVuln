"""AST Graph Models - Data structures for AST code graph."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ASTNode:
    """
    A node in the AST graph representing a code element.

    Attributes:
        id: Unique identifier (e.g., "app.py:123:call_expression")
        type: Node type from tree-sitter (call_expression, identifier, etc.)
        name: Node name (function name, variable name, etc.)
        file: Source file path
        line: Line number (1-indexed)
        column: Column number (1-indexed)
        parent_id: ID of parent node (None for root)
        children: List of child node IDs
        metadata: Additional information
    """

    id: str
    type: str
    name: str
    file: str
    line: int
    column: int = 0
    parent_id: str | None = None
    children: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ASTNode):
            return False
        return self.id == other.id


@dataclass
class ASTGraph:
    """
    AST Graph representing code structure.

    Provides:
    - Node storage and lookup
    - File-based indexing
    - Type-based indexing
    - Basic query operations
    """

    nodes: dict[str, ASTNode] = field(default_factory=dict)
    file_index: dict[str, list[str]] = field(default_factory=dict)
    type_index: dict[str, list[str]] = field(default_factory=dict)

    def add_node(self, node: ASTNode) -> None:
        """
        Add a node to the graph.

        Args:
            node: ASTNode to add
        """
        self.nodes[node.id] = node

        # Update file index
        if node.file not in self.file_index:
            self.file_index[node.file] = []
        if node.id not in self.file_index[node.file]:
            self.file_index[node.file].append(node.id)

        # Update type index
        if node.type not in self.type_index:
            self.type_index[node.type] = []
        if node.id not in self.type_index[node.type]:
            self.type_index[node.type].append(node.id)

        # Update parent's children list
        if node.parent_id and node.parent_id in self.nodes:
            parent = self.nodes[node.parent_id]
            if node.id not in parent.children:
                parent.children.append(node.id)

    def get_node(self, node_id: str) -> ASTNode | None:
        """
        Get a node by ID.

        Args:
            node_id: Node identifier

        Returns:
            ASTNode or None if not found
        """
        return self.nodes.get(node_id)

    def get_children(self, node_id: str) -> list[ASTNode]:
        """
        Get children of a node.

        Args:
            node_id: Parent node ID

        Returns:
            List of child nodes
        """
        node = self.get_node(node_id)
        if not node:
            return []

        return [self.get_node(cid) for cid in node.children if self.get_node(cid)]

    def get_nodes_by_type(self, node_type: str) -> list[ASTNode]:
        """
        Get all nodes of a specific type.

        Args:
            node_type: Node type (e.g., "call_expression")

        Returns:
            List of nodes with matching type
        """
        node_ids = self.type_index.get(node_type, [])
        return [self.get_node(nid) for nid in node_ids if self.get_node(nid)]

    def get_nodes_by_file(self, file_path: str) -> list[ASTNode]:
        """
        Get all nodes from a specific file.

        Args:
            file_path: File path

        Returns:
            List of nodes from the file
        """
        node_ids = self.file_index.get(file_path, [])
        return [self.get_node(nid) for nid in node_ids if self.get_node(nid)]

    def find_by_name(self, name: str) -> list[ASTNode]:
        """
        Find nodes by name.

        Args:
            name: Node name to search for

        Returns:
            List of matching nodes
        """
        return [node for node in self.nodes.values() if node.name == name]

    def size(self) -> int:
        """Return total number of nodes."""
        return len(self.nodes)

    def get_files(self) -> list[str]:
        """Return list of files in the graph."""
        return list(self.file_index.keys())

    def get_types(self) -> list[str]:
        """Return list of node types in the graph."""
        return list(self.type_index.keys())

    def to_dict(self) -> dict[str, Any]:
        """
        Convert graph to dictionary for serialization.

        Returns:
            Dictionary representation of the graph
        """
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type,
                    "name": n.name,
                    "file": n.file,
                    "line": n.line,
                    "column": n.column,
                    "parent_id": n.parent_id,
                    "children": n.children,
                }
                for n in self.nodes.values()
            ],
            "files": self.get_files(),
            "types": self.get_types(),
            "size": self.size(),
        }
