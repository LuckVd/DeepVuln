"""AST Graph Builder - Build AST graphs from source code using tree-sitter."""

from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.ast_engine.graph.models import ASTGraph, ASTNode
from src.layers.l3_analysis.engines.ast_engine.parser.tree_sitter_manager import (
    TreeSitterManager,
)


class ASTGraphBuilder:
    """
    Builder for creating AST graphs from source code.

    Traverses tree-sitter AST and creates ASTNode objects
    with parent-child relationships.
    """

    def __init__(self) -> None:
        """Initialize the builder."""
        self.logger = get_logger(__name__)
        self._tree_sitter_manager = TreeSitterManager()
        self._node_counter = 0

    def build_from_file(self, file_path: str | Path) -> ASTGraph:
        """
        Build an AST graph from a source file.

        Args:
            file_path: Path to the source file

        Returns:
            ASTGraph containing all nodes from the file
        """
        file_path = Path(file_path)

        if not file_path.exists():
            self.logger.warning(f"File not found: {file_path}")
            return ASTGraph()

        # Read file content
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            self.logger.error(f"Failed to read file {file_path}: {e}")
            return ASTGraph()

        # Detect language
        language = self._detect_language(file_path)
        if language is None:
            self.logger.debug(f"Unknown language for file: {file_path}")
            return ASTGraph()

        return self.build_from_code(content, language, str(file_path))

    def build_from_code(
        self, code: str, language: str, file_path: str = "<unknown>"
    ) -> ASTGraph:
        """
        Build an AST graph from source code.

        Args:
            code: Source code content
            language: Programming language
            file_path: File path for node IDs

        Returns:
            ASTGraph containing all nodes
        """
        graph = ASTGraph()
        self._node_counter = 0

        # Get language object
        lang_obj = self._tree_sitter_manager.get_language(language)
        if lang_obj is None:
            self.logger.warning(f"Language not available: {language}")
            return graph

        # Parse code
        try:
            from tree_sitter import Parser

            parser = Parser(lang_obj)
            tree = parser.parse(bytes(code, "utf-8"))
        except Exception as e:
            self.logger.error(f"Failed to parse code: {e}")
            return graph

        # Traverse AST and build graph
        self._traverse_tree(tree.root_node, file_path, code, graph)

        self.logger.info(
            f"Built AST graph: {graph.size()} nodes from {file_path}"
        )
        return graph

    def _traverse_tree(
        self,
        node: Any,
        file_path: str,
        code: str,
        graph: ASTGraph,
        parent_id: str | None = None,
    ) -> str | None:
        """
        Recursively traverse tree-sitter AST and build graph.

        Args:
            node: tree-sitter Node object
            file_path: File path for node IDs
            code: Source code content
            graph: ASTGraph to add nodes to
            parent_id: Parent node ID

        Returns:
            Node ID of the created node
        """
        # Skip leaf nodes that are just tokens
        if not hasattr(node, "children") or len(node.children) == 0:
            # Only create nodes for meaningful leaf types
            if node.type not in self._get_interesting_types():
                return None

        # Generate node ID
        node_id = self._generate_node_id(file_path, node, parent_id)

        # Get node name
        node_name = self._extract_node_name(node, code)

        # Create ASTNode
        ast_node = ASTNode(
            id=node_id,
            type=node.type,
            name=node_name,
            file=file_path,
            line=node.start_point[0] + 1,
            column=node.start_point[1] + 1,
            parent_id=parent_id,
        )

        # Add to graph
        graph.add_node(ast_node)

        # Recursively process children
        for child in node.children:
            self._traverse_tree(child, file_path, code, graph, node_id)

        return node_id

    def _generate_node_id(
        self, file_path: str, node: Any, parent_id: str | None
    ) -> str:
        """Generate a unique node ID."""
        self._node_counter += 1
        return f"{file_path}:{node.start_point[0] + 1}:{self._node_counter}"

    def _extract_node_name(self, node: Any, code: str) -> str:
        """Extract a meaningful name from the node."""
        # Try to get the text content
        try:
            text = node.text.decode("utf-8")
            # Limit name length
            if len(text) > 50:
                return text[:47] + "..."
            return text
        except Exception:
            # Fallback to type name
            return f"<{node.type}>"

    def _get_interesting_types(self) -> set[str]:
        """Return node types that should be included in the graph."""
        return {
            "call",  # Python tree-sitter uses "call" not "call_expression"
            "call_expression",  # JavaScript/TypeScript
            "function_definition",
            "function_definition",  # Python function
            "function_declaration",  # JavaScript function
            "identifier",
            "attribute",
            "string",
            "number",
            "parameter",
            "argument_list",
            "arguments",  # JavaScript arguments
            "statement",
            "block",
            "if_statement",
            "for_statement",
            "while_statement",
            "return_statement",
            "assignment",
            "assignment_expression",
            "binary_operator",
            "boolean_operator",
            "comparison_operator",
            "expression_statement",
        }

    def _detect_language(self, file_path: Path) -> str | None:
        """Detect programming language from file extension."""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
            ".rb": "ruby",
            ".php": "php",
            ".rs": "rust",
        }
        return ext_map.get(file_path.suffix)
