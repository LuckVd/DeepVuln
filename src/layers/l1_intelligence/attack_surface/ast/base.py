"""Base class for AST-based attack surface detectors using Tree-sitter."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from tree_sitter import Language, Parser

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.models import EntryPoint


class ASTDetector(ABC):
    """Base class for AST-based entry point detectors using Tree-sitter.

    This class provides the foundation for language-specific detectors
    that parse source code into AST and query for entry points.
    """

    # Subclasses must define these
    language_module: Any = None  # The tree-sitter language module (e.g., tree_sitter_java)
    language_name: str = "unknown"
    file_extensions: list[str] = []

    def __init__(self) -> None:
        """Initialize the AST detector."""
        self.logger = get_logger(__name__)
        self._language: Language | None = None
        self._parser: Parser | None = None
        self._initialized = False

    def _ensure_initialized(self) -> None:
        """Lazily initialize the parser and language."""
        if self._initialized:
            return

        if self.language_module is None:
            self.logger.warning(f"Language module not set for {self.language_name}")
            self._initialized = True
            return

        try:
            # tree-sitter 0.25+ requires wrapping the language capsule
            self._language = Language(self.language_module.language())
            self._parser = Parser(self._language)
            self.logger.debug(f"Initialized {self.language_name} AST parser")
        except Exception as e:
            self.logger.error(f"Failed to initialize {self.language_name} parser: {e}")

        self._initialized = True

    def can_parse(self, file_path: Path) -> bool:
        """Check if this detector can parse the given file.

        Args:
            file_path: Path to the source file.

        Returns:
            True if the file extension matches this detector.
        """
        return file_path.suffix in self.file_extensions

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect entry points in source code using AST parsing.

        Args:
            content: Source code content.
            file_path: Path to the source file.

        Returns:
            List of detected entry points.
        """
        self._ensure_initialized()

        if self._parser is None or self._language is None:
            self.logger.debug(f"Parser not available for {self.language_name}, skipping {file_path}")
            return []

        try:
            # Parse the source code into AST
            tree = self._parser.parse(content.encode("utf-8"))
            root = tree.root_node

            # Extract entry points using subclass implementation
            return self._extract_entry_points(root, content, file_path)

        except Exception as e:
            self.logger.warning(f"Failed to parse {file_path} with {self.language_name}: {e}")
            return []

    @abstractmethod
    def _extract_entry_points(
        self, root: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract entry points from the AST.

        Subclasses must implement this method to perform language-specific
        AST queries and extract entry points.

        Args:
            root: Root node of the AST.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of detected entry points.
        """
        pass

    def _get_text(self, node: Any, content: str) -> str:
        """Get the text content of a node.

        Args:
            node: AST node.
            content: Original source code.

        Returns:
            Text content of the node.
        """
        return content[node.start_byte : node.end_byte]

    def _get_line_number(self, node: Any) -> int:
        """Get the line number of a node (1-indexed).

        Args:
            node: AST node.

        Returns:
            Line number (1-indexed).
        """
        return node.start_point[0] + 1

    def _query(self, query_string: str) -> Any:
        """Create a query object from a query string.

        Args:
            query_string: Tree-sitter query string.

        Returns:
            Query object.
        """
        if self._language is None:
            raise RuntimeError("Language not initialized")
        return self._language.query(query_string)

    def _run_query(self, query_string: str, root: Any) -> list[tuple[str, Any]]:
        """Run a Tree-sitter query and return captures.

        Args:
            query_string: Tree-sitter query string.
            root: Root node to query from.

        Returns:
            List of (capture_name, node) tuples.
        """
        try:
            query = self._query(query_string)
            captures = query.captures(root)
            return [(name, node) for name, node in captures]
        except Exception as e:
            self.logger.debug(f"Query failed: {e}")
            return []


# Registry of all AST detectors
AST_DETECTORS: list[type[ASTDetector]] = []


def register_ast_detector(detector_cls: type[ASTDetector]) -> type[ASTDetector]:
    """Decorator to register an AST detector."""
    AST_DETECTORS.append(detector_cls)
    return detector_cls


def get_ast_detector_for_file(file_path: Path) -> ASTDetector | None:
    """Get the appropriate AST detector for a file.

    Args:
        file_path: Path to the source file.

    Returns:
        AST detector instance or None if no detector matches.
    """
    for detector_cls in AST_DETECTORS:
        detector = detector_cls()
        if detector.can_parse(file_path):
            return detector
    return None


def get_all_ast_detectors() -> list[ASTDetector]:
    """Get all registered AST detectors.

    Returns:
        List of AST detector instances.
    """
    return [cls() for cls in AST_DETECTORS]
