"""Base classes for code structure parsing."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from .models import ModuleInfo, ParseOptions


class LanguageParser(ABC):
    """Abstract base class for language-specific parsers."""

    # File extensions this parser handles
    extensions: list[str] = []
    language_name: str = ""

    def __init__(self, options: ParseOptions | None = None) -> None:
        """Initialize the parser.

        Args:
            options: Parse options.
        """
        self.options = options or ParseOptions()

    @abstractmethod
    def parse(self, content: str, file_path: Path) -> ModuleInfo:
        """Parse source code and extract structure.

        Args:
            content: Source code content.
            file_path: Path to the source file.

        Returns:
            Parsed module information.
        """
        pass

    @abstractmethod
    def parse_file(self, file_path: Path) -> ModuleInfo:
        """Parse a source file.

        Args:
            file_path: Path to the source file.

        Returns:
            Parsed module information.
        """
        pass

    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the given file.

        Args:
            file_path: Path to check.

        Returns:
            True if this parser can handle the file.
        """
        return file_path.suffix.lower() in self.extensions

    def _extract_docstring(self, content: str, node: Any | None = None) -> str | None:
        """Extract docstring from source code.

        Args:
            content: Source code content.
            node: Optional AST node for context.

        Returns:
            Docstring if found, None otherwise.
        """
        return None


class TreeSitterParser(LanguageParser):
    """Base class for Tree-sitter based parsers."""

    def __init__(self, options: ParseOptions | None = None) -> None:
        """Initialize the Tree-sitter parser.

        Args:
            options: Parse options.
        """
        super().__init__(options)
        self._parser = None
        self._language = None

    def _init_parser(self) -> None:
        """Initialize the Tree-sitter parser. Override in subclasses."""
        pass

    def _parse_tree(self, content: bytes) -> Any:
        """Parse content and return the syntax tree.

        Args:
            content: Source code as bytes.

        Returns:
            Tree-sitter tree object.
        """
        if self._parser is None:
            self._init_parser()
        return self._parser.parse(content)

    def _get_node_text(self, content: bytes, node: Any) -> str:
        """Get text content of a node.

        Args:
            content: Full source code as bytes.
            node: Tree-sitter node.

        Returns:
            Text content of the node.
        """
        return content[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _get_node_line(self, node: Any) -> int:
        """Get the starting line number of a node.

        Args:
            node: Tree-sitter node.

        Returns:
            1-based line number.
        """
        return node.start_point[0] + 1

    def _get_node_end_line(self, node: Any) -> int:
        """Get the ending line number of a node.

        Args:
            node: Tree-sitter node.

        Returns:
            1-based line number.
        """
        return node.end_point[0] + 1

    def _query_nodes(self, node: Any, query: str, content: bytes) -> list[dict[str, Any]]:
        """Query nodes using Tree-sitter query.

        Args:
            node: Root node to query.
            query: Tree-sitter query string.
            content: Source code content.

        Returns:
            List of query matches with captures.
        """
        try:
            query_obj = self._language.query(query)
            captures = query_obj.captures(node)
            return captures
        except Exception:
            return []

    def parse_file(self, file_path: Path) -> ModuleInfo:
        """Parse a source file.

        Args:
            file_path: Path to the source file.

        Returns:
            Parsed module information.
        """
        try:
            content = file_path.read_text(encoding="utf-8")
            return self.parse(content, file_path)
        except UnicodeDecodeError:
            # Try with different encodings
            for encoding in ["latin-1", "cp1252", "utf-16"]:
                try:
                    content = file_path.read_text(encoding=encoding)
                    return self.parse(content, file_path)
                except (UnicodeDecodeError, Exception):
                    continue
            # Return empty module if all encodings fail
            return ModuleInfo(
                file_path=str(file_path),
                language=self.language_name,
                parse_errors=["Failed to decode file with any encoding"],
            )
        except Exception as e:
            return ModuleInfo(
                file_path=str(file_path),
                language=self.language_name,
                parse_errors=[str(e)],
            )


class CodeStructureParser:
    """Main parser that dispatches to language-specific parsers."""

    def __init__(self, options: ParseOptions | None = None) -> None:
        """Initialize the code structure parser.

        Args:
            options: Parse options.
        """
        self.options = options or ParseOptions()
        self._parsers: dict[str, LanguageParser] = {}
        self._init_parsers()

    def _init_parsers(self) -> None:
        """Initialize language-specific parsers. Override to add more parsers."""
        # Import here to avoid circular imports
        try:
            from .languages.java_parser import JavaStructureParser

            parser = JavaStructureParser(self.options)
            for ext in parser.extensions:
                self._parsers[ext] = parser
        except ImportError:
            pass

        try:
            from .languages.python_parser import PythonStructureParser

            parser = PythonStructureParser(self.options)
            for ext in parser.extensions:
                self._parsers[ext] = parser
        except ImportError:
            pass

        try:
            from .languages.go_parser import GoStructureParser

            parser = GoStructureParser(self.options)
            for ext in parser.extensions:
                self._parsers[ext] = parser
        except ImportError:
            pass

    def get_parser(self, file_path: Path) -> LanguageParser | None:
        """Get the appropriate parser for a file.

        Args:
            file_path: Path to the file.

        Returns:
            Language parser if available, None otherwise.
        """
        ext = file_path.suffix.lower()
        return self._parsers.get(ext)

    def can_parse(self, file_path: Path) -> bool:
        """Check if a file can be parsed.

        Args:
            file_path: Path to check.

        Returns:
            True if the file can be parsed.
        """
        return file_path.suffix.lower() in self._parsers

    def parse_file(self, file_path: Path) -> ModuleInfo:
        """Parse a single file.

        Args:
            file_path: Path to the file.

        Returns:
            Parsed module information.
        """
        parser = self.get_parser(file_path)
        if parser:
            return parser.parse_file(file_path)

        return ModuleInfo(
            file_path=str(file_path),
            language="unknown",
            parse_errors=[f"No parser available for extension {file_path.suffix}"],
        )

    def parse_content(self, content: str, file_path: Path) -> ModuleInfo:
        """Parse source code content.

        Args:
            content: Source code content.
            file_path: Path for reference.

        Returns:
            Parsed module information.
        """
        parser = self.get_parser(file_path)
        if parser:
            return parser.parse(content, file_path)

        return ModuleInfo(
            file_path=str(file_path),
            language="unknown",
            parse_errors=[f"No parser available for extension {file_path.suffix}"],
        )
