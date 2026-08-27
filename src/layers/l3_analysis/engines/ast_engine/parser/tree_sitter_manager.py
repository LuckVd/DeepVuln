"""TreeSitter Manager - Manages tree-sitter language parsers."""

from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

try:
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Language = None
    Parser = None

# Language module imports (lazy loaded)
_LANGUAGE_MODULES = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
    "java": "tree_sitter_java",
    "go": "tree_sitter_go",
    "cpp": "tree_sitter_cpp",
    "c": "tree_sitter_c",
    "ruby": "tree_sitter_ruby",
    "php": "tree_sitter_php",
    "rust": "tree_sitter_rust",
}

# Multi-grammar packages expose per-grammar factory functions instead of a
# single `.language` (e.g. tree_sitter_typescript >= 0.23 ships
# language_typescript / language_tsx). Tried in order after `.language`.
_LANGUAGE_ENTRYPOINTS = {
    "typescript": ("language_typescript", "language_tsx"),
}


class TreeSitterManager:
    """
    Manager for tree-sitter language parsers.

    Provides lazy loading and caching of language parsers
    to avoid unnecessary initialization overhead.
    """

    def __init__(self) -> None:
        """Initialize the TreeSitterManager."""
        self.logger = get_logger(__name__)
        self._languages: dict[str, Any] = {}
        self._parsers: dict[str, Any] = {}

    def is_available(self) -> bool:
        """Check if tree-sitter is available."""
        return TREE_SITTER_AVAILABLE

    def get_language(self, language: str) -> Any | None:
        """
        Get a tree-sitter Language object for the given language.

        Args:
            language: Programming language name (e.g., "python", "javascript").

        Returns:
            Language object or None if not available.
        """
        if not TREE_SITTER_AVAILABLE:
            return None

        # Normalize language name
        lang_key = language.lower()

        # TypeScript special handling
        if lang_key in ("typescript", "tsx"):
            lang_key = "typescript"
        elif lang_key == "jsx":
            lang_key = "javascript"

        # Return cached if available
        if lang_key in self._languages:
            return self._languages[lang_key]

        # Try to load the language
        module_name = _LANGUAGE_MODULES.get(lang_key)
        if not module_name:
            self.logger.debug(f"No tree-sitter language module for: {language}")
            return None

        try:
            # Import the language module
            lang_module = __import__(module_name, fromlist=["language"])

            # Create Language object (tree-sitter 0.25+ API).
            # Resolve the grammar entry point: `.language` when present,
            # otherwise per-grammar factories (e.g. tree_sitter_typescript).
            init_fn = getattr(lang_module, "language", None)
            if init_fn is None:
                for attr in _LANGUAGE_ENTRYPOINTS.get(lang_key, ()):
                    init_fn = getattr(lang_module, attr, None)
                    if init_fn is not None:
                        break
            if init_fn is None:
                self.logger.error(
                    f"Language module {module_name} exposes no grammar "
                    f"entry point (.language or known factory)"
                )
                return None

            self._languages[lang_key] = Language(init_fn())
            self.logger.debug(f"Loaded tree-sitter language: {language}")

            return self._languages[lang_key]

        except ImportError as e:
            self.logger.warning(f"Failed to import {module_name}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to initialize language {language}: {e}")
            return None

    def get_parser(self, language: str) -> Any | None:
        """
        Get a tree-sitter Parser for the given language.

        Args:
            language: Programming language name.

        Returns:
            Parser object or None if language not available.
        """
        if not TREE_SITTER_AVAILABLE:
            return None

        lang_key = language.lower()

        # Return cached parser if available
        if lang_key in self._parsers:
            return self._parsers[lang_key]

        # Get the language first
        lang = self.get_language(language)
        if lang is None:
            return None

        try:
            parser = Parser(lang)
            self._parsers[lang_key] = parser
            self.logger.debug(f"Created parser for: {language}")
            return parser

        except Exception as e:
            self.logger.error(f"Failed to create parser for {language}: {e}")
            return None

    def parse_code(
        self,
        code: str,
        language: str,
    ) -> Any | None:
        """
        Parse source code into an AST.

        Args:
            code: Source code string.
            language: Programming language name.

        Returns:
            AST tree root node or None if parsing fails.
        """
        parser = self.get_parser(language)
        if parser is None:
            return None

        try:
            tree = parser.parse(bytes(code, "utf-8"))
            return tree

        except Exception as e:
            self.logger.warning(f"Failed to parse code: {e}")
            return None

    def get_supported_languages(self) -> list[str]:
        """Get list of supported language names."""
        return list(_LANGUAGE_MODULES.keys())
