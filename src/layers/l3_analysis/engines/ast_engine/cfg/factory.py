"""
CFG Builder Factory - Factory for creating language-specific CFG builders.

Provides automatic language detection and builder instantiation.
"""

from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.ast_engine.cfg.base import LanguageCFGBuilder


class CFGBuilderFactory:
    """
    Factory for creating language-specific CFG builders.

    Maintains a registry of available builders and provides automatic
    language detection.
    """

    def __init__(self) -> None:
        """Initialize the factory."""
        self.logger = get_logger(__name__)
        self._builders: dict[str, type[LanguageCFGBuilder]] = {}
        self._register_default_builders()

    def _register_default_builders(self) -> None:
        """Register the default language builders."""
        # Import and register builders
        try:
            from src.layers.l3_analysis.engines.ast_engine.cfg.builders.python_cfg import (
                PythonCFGBuilder,
            )
            self.register_builder("python", PythonCFGBuilder)
        except ImportError:
            self.logger.warning("Python CFG builder not available")

        try:
            from src.layers.l3_analysis.engines.ast_engine.cfg.builders.js_cfg import (
                JSCFGBuilder,
            )
            self.register_builder("javascript", JSCFGBuilder)
            self.register_builder("typescript", JSCFGBuilder)
        except ImportError:
            self.logger.warning("JavaScript CFG builder not available")

        try:
            from src.layers.l3_analysis.engines.ast_engine.cfg.builders.java_cfg import (
                JavaCFGBuilder,
            )
            self.register_builder("java", JavaCFGBuilder)
        except ImportError:
            self.logger.warning("Java CFG builder not available")

        try:
            from src.layers.l3_analysis.engines.ast_engine.cfg.builders.go_cfg import (
                GoCFGBuilder,
            )
            self.register_builder("go", GoCFGBuilder)
        except ImportError:
            self.logger.warning("Go CFG builder not available")

    def register_builder(
        self, language: str, builder_class: type[LanguageCFGBuilder]
    ) -> None:
        """Register a CFG builder for a language."""
        self._builders[language.lower()] = builder_class
        self.logger.debug(f"Registered CFG builder for {language}")

    def get_builder(self, language: str) -> LanguageCFGBuilder | None:
        """
        Get a CFG builder for the specified language.

        Args:
            language: Language name (python, javascript, java, go, etc.)

        Returns:
            LanguageCFGBuilder instance or None if not supported
        """
        builder_class = self._builders.get(language.lower())
        if builder_class:
            return builder_class()

        self.logger.warning(f"No CFG builder available for {language}")
        return None

    def detect_language_from_file(self, file_path: str) -> str | None:
        """
        Detect programming language from file extension.

        Args:
            file_path: Path to the source file

        Returns:
            Language name or None if unknown
        """
        import os

        ext = os.path.splitext(file_path)[1].lower()

        language_map = {
            ".py": "python",
            ".pyw": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".java": "java",
            ".go": "go",
        }

        return language_map.get(ext)


# Global factory instance
_factory = CFGBuilderFactory()


def get_cfg_builder(language: str | None = None) -> LanguageCFGBuilder | None:
    """
    Get a CFG builder, using the global factory.

    Args:
        language: Language name (optional)

    Returns:
        LanguageCFGBuilder instance or None
    """
    if language:
        return _factory.get_builder(language)
    return None


def detect_language(file_path: str) -> str | None:
    """
    Detect programming language from file path.

    Args:
        file_path: Path to the source file

    Returns:
        Language name or None
    """
    return _factory.detect_language_from_file(file_path)
