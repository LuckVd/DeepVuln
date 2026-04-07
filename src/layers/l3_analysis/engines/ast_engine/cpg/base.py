"""
Language-specific CPG Provider base class.

Defines the abstract interface for language-specific CPG path providers,
ensuring consistent behavior across different programming languages.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from src.layers.l3_analysis.engines.ast_engine.path_finder.models import AttackPath


class LanguageCPGProvider(ABC):
    """
    Abstract base class for language-specific CPG path providers.

    Each language implementation should:
    1. Build a CodePropertyGraph for the target source
    2. Use AttackPathFinder to find paths to dangerous sinks
    3. Return a list of AttackPath objects
    """

    @abstractmethod
    def get_paths(
        self,
        source_path: Path,
        sink_pattern: str,
    ) -> list[AttackPath]:
        """
        Get attack paths for a given source.

        Args:
            source_path: Path to the source file or directory
            sink_pattern: Regex pattern matching dangerous function names

        Returns:
            List of AttackPath objects, sorted by confidence
        """
        pass

    @abstractmethod
    def supports_language(self, language: str) -> bool:
        """
        Check if this provider supports the given language.

        Args:
            language: Language code (e.g., "python", "javascript")

        Returns:
            True if supported, False otherwise
        """
        pass

    @property
    @abstractmethod
    def file_patterns(self) -> list[str]:
        """
        Return file patterns for this language.

        Examples:
            Python: ["*.py"]
            JavaScript: ["*.js", "*.jsx", "*.ts", "*.tsx"]
            Java: ["*.java"]

        Returns:
            List of glob patterns
        """
        pass

    def get_file_extensions(self) -> list[str]:
        """
        Get file extensions for this language.

        Returns:
            List of extensions including the dot (e.g., [".py"])
        """
        patterns = self.file_patterns
        extensions = []

        for pattern in patterns:
            if pattern.startswith("*."):
                extensions.append(pattern)
            elif pattern.startswith("*"):
                extensions.append("." + pattern[1:])
            else:
                extensions.append(pattern)

        return extensions


class BaseCPGProvider(LanguageCPGProvider):
    """
    Base implementation with common functionality.

    Provides shared logic for CPG building and path finding
    that can be reused by language-specific providers.
    """

    def __init__(self) -> None:
        """Initialize the base provider."""
        from src.core.logger.logger import get_logger

        self.logger = get_logger(__name__)

    def _build_cpg(
        self,
        source_path: Path,
        file_patterns: list[str],
    ) -> Any:
        """
        Build a CodePropertyGraph for the source.

        Args:
            source_path: Path to the source file or directory
            file_patterns: File patterns to include

        Returns:
            CodePropertyGraph instance
        """
        from src.layers.l3_analysis.engines.ast_engine.cpg.builder import CPGBuilder

        builder = CPGBuilder()

        if source_path.is_file():
            return builder.build_from_file(source_path)

        # Directory - build from all matching files
        return builder.build_from_directory(source_path, file_patterns)

    def _find_paths(
        self,
        cpg: Any,
        sink_pattern: str,
    ) -> list[AttackPath]:
        """
        Find attack paths using the CPG.

        Args:
            cpg: CodePropertyGraph
            sink_pattern: Pattern matching dangerous sinks

        Returns:
            List of AttackPath objects
        """
        from src.layers.l3_analysis.engines.ast_engine.path_finder.finder import (
            AttackPathFinder,
        )

        finder = AttackPathFinder()
        return finder.find_paths(cpg, sink_pattern)

    def supports_file(self, file_path: Path) -> bool:
        """
        Check if a file is supported by this provider.

        Args:
            file_path: Path to check

        Returns:
            True if file extension matches
        """
        return any(
            file_path.suffix == ext.replace("*", "")
            for ext in self.file_patterns
        )
