"""
CPG Path Provider - Language-agnostic interface for attack path analysis.

Provides a unified interface for finding attack paths in source code using
Code Property Graph, routing to language-specific providers.
"""

from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.ast_engine.cpg.base import LanguageCPGProvider
from src.layers.l3_analysis.engines.ast_engine.cpg.providers.js_provider import (
    JSCPGProvider,
)
from src.layers.l3_analysis.engines.ast_engine.cpg.providers.go_provider import (
    GoCPGProvider,
)
from src.layers.l3_analysis.engines.ast_engine.cpg.providers.java_provider import (
    JavaCPGProvider,
)
from src.layers.l3_analysis.engines.ast_engine.cpg.providers.python_provider import (
    PythonCPGProvider,
)
from src.layers.l3_analysis.engines.ast_engine.path_finder.models import AttackPath


class CPGPathProvider:
    """
    Language-agnostic CPG path provider.

    Routes path analysis requests to language-specific providers based on
    automatic language detection.

    Usage:
        provider = CPGPathProvider()
        paths = provider.get_attack_paths(
            source_path=Path("/path/to/project"),
            sink_pattern="eval|exec|system"
        )
    """

    def __init__(self) -> None:
        """Initialize the path provider with language-specific implementations."""
        self.logger = get_logger(__name__)

        # Register language-specific providers
        self._providers: dict[str, LanguageCPGProvider] = {
            "python": PythonCPGProvider(),
            "javascript": JSCPGProvider(),
            "typescript": JSCPGProvider(),  # JSCPGProvider handles both
            "java": JavaCPGProvider(),
            "go": GoCPGProvider(),  # Phase 18/P2-Go
        }

    def get_attack_paths(
        self,
        source_path: Path,
        sink_pattern: str = "eval|exec|system",
    ) -> list[AttackPath]:
        """
        Get attack paths from entry points to dangerous sinks.

        Args:
            source_path: Path to the source file or directory
            sink_pattern: Regex pattern matching dangerous function names

        Returns:
            List of AttackPath objects, sorted by confidence (highest first).
            Returns empty list if:
            - Language is not supported
            - Provider fails (graceful degradation)
        """
        # 1. Detect language
        language = self._detect_language(source_path)

        if not language:
            self.logger.debug(f"Could not detect language for {source_path}")
            return []

        # 2. Get provider for this language
        provider = self._providers.get(language)

        if not provider:
            self.logger.warning(f"No CPG provider available for language: {language}")
            return []

        # 3. Get paths from provider
        try:
            paths = provider.get_paths(source_path, sink_pattern)
            self.logger.info(
                f"Found {len(paths)} attack paths for {language} in {source_path}"
            )
            return paths
        except Exception as e:
            # Graceful degradation - don't fail the scan
            self.logger.warning(f"CPG path analysis failed for {source_path}: {e}")
            return []

    def _detect_language(self, source_path: Path) -> str | None:
        """
        Detect the programming language of the source.

        Args:
            source_path: Path to file or directory

        Returns:
            Language code (e.g., "python", "javascript") or None
        """
        # File extension to language mapping
        EXTENSION_TO_LANG = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".cpp": "cpp",
            ".c": "c",
            ".cs": "csharp",
            ".rs": "rust",
        }

        if source_path.is_file():
            # Detect from file extension
            ext = source_path.suffix.lower()
            return EXTENSION_TO_LANG.get(ext)

        if source_path.is_dir():
            # For directories, detect from file extensions
            language_counts: dict[str, int] = {}

            for file_path in source_path.rglob("*"):
                if file_path.is_file() and not file_path.name.startswith("."):
                    ext = file_path.suffix.lower()
                    lang = EXTENSION_TO_LANG.get(ext)
                    if lang:
                        language_counts[lang] = language_counts.get(lang, 0) + 1

            # Return the most common language
            if language_counts:
                return max(language_counts, key=language_counts.get)

        return None

    def register_provider(
        self,
        language: str,
        provider: LanguageCPGProvider,
    ) -> None:
        """
        Register a new language-specific provider.

        Args:
            language: Language code (e.g., "javascript", "java")
            provider: Provider instance
        """
        self._providers[language] = provider
        self.logger.info(f"Registered CPG provider for language: {language}")

    def get_supported_languages(self) -> list[str]:
        """Return list of supported language codes."""
        return list(self._providers.keys())

    def supports_language(self, language: str) -> bool:
        """Check if a language is supported."""
        return language in self._providers
