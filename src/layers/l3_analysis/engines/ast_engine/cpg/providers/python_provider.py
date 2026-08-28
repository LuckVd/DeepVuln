"""
Python-specific CPG Path Provider.

Provides attack path analysis for Python source code using
Code Property Graph and AttackPathFinder.
"""

from pathlib import Path

from src.layers.l3_analysis.engines.ast_engine.cpg.base import BaseCPGProvider
from src.layers.l3_analysis.engines.ast_engine.path_finder.models import AttackPath


class PythonCPGProvider(BaseCPGProvider):
    """
    CPG path provider for Python source code.

    Supports complete Python syntax including:
    - if/while/for/try/match/async/break/continue/return
    - Lambda expressions and comprehensions
    - Decorators and context managers
    """

    # Python file patterns
    FILE_PATTERNS = ["*.py"]

    @property
    def file_patterns(self) -> list[str]:
        """Return Python file patterns."""
        return self.FILE_PATTERNS

    def get_paths(
        self,
        source_path: Path,
        sink_pattern: str | None = None,
    ) -> list[AttackPath]:
        """
        Get attack paths for Python source.

        Args:
            source_path: Path to Python file or directory
            sink_pattern: Regex pattern for dangerous functions

        Returns:
            List of AttackPath objects
        """
        if sink_pattern is None:
            sink_pattern = "eval|exec|system"

        self.logger.debug(f"Building CPG for Python source: {source_path}")

        # 1. Build CPG
        cpg = self._build_cpg(source_path, self.FILE_PATTERNS)

        if cpg.size() == 0:
            self.logger.warning(f"CPG is empty for {source_path}")
            return []

        # 2. Find paths
        paths = self._find_paths(cpg, sink_pattern)

        self.logger.info(
            f"Found {len(paths)} attack paths in Python source {source_path}"
        )

        return paths

    def supports_language(self, language: str) -> bool:
        """Check if this provider supports the given language."""
        return language == "python"
