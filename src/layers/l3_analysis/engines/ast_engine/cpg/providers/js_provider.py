"""
JavaScript/TypeScript-specific CPG Path Provider.

Provides attack path analysis for JavaScript and TypeScript source code.
"""

from pathlib import Path

from src.layers.l3_analysis.engines.ast_engine.cpg.base import BaseCPGProvider
from src.layers.l3_analysis.engines.ast_engine.path_finder.models import AttackPath


class JSCPGProvider(BaseCPGProvider):
    """
    CPG path provider for JavaScript/TypeScript source code.

    Supports:
    - if/while/for/try/switch/break/continue/return
    - Async/await
    - Arrow functions and template literals
    """

    # JavaScript/TypeScript file patterns
    FILE_PATTERNS = ["*.js", "*.jsx", "*.ts", "*.tsx"]

    @property
    def file_patterns(self) -> list[str]:
        """Return JavaScript file patterns."""
        return self.FILE_PATTERNS

    def get_paths(
        self,
        source_path: Path,
        sink_pattern: str = "eval|exec|system",
    ) -> list[AttackPath]:
        """
        Get attack paths for JavaScript/TypeScript source.

        Args:
            source_path: Path to JS/TS file or directory
            sink_pattern: Regex pattern for dangerous functions

        Returns:
            List of AttackPath objects
        """
        self.logger.debug(f"Building CPG for JavaScript source: {source_path}")

        # 1. Build CPG
        cpg = self._build_cpg(source_path, self.FILE_PATTERNS)

        if cpg.size() == 0:
            self.logger.warning(f"CPG is empty for {source_path}")
            return []

        # 2. Find paths
        paths = self._find_paths(cpg, sink_pattern)

        self.logger.info(
            f"Found {len(paths)} attack paths in JavaScript source {source_path}"
        )

        return paths

    def supports_language(self, language: str) -> bool:
        """Check if this provider supports the given language."""
        return language in {"javascript", "typescript"}
