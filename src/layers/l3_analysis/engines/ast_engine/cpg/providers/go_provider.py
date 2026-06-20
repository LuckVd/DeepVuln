"""
Go-specific CPG Path Provider.

Provides attack path analysis for Go source code using the Code Property
Graph and AttackPathFinder.

Phase 18/P2-Go: previously ``path_provider.py`` had ``"go": GoCPGProvider()``
commented out as a TODO, so Go had no CPG attack-path analysis at all.
"""

from pathlib import Path

from src.layers.l3_analysis.engines.ast_engine.cpg.base import BaseCPGProvider
from src.layers.l3_analysis.engines.ast_engine.path_finder.models import AttackPath


class GoCPGProvider(BaseCPGProvider):
    """
    CPG path provider for Go source code.

    Supports Go-specific dangerous sinks: command execution (exec.Command),
    file/path operations, template injection, deserialization (gob), etc.
    """

    FILE_PATTERNS = ["*.go"]

    @property
    def file_patterns(self) -> list[str]:
        return self.FILE_PATTERNS

    def get_paths(
        self,
        source_path: Path,
        sink_pattern: str = "exec|Command|Open|ReadFile|Template|HTML|gob",
    ) -> list[AttackPath]:
        self.logger.debug(f"Building CPG for Go source: {source_path}")

        cpg = self._build_cpg(source_path, self.FILE_PATTERNS)

        if cpg.size() == 0:
            self.logger.warning(f"CPG is empty for {source_path}")
            return []

        paths = self._find_paths(cpg, sink_pattern)

        self.logger.info(
            f"Found {len(paths)} attack paths in Go source {source_path}"
        )
        return paths

    def supports_language(self, language: str) -> bool:
        return language == "go"
