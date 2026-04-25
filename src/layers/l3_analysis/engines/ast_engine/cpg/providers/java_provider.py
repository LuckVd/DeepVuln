"""
Java-specific CPG Path Provider.

Provides attack path analysis for Java source code using
Code Property Graph and AttackPathFinder.
"""

from pathlib import Path

from src.layers.l3_analysis.engines.ast_engine.cpg.base import BaseCPGProvider
from src.layers.l3_analysis.engines.ast_engine.path_finder.models import AttackPath


class JavaCPGProvider(BaseCPGProvider):
    """
    CPG path provider for Java source code.

    Supports complete Java syntax including:
    - if/while/for/switch/try/synchronized
    - Method declarations and constructor calls
    - Spring/JAX-RS/Servlet annotations
    """

    FILE_PATTERNS = ["*.java"]

    @property
    def file_patterns(self) -> list[str]:
        return self.FILE_PATTERNS

    def get_paths(
        self,
        source_path: Path,
        sink_pattern: str = "exec|eval|Runtime|ProcessBuilder|ScriptEngine",
    ) -> list[AttackPath]:
        self.logger.debug(f"Building CPG for Java source: {source_path}")

        cpg = self._build_cpg(source_path, self.FILE_PATTERNS)

        if cpg.size() == 0:
            self.logger.warning(f"CPG is empty for {source_path}")
            return []

        paths = self._find_paths(cpg, sink_pattern)

        self.logger.info(
            f"Found {len(paths)} attack paths in Java source {source_path}"
        )
        return paths

    def supports_language(self, language: str) -> bool:
        return language == "java"
