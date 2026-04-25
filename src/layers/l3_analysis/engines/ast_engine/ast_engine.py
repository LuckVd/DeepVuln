"""AST Engine - Tree-sitter based structural vulnerability detection engine."""

from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.ast_engine.detectors import (
    DeserializationDetector,
    DangerousAPIDetector,
    FrameworkDetector,
)
from src.layers.l3_analysis.engines.ast_engine.detectors.crypto_detector import (
    CryptoMisuseDetector,
)
from src.layers.l3_analysis.engines.ast_engine.parser.tree_sitter_manager import (
    TreeSitterManager,
)
from src.layers.l3_analysis.engines.base import BaseEngine
from src.layers.l3_analysis.models import (
    ScanResult,
)


class ASTEngine(BaseEngine):
    """
    AST-based structural vulnerability detection engine.

    Uses tree-sitter to parse source code and execute structural queries
    to detect dangerous API usage, weak cryptography, and other patterns.

    This complements Semgrep (pattern matching) and CodeQL (dataflow analysis)
    by providing fast, accurate structural code understanding.

    P8-03: Now uses detector-based architecture with YAML rules.
    """

    name = "ast_engine"
    description = "AST-based structural vulnerability detection"
    supported_languages = [
        "python",
        "javascript",
        "typescript",
        "java",
        "go",
        "cpp",
        "c",
        "ruby",
        "php",
        "rust",
    ]

    def __init__(
        self,
        timeout: int = 300,
        max_memory_mb: int = 4096,
    ) -> None:
        """Initialize the AST Engine.

        Args:
            timeout: Maximum scan duration in seconds.
            max_memory_mb: Maximum memory usage in MB.
        """
        super().__init__(timeout=timeout, max_memory_mb=max_memory_mb)
        self.logger = get_logger(__name__)
        self._tree_sitter_manager = TreeSitterManager()

        # Initialize detectors (P8-03)
        self._detectors = [
            DangerousAPIDetector(),
            CryptoMisuseDetector(),
            DeserializationDetector(),
            FrameworkDetector(),
        ]

        # Collect rule IDs from all detectors
        self._rule_ids = []
        for detector in self._detectors:
            self._rule_ids.extend(detector._rules.keys())

    def is_available(self) -> bool:
        """Check if tree-sitter is available."""
        return self._tree_sitter_manager.is_available()

    async def scan(
        self,
        source_path: Path,
        **options,
    ) -> ScanResult:
        """
        Execute a scan on the given source path.

        Args:
            source_path: Path to the source code to scan.
            **options: Engine-specific options.

        Returns:
            ScanResult containing all findings.
        """
        # Validate source path
        self.validate_source_path(source_path)

        # Create scan result
        result = self.create_scan_result(
            source_path=source_path,
            rules_used=self._rule_ids,
        )

        try:
            # Get list of files to scan
            source_files = self._get_source_files(source_path)

            self.logger.info(
                f"AST Engine scanning {len(source_files)} files in {source_path}"
            )

            # Scan each file
            for file_path in source_files:
                findings = await self._scan_file(file_path)
                for finding in findings:
                    result.add_finding(finding)

            self.logger.info(
                f"AST Engine scan complete: {len(result.findings)} findings"
            )

            return self.finalize_scan_result(
                result,
                success=True,
                raw_output={
                    "files_scanned": len(source_files),
                    "findings_count": len(result.findings),
                },
            )

        except Exception as e:
            self.logger.error(f"AST Engine scan failed: {e}")
            return self.finalize_scan_result(
                result,
                success=False,
                error_message=str(e),
            )

    def _get_source_files(self, source_path: Path) -> list[Path]:
        """Get list of source files to scan.

        Args:
            source_path: Root source directory.

        Returns:
            List of source file paths.
        """
        source_files = []

        # File extensions by language
        extensions = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
            ".rb": "ruby",
            ".php": "php",
            ".rs": "rust",
        }

        for ext, language in extensions.items():
            for file_path in source_path.rglob(f"*{ext}"):
                # Skip test directories if needed
                if "test" in file_path.parts or "tests" in file_path.parts:
                    continue
                source_files.append(file_path)

        return source_files

    async def _scan_file(self, file_path: Path) -> list[Any]:
        """Scan a single file for vulnerabilities.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of findings.
        """
        findings = []

        # Read file content
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            self.logger.debug(f"Failed to read {file_path}: {e}")
            return findings

        # Detect language from extension
        language = self._detect_language(file_path)
        if language is None:
            return findings

        # Run all detectors (P8-03)
        for detector in self._detectors:
            try:
                detector_findings = await detector.detect(
                    code=content,
                    language=language,
                    file_path=str(file_path),
                )
                findings.extend(detector_findings)
            except Exception as e:
                self.logger.debug(f"Detector {detector.detector_type()} failed: {e}")

        return findings

    def _detect_language(self, file_path: Path) -> str | None:
        """Detect programming language from file extension.

        Args:
            file_path: Path to the file.

        Returns:
            Language name or None.
        """
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
            ".rb": "ruby",
            ".php": "php",
            ".rs": "rust",
        }

        return ext_map.get(file_path.suffix)
