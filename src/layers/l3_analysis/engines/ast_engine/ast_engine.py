"""AST Engine - Tree-sitter based structural vulnerability detection engine."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.ast_engine.parser.tree_sitter_manager import (
    TreeSitterManager,
)
from src.layers.l3_analysis.engines.ast_engine.queries.query_engine import QueryEngine
from src.layers.l3_analysis.engines.base import BaseEngine
from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    ScanResult,
    SeverityLevel,
)

# Built-in detection rules
# Note: Python tree-sitter uses "call" not "call_expression"
# The syntax is (call (identifier) @capture_name)
_BUILTIN_RULES = {
    "dangerous_eval": """
((call
  (identifier) @func)
 (#match? @func "^eval$"))
""",
    "dangerous_exec": """
((call
  (identifier) @func)
 (#match? @func "^exec$"))
""",
    "dangerous_os_system": """
((call
  (attribute
    object: (identifier) @obj
    attribute: (identifier) @attr))
 (#eq? @obj "os")
 (#eq? @attr "system"))
""",
    "weak_crypto_md5": """
((call
  (attribute
    object: (identifier) @obj
    attribute: (identifier) @attr))
 (#eq? @obj "hashlib")
 (#match? @attr "md5"))
""",
    "pickle_load": """
((call
  (attribute
    object: (identifier) @obj
    attribute: (identifier) @attr))
 (#eq? @obj "pickle")
 (#match? @attr "^load"))
""",
}


class ASTEngine(BaseEngine):
    """
    AST-based structural vulnerability detection engine.

    Uses tree-sitter to parse source code and execute structural queries
    to detect dangerous API usage, weak cryptography, and other patterns.

    This complements Semgrep (pattern matching) and CodeQL (dataflow analysis)
    by providing fast, accurate structural code understanding.
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
        self._query_engine = QueryEngine()

    @property
    def _tree_sitter_manager(self) -> TreeSitterManager:
        """Get the TreeSitterManager instance."""
        if not hasattr(self, "_ts_manager"):
            self._ts_manager = TreeSitterManager()
        return self._ts_manager

    @_tree_sitter_manager.setter
    def _tree_sitter_manager(self, value: TreeSitterManager) -> None:
        """Set the TreeSitterManager instance."""
        self._ts_manager = value

    @property
    def _query_engine(self) -> QueryEngine:
        """Get the QueryEngine instance."""
        if not hasattr(self, "_qe"):
            self._qe = QueryEngine()
        return self._qe

    @_query_engine.setter
    def _query_engine(self, value: QueryEngine) -> None:
        """Set the QueryEngine instance."""
        self._qe = value

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
            rules_used=list(_BUILTIN_RULES.keys()),
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

    async def _scan_file(self, file_path: Path) -> list[Finding]:
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

        # Run built-in rules
        for rule_id, query_text in _BUILTIN_RULES.items():
            results = self._query_engine.execute_query(
                query_text=query_text,
                code=content,
                language=language,
            )

            for result in results:
                finding = self._create_finding_from_query_result(
                    query_result=result,
                    rule_id=rule_id,
                    file_path=str(file_path),
                )
                if finding:
                    findings.append(finding)

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

    def _create_finding_from_query_result(
        self,
        query_result: dict[str, Any],
        rule_id: str,
        severity: SeverityLevel = SeverityLevel.HIGH,
        file_path: str | None = None,
    ) -> Finding | None:
        """Create a Finding from a query result.

        Args:
            query_result: Query result dictionary.
            rule_id: Rule identifier.
            severity: Finding severity.
            file_path: Optional file path (overrides query result).

        Returns:
            Finding object or None.
        """
        try:
            # Get location
            actual_file = file_path or query_result.get("file", "")

            location = CodeLocation(
                file=actual_file,
                line=query_result.get("line", 1),
                column=query_result.get("column", 0),
                snippet=query_result.get("text", ""),
            )

            # Get severity from rule
            final_severity = self._get_severity_for_rule(rule_id)

            # Create finding
            finding = Finding(
                id=f"ast-{rule_id}-{query_result.get('line', 0)}",
                rule_id=rule_id,
                type=FindingType.VULNERABILITY,
                severity=final_severity,
                confidence=0.8,
                title=self._get_title_for_rule(rule_id),
                description=self._get_description_for_rule(rule_id),
                location=location,
                source="ast_engine",
                metadata={
                    "capture": query_result.get("capture", ""),
                    "node_type": query_result.get("type", ""),
                },
            )

            return finding

        except Exception as e:
            self.logger.warning(f"Failed to create finding: {e}, query_result={query_result}")
            return None

    def _get_severity_for_rule(self, rule_id: str) -> SeverityLevel:
        """Get severity level for a rule.

        Args:
            rule_id: Rule identifier.

        Returns:
            Severity level.
        """
        severity_map = {
            "dangerous_eval": SeverityLevel.CRITICAL,
            "dangerous_exec": SeverityLevel.CRITICAL,
            "dangerous_os_system": SeverityLevel.HIGH,
            "weak_crypto_md5": SeverityLevel.MEDIUM,
            "pickle_load": SeverityLevel.HIGH,
        }
        return severity_map.get(rule_id, SeverityLevel.MEDIUM)

    def _get_title_for_rule(self, rule_id: str) -> str:
        """Get title for a rule.

        Args:
            rule_id: Rule identifier.

        Returns:
            Human-readable title.
        """
        title_map = {
            "dangerous_eval": "Dangerous eval() Usage",
            "dangerous_exec": "Dangerous exec() Usage",
            "dangerous_os_system": "Dangerous os.system() Call",
            "weak_crypto_md5": "Weak Cryptography (MD5)",
            "pickle_load": "Unsafe pickle deserialization",
        }
        return title_map.get(rule_id, "Structural Vulnerability Detected")

    def _get_description_for_rule(self, rule_id: str) -> str:
        """Get description for a rule.

        Args:
            rule_id: Rule identifier.

        Returns:
            Human-readable description.
        """
        desc_map = {
            "dangerous_eval": (
                "eval() executes arbitrary code from a string. "
                "If the input contains malicious code, this leads to Remote Code Execution."
            ),
            "dangerous_exec": (
                "exec() executes arbitrary Python code. "
                "If the input contains malicious code, this leads to Remote Code Execution."
            ),
            "dangerous_os_system": (
                "os.system() executes a shell command. "
                "If the command contains user input, this may lead to Command Injection."
            ),
            "weak_crypto_md5": (
                "MD5 is a weak hash function vulnerable to collision attacks. "
                "Use SHA-256 or stronger instead."
            ),
            "pickle_load": (
                "pickle.load() can execute arbitrary code during deserialization. "
                "Only unpickle trusted data or use JSON instead."
            ),
        }
        return desc_map.get(
            rule_id,
            "Structural vulnerability detected by AST analysis.",
        )
