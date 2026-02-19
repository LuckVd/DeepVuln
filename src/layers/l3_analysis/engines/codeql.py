"""
CodeQL Engine - GitHub CodeQL integration for deep dataflow analysis.

CodeQL is a powerful code analysis engine that enables deep dataflow analysis
to find complex vulnerabilities that pattern matching might miss.
"""

import json
import shutil
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.layers.l3_analysis.engines.base import BaseEngine, engine_registry
from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    ScanResult,
    SeverityLevel,
)


# CodeQL severity mapping to our SeverityLevel
SEVERITY_MAP: dict[str, SeverityLevel] = {
    "error": SeverityLevel.HIGH,
    "warning": SeverityLevel.MEDIUM,
    "note": SeverityLevel.INFO,
    "recommendation": SeverityLevel.LOW,
}

# CodeQL language names mapping
CODEQL_LANGUAGE_MAP: dict[str, str] = {
    "java": "java",
    "python": "python",
    "go": "go",
    "javascript": "javascript",
    "typescript": "javascript",  # TypeScript uses JavaScript analysis
    "c": "cpp",
    "cpp": "cpp",
    "c++": "cpp",
    "csharp": "csharp",
    "c#": "csharp",
    "ruby": "ruby",
    "swift": "swift",
    "kotlin": "java",  # Kotlin can be analyzed with Java
    "scala": "java",  # Scala can be analyzed with Java
}

# Default query suites for each language (using CodeQL pack names)
DEFAULT_QUERY_PACKS: dict[str, str] = {
    "java": "codeql/java-queries",
    "python": "codeql/python-queries",
    "go": "codeql/go-queries",
    "javascript": "codeql/javascript-queries",
    "cpp": "codeql/cpp-queries",
    "csharp": "codeql/csharp-queries",
    "ruby": "codeql/ruby-queries",
}

# Default query suites for each language
DEFAULT_QUERY_SUITES: dict[str, list[str]] = {
    "java": ["java-security-extended", "java-code-scanning"],
    "python": ["python-security-extended", "python-code-scanning"],
    "go": ["go-security-extended", "go-code-scanning"],
    "javascript": ["javascript-security-extended", "javascript-code-scanning"],
    "cpp": ["cpp-security-extended", "cpp-code-scanning"],
    "csharp": ["csharp-security-extended", "csharp-code-scanning"],
    "ruby": ["ruby-security-extended", "ruby-code-scanning"],
}

# Security query directory name within packs
SECURITY_QUERY_DIR = "Security"

# CodeQL security tags mapping to vulnerability types
TAG_TO_TYPE: dict[str, FindingType] = {
    "security": FindingType.VULNERABILITY,
    "correctness": FindingType.SUSPICIOUS,
    "maintainability": FindingType.INFO,
    "performance": FindingType.INFO,
}


class CodeQLEngine(BaseEngine):
    """
    CodeQL static analysis engine.

    Provides deep dataflow analysis using GitHub's CodeQL engine.
    Requires CodeQL CLI to be installed separately.
    """

    name = "codeql"
    description = "CodeQL deep dataflow analysis engine"
    supported_languages = [
        "java",
        "python",
        "go",
        "javascript",
        "typescript",
        "c",
        "cpp",
        "csharp",
        "ruby",
        "swift",
    ]

    def __init__(
        self,
        codeql_path: str = "codeql",
        timeout: int = 600,  # CodeQL needs more time than Semgrep
        max_memory_mb: int = 8192,  # CodeQL uses more memory
        search_path: list[str] | None = None,
    ):
        """
        Initialize the CodeQL engine.

        Args:
            codeql_path: Path to codeql binary (default: looks in PATH).
            timeout: Maximum scan duration in seconds.
            max_memory_mb: Maximum memory usage in MB.
            search_path: Additional paths to search for CodeQL packs.
        """
        super().__init__(timeout=timeout, max_memory_mb=max_memory_mb)
        self.codeql_path = codeql_path
        self.search_path = search_path
        self._version: str | None = None

    def is_available(self) -> bool:
        """
        Check if CodeQL CLI is installed and available.

        Returns:
            True if codeql can be executed.
        """
        return self.check_binary_available(self.codeql_path)

    async def get_version(self) -> str | None:
        """
        Get the CodeQL version.

        Returns:
            Version string, or None if not available.
        """
        if self._version:
            return self._version

        if not self.is_available():
            return None

        try:
            _, stdout, _ = await self.run_command(
                [self.codeql_path, "version", "--format=json"]
            )
            version_info = json.loads(stdout)
            self._version = version_info.get("version", "unknown")
            return self._version
        except Exception:
            # Fallback to plain text version
            try:
                _, stdout, _ = await self.run_command(
                    [self.codeql_path, "version"]
                )
                self._version = stdout.strip()
                return self._version
            except Exception:
                return None

    def normalize_language(self, language: str) -> str | None:
        """
        Normalize language name to CodeQL format.

        Args:
            language: Language name (e.g., "python", "JavaScript").

        Returns:
            CodeQL language name, or None if not supported.
        """
        lang_lower = language.lower()
        return CODEQL_LANGUAGE_MAP.get(lang_lower)

    async def scan(
        self,
        source_path: Path,
        language: str | None = None,
        queries: list[str] | None = None,
        query_suite: str | None = None,
        severity_filter: list[SeverityLevel] | None = None,
        database_path: Path | None = None,
        overwrite_database: bool = True,
        **options,
    ) -> ScanResult:
        """
        Execute a CodeQL scan.

        The scan consists of two phases:
        1. Create a CodeQL database from the source code
        2. Analyze the database with specified queries

        Args:
            source_path: Path to the source code to scan.
            language: Programming language (auto-detected if not specified).
            queries: List of specific query files to run.
            query_suite: Query suite name (e.g., "java-security-extended").
            severity_filter: Only return findings at these severity levels.
            database_path: Path to store the CodeQL database (temp if not specified).
            overwrite_database: Whether to overwrite existing database.
            **options: Additional options.

        Returns:
            ScanResult containing all findings.
        """
        # Validate source path
        self.validate_source_path(source_path)

        # Check if CodeQL is available
        if not self.is_available():
            result = self.create_scan_result(source_path, [])
            return self.finalize_scan_result(
                result,
                success=False,
                error_message="CodeQL CLI is not installed or not in PATH. "
                "Install from: https://github.com/github/codeql-cli-binaries/releases",
            )

        # Detect language if not specified
        if not language:
            language = await self._detect_language(source_path)

        if not language:
            result = self.create_scan_result(source_path, [])
            return self.finalize_scan_result(
                result,
                success=False,
                error_message="Could not detect programming language. "
                "Please specify --language option.",
            )

        # Normalize language
        codeql_lang = self.normalize_language(language)
        if not codeql_lang:
            result = self.create_scan_result(source_path, [])
            return self.finalize_scan_result(
                result,
                success=False,
                error_message=f"Language '{language}' is not supported by CodeQL.",
            )

        # Track rules used
        rules_used = []
        if query_suite:
            rules_used.append(query_suite)
        elif queries:
            rules_used.extend(queries)
        else:
            # Use default security suite
            default_suites = DEFAULT_QUERY_SUITES.get(codeql_lang, [])
            if default_suites:
                rules_used.append(default_suites[0])

        # Create scan result
        result = self.create_scan_result(source_path, rules_used)

        # Set up database path
        cleanup_db = False
        if database_path is None:
            # Create temporary database directory
            db_temp = tempfile.mkdtemp(prefix="codeql_db_")
            database_path = Path(db_temp)
            cleanup_db = True

        try:
            # Phase 1: Create database
            db_success = await self._create_database(
                source_path=source_path,
                database_path=database_path,
                language=codeql_lang,
                overwrite=overwrite_database,
            )

            if not db_success:
                return self.finalize_scan_result(
                    result,
                    success=False,
                    error_message="Failed to create CodeQL database. "
                    "Check if the project can be built successfully.",
                )

            # Phase 2: Analyze database
            sarif_output = await self._analyze_database(
                database_path=database_path,
                queries=queries,
                query_suite=query_suite or (DEFAULT_QUERY_SUITES.get(codeql_lang, ["security"])[0]),
                language=codeql_lang,
            )

            if sarif_output is None:
                return self.finalize_scan_result(
                    result,
                    success=False,
                    error_message="Failed to analyze CodeQL database.",
                )

            # Parse SARIF results
            findings = self._parse_sarif(
                sarif_output=sarif_output,
                source_path=source_path,
            )

            # Apply severity filter
            if severity_filter:
                findings = [f for f in findings if f.severity in severity_filter]

            # Add findings to result
            for finding in findings:
                result.add_finding(finding)

            return self.finalize_scan_result(
                result,
                success=True,
                raw_output=sarif_output,
            )

        except TimeoutError as e:
            return self.finalize_scan_result(
                result,
                success=False,
                error_message=str(e),
            )
        except Exception as e:
            return self.finalize_scan_result(
                result,
                success=False,
                error_message=f"Scan failed: {e}",
            )
        finally:
            # Cleanup temporary database
            if cleanup_db and database_path and database_path.exists():
                shutil.rmtree(database_path, ignore_errors=True)

    async def _detect_language(self, source_path: Path) -> str | None:
        """
        Detect the primary programming language of a project.

        Args:
            source_path: Path to the source code.

        Returns:
            Detected language name, or None if detection fails.
        """
        # Count files by extension
        extensions: dict[str, int] = {}

        extension_to_lang = {
            ".java": "java",
            ".py": "python",
            ".go": "go",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".c": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".cs": "csharp",
            ".rb": "ruby",
            ".swift": "swift",
            ".kt": "kotlin",
            ".scala": "scala",
        }

        for ext, count in extension_to_lang.items():
            files = list(source_path.rglob(f"*{ext}"))
            if files:
                lang = extension_to_lang.get(ext)
                if lang:
                    extensions[lang] = extensions.get(lang, 0) + len(files)

        if not extensions:
            return None

        # Return most common language
        return max(extensions, key=extensions.get)

    async def _create_database(
        self,
        source_path: Path,
        database_path: Path,
        language: str,
        overwrite: bool = True,
    ) -> bool:
        """
        Create a CodeQL database from source code.

        Args:
            source_path: Path to the source code.
            database_path: Path where the database will be created.
            language: CodeQL language name.
            overwrite: Whether to overwrite existing database.

        Returns:
            True if database creation succeeded.
        """
        cmd = [
            self.codeql_path,
            "database",
            "create",
            str(database_path),
            f"--language={language}",
            f"--source-root={source_path}",
            "--overwrite" if overwrite else "--no-overwrite",
            "--quiet",  # Reduce output noise
        ]

        # Add search path if specified
        if self.search_path:
            for path in self.search_path:
                cmd.extend(["--search-path", path])

        try:
            returncode, stdout, stderr = await self.run_command(
                cmd,
                cwd=None,  # Don't set cwd, use absolute paths in command
            )

            # CodeQL returns 0 on success
            if returncode == 0:
                return True

            # Log error for debugging
            if stderr:
                import logging
                logging.getLogger(__name__).warning(
                    f"CodeQL database creation failed: {stderr}"
                )
            return False

        except Exception as e:
            import logging
            logging.getLogger(__name__).error(
                f"CodeQL database creation exception: {e}"
            )
            return False

    async def _analyze_database(
        self,
        database_path: Path,
        queries: list[str] | None,
        query_suite: str,
        language: str,
    ) -> dict[str, Any] | None:
        """
        Analyze a CodeQL database and return SARIF results.

        Args:
            database_path: Path to the CodeQL database.
            queries: List of specific query files to run.
            query_suite: Query suite name.
            language: CodeQL language name.

        Returns:
            Parsed SARIF output, or None if analysis failed.
        """
        # Create temp file for SARIF output
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".sarif",
            delete=False,
        ) as sarif_file:
            sarif_path = Path(sarif_file.name)

        try:
            # Ensure query pack is downloaded
            query_pack = DEFAULT_QUERY_PACKS.get(language)
            if query_pack and not queries:
                await self._ensure_query_pack(query_pack)

            cmd = [
                self.codeql_path,
                "database",
                "analyze",
                str(database_path),
                "--format=sarifv2.1.0",  # Use stable SARIF version for compatibility
                f"--output={sarif_path}",
            ]

            # Add queries or query suite
            if queries:
                for query in queries:
                    cmd.append(query)
            else:
                # Resolve the query path - use specific subdirectories to avoid problematic queries
                resolved_queries = await self._resolve_query_path(language, query_suite)
                if resolved_queries:
                    # Instead of using all Security queries, use specific safe subdirectories
                    security_path = Path(resolved_queries)
                    safe_query_dirs = [
                        "CWE-022",      # Path Injection
                        "CWE-078",      # Command Injection
                        "CWE-079",      # XSS
                        "CWE-089",      # SQL Injection
                        "CWE-094",      # Code Injection
                        "CWE-611",      # XXE
                        "CWE-502",      # Unsafe Deserialization
                    ]
                    for qdir in safe_query_dirs:
                        qpath = security_path / qdir
                        if qpath.exists():
                            cmd.append(str(qpath))
                else:
                    cmd.append(query_suite)

            # Add search path if specified
            if self.search_path:
                for path in self.search_path:
                    cmd.extend(["--search-path", path])

            # Add additional options
            cmd.extend([
                "--sarif-add-baseline-file-info",  # Include baseline info
                "--sarif-add-snippets",  # Include code snippets
            ])

            returncode, stdout, stderr = await self.run_command(cmd)

            if returncode != 0:
                import logging
                logging.getLogger(__name__).warning(
                    f"CodeQL analysis failed with code {returncode}: {stderr}"
                )
                return None

            # Read and parse SARIF output
            if sarif_path.exists():
                with open(sarif_path, "r", encoding="utf-8") as f:
                    return json.load(f)

            return None

        except Exception:
            return None
        finally:
            # Cleanup SARIF file
            if sarif_path.exists():
                sarif_path.unlink()

    async def _ensure_query_pack(self, pack_name: str) -> bool:
        """
        Ensure a query pack is downloaded.

        Args:
            pack_name: Name of the query pack (e.g., 'codeql/python-queries').

        Returns:
            True if pack is available.
        """
        cmd = [
            self.codeql_path,
            "pack",
            "download",
            pack_name,
        ]

        try:
            returncode, stdout, stderr = await self.run_command(cmd)
            return returncode == 0
        except Exception:
            return False

    async def _resolve_query_path(self, language: str, query_suite: str) -> str | None:
        """
        Resolve the path to query files.

        Args:
            language: CodeQL language name.
            query_suite: Query suite name.

        Returns:
            Resolved query path, or None if not found.
        """
        import os

        # Check for downloaded packs in default location
        pack_name = DEFAULT_QUERY_PACKS.get(language)
        if not pack_name:
            return None

        # Default CodeQL pack installation location
        pack_base = Path.home() / ".codeql" / "packages"

        # Find the pack directory (may have version subdirectory)
        pack_dir = pack_base / pack_name.replace("/", "/")
        if pack_dir.exists():
            # Look for versioned directory - prefer older compatible versions
            versions = sorted(pack_dir.glob("*/"), reverse=False)
            if versions:
                security_dir = versions[0] / SECURITY_QUERY_DIR
                if security_dir.exists():
                    return str(security_dir)

        return None

    def _parse_sarif(
        self,
        sarif_output: dict[str, Any],
        source_path: Path,
    ) -> list[Finding]:
        """
        Parse SARIF output into Finding objects.

        Args:
            sarif_output: Parsed SARIF JSON.
            source_path: Path that was scanned.

        Returns:
            List of Finding objects.
        """
        findings = []

        runs = sarif_output.get("runs", [])

        for run in runs:
            tool = run.get("tool", {}).get("driver", {})
            tool_name = tool.get("name", "CodeQL")

            results = run.get("results", [])

            for result in results:
                finding = self._convert_sarif_result_to_finding(
                    result=result,
                    tool_name=tool_name,
                    source_path=source_path,
                )
                if finding:
                    findings.append(finding)

        return findings

    def _convert_sarif_result_to_finding(
        self,
        result: dict[str, Any],
        tool_name: str,
        source_path: Path,
    ) -> Finding | None:
        """
        Convert a single SARIF result to a Finding.

        Args:
            result: Single result from SARIF output.
            tool_name: Name of the analysis tool.
            source_path: Path that was scanned.

        Returns:
            Finding object, or None if conversion fails.
        """
        try:
            # Extract rule ID
            rule_id = result.get("ruleId", "unknown")

            # Extract message
            message_obj = result.get("message", {})
            message = message_obj.get("text", "No description available")

            # Extract level/severity
            level = result.get("level", "warning").lower()
            severity = SEVERITY_MAP.get(level, SeverityLevel.MEDIUM)

            # Extract location
            locations = result.get("locations", [])
            if not locations:
                return None

            location_obj = locations[0].get("physicalLocation", {})
            artifact = location_obj.get("artifactLocation", {})
            region = location_obj.get("region", {})

            file_path = artifact.get("uri", "")
            if not file_path:
                return None

            # Make path relative to source if needed
            if file_path.startswith("/"):
                try:
                    file_path = str(Path(file_path).relative_to(source_path))
                except ValueError:
                    pass

            location = CodeLocation(
                file=file_path,
                line=region.get("startLine", 1),
                column=region.get("startColumn"),
                end_line=region.get("endLine"),
                end_column=region.get("endColumn"),
                snippet=region.get("snippet", {}).get("text"),
            )

            # Extract tags and determine finding type
            properties = result.get("properties", {})
            tags = properties.get("tags", [])

            finding_type = FindingType.VULNERABILITY
            for tag in tags:
                if tag.lower() in TAG_TO_TYPE:
                    finding_type = TAG_TO_TYPE[tag.lower()]
                    break

            # Extract CWE and other references from rule metadata
            cwe = None
            owasp = None
            references = []

            related_rules = result.get("relatedRuleRules", [])
            if related_rules:
                for related in related_rules:
                    if related.get("id", "").startswith("CWE-"):
                        cwe = related["id"]

            # Extract from properties
            if "cwe" in properties:
                cwe = properties["cwe"]
            if "owasp" in properties:
                owasp = properties["owasp"]
            if "references" in properties:
                references = properties["references"]

            # Build title
            title = self._extract_title(rule_id, message)

            # Build finding
            finding = Finding(
                id=f"codeql-{uuid.uuid4().hex[:8]}",
                rule_id=rule_id,
                type=finding_type,
                severity=severity,
                confidence=0.85,  # CodeQL has high confidence by default
                title=title,
                description=message,
                location=location,
                source="codeql",
                cwe=cwe,
                owasp=owasp,
                references=references,
                tags=tags,
                metadata={
                    "sarif_level": level,
                    "tool_name": tool_name,
                },
            )

            return finding

        except Exception:
            return None

    def _extract_title(self, rule_id: str, message: str) -> str:
        """Extract a short title from rule_id and message."""
        # Use the last part of rule_id as base title
        parts = rule_id.split("/")
        if len(parts) > 1:
            base_title = parts[-1]
        else:
            base_title = rule_id

        # Clean up
        base_title = base_title.replace("-", " ").replace("_", " ")
        base_title = " ".join(
            word.capitalize() for word in base_title.split()
        )

        # If message is short enough, use it directly
        if len(message) <= 80:
            return message

        return base_title

    async def resolve_queries(
        self,
        query_suite: str,
        language: str,
    ) -> list[str]:
        """
        Resolve a query suite to a list of query files.

        Args:
            query_suite: Query suite name.
            language: CodeQL language name.

        Returns:
            List of query file paths.
        """
        cmd = [
            self.codeql_path,
            "resolve",
            "queries",
            query_suite,
        ]

        try:
            returncode, stdout, stderr = await self.run_command(cmd)

            if returncode != 0:
                return []

            # Parse output - one query per line
            return [line.strip() for line in stdout.strip().split("\n") if line.strip()]

        except Exception:
            return []

    async def list_languages(self) -> list[str]:
        """
        List languages supported by the installed CodeQL version.

        Returns:
            List of supported language names.
        """
        cmd = [
            self.codeql_path,
            "resolve",
            "languages",
            "--format=json",
        ]

        try:
            returncode, stdout, stderr = await self.run_command(cmd)

            if returncode != 0:
                return self.supported_languages

            result = json.loads(stdout)
            return [lang.get("name", "").lower() for lang in result]

        except Exception:
            return self.supported_languages


# Register the engine
engine_registry.register(CodeQLEngine())
