"""
CodeQL Engine - GitHub CodeQL integration for deep dataflow analysis.

CodeQL is a powerful code analysis engine that enables deep dataflow analysis
to find complex vulnerabilities that pattern matching might miss.
"""

import asyncio
import json
import os
import shutil
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.markup import escape

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.base import BaseEngine, engine_registry
from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    ScanResult,
    SeverityLevel,
)

logger = get_logger(__name__)


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
        auto_download_packs: bool = True,
    ):
        """
        Initialize the CodeQL engine.

        Args:
            codeql_path: Path to codeql binary (default: looks in PATH).
            timeout: Maximum scan duration in seconds.
            max_memory_mb: Maximum memory usage in MB.
            search_path: Additional paths to search for CodeQL packs.
            auto_download_packs: Whether to automatically download missing packs.
        """
        super().__init__(timeout=timeout, max_memory_mb=max_memory_mb)
        self.codeql_path = codeql_path
        self.search_path = search_path
        self.auto_download_packs = auto_download_packs
        self._version: str | None = None
        self._available_packs: dict[str, bool] = {}  # Cache for pack availability
        self._packs_checked: bool = False

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
        skip_build: bool = False,
        build_command: str | None = None,
        llm_client: Any = None,
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
            skip_build: Whether to skip the build step (use --no-build).
            build_command: Custom build command to use (overrides auto-detection).
            llm_client: LLM client for build diagnostics.
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
            # Phase 0: Build project (if required)
            build_diagnostic = None
            if not skip_build:
                build_result = await self._execute_build(
                    source_path=source_path,
                    language=codeql_lang,
                    build_command=build_command,
                    llm_client=llm_client,
                )
                if build_result and not build_result.get("success", True):
                    build_diagnostic = build_result.get("diagnostic")
                    # Log build failure but continue with database creation
                    # CodeQL might still work with partial build
                    logger.warning(
                        f"Build completed with issues. Build diagnostic: "
                        f"{build_diagnostic.to_dict() if build_diagnostic else 'None'}"
                    )

            # Phase 1: Create database
            db_success = await self._create_database(
                source_path=source_path,
                database_path=database_path,
                language=codeql_lang,
                overwrite=overwrite_database,
                skip_build=skip_build,
            )

            if not db_success:
                error_msg = "Failed to create CodeQL database. "
                if build_diagnostic:
                    error_msg += f"Build diagnostic: {build_diagnostic.root_cause}. "
                    if build_diagnostic.suggestions:
                        error_msg += f"Suggestions: {'; '.join(build_diagnostic.suggestions[:3])}"
                else:
                    error_msg += "Check if the project can be built successfully."
                return self.finalize_scan_result(
                    result,
                    success=False,
                    error_message=error_msg,
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

    async def scan_multi_language(
        self,
        source_path: Path,
        languages: list[str] | None = None,
        min_file_percentage: float = 10.0,
        **options,
    ) -> ScanResult:
        """
        Scan a multi-language project by analyzing each language separately.

        This method detects all languages in the project and creates separate
        CodeQL databases for each, combining the results.

        Args:
            source_path: Path to the source code.
            languages: Specific languages to scan (auto-detected if not specified).
            min_file_percentage: Minimum percentage for a language to be included.
            **options: Additional options passed to scan().

        Returns:
            Combined ScanResult from all language scans.
        """
        self.validate_source_path(source_path)

        # Check if CodeQL is available
        if not self.is_available():
            result = self.create_scan_result(source_path, [])
            return self.finalize_scan_result(
                result,
                success=False,
                error_message="CodeQL CLI is not installed or not in PATH.",
            )

        # Detect languages if not specified
        if not languages:
            detected = await self.detect_all_languages(source_path, min_file_percentage)
            languages = [lang for lang, count, pct in detected]

        if not languages:
            result = self.create_scan_result(source_path, [])
            return self.finalize_scan_result(
                result,
                success=False,
                error_message="No supported languages detected in the project.",
            )

        logger.info(f"Multi-language scan: detected languages: {languages}")

        # Create combined result
        combined_result = self.create_scan_result(source_path, [])
        successful_scans = 0
        failed_languages = []

        for language in languages:
            codeql_lang = self.normalize_language(language)
            if not codeql_lang:
                logger.warning(f"Language '{language}' is not supported by CodeQL, skipping.")
                continue

            logger.info(f"Scanning language: {language} (CodeQL: {codeql_lang})")

            # Find subdirectories for this language
            subdirs = self._find_language_subdirectories(source_path, codeql_lang)

            # Scan each subdirectory
            for subdir in subdirs:
                try:
                    # Create a separate database for this language/subdirectory
                    result = await self.scan(
                        source_path=subdir,
                        language=codeql_lang,
                        **options,
                    )

                    if result.success:
                        successful_scans += 1
                        # Combine findings
                        for finding in result.findings:
                            combined_result.add_finding(finding)
                    else:
                        logger.warning(
                            f"Scan failed for {language} in {subdir.name}: "
                            f"{escape(str(result.error_message))}"
                        )

                except Exception as e:
                    logger.error(
                        f"Exception scanning {language} in {subdir.name}: {escape(str(e))}"
                    )
                    failed_languages.append(f"{language} ({subdir.name})")

        # Determine overall success
        if successful_scans > 0:
            combined_result.success = True
            if failed_languages:
                combined_result.error_message = (
                    f"Partial success: {successful_scans} language(s) scanned, "
                    f"failed: {', '.join(failed_languages)}"
                )
        else:
            combined_result.success = False
            combined_result.error_message = (
                f"All language scans failed. Languages attempted: {', '.join(languages)}"
            )

        return self.finalize_scan_result(
            combined_result,
            success=combined_result.success,
            error_message=combined_result.error_message,
        )

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

    async def detect_all_languages(
        self,
        source_path: Path,
        min_file_percentage: float = 5.0,
    ) -> list[tuple[str, int, float]]:
        """
        Detect all programming languages in a project.

        Args:
            source_path: Path to the source code.
            min_file_percentage: Minimum percentage of files to include a language.

        Returns:
            List of (language, file_count, percentage) tuples, sorted by file count.
        """
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

        # Count files by language
        lang_counts: dict[str, int] = {}
        total_files = 0

        for ext in extension_to_lang:
            files = list(source_path.rglob(f"*{ext}"))
            if files:
                lang = extension_to_lang[ext]
                lang_counts[lang] = lang_counts.get(lang, 0) + len(files)
                total_files += len(files)

        if not lang_counts:
            return []

        # Calculate percentages and filter
        result = []
        for lang, count in lang_counts.items():
            percentage = (count / total_files) * 100
            if percentage >= min_file_percentage:
                result.append((lang, count, percentage))

        # Sort by file count descending
        result.sort(key=lambda x: x[1], reverse=True)
        return result

    async def is_multi_language_project(
        self,
        source_path: Path,
        min_secondary_percentage: float = 10.0,
    ) -> bool:
        """
        Check if a project contains multiple significant languages.

        Args:
            source_path: Path to the source code.
            min_secondary_percentage: Minimum percentage for a secondary language.

        Returns:
            True if the project has multiple significant languages.
        """
        languages = await self.detect_all_languages(source_path)
        significant_languages = [
            lang for lang, count, pct in languages
            if pct >= min_secondary_percentage
        ]
        return len(significant_languages) > 1

    def _find_language_subdirectories(
        self,
        source_path: Path,
        language: str,
    ) -> list[Path]:
        """
        Find subdirectories that primarily contain a specific language.

        Args:
            source_path: Root source path.
            language: Target language to find.

        Returns:
            List of paths to subdirectories containing the language.
        """
        extension_to_lang = {
            "java": [".java"],
            "python": [".py"],
            "go": [".go"],
            "javascript": [".js", ".jsx"],
            "typescript": [".ts", ".tsx"],
            "cpp": [".c", ".cpp", ".cc", ".cxx"],
            "csharp": [".cs"],
            "ruby": [".rb"],
            "swift": [".swift"],
        }

        extensions = extension_to_lang.get(language, [])
        if not extensions:
            return [source_path]

        # Common directory patterns for different project types
        subdir_patterns = [
            "src", "lib", "app", "backend", "frontend", "server", "client",
            "api", "web", "core", "main", "pkg", "cmd",
        ]

        result_dirs = []

        # Check immediate subdirectories
        for subdir in source_path.iterdir():
            if not subdir.is_dir():
                continue
            if subdir.name.startswith("."):
                continue

            # Count files of target language in this subdirectory
            lang_file_count = 0
            for ext in extensions:
                lang_file_count += len(list(subdir.rglob(f"*{ext}")))

            if lang_file_count > 0:
                result_dirs.append(subdir)

        # If no subdirectories found, use the source path itself
        if not result_dirs:
            return [source_path]

        return result_dirs

    async def _execute_build(
        self,
        source_path: Path,
        language: str,
        build_command: str | None = None,
        llm_client: Any = None,
    ) -> dict[str, Any] | None:
        """Execute build before CodeQL database creation.

        Args:
            source_path: Path to the source code.
            language: Programming language.
            build_command: Custom build command (overrides auto-detection).
            llm_client: LLM client for build diagnostics.

        Returns:
            Dict with build result and diagnostic info, or None if build skipped.
        """
        from src.layers.l3_analysis.build import (
            BuildExecutor,
            BuildSystemDetector,
            diagnose_build_failure,
        )

        # Detect build system
        detector = BuildSystemDetector()
        config = detector.detect(source_path, language)

        # Override build command if provided
        if build_command:
            config.build_command = build_command

        # Skip if no build required or no build command
        if not config.requires_build or not config.build_command:
            logger.info(f"No build required for language: {language}")
            return {"success": True, "skipped": True, "reason": "No build required"}

        # Execute build
        logger.info(
            f"Executing build for {language}. "
            f"Build system: {config.build_system.value}, "
            f"Command: {config.build_command}"
        )

        executor = BuildExecutor(timeout=self.timeout)
        result = await executor.execute(config, source_path)

        # If build failed, try to diagnose
        if not result.success and not result.skipped:
            diagnostic = diagnose_build_failure(
                result=result,
                config=config,
                source_path=source_path,
                llm_client=llm_client,
            )
            return {
                "success": False,
                "result": result,
                "diagnostic": diagnostic,
            }

        return {
            "success": True,
            "result": result,
            "diagnostic": None,
        }

    async def _create_database(
        self,
        source_path: Path,
        database_path: Path,
        language: str,
        overwrite: bool = True,
        skip_build: bool = False,
    ) -> bool:
        """
        Create a CodeQL database from source code.

        Args:
            source_path: Path to the source code.
            database_path: Path where the database will be created.
            language: CodeQL language name.
            overwrite: Whether to overwrite existing database.
            skip_build: Whether to skip the build step (--no-build).

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

        # Handle build mode
        if skip_build:
            # For languages that support --build-mode=none (C#), use it
            # For others, use --command with a no-op command
            if language == "csharp":
                cmd.append("--build-mode=none")
                logger.info("Using --build-mode=none (build step will be skipped)")
            else:
                # Use a no-op command for Go, Java, etc.
                cmd.extend(["--command", "echo 'Skipping build'"])
                logger.info("Using no-op build command (build step will be skipped)")

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
                logger.info(f"CodeQL database created successfully: {database_path}")
                return True

            # Log detailed error for debugging
            error_context = {
                "language": language,
                "source_path": str(source_path),
                "database_path": str(database_path),
                "return_code": returncode,
            }

            # Parse common error patterns and provide suggestions
            suggestion = None
            if stderr:
                stderr_lower = stderr.lower()
                if "no code could be extracted" in stderr_lower:
                    suggestion = "No extractable code found. Check if the language is correct and source files exist."
                elif "out of memory" in stderr_lower:
                    suggestion = "CodeQL ran out of memory. Try increasing max_memory_mb or reducing source size."
                elif "timeout" in stderr_lower:
                    suggestion = "Database creation timed out. Try increasing timeout or reducing source size."
                elif "unsupported language" in stderr_lower:
                    suggestion = f"Language '{language}' is not supported. Check CodeQL version and extractors."
                elif "permission denied" in stderr_lower:
                    suggestion = "Permission denied. Check file permissions and database path."

            logger.warning(
                f"CodeQL database creation failed. "
                f"Command: {escape(' '.join(cmd))}. "
                f"Return code: {returncode}. "
                f"Stderr: {escape(stderr[:1000] if stderr else 'None')}. "
                f"Context: {error_context}. "
                f"Suggestion: {suggestion or 'Check CodeQL logs for details.'}"
            )
            return False

        except Exception as e:
            logger.error(
                f"CodeQL database creation exception: {type(e).__name__}: {escape(str(e))}. "
                f"Language: {language}, Source: {source_path}"
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
                # Build error context
                error_context = {
                    "language": language,
                    "database_path": str(database_path),
                    "query_suite": query_suite,
                    "return_code": returncode,
                }

                # Parse common error patterns and provide suggestions
                suggestion = None
                if stderr:
                    stderr_lower = stderr.lower()
                    if "no queries found" in stderr_lower:
                        suggestion = f"No queries found for language '{language}'. Try downloading the query pack: codeql pack download {DEFAULT_QUERY_PACKS.get(language, 'codeql/<lang>-queries')}"
                    elif "database not found" in stderr_lower or "does not exist" in stderr_lower:
                        suggestion = "Database does not exist. Database creation may have failed."
                    elif "out of memory" in stderr_lower:
                        suggestion = "CodeQL ran out of memory during analysis. Try increasing max_memory_mb."
                    elif "timeout" in stderr_lower:
                        suggestion = "Analysis timed out. Try increasing timeout."

                logger.warning(
                    f"CodeQL analysis failed. "
                    f"Command: {escape(' '.join(cmd))}. "
                    f"Return code: {returncode}. "
                    f"Stderr: {escape(stderr[:1000] if stderr else 'None')}. "
                    f"Context: {error_context}. "
                    f"Suggestion: {suggestion or 'Check CodeQL logs for details.'}"
                )
                return None

            # Read and parse SARIF output
            if sarif_path.exists():
                with open(sarif_path, "r", encoding="utf-8") as f:
                    return json.load(f)

            logger.warning(f"SARIF output file not found: {sarif_path}")
            return None

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse SARIF output: {escape(str(e))}")
            return None
        except Exception as e:
            logger.error(
                f"CodeQL analysis exception: {type(e).__name__}: {escape(str(e))}. "
                f"Language: {language}, Database: {database_path}"
            )
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
        # Check cache first
        if pack_name in self._available_packs:
            return self._available_packs[pack_name]

        # Check if pack is already installed
        if await self._is_pack_installed(pack_name):
            self._available_packs[pack_name] = True
            return True

        # Auto-download if enabled
        if not self.auto_download_packs:
            logger.warning(
                f"Query pack '{pack_name}' is not installed and auto-download is disabled. "
                f"Run 'codeql pack download {pack_name}' manually."
            )
            self._available_packs[pack_name] = False
            return False

        logger.info(f"Downloading CodeQL query pack: {pack_name}")
        cmd = [
            self.codeql_path,
            "pack",
            "download",
            pack_name,
        ]

        try:
            returncode, stdout, stderr = await self.run_command(cmd)
            success = returncode == 0
            if success:
                logger.info(f"Successfully downloaded query pack: {pack_name}")
            else:
                logger.warning(
                    f"Failed to download query pack '{pack_name}': {stderr}"
                )
            self._available_packs[pack_name] = success
            return success
        except Exception as e:
            logger.error(f"Error downloading query pack '{pack_name}': {e}")
            self._available_packs[pack_name] = False
            return False

    async def _is_pack_installed(self, pack_name: str) -> bool:
        """
        Check if a query pack is already installed.

        Args:
            pack_name: Name of the query pack.

        Returns:
            True if pack is installed.
        """
        # Check default CodeQL pack installation location
        pack_base = Path.home() / ".codeql" / "packages"
        pack_dir = pack_base / pack_name.replace("/", os.sep if 'os' in dir() else "/")

        if pack_dir.exists():
            # Look for versioned directory
            versions = list(pack_dir.glob("*/"))
            return len(versions) > 0

        return False

    async def ensure_all_packs_for_language(self, language: str) -> bool:
        """
        Ensure all required packs for a language are downloaded.

        Args:
            language: CodeQL language name.

        Returns:
            True if all packs are available.
        """
        pack_name = DEFAULT_QUERY_PACKS.get(language)
        if not pack_name:
            logger.warning(f"No query pack defined for language: {language}")
            return False

        return await self._ensure_query_pack(pack_name)

    async def preload_common_packs(self) -> dict[str, bool]:
        """
        Pre-download commonly used query packs.

        Returns:
            Dict mapping pack names to download success status.
        """
        results = {}
        common_languages = ["python", "javascript", "java", "go"]

        logger.info("Preloading common CodeQL query packs...")

        for lang in common_languages:
            pack_name = DEFAULT_QUERY_PACKS.get(lang)
            if pack_name:
                success = await self._ensure_query_pack(pack_name)
                results[pack_name] = success

        successful = sum(1 for v in results.values() if v)
        total = len(results)
        logger.info(f"Preloaded {successful}/{total} CodeQL query packs")

        return results

    def get_pack_status(self) -> dict[str, bool]:
        """
        Get the cached status of query packs.

        Returns:
            Dict mapping pack names to availability status.
        """
        return self._available_packs.copy()

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
