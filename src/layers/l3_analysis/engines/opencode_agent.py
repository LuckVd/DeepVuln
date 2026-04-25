"""
OpenCode Agent - AI-powered security code analysis engine.

This engine uses Large Language Models (LLMs) to perform deep security audits,
complementing pattern-based tools like Semgrep and CodeQL with semantic understanding.
"""

import asyncio
import functools
import hashlib
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from src.core.utils import JSONParseError, robust_json_loads
from src.layers.l3_analysis.engines.base import BaseEngine, engine_registry
from src.layers.l3_analysis.llm.client import (
    LLMClient,
    LLMEmptyResponseError,
    LLMError,
    LLMProvider,
    LLMTruncatedResponseError,
)
from src.layers.l3_analysis.llm.ollama_client import OllamaClient
from src.layers.l3_analysis.llm.openai_client import OpenAIClient
from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    ScanResult,
    SeverityLevel,
)
from src.layers.l3_analysis.prompts.security_audit import (
    build_audit_prompt,
)

# Global LLM concurrency manager - shared across all engines
from src.core.llm import get_global_concurrency_manager

# Default models for each provider
DEFAULT_MODELS = {
    LLMProvider.OPENAI: "gpt-4",
    LLMProvider.AZURE: "gpt-4",
    LLMProvider.OLLAMA: "llama2",
    LLMProvider.CUSTOM: "unknown",
}

# Severity mapping from string to enum
SEVERITY_MAP: dict[str, SeverityLevel] = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
}

# File extensions to analyze
ANALYZABLE_EXTENSIONS = {
    ".py", ".java", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php",
    ".cs", ".swift", ".kt", ".scala", ".c", ".cpp", ".cc", ".cxx",
    ".rs", ".lua", ".pl", ".pm", ".r", ".sql",
}

# Directories to skip
SKIP_DIRECTORIES = {
    "node_modules", "venv", ".venv", "env", ".env",
    "__pycache__", ".git", ".svn", ".hg",
    "dist", "build", "target", "out", "bin",
    "vendor", "third_party", "thirdparty",
    ".tox", ".pytest_cache", ".mypy_cache",
    "migrations", "docs", "tests", "test", "spec",
}


# Module-level LRU cache for AST context extraction, keyed by file path + content hash.
_ast_cache_logger = logging.getLogger(__name__)


@functools.lru_cache(maxsize=256)
def _extract_ast_context_cached(file_path_str: str, content_hash: str) -> str | None:
    """Extract AST context for a file, cached by path and content hash.

    Returns the AST prompt section string, or None if extraction fails.
    """
    try:
        from src.layers.l3_analysis.engines.ast_engine.context import (
            ASTContextExtractor,
        )
        from src.layers.l3_analysis.engines.ast_engine.graph import (
            ASTGraphBuilder,
        )

        file_path = Path(file_path_str)
        ast_builder = ASTGraphBuilder()
        ast_graph = ast_builder.build_from_file(file_path)
        ast_extractor = ASTContextExtractor(ast_graph=ast_graph)

        code = file_path.read_text(encoding="utf-8", errors="replace")
        lines = code.split("\n")[:10]
        for line_num, line in enumerate(lines, 1):
            if line.strip():
                ast_ctx = ast_extractor.extract_for_location(
                    file_path=file_path_str,
                    line=line_num,
                    code_snippet=line.strip()[:100],
                )
                if ast_ctx.ast_structure.get("type") != "unknown":
                    return ast_ctx.to_prompt_section()
        return None
    except Exception as e:
        _ast_cache_logger.warning(f"AST context extraction failed for {file_path_str}: {e}")
        return None


class OpenCodeAgent(BaseEngine):
    """
    AI-powered security analysis engine.

    Uses LLMs to perform semantic code analysis for security vulnerabilities.
    Complements pattern-based tools by understanding code context and business logic.
    """

    name = "agent"
    description = "AI-powered deep security audit engine"
    supported_languages = [
        "python", "java", "javascript", "typescript", "go", "ruby", "php",
        "csharp", "swift", "kotlin", "scala", "c", "cpp", "rust",
    ]

    def __init__(
        self,
        llm_client: LLMClient | None = None,
        provider: str = "openai",
        model: str | None = None,
        max_file_size: int = 100000,  # 100KB max per file
        max_files: int = 50,
        max_concurrent: int | None = None,  # P5-05: None = use global config
        timeout: int = 600,
        cpg_path_provider: Any | None = None,  # P9-01: Optional CPG path provider
        **llm_options,
    ):
        """
        Initialize the OpenCode Agent.

        Args:
            llm_client: Pre-configured LLM client. If None, creates one from env.
            provider: LLM provider ("openai", "azure", "ollama").
            model: Model name. Uses provider default if not specified.
            max_file_size: Maximum file size to analyze (bytes).
            max_files: Maximum number of files to analyze.
            max_concurrent: Maximum concurrent LLM requests. None = use global config.
            timeout: Total scan timeout in seconds.
            **llm_options: Additional LLM client options.
        """
        super().__init__(timeout=timeout)

        self.max_file_size = max_file_size
        self.max_files = max_files

        # P9-01: Optional CPG path provider for attack path analysis
        self.cpg_provider = cpg_path_provider

        # P18: Use provided max_concurrent or default
        # Previously used config.local.toml, now expects explicit configuration
        self.max_concurrent = max_concurrent if max_concurrent is not None else 5

        self.logger = logging.getLogger(__name__)

        # Initialize LLM client
        if llm_client:
            self.llm = llm_client
        else:
            self.llm = self._create_llm_client(provider, model, **llm_options)

        # Token usage tracking
        self._total_tokens = 0
        self._files_failed = 0
        self._files_processed = 0

    def _create_llm_client(
        self,
        provider: str,
        model: str | None,
        **options,
    ) -> LLMClient:
        """Create an LLM client based on provider configuration.

        P18: This method no longer reads from config.local.toml.
        All configuration must be provided via parameters or llm_client.
        """
        provider_lower = provider.lower()

        # Use provided model or fall back to DEFAULT_MODELS
        # Config file reading removed as part of P18 migration

        if provider_lower == "openai":
            return OpenAIClient(
                model=model or DEFAULT_MODELS[LLMProvider.OPENAI],
                max_tokens=options.get("max_tokens", 4096),
                temperature=options.get("temperature", 0.1),
                timeout=options.get("llm_timeout", 120),
                api_key=options.get("api_key"),
                base_url=options.get("base_url"),
            )

        elif provider_lower == "azure":
            return OpenAIClient(
                model=model or DEFAULT_MODELS[LLMProvider.AZURE],
                is_azure=True,
                azure_deployment=options.get("azure_deployment"),
                azure_api_version=options.get("azure_api_version", "2024-02-15-preview"),
                max_tokens=options.get("max_tokens", 4096),
                temperature=options.get("temperature", 0.1),
                timeout=options.get("llm_timeout", 120),
            )

        elif provider_lower == "ollama":
            return OllamaClient(
                model=model or DEFAULT_MODELS[LLMProvider.OLLAMA],
                base_url=options.get("base_url"),
                max_tokens=options.get("max_tokens", 4096),
                temperature=options.get("temperature", 0.1),
                timeout=options.get("llm_timeout", 300),  # Ollama may be slower
            )

        else:
            # Try OpenAI-compatible API
            base_url = options.get("base_url") or os.getenv("LLM_BASE_URL")
            api_key = options.get("api_key") or os.getenv("LLM_API_KEY")

            if base_url:
                return OpenAIClient(
                    model=model or "unknown",
                    base_url=base_url,
                    api_key=api_key,
                    max_tokens=options.get("max_tokens", 4096),
                    temperature=options.get("temperature", 0.1),
                    timeout=options.get("llm_timeout", 120),
                )

            raise ValueError(
                f"Unknown provider '{provider}'. Specify 'openai', 'azure', 'ollama', "
                "or provide base_url for OpenAI-compatible API."
            )

    def is_available(self) -> bool:
        """Check if the agent is available (LLM client is configured)."""
        return self.llm.is_available

    def normalize_language(self, language: str) -> str | None:
        """Normalize language name."""
        lang_map = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "csharp": "csharp",
            "c#": "csharp",
            "cpp": "cpp",
            "c++": "cpp",
            "golang": "go",
        }
        lang_lower = language.lower()
        return lang_map.get(lang_lower, lang_lower)

    async def scan(
        self,
        source_path: Path,
        language: str | None = None,
        files: list[str] | None = None,
        vulnerability_focus: list[str] | None = None,
        severity_filter: list[SeverityLevel] | None = None,
        context: dict[str, Any] | None = None,
        **options,
    ) -> ScanResult:
        """
        Execute an AI-powered security scan.

        Args:
            source_path: Path to the source code.
            language: Programming language (auto-detected if not specified).
            files: Specific files to analyze (analyzes all if not specified).
            vulnerability_focus: Vulnerability types to focus on.
            severity_filter: Only return findings at these severity levels.
            context: Additional context (framework, previous findings, etc.).
            **options: Additional options.

        Returns:
            ScanResult containing all findings.
        """
        # Validate source path
        self.validate_source_path(source_path)

        # Check LLM availability
        if not self.is_available():
            result = self.create_scan_result(source_path, [])
            return self.finalize_scan_result(
                result,
                success=False,
                error_message="LLM client is not available. Configure API key "
                "(OPENAI_API_KEY) or start Ollama server.",
            )

        # Detect language if not specified
        if not language:
            language = self._detect_language(source_path)

        if not language:
            result = self.create_scan_result(source_path, [])
            return self.finalize_scan_result(
                result,
                success=False,
                error_message="Could not detect programming language. "
                "Please specify --language option.",
            )

        # Get global LLM concurrency manager (shared across all engines)
        self._llm_manager = get_global_concurrency_manager()

        # Create scan result
        result = self.create_scan_result(
            source_path,
            rules_used=["ai-security-audit"],
        )

        try:
            # Reset per-scan runtime stats
            self._files_failed = 0
            self._files_processed = 0

            # Find files to analyze
            if files:
                target_files = [
                    source_path / f if not Path(f).is_absolute() else Path(f)
                    for f in files
                ]
            else:
                target_files = self._find_analyzable_files(source_path)

            # Limit number of files
            if len(target_files) > self.max_files:
                target_files = target_files[:self.max_files]

            if not target_files:
                return self.finalize_scan_result(
                    result,
                    success=True,
                    error_message="No analyzable files found.",
                )

            # Analyze files concurrently
            all_findings = await self._analyze_files(
                files=target_files,
                source_path=source_path,
                language=language,
                vulnerability_focus=vulnerability_focus,
                context=context or {},
            )

            # Apply severity filter
            if severity_filter:
                all_findings = [
                    f for f in all_findings
                    if f.severity in severity_filter
                ]

            # Add findings to result
            for finding in all_findings:
                result.add_finding(finding)

            return self.finalize_scan_result(
                result,
                success=True,
                raw_output={
                    # files_analyzed means successful file analyses.
                    "files_analyzed": max(0, self._files_processed - self._files_failed),
                    "total_files": len(target_files),
                    "files_processed": self._files_processed,
                    "files_failed": self._files_failed,
                    "total_tokens": self._total_tokens,
                    "provider": str(self.llm.provider),
                    "model": self.llm.model,
                    "analyzed_file_paths": [str(f.relative_to(source_path)) for f in target_files],
                },
            )

        except LLMError as e:
            return self.finalize_scan_result(
                result,
                success=False,
                error_message=f"LLM error: {e}",
            )
        except Exception as e:
            return self.finalize_scan_result(
                result,
                success=False,
                error_message=f"Scan failed: {e}",
            )

    def _should_skip_file(self, file_path: Path, source_path: Path) -> bool:
        """Check if a file should be skipped based on its relative path.

        Only checks directories within the source project, not parent directories.
        This avoids false positives when the source_path itself contains
        skip directory names (e.g., /opt/target/project).
        """
        try:
            relative_path = file_path.relative_to(source_path)
            # Check each part of the relative path against skip directories
            return any(part in SKIP_DIRECTORIES for part in relative_path.parts)
        except ValueError:
            # file_path is not relative to source_path
            return True

    def _detect_language(self, source_path: Path) -> str | None:
        """Detect the primary programming language of a project."""
        extensions: dict[str, int] = {}

        extension_to_lang = {
            ".py": "python",
            ".java": "java",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp",
            ".swift": "swift",
            ".kt": "kotlin",
            ".scala": "scala",
            ".c": "c",
            ".cpp": "cpp",
            ".rs": "rust",
        }

        for ext, lang in extension_to_lang.items():
            files = list(source_path.rglob(f"*{ext}"))
            # Skip files in excluded directories (only check relative path)
            files = [
                f for f in files
                if not self._should_skip_file(f, source_path)
            ]
            if files:
                extensions[lang] = extensions.get(lang, 0) + len(files)

        if not extensions:
            return None

        return max(extensions, key=extensions.get)

    def _find_analyzable_files(self, source_path: Path) -> list[Path]:
        """Find all analyzable source files in a project."""
        files = []

        for ext in ANALYZABLE_EXTENSIONS:
            for file_path in source_path.rglob(f"*{ext}"):
                # Skip excluded directories (only check relative path)
                if self._should_skip_file(file_path, source_path):
                    continue

                # Check file size
                try:
                    if file_path.stat().st_size > self.max_file_size:
                        continue
                except OSError:
                    continue

                files.append(file_path)

        # Sort by size (analyze smaller files first)
        files.sort(key=lambda f: f.stat().st_size)

        return files

    async def _analyze_files(
        self,
        files: list[Path],
        source_path: Path,
        language: str,
        vulnerability_focus: list[str] | None,
        context: dict[str, Any],
    ) -> list[Finding]:
        """Analyze multiple files concurrently with bounded parallelism."""
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def _bounded_analyze(file_path: Path) -> list[Finding]:
            async with semaphore:
                return await self._analyze_single_file(
                    file_path=file_path,
                    source_path=source_path,
                    language=language,
                    vulnerability_focus=vulnerability_focus,
                    context=context,
                )

        tasks = [_bounded_analyze(fp) for fp in files]

        # Execute with concurrency limit via semaphore
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect all findings
        all_findings = []
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
            # Ignore exceptions (logged in _analyze_single_file)

        return all_findings

    async def _analyze_single_file(
        self,
        file_path: Path,
        source_path: Path,
        language: str,
        vulnerability_focus: list[str] | None,
        context: dict[str, Any],
    ) -> list[Finding]:
        """Analyze a single file using the LLM."""
        # Use global LLM concurrency manager (shared across all engines)
        async with self._llm_manager:  # Global concurrency limit
            try:
                self._files_processed += 1
                # Read file content
                code = file_path.read_text(encoding="utf-8", errors="replace")

                # Skip empty or very small files
                if len(code.strip()) < 20:
                    return []

                # Build prompts with enhanced context
                relative_path = str(file_path.relative_to(source_path))

                # Build enhanced context using ContextBuilder
                from src.layers.l3_analysis.task.context_builder import ContextBuilder
                context_builder = ContextBuilder()

                # Extract function names from file for per-function call chain analysis
                func_names = self._extract_function_names(code)

                # Build base enhanced context (file-level, no function filter)
                enhanced_code = context_builder.build_enhanced_context(
                    source_path=source_path,
                    file_path=relative_path,
                    function_name=None,  # File-level analysis
                    include_call_chain=False,  # We handle this per-function below
                    include_dependencies=True,
                    include_data_flow=False,  # Also requires function_name
                )

                # Append per-function call chain analysis
                for fname in func_names:
                    chain = context_builder.analyze_call_chain(
                        source_path=source_path,
                        file_path=relative_path,
                        function_name=fname,
                    )
                    if chain and chain.callers:
                        enhanced_code += "\n\n" + context_builder._format_call_chain(chain)

                # P8-06: Extract AST context for enhanced AI understanding (LRU cached)
                ast_context_str = None
                try:
                    content_hash = hashlib.sha256(
                        file_path.read_bytes()
                    ).hexdigest()[:16]
                    ast_context_str = _extract_ast_context_cached(
                        str(file_path), content_hash
                    )
                except Exception as e:
                    self.logger.debug(f"AST context cache lookup failed: {e}")

                # P9-01: Extract CPG attack paths (optional enhancement)
                cpg_paths = None
                if self.cpg_provider:
                    try:
                        # Get attack paths from CPG analysis
                        cpg_paths = self.cpg_provider.get_attack_paths(
                            source_path=file_path.parent,
                            sink_pattern="eval|exec|system|subprocess|os\\.system|popen",
                        )
                        if cpg_paths:
                            self.logger.info(
                                f"Found {len(cpg_paths)} CPG attack paths for {file_path}"
                            )
                    except Exception as e:
                        # CPG path analysis is optional - log and continue
                        self.logger.debug(f"CPG path analysis failed: {e}")

                system_prompt, user_prompt = build_audit_prompt(
                    language=language,
                    code=enhanced_code,
                    file_path=relative_path,
                    framework=context.get("framework"),
                    vulnerability_focus=vulnerability_focus,
                    context=context,
                    ast_context=ast_context_str,  # P8-06: Add AST context
                    cpg_paths=cpg_paths,  # P9-01: Add CPG paths
                )

                # Call LLM
                response = await self.llm.complete_with_context(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )

                # Track token usage
                self._total_tokens += response.usage.total_tokens

                # Parse response
                findings = self._parse_llm_response(
                    response=response.content,
                    file_path=relative_path,
                    source_path=source_path,
                )

                # P9-01: Attach CPG path information to findings
                if cpg_paths and findings:
                    for finding in findings:
                        # Match finding to most relevant CPG path
                        matched_path = self._match_finding_to_cpg_path(finding, cpg_paths)
                        if matched_path:
                            # Convert AttackPath to dict format for Finding
                            finding.cpg_path = {
                                "entry_point": matched_path.entry_point,
                                "sink": matched_path.sink,
                                "path": matched_path.path,
                                "confidence": matched_path.confidence,
                                "sanitizers": matched_path.sanitizers,
                                "reaches_sink": matched_path.reaches_sink,
                            }

                # Calibrate severity based on call chain analysis
                findings = self._calibrate_severity(
                    findings, source_path, relative_path
                )

                return findings

            except LLMTruncatedResponseError as e:
                self._files_failed += 1
                # Response was truncated - log detailed info
                self.logger.warning(
                    f"LLM response truncated for {file_path}. "
                    f"Finish reason: {e.finish_reason}, "
                    f"Token usage: {e.token_usage}. "
                    f"Suggestion: {e.suggestion}"
                )
                return []

            except LLMEmptyResponseError as e:
                self._files_failed += 1
                # Empty response - might be temporary
                self.logger.warning(
                    f"LLM returned empty response for {file_path}. "
                    f"Context: {e.context}. "
                    f"Suggestion: {e.suggestion}"
                )
                return []

            except LLMError as e:
                self._files_failed += 1
                # Other LLM errors - log with full context
                self.logger.warning(
                    f"LLM error analyzing {file_path}: {e}. "
                    f"Is retryable: {e.is_retryable}, "
                    f"Context: {e.context}, "
                    f"Suggestion: {e.suggestion}"
                )
                return []

            except Exception as e:
                self._files_failed += 1
                self.logger.error(
                    f"Unexpected error analyzing {file_path}: {type(e).__name__}: {e}"
                )
                return []

    @staticmethod
    def _extract_function_names(code: str) -> list[str]:
        """Extract top-level and class method function names from source code."""
        import re

        names = []
        for match in re.finditer(
            r'(?:^|\n)[ \t]*(?:async\s+)?def\s+(\w+)\s*\(',
            code,
        ):
            name = match.group(1)
            # Skip dunder methods and test helpers
            if not name.startswith('__'):
                names.append(name)

        # Also match JS/TS function declarations and arrow functions
        for match in re.finditer(
            r'(?:^|\n)[ \t]*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(',
            code,
        ):
            names.append(match.group(1))

        return names

    def _calibrate_severity(
        self,
        findings: list[Finding],
        source_path: Path,
        file_path: str,
    ) -> list[Finding]:
        """Calibrate severity based on call chain reachability analysis.

        If a finding claims user_controlled but all callers pass hardcoded
        literals, downgrade severity to LOW and correct the metadata.
        """
        if not findings:
            return findings

        from src.layers.l3_analysis.task.context_builder import (
            ContextBuilder,
            _is_likely_dynamic_arg,
        )

        cb = ContextBuilder()

        # Build a map: func_name -> all_callers_hardcoded
        # by analyzing each function in the file
        hardcoded_funcs: set[str] = set()
        func_names = self._extract_function_names(
            (source_path / file_path).read_text(encoding="utf-8", errors="replace")
        )
        for fname in func_names:
            try:
                chain = cb.analyze_call_chain(
                    source_path=source_path,
                    file_path=file_path,
                    function_name=fname,
                )
            except Exception:
                continue
            if not chain or chain.is_entry_point or not chain.callers:
                continue
            callers_with_expr = [
                c for c in chain.callers if c.get("call_expression")
            ]
            if not callers_with_expr:
                continue
            if all(
                not _is_likely_dynamic_arg(c["call_expression"], fname)
                for c in callers_with_expr
            ):
                hardcoded_funcs.add(fname)

        # If no functions have all-hardcoded callers, nothing to calibrate
        if not hardcoded_funcs:
            return findings

        # Calibrate findings that mention hardcoded-only functions
        for finding in findings:
            if finding.severity not in (
                SeverityLevel.CRITICAL,
                SeverityLevel.HIGH,
                SeverityLevel.MEDIUM,
            ):
                continue
            if not finding.metadata.get("user_controlled"):
                continue

            # Check if finding's title or description mentions a hardcoded func
            finding_text = f"{finding.title} {finding.description}"
            matched_func = None
            for fname in hardcoded_funcs:
                if fname in finding_text:
                    matched_func = fname
                    break
            if not matched_func:
                continue

            original_severity = finding.severity.value
            finding.severity = SeverityLevel.LOW
            finding.metadata["severity_adjustment"] = {
                "original": original_severity,
                "adjusted": "low",
                "reason": (
                    f"All callers of {matched_func}() pass hardcoded literals — "
                    "parameter not user-controlled"
                ),
                "factor": "call_chain_verification",
            }
            finding.metadata["user_controlled"] = False
            finding.confidence = min(finding.confidence, 0.4)
            self.logger.info(
                f"Severity calibrated: {finding.title} "
                f"{original_severity} -> low (all callers hardcoded)"
            )

        return findings

    def _parse_llm_response(
        self,
        response: str,
        file_path: str,
        source_path: Path,
    ) -> list[Finding]:
        """Parse LLM response into Finding objects.

        Also parses suspicious_code section from the response.
        """
        findings = []

        try:
            # Use robust JSON parser to handle GLM-5's unstable JSON format
            data = robust_json_loads(response)

            # Parse findings array
            for item in data.get("findings", []):
                finding = self._convert_to_finding(
                    item=item,
                    file_path=file_path,
                    source_path=source_path,
                )
                if finding:
                    findings.append(finding)

            # Parse suspicious_code array - these are lower confidence findings
            # that need manual review or further verification
            for item in data.get("suspicious_code", []):
                finding = self._convert_suspicious_to_finding(
                    item=item,
                    file_path=file_path,
                    source_path=source_path,
                )
                if finding:
                    findings.append(finding)
                    self.logger.info(
                        f"Found suspicious code in {file_path}: "
                        f"{item.get('why_suspicious', 'unknown')}"
                    )

        except JSONParseError as e:
            # Log detailed error for debugging
            response_preview = response[:500] + "..." if len(response) > 500 else response
            self.logger.warning(
                f"Failed to parse LLM response as JSON for {file_path}. "
                f"Error: {e}. Response preview: {response_preview}"
            )
        except Exception as e:
            self.logger.error(
                f"Unexpected error parsing LLM response for {file_path}: "
                f"{type(e).__name__}: {e}"
            )

        return findings

    def _convert_suspicious_to_finding(
        self,
        item: dict[str, Any],
        file_path: str,
        source_path: Path,
    ) -> Finding | None:
        """Convert a suspicious_code item to a Finding object.

        Suspicious code findings have lower confidence and are marked
        for manual review.
        """
        try:
            # Parse location (format: "file.py:45" or just line number)
            location_str = item.get("location", f"{file_path}:1")
            if ":" in location_str:
                parts = location_str.rsplit(":", 1)
                loc_file = parts[0] if parts[0] else file_path
                try:
                    line = int(parts[1])
                except ValueError:
                    line = 1
            else:
                loc_file = file_path
                try:
                    line = int(location_str)
                except ValueError:
                    line = 1

            # Create location
            location = CodeLocation(
                file=loc_file,
                line=line,
                end_line=line,
                snippet=item.get("code_snippet"),
            )

            # Map vulnerability type
            vuln_type = item.get("potential_vulnerability", "suspicious")
            why_suspicious = item.get("why_suspicious", "Suspicious code pattern detected")

            # Build title - prefix with [Suspicious] to indicate needs review
            title = f"[Suspicious] {why_suspicious[:80]}"

            # Build finding with LOW severity for suspicious code
            finding = Finding(
                id=f"suspicious-{uuid.uuid4().hex[:8]}",
                rule_id=f"suspicious_{vuln_type}",
                type=FindingType.VULNERABILITY,
                severity=SeverityLevel.LOW,  # Suspicious code is always LOW
                confidence=float(item.get("confidence", 0.3)),
                title=title,
                description=why_suspicious,
                fix_suggestion=item.get("recommended_action"),
                location=location,
                source="agent",
                cwe=None,
                owasp=None,
                metadata={
                    "is_suspicious": True,
                    "potential_vulnerability": vuln_type,
                    "recommended_action": item.get("recommended_action"),
                },
            )

            return finding

        except Exception as e:
            self.logger.debug(f"Failed to parse suspicious code item: {e}")
            return None

    def _convert_to_finding(
        self,
        item: dict[str, Any],
        file_path: str,
        source_path: Path,
    ) -> Finding | None:
        """Convert a parsed finding dict to a Finding object."""
        try:
            # Extract severity
            severity_str = item.get("severity", "medium").lower()
            severity = SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)

            # Extract line numbers
            line = item.get("line", 1)
            end_line = item.get("end_line") or line

            # Create location
            location = CodeLocation(
                file=file_path,
                line=line,
                end_line=end_line,
                snippet=item.get("code_snippet"),
            )

            # Map vulnerability type
            vuln_type = item.get("type", "unknown")
            cwe = item.get("cwe")
            owasp = item.get("owasp")

            # Build title
            title = item.get("title", "Security Issue")
            description = item.get("description", "")

            # Build finding
            finding = Finding(
                id=f"agent-{uuid.uuid4().hex[:8]}",
                rule_id=vuln_type,
                type=FindingType.VULNERABILITY,
                severity=severity,
                confidence=float(item.get("confidence", 0.7)),
                title=title,
                description=description,
                fix_suggestion=item.get("recommendation"),
                location=location,
                source="agent",
                cwe=cwe,
                owasp=owasp,
                metadata={
                    "dataflow": item.get("dataflow"),
                    "security_score": item.get("security_score"),
                    # New exploitability fields
                    "attack_surface": item.get("attack_surface"),
                    "user_controlled": item.get("user_controlled"),
                    "exploitation_conditions": item.get("exploitation_conditions"),
                },
            )

            return finding

        except Exception:
            return None

    def _match_finding_to_cpg_path(
        self,
        finding: Finding,
        cpg_paths: list[Any],
    ) -> Any | None:
        """
        Match a finding to the most relevant CPG attack path.

        Args:
            finding: The Finding object
            cpg_paths: List of AttackPath objects

        Returns:
            Best matching AttackPath or None
        """
        if not cpg_paths:
            return None

        # Find paths that match the finding's line number
        finding_line = finding.location.line
        best_path = None
        best_score = -1

        for path in cpg_paths:
            # Check if any node in the path matches the finding line
            line_match_score = 0
            for node_id in path.path:
                # Extract line number from node ID
                # Format: "cpg:ast:file:line:type" or "cpg:call:file:line:type"
                parts = node_id.split(":")
                if len(parts) >= 3:
                    try:
                        node_line = int(parts[2])
                        # Higher score for exact line match
                        if node_line == finding_line:
                            line_match_score += 10
                        # Partial score for nearby lines
                        elif abs(node_line - finding_line) <= 5:
                            line_match_score += max(5 - abs(node_line - finding_line), 1)
                    except (ValueError, IndexError):
                        pass

            # Combine with path confidence
            combined_score = line_match_score + (path.confidence * 5)

            if combined_score > best_score:
                best_score = combined_score
                best_path = path

        return best_path

    async def analyze_code_snippet(
        self,
        code: str,
        language: str,
        file_path: str = "snippet",
        context: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """
        Analyze a code snippet directly.

        Args:
            code: Code to analyze.
            language: Programming language.
            file_path: Virtual file path for context.
            context: Additional context.

        Returns:
            List of findings.
        """
        if not self.is_available():
            return []

        system_prompt, user_prompt = build_audit_prompt(
            language=language,
            code=code,
            file_path=file_path,
            context=context,
            cpg_paths=None,  # CPG paths not supported for snippet analysis
        )

        try:
            response = await self.llm.complete_with_context(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )

            self._total_tokens += response.usage.total_tokens

            return self._parse_llm_response(
                response=response.content,
                file_path=file_path,
                source_path=Path("."),
            )

        except LLMError:
            return []

    def get_token_usage(self) -> int:
        """Get total tokens used across all analyses."""
        return self._total_tokens


# Register the engine
engine_registry.register(OpenCodeAgent())
