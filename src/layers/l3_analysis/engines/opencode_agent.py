"""
OpenCode Agent - AI-powered security code analysis engine.

This engine uses Large Language Models (LLMs) to perform deep security audits,
complementing pattern-based tools like Semgrep and CodeQL with semantic understanding.
"""

import asyncio
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.utils import JSONParseError, robust_json_loads
from src.layers.l3_analysis.engines.base import BaseEngine, engine_registry
from src.layers.l3_analysis.llm.client import LLMClient, LLMError, LLMProvider
from src.layers.l3_analysis.llm.openai_client import OpenAIClient
from src.layers.l3_analysis.llm.ollama_client import OllamaClient
from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    ScanResult,
    SeverityLevel,
)
from src.layers.l3_analysis.prompts.security_audit import (
    SecurityAuditPrompt,
    build_audit_prompt,
)


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
        max_concurrent: int = 3,
        timeout: int = 600,
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
            max_concurrent: Maximum concurrent LLM requests.
            timeout: Total scan timeout in seconds.
            **llm_options: Additional LLM client options.
        """
        super().__init__(timeout=timeout)

        self.max_file_size = max_file_size
        self.max_files = max_files
        self.max_concurrent = max_concurrent

        # Initialize LLM client
        if llm_client:
            self.llm = llm_client
        else:
            self.llm = self._create_llm_client(provider, model, **llm_options)

        # Semaphore for concurrent request limiting
        self._semaphore: asyncio.Semaphore | None = None

        # Token usage tracking
        self._total_tokens = 0

    def _create_llm_client(
        self,
        provider: str,
        model: str | None,
        **options,
    ) -> LLMClient:
        """Create an LLM client based on provider configuration."""
        provider_lower = provider.lower()

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

        # Initialize semaphore for concurrent requests
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

        # Create scan result
        result = self.create_scan_result(
            source_path,
            rules_used=["ai-security-audit"],
        )

        try:
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
                    "files_analyzed": len(target_files),
                    "total_tokens": self._total_tokens,
                    "provider": str(self.llm.provider),
                    "model": self.llm.model,
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
            # Skip files in excluded directories
            files = [
                f for f in files
                if not any(skip in f.parts for skip in SKIP_DIRECTORIES)
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
                # Skip excluded directories
                if any(skip in file_path.parts for skip in SKIP_DIRECTORIES):
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
        """Analyze multiple files concurrently."""
        tasks = []

        for file_path in files:
            task = self._analyze_single_file(
                file_path=file_path,
                source_path=source_path,
                language=language,
                vulnerability_focus=vulnerability_focus,
                context=context,
            )
            tasks.append(task)

        # Execute with concurrency limit
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
        async with self._semaphore:  # Limit concurrency
            try:
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
                enhanced_code = context_builder.build_enhanced_context(
                    source_path=source_path,
                    file_path=relative_path,
                    include_call_chain=True,
                    include_dependencies=True,
                    include_data_flow=True,
                )

                system_prompt, user_prompt = build_audit_prompt(
                    language=language,
                    code=enhanced_code,
                    file_path=relative_path,
                    framework=context.get("framework"),
                    vulnerability_focus=vulnerability_focus,
                    context=context,
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

                return findings

            except LLMError as e:
                # Log error but continue with other files
                import logging
                logging.getLogger(__name__).warning(
                    f"LLM error analyzing {file_path}: {e}"
                )
                return []

            except Exception as e:
                import logging
                logging.getLogger(__name__).error(
                    f"Error analyzing {file_path}: {e}"
                )
                return []

    def _parse_llm_response(
        self,
        response: str,
        file_path: str,
        source_path: Path,
    ) -> list[Finding]:
        """Parse LLM response into Finding objects."""
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

        except JSONParseError:
            # Try to extract findings from unstructured response
            pass

        return findings

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
