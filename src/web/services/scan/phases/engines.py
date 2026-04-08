"""Engine scanning phase.

This phase runs multiple scanning engines in parallel.
"""

from pathlib import Path
from typing import Any
import asyncio
import logging


from .base import ScanPhase, PhaseResult

logger = logging.getLogger(__name__)


class EngineScanPhase(ScanPhase):
    """Engine scanning phase (L2/L3).

    This phase runs multiple scanning engines (Semgrep, CodeQL, Agent) in parallel.
    """

    def __init__(self, engines: list[str] | None = None):
        """Initialize engine scan phase.

        Args:
            engines: List of engines to run (default: ["semgrep", "codeql", "agent"])
        """
        super().__init__(
            name="L2_L3_engines",
            description="Parallel Engine Scan",
        )
        self.engines = engines or ["semgrep", "codeql", "agent"]

    async def execute(
        self,
        context: "ScanContext",  # noqa: F821
    ) -> PhaseResult:
        """Execute engine scanning phase.

        Args:
            context: Scan context

        Returns:
            Phase result with all findings from engines
        """
        all_findings: list[dict[str, Any]] = []
        tasks = []
        total_tokens = 0

        # Get data from preparation phase
        primary_lang = context.data.get("primary_language", "python")  # type: ignore
        all_languages = context.data.get("all_languages", [primary_lang])  # type: ignore

        # Prepare LLM client for Agent engine
        llm_client = None
        if "agent" in self.engines and context.config.model:
            try:
                from src.core.config import get_llm_config, get_openai_config
                from src.layers.l3_analysis.llm.openai_client import OpenAIClient

                llm_config = get_llm_config()
                openai_config = get_openai_config()
                llm_client = OpenAIClient(
                    model=context.config.model,
                    api_key=openai_config.get("api_key"),
                    base_url=openai_config.get("base_url"),
                    max_tokens=llm_config.get("max_tokens", 4096),
                )
            except Exception as e:
                logger.warning(f"Failed to initialize LLM client for agent: {e}")
                self.engines = [e for e in self.engines if e != "agent"]

        # Create engine tasks
        for engine_name in self.engines:
            if engine_name == "semgrep":
                tasks.append(self._run_semgrep(context, primary_lang))
            elif engine_name == "codeql":
                tasks.append(self._run_codeql(context, all_languages))
            elif engine_name == "agent":
                tasks.append(self._run_agent(context, primary_lang, llm_client))

        # Run engines in parallel
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for engine_name, result in zip(self.engines, results):
                if isinstance(result, Exception):
                    logger.error(f"{engine_name} engine failed: {result}")
                    continue

                if result and result.findings:
                    engine_findings = self._convert_findings(result.findings, engine_name)
                    all_findings.extend(engine_findings)
                    total_tokens += result.tokens_used or 0

                    logger.info(f"{engine_name.capitalize()}: {len(engine_findings)} findings")

        # Update context
        for finding in all_findings:
            await context.add_finding(finding)

        return PhaseResult(
            success=True,
            findings=all_findings,
            tokens_used=total_tokens,
        )

    async def _run_semgrep(
        self,
        context: "ScanContext",  # noqa: F821
        primary_lang: str,
    ):
        """Run Semgrep engine.

        Args:
            context: Scan context
            primary_lang: Primary language

        Returns:
            Scan result with findings
        """
        from src.layers.l3_analysis.engines.semgrep import SemgrepEngine

        engine = SemgrepEngine()
        if not engine.is_available():
            logger.warning("Semgrep not available")
            return None

        return await engine.scan(
            source_path=context.source_path,
            language=primary_lang.lower(),
        )

    async def _run_codeql(
        self,
        context: "ScanContext",  # noqa: F821
        all_languages: list[str],
    ):
        """Run CodeQL engine.

        Args:
            context: Scan context
            all_languages: List of detected languages

        Returns:
            Scan result with findings
        """
        from src.layers.l3_analysis.engines.codeql import CodeQLEngine

        engine = CodeQLEngine()
        if not engine.is_available():
            logger.warning("CodeQL not available")
            return None

        # Check if we need multi-language support
        codeql_langs = {
            "java", "python", "go", "javascript", "typescript",
            "c", "cpp", "csharp", "ruby", "swift",
        }
        detected = [lang.lower() for lang in all_languages if lang.lower() in codeql_langs]

        if len(detected) > 1:
            # Multi-language scan
            return await engine.scan_multi_language(
                source_path=context.source_path,
                languages=detected,
            )
        else:
            # Single language scan
            lang = detected[0] if detected else "python"
            return await engine.scan(
                source_path=context.source_path,
                language=lang,
            )

    async def _run_agent(
        self,
        context: "ScanContext",  # noqa: F821
        primary_lang: str,
        llm_client,
    ):
        """Run Agent engine.

        Args:
            context: Scan context
            primary_lang: Primary language
            llm_client: LLM client

        Returns:
            Scan result with findings
        """
        from src.layers.l3_analysis.engines.opencode_agent import OpenCodeAgent

        if not llm_client:
            logger.warning("Agent requires LLM client")
            return None

        agent = OpenCodeAgent(
            llm_client=llm_client,
            language=primary_lang.lower(),
            max_files=context.config.agent_max_files,
        )

        if not agent.is_available():
            logger.warning("Agent not available")
            return None

        return await agent.scan(
            source_path=context.source_path,
            vulnerability_focus=[
                "sql_injection",
                "xss",
                "command_injection",
                "path_traversal",
                "ssrf",
                "hardcoded_secrets",
                "crypto_weakness",
                "auth_bypass",
            ],
        )

    def _convert_findings(
        self,
        findings: list[Any] | None,
        engine: str,
    ) -> list[dict[str, Any]]:
        """Convert engine findings to standard format.

        Args:
            findings: Engine-specific findings
            engine: Engine name

        Returns:
            Standardized finding dictionaries
        """
        if not findings:
            return []

        result = []
        for f in findings:
            # Handle different finding formats
            if hasattr(f, "model_dump"):
                finding_dict = f.model_dump()
            elif hasattr(f, "dict"):
                finding_dict = f.dict()
            elif isinstance(f, dict):
                finding_dict = f
            else:
                # Extract basic attributes
                finding_dict = {
                    "file_path": getattr(f, "file_path", ""),
                    "line_start": getattr(f, "line_start", 0),
                    "severity": getattr(f, "severity", "medium"),
                    "vuln_type": getattr(f, "vuln_type", "unknown"),
                    "title": getattr(f, "title", "Untitled"),
                    "description": getattr(f, "description", ""),
                }

            finding_dict["engine"] = engine
            result.append(finding_dict)

        return result
