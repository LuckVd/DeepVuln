"""
CodeQL Readiness Gate - Enhanced readiness checking with LLM decision.

This module provides intelligent readiness checking for CodeQL scanning,
integrating LLM language decision, build profiling, and tool compatibility.
"""

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.build import (
    BuildTarget,
    BuildTargetExtractor,
    ModuleDiscovery,
    MonorepoInfo,
    ReadinessReport,
    ToolResolver,
    ToolType,
    VersionDetector,
    VersionRequirement,
    extract_build_targets,
    generate_readiness_report,
)
from src.layers.l3_analysis.decision import (
    CodeQLLanguageDecider,
    DecisionConstraints,
    DecisionError,
    LanguageDecision,
    LanguageDecisionInput,
    LanguageDecisionMetrics,
    LanguageRecommendation,
    LanguageStructure,
    SkippedLanguage,
)
from src.layers.l3_analysis.llm.client import LLMClient

logger = get_logger(__name__)

# Lazy import for builders to avoid circular dependencies
_BuilderRegistry: Any = None


def _get_builder_registry() -> Any:
    """Lazy load builder registry."""
    global _BuilderRegistry
    if _BuilderRegistry is None:
        from src.layers.l3_analysis.build.builders import BuilderRegistry
        _BuilderRegistry = BuilderRegistry
    return _BuilderRegistry


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class ReadinessGateResult:
    """Result of enhanced readiness gate check."""

    # Basic status
    ready: bool = False
    status: str = "not_checked"  # "enabled", "gated", "forced", "error", "not_checked"

    # Language decision
    selected_languages: list[str] = field(default_factory=list)
    skipped_languages: list[SkippedLanguage] = field(default_factory=list)
    decision_source: str = "none"  # "llm", "baseline", "forced", "none"

    # Decision metrics
    decision_metrics: LanguageDecisionMetrics | None = field(
        default=None,
    )

    # Build profile
    modules: list[Any] = field(default_factory=list)  # ModuleSummary list
    build_targets: list[BuildTarget] = field(default_factory=list)
    version_requirement: VersionRequirement | None = None

    # Tool readiness
    tool_report: ReadinessReport | None = None

    # Build analysis (from Builders)
    build_warnings: dict[str, list[str]] = field(default_factory=dict)  # target_name -> warnings
    build_skip_reasons: dict[str, str] = field(default_factory=dict)  # target_name -> skip_reason

    # Reasons
    skip_reasons: dict[str, str] = field(default_factory=list)
    message: str = ""

    # Error info
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "ready": self.ready,
            "status": self.status,
            "selected_languages": self.selected_languages,
            "skipped_languages": [
                {"language": s.language, "reason": s.reason}
                for s in self.skipped_languages
            ],
            "decision_source": self.decision_source,
            "decision_metrics": self.decision_metrics.to_summary_dict() if self.decision_metrics else None,
            "modules_count": len(self.modules),
            "build_targets_count": len(self.build_targets),
            "tool_report": self.tool_report.to_dict() if self.tool_report else None,
            "build_warnings": self.build_warnings,
            "build_skip_reasons": self.build_skip_reasons,
            "skip_reasons": self.skip_reasons,
            "message": self.message,
            "error": self.error,
        }


@dataclass
class BuildReadinessInfo:
    """Build readiness analysis from language-specific builder."""

    target_name: str
    language: str
    buildable: bool
    warnings: list[str] = field(default_factory=list)
    skip_reason: str | None = None
    build_command: str | None = None
    detected_files: list[str] = field(default_factory=list)


# =============================================================================
# CodeQL Readiness Gate
# =============================================================================


class CodeQLReadinessGate:
    """Enhanced readiness gate with LLM decision and build profiling.

    Provides a three-layer decision process:
    1. Basic CodeQL check (availability, language support)
    2. Intelligent decision (LLM language selection, build profiling)
    3. Tool check (tool compatibility and readiness)
    """

    def __init__(
        self,
        project_path: Path,
        llm_client: LLMClient | None = None,
        constraints: DecisionConstraints | None = None,
        startup_timeout: int = 15,
    ):
        """Initialize the readiness gate.

        Args:
            project_path: Root path of the project to analyze.
            llm_client: LLM client for AI decision making.
            constraints: Decision constraints configuration.
            startup_timeout: Timeout for basic CodeQL checks.
        """
        self.project_path = project_path
        self.llm_client = llm_client
        self.constraints = constraints or DecisionConstraints()
        self.startup_timeout = startup_timeout

        # Sub-components (lazy initialization)
        self._decider: CodeQLLanguageDecider | None = None
        self._module_discovery: ModuleDiscovery | None = None
        self._version_detector: VersionDetector | None = None
        self._tool_resolver: ToolResolver | None = None

    @property
    def decider(self) -> CodeQLLanguageDecider:
        """Get or create the language decider."""
        if self._decider is None:
            self._decider = CodeQLLanguageDecider(
                llm_client=self.llm_client,
                project_path=self.project_path,
                constraints=self.constraints,
            )
        return self._decider

    @property
    def module_discovery(self) -> ModuleDiscovery:
        """Get or create the module discovery."""
        if self._module_discovery is None:
            self._module_discovery = ModuleDiscovery(self.project_path)
        return self._module_discovery

    @property
    def version_detector(self) -> VersionDetector:
        """Get or create the version detector."""
        if self._version_detector is None:
            self._version_detector = VersionDetector(self.project_path)
        return self._version_detector

    @property
    def tool_resolver(self) -> ToolResolver:
        """Get or create the tool resolver."""
        if self._tool_resolver is None:
            self._tool_resolver = ToolResolver()
        return self._tool_resolver

    async def check(self, force: bool = False) -> ReadinessGateResult:
        """Run full readiness check.

        Args:
            force: If True, skip LLM decision and tool checks, enable all languages.

        Returns:
            ReadinessGateResult with complete decision information.
        """
        if force:
            return self._create_force_result()

        # Step 1: Basic CodeQL check
        basic_result = await self._basic_check()
        if not basic_result.get("ready", False):
            return self._create_basic_failure_result(basic_result)

        # Step 2: Build profiling
        try:
            monorepo_info = self.module_discovery.discover()
            modules = monorepo_info.modules if monorepo_info else []
            build_targets = extract_build_targets(self.project_path, modules)
            version_req = self.version_detector.detect()
        except Exception as e:
            logger.warning(f"Build profiling failed: {e}")
            modules = []
            build_targets = []
            version_req = VersionRequirement(module_path=self.project_path)

        # Step 2b: Analyze build readiness using language-specific builders
        build_readiness = self._analyze_build_readiness(build_targets)
        build_warnings = {}
        build_skip_reasons = {}

        for info in build_readiness:
            if info.warnings:
                build_warnings[info.target_name] = info.warnings
            if info.skip_reason:
                build_skip_reasons[info.target_name] = info.skip_reason

        # Step 3: Tool readiness
        tool_report = self._check_tools(build_targets, version_req)

        # Step 4: LLM decision (with timing)
        decision_start_time = time.perf_counter()
        decision_result = await self._make_decision(modules, build_targets, tool_report)
        decision_end_time = time.perf_counter()
        decision_time_ms = (decision_end_time - decision_start_time) * 1000

        if isinstance(decision_result, DecisionError):
            # Fallback to baseline
            logger.warning(f"LLM decision failed: {decision_result.error}, using baseline")
            decision_result = self._make_baseline_decision(modules, build_targets)
            decision_source = "baseline"
        else:
            decision_source = decision_result.source if hasattr(decision_result, "source") else "llm"

        # Build final result
        selected = []
        skipped = []
        skip_reasons = {}
        decision_metrics = None

        if isinstance(decision_result, LanguageDecision):
            selected = decision_result.recommended_languages
            # Convert string list to SkippedLanguage objects
            skipped = [
                SkippedLanguage(language=lang, reason=decision_result.skip_reasons.get(lang, ""))
                for lang in decision_result.skipped_languages
            ]
            skip_reasons = decision_result.skip_reasons
            decision_source = decision_result.decision_source

            # Create decision metrics
            decision_metrics = LanguageDecisionMetrics(
                decision_source=decision_source,
                languages_selected=selected,
                languages_skipped=decision_result.skipped_languages,
                decision_time_ms=decision_time_ms,
            )

        return ReadinessGateResult(
            ready=True,
            status="enabled",
            selected_languages=selected,
            skipped_languages=skipped,
            decision_source=decision_source,
            decision_metrics=decision_metrics,
            modules=modules,
            build_targets=build_targets,
            version_requirement=version_req,
            tool_report=tool_report,
            build_warnings=build_warnings,
            build_skip_reasons=build_skip_reasons,
            skip_reasons=skip_reasons,
            message=f"CodeQL ready for {len(selected)} language(s)",
        )

    def _analyze_build_readiness(
        self, build_targets: list[BuildTarget]
    ) -> list[BuildReadinessInfo]:
        """Analyze build readiness using language-specific builders.

        Args:
            build_targets: List of build targets from BuildTargetExtractor.

        Returns:
            List of BuildReadinessInfo for each target.
        """
        results = []

        try:
            registry = _get_builder_registry()
        except Exception as e:
            logger.warning(f"Could not load builder registry: {e}")
            return results

        for target in build_targets:
            try:
                builder = registry.get(target.language)
                if not builder:
                    # No specialized builder for this language
                    results.append(
                        BuildReadinessInfo(
                            target_name=target.name,
                            language=target.language,
                            buildable=True,  # Assume buildable without specialized analysis
                        )
                    )
                    continue

                # Analyze using the builder
                output = builder.analyze(target.path)

                results.append(
                    BuildReadinessInfo(
                        target_name=target.name,
                        language=target.language,
                        buildable=output.is_buildable,
                        warnings=output.warnings,
                        skip_reason=output.skip_reason,
                        build_command=output.build_command,
                        detected_files=output.detected_files,
                    )
                )

                if output.warnings:
                    logger.debug(
                        f"Build warnings for {target.name}: {output.warnings}"
                    )

            except Exception as e:
                logger.warning(f"Builder analysis failed for {target.name}: {e}")
                results.append(
                    BuildReadinessInfo(
                        target_name=target.name,
                        language=target.language,
                        buildable=True,
                        warnings=[f"Builder analysis failed: {e}"],
                    )
                )

        return results

    async def _basic_check(self) -> dict[str, Any]:
        """Run basic CodeQL availability check.

        Returns:
            Dictionary with check results.
        """
        from src.layers.l3_analysis.engines.codeql import CodeQLEngine

        result = {
            "ready": False,
            "reason": None,
            "message": None,
        }

        try:
            engine = CodeQLEngine(auto_download_packs=False)
            readiness = await engine.check_readiness(
                source_path=self.project_path,
                startup_timeout=self.startup_timeout,
            )
            result.update(readiness)
        except Exception as e:
            result["reason"] = "check_error"
            result["message"] = str(e)

        return result

    def _create_force_result(self) -> ReadinessGateResult:
        """Create result for forced mode."""
        # Get all detected languages
        try:
            monorepo_info = self.module_discovery.discover()
            modules = monorepo_info.modules if monorepo_info else []
            all_languages = list(set(m.language for m in modules if m.language))
        except Exception:
            all_languages = []
            modules = []

        decision_metrics = LanguageDecisionMetrics(
            decision_source="forced",
            languages_selected=all_languages,
            languages_skipped=[],
            decision_time_ms=0.0,
        )

        return ReadinessGateResult(
            ready=True,
            status="forced",
            selected_languages=all_languages,
            skipped_languages=[],
            decision_source="forced",
            decision_metrics=decision_metrics,
            modules=modules,
            build_targets=[],
            version_requirement=None,
            tool_report=None,
            skip_reasons={},
            message="CodeQL forced by user request, readiness gate bypassed",
        )

    def _create_basic_failure_result(self, basic_result: dict[str, Any]) -> ReadinessGateResult:
        """Create result for basic check failure."""
        return ReadinessGateResult(
            ready=False,
            status="gated",
            selected_languages=[],
            skipped_languages=[],
            decision_source="none",
            decision_metrics=None,
            message=basic_result.get("message", "CodeQL basic check failed"),
            error=basic_result.get("reason"),
        )

    def _check_tools(
        self,
        build_targets: list[BuildTarget],
        version_req: VersionRequirement | None,
    ) -> ReadinessReport:
        """Check tool readiness for build targets.

        Args:
            build_targets: List of build targets.
            version_req: Version requirements.

        Returns:
            ReadinessReport with tool status.
        """
        # Build requirements from build targets
        requirements: dict[ToolType, str | None] = {}

        if version_req:
            if version_req.java_version:
                requirements[ToolType.JAVA] = f">={version_req.java_version}"
            if version_req.go_version:
                requirements[ToolType.GO] = f">={version_req.go_version}"
            if version_req.node_version:
                requirements[ToolType.NODE] = f">={version_req.node_version}"

        # Generate report
        from src.layers.l3_analysis.build.tool_resolver import ProvisionPolicy

        return generate_readiness_report(
            requirements=requirements,
            policy=ProvisionPolicy.REUSE_ONLY,
            resolver=self.tool_resolver,
        )

    async def _make_decision(
        self,
        modules: list[Any],
        build_targets: list[BuildTarget],
        tool_report: ReadinessReport | None,
    ) -> LanguageDecision | DecisionError:
        """Make LLM-based language decision.

        Args:
            modules: List of module summaries.
            build_targets: List of build targets.
            tool_report: Tool readiness report.

        Returns:
            LanguageDecision on success, DecisionError on failure.
        """
        # Build language structures from modules
        language_structures = self._build_language_structures(modules, build_targets)

        # Create decision input
        input_data = LanguageDecisionInput(
            project_path=str(self.project_path),
            languages=language_structures,
            constraints=self.constraints,
        )

        # Make decision
        return await self.decider.decide(input_data)

    def _make_baseline_decision(
        self,
        modules: list[Any],
        build_targets: list[BuildTarget],
    ) -> LanguageDecision:
        """Make baseline (deterministic) language decision.

        Args:
            modules: List of module summaries.
            build_targets: List of build targets.

        Returns:
            LanguageDecision from baseline strategy.
        """
        # Use decider's baseline method
        language_structures = self._build_language_structures(modules, build_targets)

        input_data = LanguageDecisionInput(
            project_path=str(self.project_path),
            languages=language_structures,
            constraints=self.constraints,
        )

        return self.decider._make_baseline_decision(input_data)

    def _build_language_structures(
        self,
        modules: list[Any],
        build_targets: list[BuildTarget],
    ) -> list[LanguageStructure]:
        """Build language structures from modules and targets.

        Args:
            modules: List of module summaries.
            build_targets: List of build targets.

        Returns:
            List of LanguageStructure for decision input.
        """
        # Group by language
        lang_data: dict[str, dict[str, Any]] = {}

        for module in modules:
            lang = getattr(module, "primary_language", None) or getattr(module, "language", "unknown")
            if lang not in lang_data:
                lang_data[lang] = {
                    "line_count": 0,
                    "file_count": 0,
                    "role": "secondary",
                }

            lang_data[lang]["line_count"] += getattr(module, "loc_estimate", 0) or getattr(module, "loc", 0)
            lang_data[lang]["file_count"] += getattr(module, "file_count", 0)

        # Determine primary language by line count
        if lang_data:
            primary_lang = max(lang_data.keys(), key=lambda k: lang_data[k]["line_count"])
            lang_data[primary_lang]["role"] = "primary"

        # Create LanguageStructure objects
        structures = []
        for lang, data in lang_data.items():
            structures.append(
                LanguageStructure(
                    name=lang,
                    line_count=data["line_count"],
                    file_count=data["file_count"],
                    role=data["role"],
                )
            )

        return structures


# =============================================================================
# Convenience Functions
# =============================================================================


async def check_codeql_readiness(
    project_path: Path,
    llm_client: LLMClient | None = None,
    force: bool = False,
) -> ReadinessGateResult:
    """Convenience function to check CodeQL readiness.

    Args:
        project_path: Root path of the project.
        llm_client: LLM client for AI decision.
        force: If True, skip LLM decision and enable all languages.

    Returns:
        ReadinessGateResult with complete decision information.
    """
    gate = CodeQLReadinessGate(
        project_path=project_path,
        llm_client=llm_client,
    )
    return await gate.check(force=force)
