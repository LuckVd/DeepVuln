"""
Smart Scanner - Integrates L1 tech stack detection with L3 analysis engines.

Automatically selects appropriate rules and engines based on detected technologies.
"""

from pathlib import Path
from typing import Any

from src.layers.l3_analysis.engines.base import EngineRegistry
from src.layers.l3_analysis.engines.semgrep import OFFICIAL_RULE_SETS, SemgrepEngine
from src.layers.l3_analysis.models import Finding, ScanResult, SeverityLevel
from src.layers.l3_analysis.strategy.engine import StrategyEngine
from src.layers.l3_analysis.strategy.models import AuditStrategy, AuditTarget


# Language to rule set mapping
LANGUAGE_RULE_SETS: dict[str, list[str]] = {
    "java": ["java", "security"],
    "python": ["python", "security"],
    "go": ["go", "security"],
    "javascript": ["javascript", "security"],
    "typescript": ["typescript", "javascript", "security"],
    "ruby": ["ruby", "security"],
    "php": ["php", "security"],
    "c": ["c", "security"],
    "cpp": ["cpp", "c", "security"],
    "csharp": ["csharp", "security"],
    "rust": ["rust", "security"],
    "kotlin": ["kotlin", "java", "security"],
    "scala": ["scala", "java", "security"],
}

# Framework-specific rule sets
FRAMEWORK_RULE_SETS: dict[str, list[str]] = {
    "spring": ["java", "security"],
    "springboot": ["java", "security"],
    "django": ["python", "security"],
    "flask": ["python", "security"],
    "fastapi": ["python", "security"],
    "express": ["javascript", "security"],
    "react": ["javascript", "typescript", "security"],
    "vue": ["javascript", "typescript", "security"],
    "gin": ["go", "security"],
    "echo": ["go", "security"],
    "rails": ["ruby", "security"],
    "laravel": ["php", "security"],
}

# Framework to language mapping
FRAMEWORK_TO_LANGUAGE: dict[str, str] = {
    "spring": "java",
    "springboot": "java",
    "django": "python",
    "flask": "python",
    "fastapi": "python",
    "express": "javascript",
    "react": "javascript",
    "vue": "javascript",
    "gin": "go",
    "echo": "go",
    "rails": "ruby",
    "laravel": "php",
}


class SmartScanner:
    """
    Smart scanner that automatically selects rules based on project tech stack.

    Integrates with L1 tech stack detection to provide intelligent rule selection.
    Also integrates with StrategyEngine for priority-based auditing.
    """

    def __init__(
        self,
        engine_registry: EngineRegistry | None = None,
        custom_rules_dir: Path | None = None,
        semgrep_engine: SemgrepEngine | None = None,
        strategy_engine: StrategyEngine | None = None,
    ):
        """
        Initialize the smart scanner.

        Args:
            engine_registry: Registry of available engines.
            custom_rules_dir: Directory containing custom rules.
            semgrep_engine: Direct SemgrepEngine instance (takes priority over registry).
            strategy_engine: Strategy engine for priority-based auditing.
        """
        self.engine_registry = engine_registry
        self.custom_rules_dir = custom_rules_dir
        self._semgrep_engine = semgrep_engine
        self._strategy_engine = strategy_engine

    def _get_semgrep_engine(self) -> SemgrepEngine | None:
        """Get Semgrep engine from registry or use provided instance."""
        if self._semgrep_engine:
            return self._semgrep_engine
        if self.engine_registry:
            return self.engine_registry.get("semgrep")
        # Create a new instance if no registry or engine provided
        engine = SemgrepEngine()
        return engine if engine.is_available() else None

    async def scan_project(
        self,
        source_path: Path,
        tech_stack: dict[str, Any] | None = None,
        severity_filter: list[SeverityLevel] | None = None,
        use_auto_config: bool = False,
        additional_rule_sets: list[str] | None = None,
    ) -> ScanResult:
        """
        Scan a project with automatic rule selection.

        Args:
            source_path: Path to the source code.
            tech_stack: Detected tech stack from L1. If None, will use auto detection.
            severity_filter: Filter findings by severity.
            use_auto_config: Let Semgrep auto-detect rules.
            additional_rule_sets: Additional rule sets to include.

        Returns:
            ScanResult with all findings.
        """
        # Get the Semgrep engine
        semgrep_engine = self._get_semgrep_engine()
        if not semgrep_engine or not semgrep_engine.is_available():
            raise RuntimeError("Semgrep engine is not available")

        # Determine rules based on tech stack
        if use_auto_config:
            rule_sets = None  # Let Semgrep auto-detect
            languages = None
        else:
            rule_sets, languages = self._select_rules(
                tech_stack=tech_stack,
                additional_rule_sets=additional_rule_sets,
            )

        # Find custom rules
        custom_rules = self._find_custom_rules(
            languages=languages,
            tech_stack=tech_stack,
        )

        # Run the scan
        result = await semgrep_engine.scan(
            source_path=source_path,
            rules=custom_rules if custom_rules else None,
            rule_sets=rule_sets,
            languages=languages,
            severity_filter=severity_filter,
            use_auto_config=use_auto_config,
        )

        # Deduplicate findings
        result.deduplicate_findings()

        # Sort by severity
        result.sort_by_severity()

        return result

    def _select_rules(
        self,
        tech_stack: dict[str, Any] | None,
        additional_rule_sets: list[str] | None = None,
    ) -> tuple[list[str], list[str] | None]:
        """
        Select appropriate rules based on tech stack.

        Args:
            tech_stack: Detected tech stack.
            additional_rule_sets: Additional rule sets to include.

        Returns:
            Tuple of (rule_sets, languages).
        """
        rule_sets: set[str] = set()
        languages: set[str] = set()

        # Always include security rules
        rule_sets.add("security")

        if tech_stack:
            # Extract languages
            detected_languages = tech_stack.get("languages", [])
            for lang in detected_languages:
                lang_lower = lang.lower()
                if lang_lower in LANGUAGE_RULE_SETS:
                    languages.add(lang_lower)
                    rule_sets.update(LANGUAGE_RULE_SETS[lang_lower])

            # Extract frameworks
            detected_frameworks = tech_stack.get("frameworks", [])
            for fw in detected_frameworks:
                fw_lower = fw.lower() if isinstance(fw, str) else fw.get("name", "").lower()
                if fw_lower in FRAMEWORK_RULE_SETS:
                    rule_sets.update(FRAMEWORK_RULE_SETS[fw_lower])
                if fw_lower in FRAMEWORK_TO_LANGUAGE:
                    languages.add(FRAMEWORK_TO_LANGUAGE[fw_lower])

        # Add additional rule sets
        if additional_rule_sets:
            rule_sets.update(additional_rule_sets)

        # Validate rule sets exist
        valid_rule_sets = [
            rs for rs in rule_sets
            if rs in OFFICIAL_RULE_SETS or rs.startswith("p/")
        ]

        return list(valid_rule_sets), list(languages) if languages else None

    def _find_custom_rules(
        self,
        languages: list[str] | None,
        tech_stack: dict[str, Any] | None,
    ) -> list[str]:
        """
        Find custom rule files/directories.

        Args:
            languages: Detected languages.
            tech_stack: Detected tech stack.

        Returns:
            List of custom rule paths.
        """
        custom_rules: list[str] = []

        if not self.custom_rules_dir or not self.custom_rules_dir.exists():
            return custom_rules

        # Check for language-specific rules
        if languages:
            for lang in languages:
                lang_rule_dir = self.custom_rules_dir / "semgrep" / lang
                if lang_rule_dir.exists() and lang_rule_dir.is_dir():
                    # Check if directory has any .yaml files
                    if list(lang_rule_dir.glob("*.yaml")):
                        custom_rules.append(str(lang_rule_dir))

        # Check for general custom rules
        general_rules = self.custom_rules_dir / "semgrep" / "custom"
        if general_rules.exists() and general_rules.is_dir():
            if list(general_rules.glob("*.yaml")):
                custom_rules.append(str(general_rules))

        return custom_rules

    def get_recommended_rules(
        self,
        tech_stack: dict[str, Any],
    ) -> dict[str, list[str]]:
        """
        Get recommended rule sets for a tech stack.

        Args:
            tech_stack: Detected tech stack.

        Returns:
            Dictionary with 'rule_sets' and 'languages' keys.
        """
        rule_sets, languages = self._select_rules(tech_stack)

        return {
            "rule_sets": rule_sets,
            "languages": languages or [],
            "custom_rules": self._find_custom_rules(languages, tech_stack),
        }

    def create_audit_strategy(
        self,
        source_path: Path,
        project_name: str | None = None,
        attack_surface_report: Any | None = None,
        settings: dict[str, Any] | None = None,
    ) -> AuditStrategy:
        """
        Create an audit strategy for the project.

        Args:
            source_path: Path to the source code.
            project_name: Project name (defaults to directory name).
            attack_surface_report: Attack surface analysis from L1.
            settings: Strategy settings overrides.

        Returns:
            AuditStrategy with priorities and engine allocations.
        """
        if not self._strategy_engine:
            self._strategy_engine = StrategyEngine()

        return self._strategy_engine.create_strategy(
            source_path=source_path,
            project_name=project_name,
            attack_surface=attack_surface_report,
            settings=settings,
        )

    async def scan_with_strategy(
        self,
        source_path: Path,
        strategy: AuditStrategy | None = None,
        attack_surface_report: Any | None = None,
        tech_stack: dict[str, Any] | None = None,
    ) -> ScanResult:
        """
        Scan using a priority-based strategy.

        This method:
        1. Creates or uses a strategy
        2. Executes scans in priority order
        3. Can stop early on critical findings

        Args:
            source_path: Path to the source code.
            strategy: Pre-computed audit strategy.
            attack_surface_report: Attack surface analysis from L1.
            tech_stack: Detected tech stack.

        Returns:
            Combined ScanResult from all executed scans.
        """
        # Create strategy if not provided
        if not strategy:
            strategy = self.create_audit_strategy(
                source_path=source_path,
                attack_surface_report=attack_surface_report,
            )

        # Get execution order
        if not self._strategy_engine:
            self._strategy_engine = StrategyEngine()

        execution_order = self._strategy_engine.get_execution_order(strategy)

        # Initialize combined result
        combined_result = ScanResult(
            source_path=str(source_path),
            engine="smart_scanner",
        )

        # Execute each priority group
        for group_name, group in execution_order:
            # Skip if no targets
            if not group.targets:
                continue

            # Get target files
            target_files = list(set(t.file_path for t in group.targets))

            # Run each engine in the group
            for allocation in group.engine_allocations:
                if not allocation.enabled:
                    continue

                engine_result = await self._run_engine_allocation(
                    source_path=source_path,
                    allocation=allocation,
                    target_files=target_files,
                    tech_stack=tech_stack,
                )

                if engine_result:
                    combined_result.merge_results(engine_result)

                    # Check for critical findings (stop on critical)
                    if strategy.stop_on_critical:
                        critical_count = engine_result.by_severity.get("critical", 0)
                        if critical_count > 0:
                            combined_result.metadata["stopped_early"] = True
                            combined_result.metadata["stop_reason"] = "critical_finding"
                            break

            # Check if we should stop
            if combined_result.metadata.get("stopped_early"):
                break

        # Deduplicate and sort
        combined_result.deduplicate_findings()
        combined_result.sort_by_severity()

        return combined_result

    async def _run_engine_allocation(
        self,
        source_path: Path,
        allocation: Any,  # EngineAllocation
        target_files: list[str],
        tech_stack: dict[str, Any] | None,
    ) -> ScanResult | None:
        """
        Run a specific engine allocation.

        Args:
            source_path: Path to source code.
            allocation: Engine allocation configuration.
            target_files: Files to scan.
            tech_stack: Detected tech stack.

        Returns:
            ScanResult from the engine, or None if engine unavailable.
        """
        engine_name = allocation.engine

        if engine_name == "semgrep":
            semgrep_engine = self._get_semgrep_engine()
            if not semgrep_engine:
                return None

            # Build rule configuration
            rule_sets = allocation.rules if allocation.rules else ["security"]

            return await semgrep_engine.scan(
                source_path=source_path,
                rule_sets=rule_sets,
                severity_filter=None,
            )

        elif engine_name == "codeql":
            # CodeQL integration (placeholder for now)
            if self.engine_registry:
                codeql_engine = self.engine_registry.get("codeql")
                if codeql_engine:
                    return await codeql_engine.scan(source_path=source_path)
            return None

        elif engine_name == "agent":
            # Agent integration (placeholder for now)
            if self.engine_registry:
                agent_engine = self.engine_registry.get("agent")
                if agent_engine:
                    return await agent_engine.scan(source_path=source_path)
            return None

        return None


def create_smart_scanner(
    project_root: Path | None = None,
) -> SmartScanner:
    """
    Create a SmartScanner with project-specific configuration.

    Args:
        project_root: Root directory of the project.

    Returns:
        Configured SmartScanner instance.
    """
    custom_rules_dir = None
    if project_root:
        rules_dir = project_root / "rules"
        if rules_dir.exists():
            custom_rules_dir = rules_dir

    return SmartScanner(
        custom_rules_dir=custom_rules_dir,
    )
