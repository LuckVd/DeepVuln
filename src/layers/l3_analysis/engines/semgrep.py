"""
Semgrep Engine - Semgrep integration for fast pattern matching.

Semgrep is a fast, customizable static analysis tool for finding bugs,
detecting vulnerabilities, and enforcing code patterns.

Enhanced with:
- Rule Gating for 77-91% noise reduction
- Finding Budget for meltdown prevention
- File Filtering for scan surface control
- AST Validation for literal rule elimination
"""

import json
import uuid
from pathlib import Path
from typing import Any

import yaml

from src.core.finding_budget import FindingBudget, FindingBudgetResult
from src.core.logger.logger import get_logger
from src.core.rule_ast_validator import (
    ASTValidationSummary,
    RuleASTValidator,
)
from src.layers.l3_analysis.engines.base import BaseEngine, engine_registry
from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    ScanResult,
    SeverityLevel,
)

# Semgrep severity mapping to our SeverityLevel
SEVERITY_MAP: dict[str, SeverityLevel] = {
    "ERROR": SeverityLevel.HIGH,
    "WARNING": SeverityLevel.MEDIUM,
    "INFO": SeverityLevel.INFO,
}

# Semgrep confidence/category mapping to FindingType
CATEGORY_TO_TYPE: dict[str, FindingType] = {
    "security": FindingType.VULNERABILITY,
    "correctness": FindingType.SUSPICIOUS,
    "best-practice": FindingType.INFO,
    "performance": FindingType.INFO,
    "maintainability": FindingType.INFO,
}

# Official Semgrep rule sets
# Note: Semgrep registry URLs have changed. Use 'auto' for best results.
OFFICIAL_RULE_SETS = {
    "security": "auto",  # Use auto which includes security rules
    "owasp-top-ten": "auto",
    "java": "auto",
    "python": "auto",
    "go": "auto",
    "javascript": "auto",
    "typescript": "auto",
    "cwe-top-25": "auto",
    "secrets": "auto",
    "default": "auto",
}


class SemgrepEngine(BaseEngine):
    """
    Semgrep static analysis engine with Rule Gating and Finding Budget support.

    Provides fast pattern matching for known vulnerability patterns
    using Semgrep's powerful pattern syntax.

    Enhanced with:
    - Intelligent rule gating to reduce false positives by 77-91%
      through TechStack and AttackSurface analysis
    - Finding Budget circuit breaker to prevent finding explosions
      from overwhelming downstream Agent processing
    """

    name = "semgrep"
    description = "Semgrep fast pattern matching engine with rule gating"
    supported_languages = [
        "java",
        "python",
        "go",
        "javascript",
        "typescript",
        "jsx",
        "tsx",
        "c",
        "cpp",
        "csharp",
        "ruby",
        "php",
        "scala",
        "kotlin",
        "rust",
        "swift",
        "terraform",
        "yaml",
        "json",
        "dockerfile",
    ]

    def __init__(
        self,
        semgrep_path: str = "semgrep",
        timeout: int = 300,
        max_memory_mb: int = 4096,
        use_docker: bool = False,
    ):
        """
        Initialize the Semgrep engine.

        Args:
            semgrep_path: Path to semgrep binary (default: looks in PATH).
            timeout: Maximum scan duration in seconds.
            max_memory_mb: Maximum memory usage in MB.
            use_docker: Whether to run semgrep in Docker.
        """
        super().__init__(timeout=timeout, max_memory_mb=max_memory_mb)
        self.semgrep_path = semgrep_path
        self.use_docker = use_docker
        self.logger = get_logger(__name__)

    def is_available(self) -> bool:
        """
        Check if Semgrep CLI is installed and available.

        Returns:
            True if semgrep can be executed.
        """
        return self.check_binary_available(self.semgrep_path)

    async def get_version(self) -> str | None:
        """
        Get the Semgrep version.

        Returns:
            Version string, or None if not available.
        """
        if not self.is_available():
            return None
        try:
            _, stdout, _ = await self.run_command(
                [self.semgrep_path, "--version"]
            )
            return stdout.strip()
        except Exception:
            return None

    async def scan(
        self,
        source_path: Path,
        rules: list[str] | None = None,
        rule_sets: list[str] | None = None,
        languages: list[str] | None = None,
        severity_filter: list[SeverityLevel] | None = None,
        exclude_patterns: list[str] | None = None,
        include_patterns: list[str] | None = None,
        use_auto_config: bool = False,
        tech_stack: Any | None = None,
        attack_surface: Any | None = None,
        use_rule_gating: bool = True,
        use_finding_budget: bool = True,
        use_file_filtering: bool = True,
        use_ast_validation: bool = True,
        **options,
    ) -> ScanResult:
        """
        Execute a Semgrep scan with rule gating, file filtering, and finding budget.

        Args:
            source_path: Path to the source code to scan.
            rules: List of custom rule file/directory paths.
            rule_sets: List of official rule set names (e.g., ["security", "java"]).
            languages: Restrict scan to these languages (overrides auto-detection).
            severity_filter: Only return findings at these severity levels.
            exclude_patterns: Glob patterns to exclude (added to auto-generated).
            include_patterns: Glob patterns to include.
            use_auto_config: Let Semgrep auto-detect rules (equivalent to --config auto).
            tech_stack: TechStack object for rule gating and file filtering.
            attack_surface: AttackSurfaceReport object for rule gating and file filtering.
            use_rule_gating: Whether to apply rule gating (default: True).
            use_finding_budget: Whether to apply finding budget limits (default: True).
            use_file_filtering: Whether to apply file filtering (default: True).
            use_ast_validation: Whether to validate rules for AST matching (default: True).
            **options: Additional options.

        Returns:
            ScanResult containing all findings.
        """
        # Validate source path
        self.validate_source_path(source_path)

        # Apply rule gating if enabled and tech_stack available
        gating_result = None
        excluded_rule_ids = []

        if use_rule_gating and (tech_stack or attack_surface):
            try:
                from src.core.rule_gating import RuleGatingEngine

                gating_engine = RuleGatingEngine(
                    tech_stack=tech_stack,
                    attack_surface=attack_surface,
                )
                gating_result = gating_engine.evaluate()
                excluded_rule_ids = gating_result.disabled_rule_ids

                self.logger.info(
                    f"Rule gating applied: mode={gating_result.mode}, "
                    f"disabled_packs={len(gating_result.disabled_packs)}, "
                    f"excluded_rules={len(excluded_rule_ids)}, "
                    f"reduction={gating_result.get_reduction_percentage():.1f}%"
                )
            except Exception as e:
                self.logger.warning(f"Rule gating failed, continuing without: {e}")

        # Apply file filtering if enabled
        filtering_result = None
        if use_file_filtering and (tech_stack or attack_surface):
            try:
                from src.core.file_filtering import FileFilteringEngine

                filter_engine = FileFilteringEngine(
                    tech_stack=tech_stack,
                    attack_surface=attack_surface,
                )
                filtering_result = filter_engine.build()

                self.logger.info(
                    f"File filtering applied: "
                    f"exclude_dirs={len(filtering_result.exclude_dirs)}, "
                    f"exclude_patterns={len(filtering_result.exclude_patterns)}, "
                    f"lang_flags={filtering_result.lang_flags}"
                )
            except Exception as e:
                self.logger.warning(f"File filtering failed, continuing without: {e}")

        # Apply AST validation if enabled
        ast_validation_result = None
        if use_ast_validation and rules:
            try:
                ast_validation_result = self._validate_rules_ast(rules)
                if ast_validation_result.rejected_count > 0:
                    # Add rejected rule IDs to excluded list
                    excluded_rule_ids.extend(ast_validation_result.disabled_literal_rules)
                    self.logger.info(
                        f"AST validation applied: "
                        f"valid={ast_validation_result.validated_count}, "
                        f"rejected={ast_validation_result.rejected_count}, "
                        f"rejection_rate={ast_validation_result.rejection_rate}"
                    )
            except Exception as e:
                self.logger.warning(f"AST validation failed, continuing without: {e}")

        # Merge user patterns with auto-generated patterns
        final_exclude_patterns = list(exclude_patterns) if exclude_patterns else []
        final_include_patterns = list(include_patterns) if include_patterns else []
        final_languages = list(languages) if languages else None

        if filtering_result:
            # Merge exclude patterns (user + auto)
            for pattern in filtering_result.exclude_patterns:
                if pattern not in final_exclude_patterns:
                    final_exclude_patterns.append(pattern)

            # Merge include patterns (user + auto)
            for pattern in filtering_result.include_patterns:
                if pattern not in final_include_patterns:
                    final_include_patterns.append(pattern)

            # Use auto-detected languages if not explicitly provided
            if not final_languages and filtering_result.lang_flags:
                final_languages = filtering_result.lang_flags

        # Build the semgrep command
        cmd = await self._build_scan_command(
            source_path=source_path,
            rules=rules,
            rule_sets=rule_sets,
            languages=final_languages,
            exclude_patterns=final_exclude_patterns,
            include_patterns=final_include_patterns,
            use_auto_config=use_auto_config,
            excluded_rule_ids=excluded_rule_ids,
            filtering_result=filtering_result,
        )

        # Track rules used
        rules_used = self._get_rules_used(
            rules=rules,
            rule_sets=rule_sets,
            use_auto_config=use_auto_config,
        )

        # Create scan result
        result = self.create_scan_result(source_path, rules_used)

        # Store gating info in metadata
        if gating_result:
            result.metadata["rule_gating"] = gating_result.to_dict()

        # Store file filtering info in metadata
        if filtering_result:
            result.metadata["file_filtering"] = filtering_result.to_dict()

        # Store AST validation info in metadata
        if ast_validation_result:
            result.metadata["ast_validation"] = ast_validation_result.to_dict()

        try:
            # Run semgrep
            returncode, stdout, stderr = await self.run_command(
                cmd,
                cwd=source_path,
            )

            # Parse JSON output
            try:
                semgrep_output = json.loads(stdout)
            except json.JSONDecodeError:
                return self.finalize_scan_result(
                    result,
                    success=False,
                    error_message=f"Failed to parse Semgrep output: {stderr}",
                )

            # Process results
            findings = self._parse_results(
                semgrep_output=semgrep_output,
                source_path=source_path,
            )

            # Apply filters
            if severity_filter:
                findings = [
                    f
                    for f in findings
                    if f.severity in severity_filter
                ]

            # Apply Finding Budget to prevent meltdown
            if use_finding_budget:
                budget_result = self._apply_finding_budget(findings)

                # Store budget info in metadata
                result.metadata["finding_budget"] = budget_result.to_dict()

                # Use filtered findings
                final_findings = budget_result.filtered_findings

                if budget_result.dropped_count > 0:
                    self.logger.info(
                        f"Finding budget applied: mode={budget_result.budget_mode}, "
                        f"original={budget_result.original_count}, "
                        f"filtered={len(final_findings)}, "
                        f"dropped={budget_result.dropped_count}"
                    )
            else:
                final_findings = findings
                result.metadata["finding_budget"] = {
                    "budget_mode": "disabled",
                    "dropped_count": 0,
                    "triggered_rules": [],
                    "triggered_files": [],
                }

            # Add findings to result
            for finding in final_findings:
                result.add_finding(finding)

            return self.finalize_scan_result(
                result,
                success=True,
                raw_output=semgrep_output,
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

    async def _build_scan_command(
        self,
        source_path: Path,
        rules: list[str] | None,
        rule_sets: list[str] | None,
        languages: list[str] | None,
        exclude_patterns: list[str] | None,
        include_patterns: list[str] | None,
        use_auto_config: bool,
        excluded_rule_ids: list[str] | None = None,
        filtering_result: Any | None = None,
    ) -> list[str]:
        """
        Build the semgrep command line.

        Args:
            source_path: Path to scan.
            rules: Custom rule paths.
            rule_sets: Official rule set names.
            languages: Language filter.
            exclude_patterns: Exclude patterns.
            include_patterns: Include patterns.
            use_auto_config: Use auto config.
            excluded_rule_ids: Rule IDs to exclude from rule gating.
            filtering_result: FileFilteringResult with exclude_dirs.

        Returns:
            Command as list of strings.
        """
        cmd = [
            self.semgrep_path,
            "--json",
            "--quiet",
        ]

        # Add config options
        configs = []
        using_auto = use_auto_config

        if use_auto_config:
            configs.append("auto")
        else:
            # Add custom rules
            if rules:
                configs.extend(rules)

            # Add rule sets
            if rule_sets:
                for rule_set in rule_sets:
                    if rule_set in OFFICIAL_RULE_SETS:
                        config_value = OFFICIAL_RULE_SETS[rule_set]
                        if config_value == "auto":
                            using_auto = True
                        configs.append(config_value)
                    else:
                        # Assume it's already a valid config reference
                        configs.append(rule_set)

        # Enable metrics if using auto config (required for --config auto)
        if using_auto:
            cmd.append("--metrics=on")
        else:
            cmd.append("--metrics=off")

        # Only add --config if we have configs specified
        # If no configs, semgrep will use minimal default rules
        if configs:
            cmd.extend(["--config", ",".join(configs)])

        # Add language filter
        if languages:
            for lang in languages:
                cmd.extend(["--lang", lang])

        # Add exclude patterns
        if exclude_patterns:
            for pattern in exclude_patterns:
                cmd.extend(["--exclude", pattern])

        # Add include patterns
        if include_patterns:
            for pattern in include_patterns:
                cmd.extend(["--include", pattern])

        # Add exclude directories from file filtering
        if filtering_result:
            for dir_name in filtering_result.exclude_dirs:
                cmd.extend(["--exclude", dir_name])

        # Add excluded rule IDs from rule gating
        if excluded_rule_ids:
            for rule_id in excluded_rule_ids:
                cmd.extend(["--exclude-rule", rule_id])

        # Add target path
        cmd.append(str(source_path))

        return cmd

    def _get_rules_used(
        self,
        rules: list[str] | None,
        rule_sets: list[str] | None,
        use_auto_config: bool,
    ) -> list[str]:
        """Get list of rules used for tracking."""
        rules_used = []

        if use_auto_config:
            rules_used.append("auto")
        else:
            if rules:
                rules_used.extend(rules)
            if rule_sets:
                rules_used.extend(rule_sets)

        return rules_used

    def _parse_results(
        self,
        semgrep_output: dict[str, Any],
        source_path: Path,
    ) -> list[Finding]:
        """
        Parse Semgrep JSON output into Finding objects.

        Args:
            semgrep_output: Parsed JSON output from semgrep.
            source_path: Path that was scanned.

        Returns:
            List of Finding objects.
        """
        findings = []

        results = semgrep_output.get("results", [])

        for result in results:
            finding = self._convert_result_to_finding(result, source_path)
            if finding:
                findings.append(finding)

        return findings

    def _convert_result_to_finding(
        self,
        result: dict[str, Any],
        source_path: Path,
    ) -> Finding | None:
        """
        Convert a single Semgrep result to a Finding.

        Args:
            result: Single result from Semgrep JSON output.
            source_path: Path that was scanned.

        Returns:
            Finding object, or None if conversion fails.
        """
        try:
            # Extract basic info
            check_id = result.get("check_id", "unknown")
            path = result.get("path", "")

            # Extract location
            start = result.get("start", {})
            end = result.get("end", {})

            location = CodeLocation(
                file=path,
                line=start.get("line", 1),
                column=start.get("col"),
                end_line=end.get("line"),
                end_column=end.get("col"),
                snippet=result.get("extra", {}).get("lines"),
            )

            # Extract extra info
            extra = result.get("extra", {})

            # Determine severity
            semgrep_severity = extra.get("severity", "INFO").upper()
            severity = SEVERITY_MAP.get(semgrep_severity, SeverityLevel.MEDIUM)

            # Override with metadata severity if present
            metadata = extra.get("metadata", {})
            if "severity" in metadata:
                meta_severity = metadata["severity"].upper()
                if meta_severity == "CRITICAL":
                    severity = SeverityLevel.CRITICAL
                elif meta_severity == "HIGH":
                    severity = SeverityLevel.HIGH
                elif meta_severity == "MEDIUM":
                    severity = SeverityLevel.MEDIUM
                elif meta_severity == "LOW":
                    severity = SeverityLevel.LOW

            # Determine finding type from category
            category = metadata.get("category", "security")
            finding_type = CATEGORY_TO_TYPE.get(
                category.lower(),
                FindingType.VULNERABILITY,
            )

            # Extract title and description
            message = extra.get("message", "No description available")
            title = self._extract_title(check_id, message)

            # Extract references
            references = metadata.get("references", [])
            if isinstance(references, list):
                references = [r for r in references if isinstance(r, str)]

            # Extract CWE and OWASP
            cwe = self._extract_cwe(metadata)
            owasp = self._extract_owasp(metadata)

            # Extract tags
            tags = []
            if "technology" in metadata:
                tech = metadata["technology"]
                if isinstance(tech, list):
                    tags.extend(tech)
            if "confidence" in metadata:
                tags.append(f"confidence:{metadata['confidence']}")

            # Build finding
            finding = Finding(
                id=f"semgrep-{uuid.uuid4().hex[:8]}",
                rule_id=check_id,
                type=finding_type,
                severity=severity,
                confidence=self._extract_confidence(metadata),
                title=title,
                description=message,
                location=location,
                source="semgrep",
                cwe=cwe,
                owasp=owasp,
                references=references,
                tags=tags,
                metadata={
                    "semgrep_metadata": metadata,
                    "metavars": extra.get("metavars", {}),
                },
            )

            return finding

        except Exception:
            return None

    def _extract_title(self, check_id: str, message: str) -> str:
        """Extract a short title from check_id and message."""
        # Use the last part of check_id as base title
        parts = check_id.split(".")
        base_title = parts[-1] if parts else "Security Issue"

        # Clean up and capitalize
        base_title = base_title.replace("-", " ").replace("_", " ")
        base_title = " ".join(
            word.capitalize() for word in base_title.split()
        )

        # If message is short enough, use it directly
        if len(message) <= 80:
            return message

        return base_title

    def _extract_cwe(self, metadata: dict[str, Any]) -> str | None:
        """Extract CWE identifier from metadata."""
        cwe = metadata.get("cwe")
        if cwe:
            if isinstance(cwe, list):
                cwe = cwe[0]
            # Normalize format
            if isinstance(cwe, str):
                if cwe.startswith("CWE-"):
                    return cwe
                elif cwe.isdigit():
                    return f"CWE-{cwe}"
        return None

    def _extract_owasp(self, metadata: dict[str, Any]) -> str | None:
        """Extract OWASP category from metadata."""
        owasp = metadata.get("owasp")
        if owasp:
            if isinstance(owasp, list):
                owasp = owasp[0]
            if isinstance(owasp, str):
                return owasp
        return None

    def _extract_confidence(self, metadata: dict[str, Any]) -> float:
        """Extract confidence score from metadata."""
        confidence = metadata.get("confidence", "MEDIUM").lower()
        confidence_map = {
            "high": 0.9,
            "medium": 0.7,
            "low": 0.5,
        }
        return confidence_map.get(confidence, 0.8)

    def _apply_finding_budget(self, findings: list[Finding]) -> FindingBudgetResult:
        """
        Apply finding budget limits to prevent meltdown.

        This enforces hard limits on findings per rule, per file, and
        per project to prevent explosion of findings from overwhelming
        the Agent.

        Args:
            findings: List of Finding objects from Semgrep.

        Returns:
            FindingBudgetResult with filtered findings and metadata.
        """
        budget = FindingBudget()
        return budget.apply(findings)

    def _validate_rules_ast(
        self,
        rule_paths: list[str],
    ) -> ASTValidationSummary:
        """
        Validate rules for AST semantic matching.

        This method loads rule files, parses them, and validates that
        they have AST-level semantic matching capabilities. Rules that
        only perform literal string matching are rejected.

        Args:
            rule_paths: List of paths to rule files or directories.

        Returns:
            ASTValidationSummary with validation results.
        """
        validator = RuleASTValidator()
        all_rules = []

        # Load rules from all paths
        for path_str in rule_paths:
            path = Path(path_str)
            try:
                if path.is_file():
                    rules = self._load_rule_file(path)
                    all_rules.extend(rules)
                elif path.is_dir():
                    rules = self._load_rule_directory(path)
                    all_rules.extend(rules)
            except Exception as e:
                self.logger.debug(f"Could not load rules from {path_str}: {e}")

        # Validate and filter rules
        if not all_rules:
            return ASTValidationSummary()

        _, summary = validator.validate_rules(all_rules)
        return summary

    def _load_rule_file(self, path: Path) -> list[dict[str, Any]]:
        """
        Load rules from a single YAML file.

        Args:
            path: Path to the rule file.

        Returns:
            List of rule dictionaries.
        """
        rules = []
        try:
            with open(path, encoding="utf-8") as f:
                content = yaml.safe_load(f)

            if content is None:
                return rules

            # Handle both single rule and rules array
            if isinstance(content, dict):
                if "rules" in content:
                    rules.extend(content["rules"])
                elif "id" in content:
                    rules.append(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        if "rules" in item:
                            rules.extend(item["rules"])
                        elif "id" in item:
                            rules.append(item)

        except Exception as e:
            self.logger.debug(f"Error loading rule file {path}: {e}")

        return rules

    def _load_rule_directory(self, path: Path) -> list[dict[str, Any]]:
        """
        Load rules from a directory.

        Args:
            path: Path to the rule directory.

        Returns:
            List of rule dictionaries.
        """
        rules = []
        try:
            for yaml_file in path.rglob("*.yaml"):
                rules.extend(self._load_rule_file(yaml_file))
            for yaml_file in path.rglob("*.yml"):
                rules.extend(self._load_rule_file(yaml_file))
        except Exception as e:
            self.logger.debug(f"Error loading rules from directory {path}: {e}")

        return rules


# Register the engine
engine_registry.register(SemgrepEngine())
