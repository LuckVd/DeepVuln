"""
Semgrep Engine - Semgrep integration for fast pattern matching.

Semgrep is a fast, customizable static analysis tool for finding bugs,
detecting vulnerabilities, and enforcing code patterns.
"""

import json
import uuid
from datetime import datetime
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
OFFICIAL_RULE_SETS = {
    "security": "p/security",
    "owasp-top-ten": "p/owasp-top-ten",
    "java": "p/java",
    "python": "p/python",
    "go": "p/golang",
    "javascript": "p/javascript",
    "typescript": "p/typescript",
    "cwe-top-25": "p/cwe-top-25",
    "secrets": "p/secrets",
    "default": "p/default",
}


class SemgrepEngine(BaseEngine):
    """
    Semgrep static analysis engine.

    Provides fast pattern matching for known vulnerability patterns
    using Semgrep's powerful pattern syntax.
    """

    name = "semgrep"
    description = "Semgrep fast pattern matching engine"
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
        **options,
    ) -> ScanResult:
        """
        Execute a Semgrep scan.

        Args:
            source_path: Path to the source code to scan.
            rules: List of custom rule file/directory paths.
            rule_sets: List of official rule set names (e.g., ["security", "java"]).
            languages: Restrict scan to these languages.
            severity_filter: Only return findings at these severity levels.
            exclude_patterns: Glob patterns to exclude.
            include_patterns: Glob patterns to include.
            use_auto_config: Let Semgrep auto-detect rules (equivalent to --config auto).
            **options: Additional options.

        Returns:
            ScanResult containing all findings.
        """
        # Validate source path
        self.validate_source_path(source_path)

        # Build the semgrep command
        cmd = await self._build_scan_command(
            source_path=source_path,
            rules=rules,
            rule_sets=rule_sets,
            languages=languages,
            exclude_patterns=exclude_patterns,
            include_patterns=include_patterns,
            use_auto_config=use_auto_config,
        )

        # Track rules used
        rules_used = self._get_rules_used(
            rules=rules,
            rule_sets=rule_sets,
            use_auto_config=use_auto_config,
        )

        # Create scan result
        result = self.create_scan_result(source_path, rules_used)

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

            # Add findings to result
            for finding in findings:
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

        Returns:
            Command as list of strings.
        """
        cmd = [
            self.semgrep_path,
            "--json",
            "--quiet",
        ]

        # Determine if we need metrics for auto config
        # Note: --config auto requires metrics to be enabled
        if use_auto_config:
            # auto config requires metrics
            cmd.append("--metrics=on")
        else:
            cmd.append("--metrics=off")

        # Add config options
        configs = []

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
                        configs.append(OFFICIAL_RULE_SETS[rule_set])
                    else:
                        # Assume it's already a valid config reference
                        configs.append(rule_set)

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


# Register the engine
engine_registry.register(SemgrepEngine())
