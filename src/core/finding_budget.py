"""
Finding Budget - Misreport Meltdown Prevention System.

This module provides a circuit breaker mechanism to prevent explosion of findings
from overwhelming the Agent. It enforces hard limits on findings per rule,
per file, and per project.

Target: Never explode, Agent never overwhelmed.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from src.core.logger.logger import get_logger


class BudgetMode(str, Enum):
    """Finding budget modes."""

    NORMAL = "normal"
    THROTTLED = "throttled"
    MELTDOWN = "meltdown"


# Budget thresholds
MAX_PER_RULE = 50  # Single rule max findings
MAX_PER_FILE = 80  # Single file max findings
MAX_TOTAL = 1000  # Project total max findings

# Meltdown thresholds (higher limits that trigger meltdown mode)
MELTDOWN_PER_RULE = 200
MELTDOWN_PER_FILE = 300
MELTDOWN_TOTAL = 1500

# Throttled mode trigger
THROTTLED_RULE_COUNT = 3  # Number of rules exceeding limit to trigger throttled

# Generic rule patterns to disable in meltdown mode
GENERIC_RULE_PATTERNS = [
    "generic.",
    "default.",
    "common.",
    "general.",
    "misc.",
]

# High severity levels to keep in meltdown mode
HIGH_SEVERITY_LEVELS = {"critical", "high", "error"}


@dataclass
class FindingBudgetResult:
    """
    Result of applying finding budget limits.

    Contains filtered findings and metadata about what was dropped.
    """

    filtered_findings: list[Any] = field(default_factory=list)
    dropped_count: int = 0
    triggered_rules: list[str] = field(default_factory=list)
    triggered_files: list[str] = field(default_factory=list)
    budget_mode: Literal["normal", "throttled", "meltdown"] = "normal"

    # Statistics
    original_count: int = 0
    per_rule_dropped: dict[str, int] = field(default_factory=dict)
    per_file_dropped: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "budget_mode": self.budget_mode,
            "dropped_count": self.dropped_count,
            "triggered_rules": self.triggered_rules,
            "triggered_files": self.triggered_files,
            "statistics": {
                "original_count": self.original_count,
                "filtered_count": len(self.filtered_findings),
                "reduction_percentage": self.get_reduction_percentage(),
                "per_rule_dropped": self.per_rule_dropped,
                "per_file_dropped": self.per_file_dropped,
            },
        }

    def get_reduction_percentage(self) -> float:
        """Calculate the reduction percentage."""
        if self.original_count == 0:
            return 0.0
        return (self.dropped_count / self.original_count) * 100


class FindingBudget:
    """
    Finding Budget Engine - Circuit breaker for findings.

    Prevents explosion of findings from overwhelming the Agent by enforcing
    hard limits on findings per rule, per file, and per project.

    Modes:
    - normal: Within all limits
    - throttled: 3+ rules exceeded per-rule limit
    - meltdown: Severe overflow, keep only high severity
    """

    def __init__(
        self,
        max_per_rule: int = MAX_PER_RULE,
        max_per_file: int = MAX_PER_FILE,
        max_total: int = MAX_TOTAL,
        meltdown_per_rule: int = MELTDOWN_PER_RULE,
        meltdown_per_file: int = MELTDOWN_PER_FILE,
        meltdown_total: int = MELTDOWN_TOTAL,
        throttled_rule_count: int = THROTTLED_RULE_COUNT,
    ):
        """
        Initialize the Finding Budget engine.

        Args:
            max_per_rule: Maximum findings per rule.
            max_per_file: Maximum findings per file.
            max_total: Maximum total findings.
            meltdown_per_rule: Threshold to trigger meltdown per rule.
            meltdown_per_file: Threshold to trigger meltdown per file.
            meltdown_total: Threshold to trigger meltdown total.
            throttled_rule_count: Number of rules to trigger throttled mode.
        """
        self.logger = get_logger(__name__)
        self.max_per_rule = max_per_rule
        self.max_per_file = max_per_file
        self.max_total = max_total
        self.meltdown_per_rule = meltdown_per_rule
        self.meltdown_per_file = meltdown_per_file
        self.meltdown_total = meltdown_total
        self.throttled_rule_count = throttled_rule_count

    def apply(self, findings: list[Any]) -> FindingBudgetResult:
        """
        Apply budget limits to findings.

        Args:
            findings: List of Finding objects.

        Returns:
            FindingBudgetResult with filtered findings and metadata.
        """
        result = FindingBudgetResult(original_count=len(findings))

        if not findings:
            return result

        # Step 1: Analyze findings distribution
        rule_counts: dict[str, list[Any]] = {}
        file_counts: dict[str, list[Any]] = {}

        for finding in findings:
            rule_id = self._get_rule_id(finding)
            file_path = self._get_file_path(finding)

            if rule_id not in rule_counts:
                rule_counts[rule_id] = []
            rule_counts[rule_id].append(finding)

            if file_path not in file_counts:
                file_counts[file_path] = []
            file_counts[file_path].append(finding)

        # Step 2: Check for meltdown conditions
        meltdown_triggered = self._check_meltdown_conditions(
            rule_counts, file_counts, len(findings)
        )

        if meltdown_triggered:
            result.budget_mode = "meltdown"
            self.logger.warning(
                f"Meltdown mode triggered: total={len(findings)}, "
                f"max_rule={max(len(v) for v in rule_counts.values()) if rule_counts else 0}, "
                f"max_file={max(len(v) for v in file_counts.values()) if file_counts else 0}"
            )
            return self._apply_meltdown_mode(findings, result)

        # Step 3: Check for throttled conditions
        rules_exceeded = sum(
            1 for findings_list in rule_counts.values()
            if len(findings_list) > self.max_per_rule
        )

        if rules_exceeded >= self.throttled_rule_count:
            result.budget_mode = "throttled"
            self.logger.info(
                f"Throttled mode triggered: {rules_exceeded} rules exceeded limit"
            )

        # Step 4: Apply per-rule limits
        filtered = self._apply_per_rule_limits(findings, rule_counts, result)

        # Step 5: Apply per-file limits
        filtered = self._apply_per_file_limits(filtered, result)

        # Step 6: Apply total limit
        filtered = self._apply_total_limit(filtered, result)

        result.filtered_findings = filtered
        result.dropped_count = result.original_count - len(filtered)

        self.logger.info(
            f"Finding budget applied: mode={result.budget_mode}, "
            f"original={result.original_count}, "
            f"filtered={len(filtered)}, "
            f"dropped={result.dropped_count} ({result.get_reduction_percentage():.1f}%)"
        )

        return result

    def _get_rule_id(self, finding: Any) -> str:
        """Extract rule ID from finding."""
        if hasattr(finding, "rule_id"):
            return finding.rule_id or "unknown"
        if isinstance(finding, dict):
            return finding.get("rule_id", finding.get("check_id", "unknown"))
        return "unknown"

    def _get_file_path(self, finding: Any) -> str:
        """Extract file path from finding."""
        if hasattr(finding, "location") and hasattr(finding.location, "file"):
            return finding.location.file or "unknown"
        if hasattr(finding, "file"):
            return finding.file or "unknown"
        if isinstance(finding, dict):
            location = finding.get("location", {})
            if isinstance(location, dict):
                return location.get("file", "unknown")
            return finding.get("file", finding.get("path", "unknown"))
        return "unknown"

    def _get_severity(self, finding: Any) -> str:
        """Extract severity from finding."""
        if hasattr(finding, "severity"):
            severity = finding.severity
            if hasattr(severity, "value"):
                return severity.value.lower()
            return str(severity).lower()
        if isinstance(finding, dict):
            severity = finding.get("severity", "info")
            if hasattr(severity, "value"):
                return severity.value.lower()
            return str(severity).lower()
        return "info"

    def _is_generic_rule(self, finding: Any) -> bool:
        """Check if finding is from a generic rule."""
        rule_id = self._get_rule_id(finding).lower()
        for pattern in GENERIC_RULE_PATTERNS:
            if pattern in rule_id:
                return True
        return False

    def _check_meltdown_conditions(
        self,
        rule_counts: dict[str, list[Any]],
        file_counts: dict[str, list[Any]],
        total_count: int,
    ) -> bool:
        """Check if meltdown conditions are met."""
        # Check total
        if total_count > self.meltdown_total:
            return True

        # Check per-rule
        for rule_id, findings_list in rule_counts.items():
            if len(findings_list) > self.meltdown_per_rule:
                return True

        # Check per-file
        for file_path, findings_list in file_counts.items():
            if len(findings_list) > self.meltdown_per_file:
                return True

        return False

    def _apply_meltdown_mode(
        self,
        findings: list[Any],
        result: FindingBudgetResult,
    ) -> FindingBudgetResult:
        """Apply meltdown mode - keep only high severity, disable generic rules."""
        filtered = []

        for finding in findings:
            severity = self._get_severity(finding)
            is_generic = self._is_generic_rule(finding)

            # Keep only high severity and non-generic rules
            if severity in HIGH_SEVERITY_LEVELS and not is_generic:
                filtered.append(finding)

        result.filtered_findings = filtered
        result.dropped_count = result.original_count - len(filtered)

        # Record all rules as triggered in meltdown
        rule_counts: dict[str, int] = {}
        for finding in findings:
            rule_id = self._get_rule_id(finding)
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

        for rule_id, count in rule_counts.items():
            if count > self.max_per_rule:
                result.triggered_rules.append(rule_id)
                result.per_rule_dropped[rule_id] = count - min(count, self.max_per_rule)

        self.logger.info(
            f"Meltdown mode applied: kept {len(filtered)} high-severity findings, "
            f"dropped {result.dropped_count}"
        )

        return result

    def _apply_per_rule_limits(
        self,
        findings: list[Any],
        rule_counts: dict[str, list[Any]],
        result: FindingBudgetResult,
    ) -> list[Any]:
        """Apply per-rule limits."""
        kept_by_rule: dict[str, list[Any]] = {}

        for rule_id, findings_list in rule_counts.items():
            if len(findings_list) > self.max_per_rule:
                # Keep first max_per_rule findings
                kept_by_rule[rule_id] = findings_list[: self.max_per_rule]
                dropped = len(findings_list) - self.max_per_rule
                result.triggered_rules.append(rule_id)
                result.per_rule_dropped[rule_id] = dropped
                self.logger.debug(
                    f"Rule {rule_id}: {len(findings_list)} findings, "
                    f"keeping {self.max_per_rule}, dropping {dropped}"
                )
            else:
                kept_by_rule[rule_id] = findings_list

        # Flatten back to list
        filtered = []
        for findings_list in kept_by_rule.values():
            filtered.extend(findings_list)

        return filtered

    def _apply_per_file_limits(
        self,
        findings: list[Any],
        result: FindingBudgetResult,
    ) -> list[Any]:
        """Apply per-file limits."""
        file_counts: dict[str, list[Any]] = {}

        for finding in findings:
            file_path = self._get_file_path(finding)
            if file_path not in file_counts:
                file_counts[file_path] = []
            file_counts[file_path].append(finding)

        filtered = []
        for file_path, findings_list in file_counts.items():
            if len(findings_list) > self.max_per_file:
                # Keep first max_per_file findings
                filtered.extend(findings_list[: self.max_per_file])
                dropped = len(findings_list) - self.max_per_file
                result.triggered_files.append(file_path)
                result.per_file_dropped[file_path] = dropped
                self.logger.debug(
                    f"File {file_path}: {len(findings_list)} findings, "
                    f"keeping {self.max_per_file}, dropping {dropped}"
                )
            else:
                filtered.extend(findings_list)

        return filtered

    def _apply_total_limit(
        self,
        findings: list[Any],
        result: FindingBudgetResult,
    ) -> list[Any]:
        """Apply total project limit."""
        if len(findings) > self.max_total:
            # Keep first max_total findings
            original_len = len(findings)
            findings = findings[: self.max_total]
            dropped = original_len - self.max_total
            self.logger.warning(
                f"Total limit exceeded: {original_len} findings, "
                f"keeping {self.max_total}, dropping {dropped}"
            )
            # Add to dropped count
            result.dropped_count += dropped

        return findings


def create_finding_budget(
    max_per_rule: int = MAX_PER_RULE,
    max_per_file: int = MAX_PER_FILE,
    max_total: int = MAX_TOTAL,
) -> FindingBudget:
    """
    Factory function to create a FindingBudget instance.

    Args:
        max_per_rule: Maximum findings per rule.
        max_per_file: Maximum findings per file.
        max_total: Maximum total findings.

    Returns:
        Configured FindingBudget instance.
    """
    return FindingBudget(
        max_per_rule=max_per_rule,
        max_per_file=max_per_file,
        max_total=max_total,
    )
