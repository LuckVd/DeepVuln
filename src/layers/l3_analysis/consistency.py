"""
Global Adjudication Consistency Module

This module implements the Global Adjudication Consistency Layer that ensures:
1. Same vulnerability cannot have conflicting statuses
2. Exploitability must be consistent with final_status
3. Multi-engine results cannot contradict each other
4. No confirmed + not_exploitable coexistence
5. No status regression violating adjudication rules

Core Principle: Strong Consistency - No Silent Fixes, No Auto-Merge, Explicit Errors Only

This is the FINAL consistency check before output. All conflicts must be
explicitly raised as GlobalAdjudicationError - never silently corrected.
"""

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from src.core.logger.logger import get_logger


class StatusLevel(IntEnum):
    """
    Status hierarchy level for consistency checking.

    Higher values = more severe/exploitable.
    Used to detect status regression conflicts.
    """

    NOT_EXPLOITABLE = 0
    INFORMATIONAL = 1
    CONDITIONAL = 2
    EXPLOITABLE = 3


# Mapping from status string to level
STATUS_LEVELS: dict[str, int] = {
    "not_exploitable": StatusLevel.NOT_EXPLOITABLE,
    "informational": StatusLevel.INFORMATIONAL,
    "conditional": StatusLevel.CONDITIONAL,
    "exploitable": StatusLevel.EXPLOITABLE,
    # Aliases
    "safe": StatusLevel.NOT_EXPLOITABLE,
    "confirmed": StatusLevel.EXPLOITABLE,
}


class GlobalAdjudicationError(Exception):
    """
    Global adjudication consistency error.

    This exception is raised when the adjudication system detects
    a logical inconsistency that violates the strong consistency model.

    This should NEVER be caught and silently handled - it indicates
    a fundamental logic error in the adjudication pipeline.
    """

    def __init__(self, message: str, findings: list[Any] | None = None):
        self.findings = findings or []
        super().__init__(message)


@dataclass
class ConflictInfo:
    """Information about a detected conflict."""

    conflict_type: str
    """Type of conflict detected."""

    finding_ids: list[str]
    """IDs of findings involved in the conflict."""

    details: str
    """Human-readable details about the conflict."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for metadata storage."""
        return {
            "conflict_type": self.conflict_type,
            "finding_ids": self.finding_ids,
            "details": self.details,
        }


@dataclass
class ConsistencyCheckResult:
    """Result of consistency check."""

    passed: bool
    """Whether all checks passed."""

    findings_checked: int = 0
    """Number of findings checked."""

    conflicts: list[ConflictInfo] = field(default_factory=list)
    """List of detected conflicts."""

    error: str | None = None
    """Error message if check failed."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for metadata storage."""
        return {
            "checked": True,
            "passed": self.passed,
            "findings_checked": self.findings_checked,
            "conflicts_found": len(self.conflicts),
            "error": self.error,
        }


def generate_logical_vuln_id(finding: Any) -> str:
    """
    Generate a logical vulnerability ID for deduplication.

    This ID is used to identify the same logical vulnerability across
    different engines (Semgrep, CodeQL, Agent).

    Formula: hash(rule_id + file_path + sink_signature)

    Args:
        finding: Finding object with rule_id and location.

    Returns:
        Logical vulnerability ID string.
    """
    # Extract components
    rule_id = getattr(finding, "rule_id", None) or "unknown"
    file_path = ""
    sink_signature = ""

    # Get file path from location
    if hasattr(finding, "location"):
        loc = finding.location
        if hasattr(loc, "file"):
            file_path = loc.file
        # Add line for more specificity
        if hasattr(loc, "line"):
            file_path = f"{file_path}:{loc.line}"

    # Get sink signature from metadata if available
    if hasattr(finding, "metadata") and isinstance(finding.metadata, dict):
        sink_signature = finding.metadata.get("sink_signature", "")
        if not sink_signature:
            # Try other common keys
            sink_signature = finding.metadata.get("sink", "")
            if not sink_signature:
                sink_signature = finding.metadata.get("taint_sink", "")

    # Normalize and hash
    combined = f"{rule_id}|{file_path}|{sink_signature}"
    hash_value = hashlib.sha256(combined.encode()).hexdigest()[:16]

    return f"vuln_{hash_value}"


class AdjudicationConsistencyChecker:
    """
    Global adjudication consistency checker.

    Enforces 5 mandatory rules:
    1. Exploitability must match final_status
    2. Same logical_vuln_id cannot have EXPLOITABLE + NOT_EXPLOITABLE
    3. Cross-engine status conflicts are not allowed
    4. Status regression is not allowed
    5. final_status cannot be None

    All violations raise GlobalAdjudicationError.
    No silent fixes, no auto-merge, explicit errors only.
    """

    def __init__(self, strict: bool = True):
        """
        Initialize the consistency checker.

        Args:
            strict: If True, raise exceptions on conflicts.
                   If False, return result with conflicts listed.
        """
        self.strict = strict
        self.logger = get_logger(__name__)

    def validate_findings(self, findings: list[Any]) -> ConsistencyCheckResult:
        """
        Execute global consistency check on all findings.

        This is the main entry point for consistency validation.
        Checks all 5 mandatory rules across all findings.

        Args:
            findings: List of Finding objects to validate.

        Returns:
            ConsistencyCheckResult with validation results.

        Raises:
            GlobalAdjudicationError: If strict=True and conflicts found.
        """
        result = ConsistencyCheckResult(passed=True)
        result.findings_checked = len(findings)

        if not findings:
            result.passed = True
            return result

        # Group findings by logical_vuln_id
        vuln_groups: dict[str, list[Any]] = {}
        for finding in findings:
            vuln_id = self._get_logical_vuln_id(finding)
            if vuln_id not in vuln_groups:
                vuln_groups[vuln_id] = []
            vuln_groups[vuln_id].append(finding)

        # Rule 5: Check all findings have final_status
        for finding in findings:
            conflict = self._check_rule_5(finding)
            if conflict:
                result.conflicts.append(conflict)

        # Rule 1: Check exploitability matches final_status
        for finding in findings:
            conflict = self._check_rule_1(finding)
            if conflict:
                result.conflicts.append(conflict)

        # Rules 2, 3, 4: Check within each vulnerability group
        for vuln_id, group_findings in vuln_groups.items():
            if len(group_findings) > 1:
                # Rule 2: No EXPLOITABLE + NOT_EXPLOITABLE in same group
                conflict = self._check_rule_2(vuln_id, group_findings)
                if conflict:
                    result.conflicts.append(conflict)

                # Rule 3: No cross-engine status conflicts
                conflict = self._check_rule_3(vuln_id, group_findings)
                if conflict:
                    result.conflicts.append(conflict)

                # Rule 4: No status regression
                conflict = self._check_rule_4(vuln_id, group_findings)
                if conflict:
                    result.conflicts.append(conflict)

        # Determine result
        result.passed = len(result.conflicts) == 0

        if not result.passed:
            error_details = "; ".join(c.details for c in result.conflicts[:3])
            result.error = f"Found {len(result.conflicts)} consistency conflicts: {error_details}"

            if self.strict:
                finding_ids = []
                for c in result.conflicts:
                    finding_ids.extend(c.finding_ids)
                raise GlobalAdjudicationError(
                    result.error,
                    findings=[f for f in findings if f.id in finding_ids],
                )

        self.logger.info(
            f"Consistency check: {result.findings_checked} findings, "
            f"{len(result.conflicts)} conflicts, passed={result.passed}"
        )

        return result

    def _get_logical_vuln_id(self, finding: Any) -> str:
        """Get or generate logical vulnerability ID."""
        # Check if already has logical_vuln_id
        if hasattr(finding, "logical_vuln_id") and finding.logical_vuln_id:
            return finding.logical_vuln_id

        # Generate from finding attributes
        return generate_logical_vuln_id(finding)

    def _get_exploitability(self, finding: Any) -> str | None:
        """Get exploitability value from finding."""
        if hasattr(finding, "exploitability") and finding.exploitability:
            return finding.exploitability.lower().strip()

        # Check metadata
        if hasattr(finding, "metadata") and isinstance(finding.metadata, dict):
            exp = finding.metadata.get("exploitability")
            if exp:
                if hasattr(exp, "value"):
                    return exp.value.lower().strip()
                return str(exp).lower().strip()

        return None

    def _get_final_status(self, finding: Any) -> str | None:
        """Get final_status value from finding."""
        if hasattr(finding, "final_status") and finding.final_status:
            status = finding.final_status
            if hasattr(status, "value"):
                return status.value.lower().strip()
            return str(status).lower().strip()
        return None

    def _get_status_level(self, status: str) -> int:
        """Get numeric level for a status."""
        normalized = status.lower().strip()
        return STATUS_LEVELS.get(normalized, StatusLevel.CONDITIONAL)

    def _check_rule_1(self, finding: Any) -> ConflictInfo | None:
        """
        Rule 1: Exploitability must match final_status.

        If exploitability is NOT_EXPLOITABLE, final_status must also be NOT_EXPLOITABLE.
        """
        exploitability = self._get_exploitability(finding)
        final_status = self._get_final_status(finding)

        if not exploitability or not final_status:
            return None

        # Normalize for comparison
        exp_normalized = exploitability.lower().strip()
        status_normalized = final_status.lower().strip()

        # Check for mismatch
        if exp_normalized in ["not_exploitable", "safe"]:
            if status_normalized != "not_exploitable":
                return ConflictInfo(
                    conflict_type="RULE_1_EXPLOITABILITY_STATUS_MISMATCH",
                    finding_ids=[finding.id],
                    details=f"Finding {finding.id}: exploitability={exploitability} "
                           f"but final_status={final_status}",
                )

        if exp_normalized in ["exploitable", "confirmed"]:
            if status_normalized == "not_exploitable":
                return ConflictInfo(
                    conflict_type="RULE_1_EXPLOITABILITY_STATUS_MISMATCH",
                    finding_ids=[finding.id],
                    details=f"Finding {finding.id}: exploitability={exploitability} "
                           f"but final_status={final_status}",
                )

        return None

    def _check_rule_2(
        self, vuln_id: str, findings: list[Any]
    ) -> ConflictInfo | None:
        """
        Rule 2: Same logical_vuln_id cannot have EXPLOITABLE + NOT_EXPLOITABLE.

        This is a critical inconsistency - the same vulnerability cannot be
        both exploitable and not exploitable.
        """
        has_exploitable = False
        has_not_exploitable = False
        finding_ids = []

        for finding in findings:
            status = self._get_final_status(finding)
            if status:
                normalized = status.lower().strip()
                if normalized == "exploitable":
                    has_exploitable = True
                    finding_ids.append(finding.id)
                elif normalized == "not_exploitable":
                    has_not_exploitable = True
                    finding_ids.append(finding.id)

        if has_exploitable and has_not_exploitable:
            return ConflictInfo(
                conflict_type="RULE_2_STATUS_CONFLICT",
                finding_ids=finding_ids,
                details=f"Vulnerability {vuln_id} has both EXPLOITABLE and "
                       f"NOT_EXPLOITABLE statuses across findings",
            )

        return None

    def _check_rule_3(
        self, vuln_id: str, findings: list[Any]
    ) -> ConflictInfo | None:
        """
        Rule 3: No cross-engine status conflicts.

        Different engines should not produce contradictory statuses
        for the same logical vulnerability.
        """
        engine_statuses: dict[str, str] = {}
        finding_ids = []

        for finding in findings:
            source = getattr(finding, "source", "unknown")
            status = self._get_final_status(finding)

            if status:
                normalized = status.lower().strip()
                if source in engine_statuses:
                    if engine_statuses[source] != normalized:
                        finding_ids.append(finding.id)
                else:
                    engine_statuses[source] = normalized

        # Check for conflicts between engines
        unique_statuses = set(engine_statuses.values())
        if len(unique_statuses) > 1 and len(engine_statuses) > 1:
            # Check if statuses are truly conflicting (not just different levels)
            levels = [self._get_status_level(s) for s in unique_statuses]
            if max(levels) > StatusLevel.CONDITIONAL and min(levels) < StatusLevel.CONDITIONAL:
                return ConflictInfo(
                    conflict_type="RULE_3_CROSS_ENGINE_CONFLICT",
                    finding_ids=finding_ids,
                    details=f"Vulnerability {vuln_id} has conflicting statuses "
                           f"across engines: {engine_statuses}",
                )

        return None

    def _check_rule_4(
        self, vuln_id: str, findings: list[Any]
    ) -> ConflictInfo | None:
        """
        Rule 4: No status regression.

        Status hierarchy: NOT_EXPLOITABLE < INFORMATIONAL < CONDITIONAL < EXPLOITABLE

        All findings for the same vulnerability should converge to the highest
        status level, not have arbitrary different levels.
        """
        levels: list[tuple[str, str, int]] = []  # (finding_id, status, level)

        for finding in findings:
            status = self._get_final_status(finding)
            if status:
                level = self._get_status_level(status)
                levels.append((finding.id, status, level))

        if not levels:
            return None

        # Find max and min levels
        max_level = max(l[2] for l in levels)
        min_level = min(l[2] for l in levels)

        # If there's a significant gap (>1 level), it's a regression issue
        if max_level - min_level >= 2:
            finding_ids = [l[0] for l in levels]
            status_details = [(l[1], l[2]) for l in levels]
            return ConflictInfo(
                conflict_type="RULE_4_STATUS_REGRESSION",
                finding_ids=finding_ids,
                details=f"Vulnerability {vuln_id} has status regression: "
                       f"levels range from {min_level} to {max_level} "
                       f"({status_details})",
            )

        return None

    def _check_rule_5(self, finding: Any) -> ConflictInfo | None:
        """
        Rule 5: final_status cannot be None.

        Every finding must have a final_status after adjudication.
        """
        final_status = self._get_final_status(finding)

        if final_status is None:
            return ConflictInfo(
                conflict_type="RULE_5_MISSING_FINAL_STATUS",
                finding_ids=[finding.id],
                details=f"Finding {finding.id} has no final_status after adjudication",
            )

        return None


def validate_consistency(
    findings: list[Any],
    strict: bool = True,
) -> ConsistencyCheckResult:
    """
    Convenience function to validate consistency of findings.

    Args:
        findings: List of Finding objects to validate.
        strict: If True, raise exceptions on conflicts.

    Returns:
        ConsistencyCheckResult with validation results.

    Raises:
        GlobalAdjudicationError: If strict=True and conflicts found.
    """
    checker = AdjudicationConsistencyChecker(strict=strict)
    return checker.validate_findings(findings)


# Module exports
__all__ = [
    "StatusLevel",
    "STATUS_LEVELS",
    "GlobalAdjudicationError",
    "ConflictInfo",
    "ConsistencyCheckResult",
    "generate_logical_vuln_id",
    "AdjudicationConsistencyChecker",
    "validate_consistency",
]
