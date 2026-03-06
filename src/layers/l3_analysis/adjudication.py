"""
Exploitability Adjudication Module

This module implements the Exploitability Override mechanism where
exploitability becomes the primary adjudication factor for determining
the final status of a vulnerability finding.

Core Principle: Exploitability > Severity > Confidence

Rules:
1. NOT_EXPLOITABLE → final_status = not_exploitable (unconditional override)
2. UNLIKELY + HIGH/CRITICAL → downgraded to conditional
3. EXPLOITABLE + HIGH/CRITICAL → final_status = exploitable
4. No exploitability → default to conditional

This is ADJUDICATION logic, not SCORING logic.
- final_score is preserved for sorting
- final_status is the adjudication result

P4-03: Global Adjudication Consistency
- After adjudication, global consistency is enforced
- Consistency violations raise GlobalAdjudicationError
- No silent fixes, no auto-merge, explicit errors only
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.consistency import (
    AdjudicationConsistencyChecker,
    ConsistencyCheckResult,
    GlobalAdjudicationError,
)
from src.layers.l3_analysis.deduplicator import (
    ASTDeduplicator,
    DeduplicationResult,
)
from src.layers.l3_analysis.reporting import (
    apply_report_status,
)


class FinalStatus(str, Enum):
    """
    Final adjudication status based on exploitability override.

    This is the authoritative status that determines how findings
    should be treated in reports and workflows.
    """

    EXPLOITABLE = "exploitable"
    """Confirmed exploitable - requires immediate action."""

    CONDITIONAL = "conditional"
    """Potentially exploitable - requires context review."""

    NOT_EXPLOITABLE = "not_exploitable"
    """Confirmed not exploitable - informational only."""

    INFORMATIONAL = "informational"
    """Low severity or context-dependent - no immediate action."""


class ArchitectureViolationError(Exception):
    """
    Raised when an architectural constraint is violated.

    This should never happen in normal operation. It indicates
    a logic error in the adjudication system.
    """

    pass


@dataclass
class AdjudicationResult:
    """
    Result of applying exploitability override to a finding.
    """

    finding_id: str
    """ID of the finding that was adjudicated."""

    final_status: FinalStatus
    """The adjudicated final status."""

    exploitability: str | None
    """The exploitability value used for adjudication."""

    severity: str
    """The original severity value."""

    override_applied: bool = False
    """Whether an override was applied (vs default behavior)."""

    override_reason: str = ""
    """Human-readable reason for the override."""

    conflict_detected: bool = False
    """Whether a conflict was detected (should not happen)."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for metadata storage."""
        return {
            "finding_id": self.finding_id,
            "final_status": self.final_status.value,
            "exploitability": self.exploitability,
            "severity": self.severity,
            "override_applied": self.override_applied,
            "override_reason": self.override_reason,
            "conflict_detected": self.conflict_detected,
        }


@dataclass
class AdjudicationSummary:
    """
    Summary of adjudication results for a batch of findings.
    """

    total_findings: int = 0
    """Total number of findings adjudicated."""

    by_status: dict[str, int] = field(default_factory=lambda: {
        "exploitable": 0,
        "conditional": 0,
        "not_exploitable": 0,
        "informational": 0,
    })
    """Count of findings by final status."""

    overrides_applied: int = 0
    """Number of findings where override was applied."""

    conflicts_detected: int = 0
    """Number of conflicts detected (should be 0)."""

    # P4-03: Global consistency check result
    consistency_check: dict[str, Any] | None = None
    """Result of global consistency check (P4-03)."""

    # P4-04: Deduplication result
    deduplication: dict[str, Any] | None = None
    """Result of semantic deduplication (P4-04)."""

    # P4-05: Unified report status counts
    report_status: dict[str, int] | None = None
    """Count of findings by unified report status (P4-05)."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for metadata storage."""
        return {
            "override_enabled": True,
            "total_findings": self.total_findings,
            "overrides_applied": self.overrides_applied,
            "conflict_detected": self.conflicts_detected > 0,
            "by_status": self.by_status,
            "consistency_check": self.consistency_check,
            "deduplication": self.deduplication,
            "report_status": self.report_status,
        }


def get_exploitability_value(finding: Any) -> str | None:
    """
    Extract exploitability value from a finding.

    Checks multiple locations where exploitability might be stored:
    1. finding.exploitability (direct attribute)
    2. finding.metadata["exploitability"] (in metadata)

    Args:
        finding: Finding object.

    Returns:
        Exploitability string or None if not found.
    """
    # Check direct attribute
    if hasattr(finding, "exploitability"):
        exp = finding.exploitability
        if exp is not None:
            if hasattr(exp, "value"):
                return exp.value
            return str(exp).lower()

    # Check metadata
    if hasattr(finding, "metadata") and isinstance(finding.metadata, dict):
        exp = finding.metadata.get("exploitability")
        if exp is not None:
            if hasattr(exp, "value"):
                return exp.value
            return str(exp).lower()

    return None


def get_severity_value(finding: Any) -> str:
    """
    Extract severity value from a finding.

    Args:
        finding: Finding object.

    Returns:
        Severity string (lowercase).
    """
    if hasattr(finding, "severity"):
        sev = finding.severity
        if hasattr(sev, "value"):
            return sev.value.lower()
        return str(sev).lower()
    return "medium"  # Default


def apply_exploitability_override(finding: Any) -> AdjudicationResult:
    """
    Apply exploitability override to determine final status.

    This is the core adjudication function that enforces the rule:
    Exploitability > Severity > Confidence

    Rules Applied:
    1. NOT_EXPLOITABLE → unconditional override to not_exploitable
    2. UNLIKELY + HIGH/CRITICAL → downgrade to conditional
    3. EXPLOITABLE + HIGH/CRITICAL → exploitable
    4. No exploitability → default to conditional

    Args:
        finding: Finding object to adjudicate.

    Returns:
        AdjudicationResult with the final status and details.
    """
    logger = get_logger(__name__)

    # Extract values
    finding_id = getattr(finding, "id", "unknown")
    exploitability = get_exploitability_value(finding)
    severity = get_severity_value(finding)

    # Normalize exploitability for comparison
    exp_normalized = None
    if exploitability:
        exp_normalized = exploitability.lower().strip()

    # Determine final status based on rules

    # Rule 1: NOT_EXPLOITABLE - unconditional override
    if exp_normalized in ["not_exploitable", "not exploitable", "safe"]:
        result = AdjudicationResult(
            finding_id=finding_id,
            final_status=FinalStatus.NOT_EXPLOITABLE,
            exploitability=exploitability,
            severity=severity,
            override_applied=True,
            override_reason="NOT_EXPLOITABLE overrides all other factors",
        )

        # Apply to finding
        if hasattr(finding, "final_status"):
            finding.final_status = FinalStatus.NOT_EXPLOITABLE

        logger.debug(f"Finding {finding_id}: NOT_EXPLOITABLE override applied")
        return result

    # Rule 2: UNLIKELY - downgrade HIGH/CRITICAL to conditional
    if exp_normalized == "unlikely":
        if severity in ["high", "critical"]:
            result = AdjudicationResult(
                finding_id=finding_id,
                final_status=FinalStatus.CONDITIONAL,
                exploitability=exploitability,
                severity=severity,
                override_applied=True,
                override_reason=f"UNLIKELY downgrades {severity.upper()} to CONDITIONAL",
            )
        else:
            result = AdjudicationResult(
                finding_id=finding_id,
                final_status=FinalStatus.CONDITIONAL,
                exploitability=exploitability,
                severity=severity,
                override_applied=False,
                override_reason="UNLIKELY with lower severity defaults to CONDITIONAL",
            )

        if hasattr(finding, "final_status"):
            finding.final_status = result.final_status

        return result

    # Rule 3: EXPLOITABLE - can confirm high severity
    if exp_normalized in ["exploitable", "confirmed"]:
        if severity in ["high", "critical"]:
            result = AdjudicationResult(
                finding_id=finding_id,
                final_status=FinalStatus.EXPLOITABLE,
                exploitability=exploitability,
                severity=severity,
                override_applied=True,
                override_reason=f"EXPLOITABLE confirms {severity.upper()} as EXPLOITABLE",
            )
        else:
            # Lower severity exploitable stays conditional
            result = AdjudicationResult(
                finding_id=finding_id,
                final_status=FinalStatus.CONDITIONAL,
                exploitability=exploitability,
                severity=severity,
                override_applied=False,
                override_reason=f"EXPLOITABLE with {severity} defaults to CONDITIONAL",
            )

        if hasattr(finding, "final_status"):
            finding.final_status = result.final_status

        return result

    # Rule 4: LIKELY - elevated but not confirmed
    if exp_normalized == "likely":
        if severity in ["high", "critical"]:
            result = AdjudicationResult(
                finding_id=finding_id,
                final_status=FinalStatus.CONDITIONAL,
                exploitability=exploitability,
                severity=severity,
                override_applied=True,
                override_reason=f"LIKELY with {severity.upper()} remains CONDITIONAL (not confirmed)",
            )
        else:
            result = AdjudicationResult(
                finding_id=finding_id,
                final_status=FinalStatus.CONDITIONAL,
                exploitability=exploitability,
                severity=severity,
                override_applied=False,
                override_reason="LIKELY defaults to CONDITIONAL",
            )

        if hasattr(finding, "final_status"):
            finding.final_status = result.final_status

        return result

    # Rule 5: POSSIBLE - default conditional
    if exp_normalized == "possible":
        result = AdjudicationResult(
            finding_id=finding_id,
            final_status=FinalStatus.CONDITIONAL,
            exploitability=exploitability,
            severity=severity,
            override_applied=False,
            override_reason="POSSIBLE defaults to CONDITIONAL",
        )

        if hasattr(finding, "final_status"):
            finding.final_status = FinalStatus.CONDITIONAL

        return result

    # Rule 6: No exploitability - default to conditional
    result = AdjudicationResult(
        finding_id=finding_id,
        final_status=FinalStatus.CONDITIONAL,
        exploitability=exploitability,
        severity=severity,
        override_applied=False,
        override_reason="No exploitability value - defaulting to CONDITIONAL",
    )

    if hasattr(finding, "final_status"):
        finding.final_status = FinalStatus.CONDITIONAL

    return result


def validate_no_conflict(finding: Any) -> bool:
    """
    Validate that there is no conflict between exploitability and final_status.

    A conflict occurs when:
    - exploitability is NOT_EXPLOITABLE
    - final_status is EXPLOITABLE

    This should NEVER happen if apply_exploitability_override is used correctly.

    Args:
        finding: Finding object to validate.

    Returns:
        True if no conflict, raises ArchitectureViolationError if conflict.

    Raises:
        ArchitectureViolationError: If a conflict is detected.
    """
    exploitability = get_exploitability_value(finding)
    final_status = getattr(finding, "final_status", None)

    if final_status is None:
        return True

    # Normalize values
    exp_normalized = exploitability.lower().strip() if exploitability else None
    status_value = final_status.value if hasattr(final_status, "value") else str(final_status)

    # Check for conflict
    if exp_normalized in ["not_exploitable", "not exploitable", "safe"]:
        if status_value == "exploitable":
            finding_id = getattr(finding, "id", "unknown")
            raise ArchitectureViolationError(
                f"Finding {finding_id} has conflict: "
                f"exploitability={exploitability} but final_status={status_value}. "
                f"This indicates a logic error in the adjudication system."
            )

    return True


def adjudicate_findings(
    findings: list[Any],
    validate: bool = True,
    strict_consistency: bool = True,
    enable_deduplication: bool = True,
) -> tuple[list[Any], AdjudicationSummary]:
    """
    Apply exploitability override to a batch of findings.

    This function:
    1. Applies exploitability override to each finding
    2. Validates for individual conflicts
    3. Performs semantic deduplication (P4-04)
    4. Enforces global consistency (P4-03)
    5. Returns summary statistics

    Args:
        findings: List of Finding objects to adjudicate.
        validate: Whether to validate for conflicts (default: True).
        strict_consistency: If True, raise GlobalAdjudicationError on consistency
                           violations. If False, return result with conflicts listed.
        enable_deduplication: If True, perform semantic deduplication (default: True).

    Returns:
        Tuple of (adjudicated_findings, summary).

    Raises:
        GlobalAdjudicationError: If strict_consistency=True and global consistency
                                violations are detected.
    """
    logger = get_logger(__name__)
    summary = AdjudicationSummary()
    summary.total_findings = len(findings)

    for finding in findings:
        # Apply override
        result = apply_exploitability_override(finding)

        # Track statistics
        status_key = result.final_status.value
        summary.by_status[status_key] = summary.by_status.get(status_key, 0) + 1

        if result.override_applied:
            summary.overrides_applied += 1

        # Validate for conflicts
        if validate:
            try:
                validate_no_conflict(finding)
            except ArchitectureViolationError as e:
                summary.conflicts_detected += 1
                logger.error(f"Conflict detected: {e}")

    # P4-04: Semantic Deduplication
    # Deduplicate AFTER adjudication but BEFORE consistency check
    if enable_deduplication:
        deduplicator = ASTDeduplicator()
        dedup_result = deduplicator.deduplicate(findings)

        # Update findings to deduplicated list
        findings = dedup_result.unique_findings

        # Store deduplication result in summary metadata
        summary.deduplication = dedup_result.to_dict()

        logger.info(
            f"Semantic deduplication: {summary.total_findings} -> {len(findings)} findings "
            f"({dedup_result.removed_count} removed, {dedup_result.merged_groups} groups merged)"
        )

    # P4-03: Global Adjudication Consistency Check
    # This is the FINAL consistency check before output.
    # All conflicts are explicitly raised - never silently corrected.
    consistency_checker = AdjudicationConsistencyChecker(strict=strict_consistency)
    consistency_result = consistency_checker.validate_findings(findings)

    # Store consistency check result in summary metadata
    if not hasattr(summary, 'consistency_check'):
        summary.consistency_check = None  # type: ignore
    summary.consistency_check = consistency_result.to_dict()  # type: ignore

    if not consistency_result.passed:
        logger.error(
            f"Global adjudication consistency check failed: "
            f"{len(consistency_result.conflicts)} conflicts found"
        )
        # In strict mode, GlobalAdjudicationError is already raised by the checker
        # In non-strict mode, we just log and continue

    # P4-05: Apply unified report status
    # This is the FINAL step - map internal states to unified report status
    report_counts = apply_report_status(findings)
    summary.report_status = report_counts  # type: ignore

    logger.info(
        f"Applied report status: {report_counts}"
    )

    return findings, summary


def get_final_status(finding: Any) -> FinalStatus:
    """
    Get the final status of a finding.

    If final_status is not set, applies the override and returns the result.

    Args:
        finding: Finding object.

    Returns:
        FinalStatus enum value.
    """
    if hasattr(finding, "final_status") and finding.final_status is not None:
        status = finding.final_status
        if isinstance(status, FinalStatus):
            return status
        # Handle string values
        return FinalStatus(status)

    # Apply override if not set
    result = apply_exploitability_override(finding)
    return result.final_status


def is_exploitable(finding: Any) -> bool:
    """
    Check if a finding is adjudicated as exploitable.

    Args:
        finding: Finding object.

    Returns:
        True if final_status is EXPLOITABLE.
    """
    status = get_final_status(finding)
    return status == FinalStatus.EXPLOITABLE


def requires_action(finding: Any) -> bool:
    """
    Check if a finding requires action.

    Findings that require action:
    - EXPLOITABLE
    - CONDITIONAL

    Findings that don't require action:
    - NOT_EXPLOITABLE
    - INFORMATIONAL

    Args:
        finding: Finding object.

    Returns:
        True if finding requires action.
    """
    status = get_final_status(finding)
    return status in [FinalStatus.EXPLOITABLE, FinalStatus.CONDITIONAL]


# Convenience exports
__all__ = [
    "FinalStatus",
    "ArchitectureViolationError",
    "AdjudicationResult",
    "AdjudicationSummary",
    "apply_exploitability_override",
    "validate_no_conflict",
    "adjudicate_findings",
    "get_final_status",
    "is_exploitable",
    "requires_action",
    "get_exploitability_value",
    "get_severity_value",
    # P4-03: Re-export consistency types for convenience
    "GlobalAdjudicationError",
    "AdjudicationConsistencyChecker",
    "ConsistencyCheckResult",
    # P4-04: Re-export deduplication types for convenience
    "ASTDeduplicator",
    "DeduplicationResult",
]
