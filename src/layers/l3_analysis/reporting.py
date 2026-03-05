"""
Unified Report Status Module

This module implements the unified report status system that provides
a consistent, stable, and simple status for external output.

Core Principle: Internal Complexity, External Simplicity

The system internally tracks many attributes:
- severity
- exploitability
- final_score
- final_status
- duplicate_count
- related_engines

But the EXTERNAL output only exposes FOUR states:
- EXPLOITABLE: Confirmed exploitable - requires immediate action
- CONDITIONAL: Potentially exploitable - requires context review
- INFORMATIONAL: Low severity or context-dependent - no immediate action
- SUPPRESSED: Filtered out (duplicate, budget exceeded, etc.)

P4-05: Report Status Unification
- Only four states in output
- No "confirmed" as status (use EXPLOITABLE)
- Severity only for sorting/display, not status
- CI-friendly output
"""

from enum import Enum
from typing import Any

from src.core.logger.logger import get_logger


class ReportStatus(str, Enum):
    """
    Unified report status for external output.

    This is the ONLY status that should appear in reports and CLI output.
    All internal states are mapped to these four values.

    Order (highest to lowest priority):
    1. EXPLOITABLE - Requires immediate action
    2. CONDITIONAL - Requires context review
    3. INFORMATIONAL - No immediate action needed
    4. SUPPRESSED - Filtered out, not shown
    """

    EXPLOITABLE = "exploitable"
    """Confirmed exploitable - requires immediate action."""

    CONDITIONAL = "conditional"
    """Potentially exploitable - requires context review."""

    INFORMATIONAL = "informational"
    """Low severity or context-dependent - no immediate action."""

    SUPPRESSED = "suppressed"
    """Filtered out (duplicate, budget exceeded, gated, etc.)."""


# Status priority for sorting (higher = more urgent)
STATUS_PRIORITY = {
    ReportStatus.EXPLOITABLE: 4,
    ReportStatus.CONDITIONAL: 3,
    ReportStatus.INFORMATIONAL: 2,
    ReportStatus.SUPPRESSED: 1,
}


def is_suppressed(finding: Any) -> bool:
    """
    Check if a finding should be suppressed.

    Suppression conditions:
    1. duplicate_count > 0 AND finding was merged (removed from output)
    2. metadata.suppressed = True
    3. metadata.filtered_by = "finding_budget" | "rule_gating" | "ast_validator"

    Args:
        finding: Finding object to check.

    Returns:
        True if finding should be suppressed.
    """
    # Check explicit suppression flag
    if hasattr(finding, "metadata") and isinstance(finding.metadata, dict):
        if finding.metadata.get("suppressed") is True:
            return True

        # Check if filtered by budget, gating, or validation
        filtered_by = finding.metadata.get("filtered_by")
        if filtered_by in ["finding_budget", "rule_gating", "ast_validator", "file_filter"]:
            return True

    # Note: duplicate_count > 0 on a finding in the output means it's the PRIMARY
    # finding that absorbed duplicates - it should NOT be suppressed.
    # Only findings that were REMOVED during deduplication are suppressed.
    # Those are not in the output list, so we don't need to check duplicate_count here.

    return False


def get_final_status_value(finding: Any) -> str | None:
    """
    Extract final_status value from a finding.

    Args:
        finding: Finding object.

    Returns:
        final_status string or None.
    """
    if not hasattr(finding, "final_status"):
        return None

    status = finding.final_status
    if status is None:
        return None

    # Handle enum
    if hasattr(status, "value"):
        return status.value.lower().strip()

    return str(status).lower().strip()


def map_to_report_status(finding: Any) -> ReportStatus:
    """
    Map a finding's internal state to a unified report status.

    Mapping rules (in order of priority):

    1. SUPPRESSED: If finding is suppressed (see is_suppressed())

    2. EXPLOITABLE: If final_status is "exploitable"

    3. CONDITIONAL: If final_status is "conditional"

    4. INFORMATIONAL: If final_status is "not_exploitable" or "informational"

    5. Default to CONDITIONAL if no status available

    IMPORTANT: This function does NOT use severity to determine status.
    Severity is only for sorting and display purposes.

    Args:
        finding: Finding object to map.

    Returns:
        ReportStatus enum value.
    """
    logger = get_logger(__name__)

    # Rule 2: Check if suppressed first
    if is_suppressed(finding):
        return ReportStatus.SUPPRESSED

    # Get final_status
    final_status = get_final_status_value(finding)

    # Rule 1: Map final_status to report_status
    if final_status:
        if final_status == "exploitable":
            return ReportStatus.EXPLOITABLE
        elif final_status == "conditional":
            return ReportStatus.CONDITIONAL
        elif final_status in ["not_exploitable", "informational"]:
            return ReportStatus.INFORMATIONAL

    # Default to CONDITIONAL if no status
    logger.debug(
        f"Finding {getattr(finding, 'id', 'unknown')} has no final_status, "
        f"defaulting to CONDITIONAL"
    )
    return ReportStatus.CONDITIONAL


def apply_report_status(findings: list[Any]) -> dict[str, int]:
    """
    Apply report status to a list of findings.

    This function:
    1. Maps each finding to a ReportStatus
    2. Sets finding.report_status
    3. Returns count by status

    Args:
        findings: List of Finding objects.

    Returns:
        Dictionary with count by status.
    """
    counts = {
        "exploitable": 0,
        "conditional": 0,
        "informational": 0,
        "suppressed": 0,
    }

    for finding in findings:
        status = map_to_report_status(finding)

        # Set report_status on finding
        if hasattr(finding, "report_status"):
            finding.report_status = status.value  # type: ignore

        counts[status.value] += 1

    return counts


def sort_by_report_status(findings: list[Any], descending: bool = True) -> list[Any]:
    """
    Sort findings by report status priority.

    Order (descending):
    1. EXPLOITABLE
    2. CONDITIONAL
    3. INFORMATIONAL
    4. SUPPRESSED

    Args:
        findings: List of Finding objects.
        descending: If True, highest priority first.

    Returns:
        Sorted list of findings.
    """
    def get_priority(finding: Any) -> int:
        status_str = getattr(finding, "report_status", None)
        if status_str is None:
            # Calculate if not set
            status = map_to_report_status(finding)
            return STATUS_PRIORITY.get(status, 0)

        try:
            status = ReportStatus(status_str)
            return STATUS_PRIORITY.get(status, 0)
        except ValueError:
            return 0

    return sorted(findings, key=get_priority, reverse=descending)


def get_status_display(status: ReportStatus | str) -> tuple[str, str]:
    """
    Get display information for a status.

    Args:
        status: ReportStatus enum or string value.

    Returns:
        Tuple of (emoji, color) for display.
    """
    if isinstance(status, str):
        try:
            status = ReportStatus(status)
        except ValueError:
            return ("❓", "white")

    display_map = {
        ReportStatus.EXPLOITABLE: ("🔴", "red"),
        ReportStatus.CONDITIONAL: ("🟡", "yellow"),
        ReportStatus.INFORMATIONAL: ("🔵", "blue"),
        ReportStatus.SUPPRESSED: ("⚫", "dim"),
    }

    return display_map.get(status, ("❓", "white"))


def filter_non_suppressed(findings: list[Any]) -> list[Any]:
    """
    Filter out suppressed findings from a list.

    Args:
        findings: List of Finding objects.

    Returns:
        List with suppressed findings removed.
    """
    return [
        f for f in findings
        if map_to_report_status(f) != ReportStatus.SUPPRESSED
    ]


def get_actionable_findings(findings: list[Any]) -> list[Any]:
    """
    Get findings that require action (EXPLOITABLE or CONDITIONAL).

    Args:
        findings: List of Finding objects.

    Returns:
        List of actionable findings.
    """
    return [
        f for f in findings
        if map_to_report_status(f) in [ReportStatus.EXPLOITABLE, ReportStatus.CONDITIONAL]
    ]


# Module exports
__all__ = [
    "ReportStatus",
    "STATUS_PRIORITY",
    "is_suppressed",
    "get_final_status_value",
    "map_to_report_status",
    "apply_report_status",
    "sort_by_report_status",
    "get_status_display",
    "filter_non_suppressed",
    "get_actionable_findings",
]
