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


def apply_full_report_status(findings: list[Any]) -> dict[str, int]:
    """
    P6-04: Apply full report status including subtypes.

    This function:
    1. Maps each finding to a ReportStatus
    2. Applies conditional/informational subtypes
    3. Sets all status fields on findings
    4. Returns count by status and subtype

    Args:
        findings: List of Finding objects.

    Returns:
        Dictionary with count by status and subtype.
    """
    # Apply base status
    base_counts = apply_report_status(findings)

    # Apply subtypes
    subtype_counts = apply_status_subtypes(findings)

    # Combine counts
    return {
        **base_counts,
        **subtype_counts,
    }


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


# =============================================================================
# P6-03: Evidence Strength Display
# =============================================================================

# Evidence strength display map
EVIDENCE_STRENGTH_DISPLAY = {
    "strong": ("💪", "green", "Strong evidence - multi-engine validation"),
    "medium": ("👍", "yellow", "Medium evidence - high confidence detection"),
    "weak": ("⚠️", "orange", "Weak evidence - needs manual verification"),
    "speculative": ("❓", "red", "Speculative - likely false positive"),
}


def get_evidence_strength_display(finding: Any) -> tuple[str, str, str]:
    """
    Get display information for evidence strength.

    Args:
        finding: Finding object with evidence_strength attribute.

    Returns:
        Tuple of (emoji, color, description) for display.
    """
    strength = getattr(finding, "evidence_strength", None)
    if strength is None:
        return ("❔", "white", "Not assessed")

    # Handle enum or string
    strength_str = strength.value if hasattr(strength, "value") else str(strength)

    return EVIDENCE_STRENGTH_DISPLAY.get(
        strength_str,
        ("❔", "white", "Unknown evidence strength")
    )


def get_evidence_strength_counts(findings: list[Any]) -> dict[str, int]:
    """
    Count findings by evidence strength.

    Args:
        findings: List of Finding objects.

    Returns:
        Dictionary with count by evidence strength.
    """
    counts = {
        "strong": 0,
        "medium": 0,
        "weak": 0,
        "speculative": 0,
        "not_assessed": 0,
    }

    for finding in findings:
        strength = getattr(finding, "evidence_strength", None)
        if strength is None:
            counts["not_assessed"] += 1
            continue

        # Handle enum or string
        strength_str = strength.value if hasattr(strength, "value") else str(strength)
        if strength_str in counts:
            counts[strength_str] += 1
        else:
            counts["not_assessed"] += 1

    return counts


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
    "apply_full_report_status",
    "sort_by_report_status",
    "get_status_display",
    "filter_non_suppressed",
    "get_actionable_findings",
    # P6-03: Evidence strength
    "EVIDENCE_STRENGTH_DISPLAY",
    "get_evidence_strength_display",
    "get_evidence_strength_counts",
    # P6-04: Status subtypes
    "determine_conditional_subtype",
    "determine_informational_subtype",
    "apply_status_subtypes",
    "apply_full_report_status",
    "get_subtype_display",
    "get_subtype_counts",
    "STATUS_SUBTYPE_DISPLAY",
]


# =============================================================================
# P6-04: Status Subtypes (Taint Analysis + Verification Methodology Integration)
# =============================================================================

# Status subtype display map
STATUS_SUBTYPE_DISPLAY = {
    # Conditional subtypes
    "conditional-strong": ("🟠", "orange", "高置信条件 - 需环境验证"),
    "conditional-weak": ("🟡", "yellow", "低置信条件 - 需人工确认"),
    # Informational subtypes
    "not_exploitable": ("🟢", "green", "确认不可利用"),
    "speculative_signal": ("⚪", "gray", "推测性信号 - 可能误报"),
    "environmental_risk": ("🔵", "blue", "环境相关风险"),
}


def _get_evidence_strength_value(finding: Any) -> str | None:
    """Extract evidence_strength value from finding."""
    strength = getattr(finding, "evidence_strength", None)
    if strength is None:
        return None
    return strength.value if hasattr(strength, "value") else str(strength)


def _get_exploitability_value(finding: Any) -> str | None:
    """Extract exploitability value from finding."""
    exploitability = getattr(finding, "exploitability", None)
    if exploitability is None:
        return None
    return str(exploitability).lower().strip()


def _get_finding_type_value(finding: Any) -> str | None:
    """Extract finding type value from finding."""
    finding_type = getattr(finding, "type", None)
    if finding_type is None:
        return None
    return finding_type.value if hasattr(finding_type, "value") else str(finding_type)


def determine_conditional_subtype(finding: Any) -> str:
    """
    P6-04a: Determine conditional subtype based on evidence and exploitability.

    Classification rules:
    - conditional-strong: High confidence but needs environment verification
      - evidence_strength = strong/medium AND exploitability = likely/possible
    - conditional-weak: Lower confidence, needs manual confirmation
      - evidence_strength = weak OR exploitability = possible/unlikely

    Args:
        finding: Finding object with evidence_strength and exploitability.

    Returns:
        Subtype string: "conditional-strong" or "conditional-weak"
    """
    evidence = _get_evidence_strength_value(finding)
    exploitability = _get_exploitability_value(finding)

    # Strong evidence + likely/possible exploitability = conditional-strong
    if evidence in ["strong", "medium"]:
        if exploitability in ["likely", "possible", "exploitable"]:
            return "conditional-strong"
        # Strong evidence but exploitability unclear
        if exploitability is None:
            return "conditional-strong"

    # Weak evidence or unlikely exploitability = conditional-weak
    if evidence == "weak":
        return "conditional-weak"

    # Default to weak if uncertain
    if exploitability in ["unlikely"]:
        return "conditional-weak"

    # Default to strong if has cross-engine validation
    related_engines = getattr(finding, "related_engines", [])
    if len(related_engines) >= 2:
        return "conditional-strong"

    # Default to weak
    return "conditional-weak"


def determine_informational_subtype(finding: Any) -> str:
    """
    P6-04b: Determine informational subtype based on verification methodology.

    Classification rules:
    - not_exploitable: Confirmed as not exploitable
      - exploitability = not_exploitable
    - speculative_signal: Speculative finding, likely false positive
      - evidence_strength = speculative OR finding.type = suspicious
    - environmental_risk: Requires specific conditions to exploit
      - metadata indicates config/permission requirements

    Args:
        finding: Finding object with exploitability, evidence_strength, etc.

    Returns:
        Subtype string: "not_exploitable", "speculative_signal", or "environmental_risk"
    """
    evidence = _get_evidence_strength_value(finding)
    exploitability = _get_exploitability_value(finding)
    finding_type = _get_finding_type_value(finding)

    # Rule 1: Not exploitable
    if exploitability == "not_exploitable":
        return "not_exploitable"

    # Rule 2: Speculative signal
    if evidence == "speculative":
        return "speculative_signal"
    if finding_type == "suspicious":
        return "speculative_signal"

    # Rule 3: Check for environmental requirements
    metadata = getattr(finding, "metadata", {})
    if isinstance(metadata, dict):
        # Check for environmental indicators
        if metadata.get("requires_auth") or metadata.get("requires_config"):
            return "environmental_risk"
        if metadata.get("environmental_conditions"):
            return "environmental_risk"
        # Check confidence score
        confidence_score = getattr(finding, "confidence_score", None)
        if confidence_score is not None and confidence_score < 50:
            return "speculative_signal"

    # Default to not_exploitable for informational
    return "not_exploitable"


def apply_status_subtypes(findings: list[Any]) -> dict[str, int]:
    """
    P6-04: Apply status subtypes to findings.

    This function:
    1. Determines subtype for each finding based on its status
    2. Sets finding.conditional_subtype or finding.informational_subtype
    3. Returns count by subtype

    Args:
        findings: List of Finding objects.

    Returns:
        Dictionary with count by subtype.
    """
    counts = {
        "conditional-strong": 0,
        "conditional-weak": 0,
        "not_exploitable": 0,
        "speculative_signal": 0,
        "environmental_risk": 0,
    }

    for finding in findings:
        status = map_to_report_status(finding)

        if status == ReportStatus.CONDITIONAL:
            subtype = determine_conditional_subtype(finding)
            if hasattr(finding, "conditional_subtype"):
                finding.conditional_subtype = subtype  # type: ignore
            counts[subtype] += 1

        elif status == ReportStatus.INFORMATIONAL:
            subtype = determine_informational_subtype(finding)
            if hasattr(finding, "informational_subtype"):
                finding.informational_subtype = subtype  # type: ignore
            counts[subtype] += 1

    return counts


def get_subtype_display(finding: Any) -> tuple[str, str, str]:
    """
    Get display information for a finding's subtype.

    Args:
        finding: Finding object with conditional_subtype or informational_subtype.

    Returns:
        Tuple of (emoji, color, description) for display.
    """
    # Check conditional subtype
    conditional = getattr(finding, "conditional_subtype", None)
    if conditional:
        subtype = conditional.value if hasattr(conditional, "value") else str(conditional)
        return STATUS_SUBTYPE_DISPLAY.get(subtype, ("❓", "white", "Unknown subtype"))

    # Check informational subtype
    informational = getattr(finding, "informational_subtype", None)
    if informational:
        subtype = informational.value if hasattr(informational, "value") else str(informational)
        return STATUS_SUBTYPE_DISPLAY.get(subtype, ("❓", "white", "Unknown subtype"))

    # No subtype
    return ("❓", "white", "No subtype")


def get_subtype_counts(findings: list[Any]) -> dict[str, int]:
    """
    Count findings by subtype.

    Args:
        findings: List of Finding objects.

    Returns:
        Dictionary with count by subtype.
    """
    counts = {
        "conditional-strong": 0,
        "conditional-weak": 0,
        "not_exploitable": 0,
        "speculative_signal": 0,
        "environmental_risk": 0,
        "no_subtype": 0,
    }

    for finding in findings:
        # Check conditional subtype
        conditional = getattr(finding, "conditional_subtype", None)
        if conditional:
            subtype = conditional.value if hasattr(conditional, "value") else str(conditional)
            if subtype in counts:
                counts[subtype] += 1
                continue

        # Check informational subtype
        informational = getattr(finding, "informational_subtype", None)
        if informational:
            subtype = informational.value if hasattr(informational, "value") else str(informational)
            if subtype in counts:
                counts[subtype] += 1
                continue

        counts["no_subtype"] += 1

    return counts
