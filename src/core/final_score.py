"""
Final Score Calculator - Unified scoring system for vulnerability findings.

This module provides a standardized scoring mechanism that combines:
- Severity (40% weight)
- Exploitability (40% weight)
- Confidence (20% weight)
- Engine weight multiplier

The final score enables consistent prioritization across all analysis engines
(Semgrep, CodeQL, Agent) and prepares for Exploitability-based adjudication.

Core principle: Precision over recall. Build foundation, don't replace.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.core.logger.logger import get_logger


# =============================================================================
# Constants - All weights are configurable constants for easy tuning
# =============================================================================

# Score component weights (must sum to 1.0)
SEVERITY_WEIGHT: float = 0.4
EXPLOITABILITY_WEIGHT: float = 0.4
CONFIDENCE_WEIGHT: float = 0.2

# Severity score mapping
SEVERITY_SCORES: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.4,
    "info": 0.2,
}

# Exploitability score mapping
EXPLOITABILITY_SCORES: dict[str, float] = {
    "exploitable": 1.0,
    "likely": 0.7,
    "possible": 0.5,
    "unlikely": 0.3,
    "not_exploitable": 0.0,
    # Aliases
    "confirmed": 1.0,  # Alias for exploitable
    "potential": 0.5,  # Alias for possible
    "safe": 0.0,  # Alias for not_exploitable
}

# Engine weight mapping (based on engine reliability/depth)
ENGINE_WEIGHTS: dict[str, float] = {
    "opencode_agent": 1.2,  # Agent has deepest analysis
    "agent": 1.2,  # Alias
    "codeql": 1.0,  # CodeQL has good dataflow analysis
    "semgrep": 0.8,  # Semgrep is fast but less deep
    # Default for unknown engines
    "default": 1.0,
}

# Confidence score thresholds
CONFIDENCE_THRESHOLDS: list[tuple[float, float]] = [
    (0.9, 1.0),  # High confidence
    (0.7, 0.9),  # Medium-high
    (0.5, 0.7),  # Medium
    (0.3, 0.5),  # Low-medium
    (0.0, 0.3),  # Low
]


class ExploitabilityLevel(str, Enum):
    """Exploitability level for findings."""

    EXPLOITABLE = "exploitable"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"
    NOT_EXPLOITABLE = "not_exploitable"


@dataclass
class FinalScore:
    """
    Final score calculation result with full breakdown.

    Stores all components used in the final score calculation for
    transparency and debugging.
    """

    total: float
    """Final calculated score (0.0 - 1.2 with engine weight)."""

    severity_score: float
    """Normalized severity score (0.0 - 1.0)."""

    exploitability_score: float
    """Normalized exploitability score (0.0 - 1.0)."""

    confidence_score: float
    """Normalized confidence score (0.0 - 1.0)."""

    engine_weight: float
    """Engine weight multiplier."""

    formula: str = field(default="")
    """Human-readable formula used for calculation."""

    raw_severity: str | None = field(default=None)
    """Original severity value."""

    raw_exploitability: str | None = field(default=None)
    """Original exploitability value."""

    raw_confidence: float | None = field(default=None)
    """Original confidence value."""

    engine: str | None = field(default=None)
    """Engine that produced this finding."""

    def __post_init__(self):
        """Generate formula string if not provided."""
        if not self.formula:
            self.formula = (
                f"({self.severity_score:.2f} * {SEVERITY_WEIGHT} + "
                f"{self.exploitability_score:.2f} * {EXPLOITABILITY_WEIGHT} + "
                f"{self.confidence_score:.2f} * {CONFIDENCE_WEIGHT}) * "
                f"{self.engine_weight:.1f} = {self.total:.3f}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for metadata storage."""
        return {
            "total": round(self.total, 4),
            "severity_score": round(self.severity_score, 4),
            "exploitability_score": round(self.exploitability_score, 4),
            "confidence_score": round(self.confidence_score, 4),
            "engine_weight": round(self.engine_weight, 2),
            "formula": self.formula,
            "raw_severity": self.raw_severity,
            "raw_exploitability": self.raw_exploitability,
            "raw_confidence": self.raw_confidence,
            "engine": self.engine,
        }


def get_severity_score(severity: str | None) -> float:
    """
    Convert severity level to numeric score.

    Args:
        severity: Severity level string (case-insensitive).

    Returns:
        Numeric score (0.0 - 1.0). Defaults to 0.5 for unknown.
    """
    if severity is None:
        return 0.5  # Default to medium for unknown

    normalized = severity.lower().strip()
    return SEVERITY_SCORES.get(normalized, 0.5)


def get_exploitability_score(exploitability: str | None) -> float:
    """
    Convert exploitability level to numeric score.

    Args:
        exploitability: Exploitability level string (case-insensitive).

    Returns:
        Numeric score (0.0 - 1.0). Defaults to 0.5 for unknown.
    """
    if exploitability is None:
        return 0.5  # Default to possible for unknown

    normalized = exploitability.lower().strip()
    return EXPLOITABILITY_SCORES.get(normalized, 0.5)


def get_confidence_score(confidence: float | None) -> float:
    """
    Normalize confidence value.

    Args:
        confidence: Confidence value (0.0 - 1.0).

    Returns:
        Normalized confidence score (0.0 - 1.0).
    """
    if confidence is None:
        return 0.7  # Default to medium-high for unknown

    # Clamp to valid range
    confidence = max(0.0, min(1.0, confidence))

    return confidence


def get_engine_weight(engine: str | None) -> float:
    """
    Get weight multiplier for an analysis engine.

    Args:
        engine: Engine name (case-insensitive).

    Returns:
        Weight multiplier. Defaults to 1.0 for unknown.
    """
    if engine is None:
        return ENGINE_WEIGHTS["default"]

    normalized = engine.lower().strip()
    return ENGINE_WEIGHTS.get(normalized, ENGINE_WEIGHTS["default"])


def calculate_final_score(
    severity: str | None = None,
    exploitability: str | None = None,
    confidence: float | None = None,
    engine: str | None = None,
    *,
    # Allow passing raw values for flexibility
    severity_score: float | None = None,
    exploitability_score: float | None = None,
    confidence_score: float | None = None,
    engine_weight: float | None = None,
) -> FinalScore:
    """
    Calculate final score from components.

    Formula:
        final_score = (
            severity_score * SEVERITY_WEIGHT +
            exploitability_score * EXPLOITABILITY_WEIGHT +
            confidence_score * CONFIDENCE_WEIGHT
        ) * engine_weight

    Args:
        severity: Severity level string.
        exploitability: Exploitability level string.
        confidence: Confidence value (0.0 - 1.0).
        engine: Engine name.

        severity_score: Pre-calculated severity score (overrides severity).
        exploitability_score: Pre-calculated exploitability score (overrides exploitability).
        confidence_score: Pre-calculated confidence score (overrides confidence).
        engine_weight: Pre-calculated engine weight (overrides engine).

    Returns:
        FinalScore object with full breakdown.
    """
    # Calculate or use provided scores
    sev_score = severity_score if severity_score is not None else get_severity_score(severity)
    exp_score = exploitability_score if exploitability_score is not None else get_exploitability_score(exploitability)
    conf_score = confidence_score if confidence_score is not None else get_confidence_score(confidence)
    eng_weight = engine_weight if engine_weight is not None else get_engine_weight(engine)

    # Calculate weighted base score
    base_score = (
        sev_score * SEVERITY_WEIGHT +
        exp_score * EXPLOITABILITY_WEIGHT +
        conf_score * CONFIDENCE_WEIGHT
    )

    # Apply engine weight
    total = base_score * eng_weight

    return FinalScore(
        total=total,
        severity_score=sev_score,
        exploitability_score=exp_score,
        confidence_score=conf_score,
        engine_weight=eng_weight,
        raw_severity=severity,
        raw_exploitability=exploitability,
        raw_confidence=confidence,
        engine=engine,
    )


def calculate_finding_score(finding: Any, engine: str | None = None) -> FinalScore:
    """
    Calculate final score for a Finding object.

    This is a convenience function that extracts values from a Finding
    object and calculates the final score.

    Args:
        finding: Finding object with severity, confidence, and optionally exploitability.
        engine: Engine name (uses finding.source if not provided).

    Returns:
        FinalScore object with full breakdown.
    """
    # Extract severity
    severity = None
    if hasattr(finding, "severity"):
        sev = finding.severity
        if hasattr(sev, "value"):
            severity = sev.value
        else:
            severity = str(sev)

    # Extract exploitability (may not exist yet)
    exploitability = None
    if hasattr(finding, "exploitability"):
        exp = finding.exploitability
        if hasattr(exp, "value"):
            exploitability = exp.value
        else:
            exploitability = str(exp)
    elif hasattr(finding, "metadata") and isinstance(finding.metadata, dict):
        # Check metadata for exploitability info
        exploitability = finding.metadata.get("exploitability")
        if exploitability and hasattr(exploitability, "value"):
            exploitability = exploitability.value

    # Extract confidence
    confidence = None
    if hasattr(finding, "confidence"):
        confidence = finding.confidence

    # Extract engine
    if engine is None and hasattr(finding, "source"):
        engine = finding.source

    return calculate_final_score(
        severity=severity,
        exploitability=exploitability,
        confidence=confidence,
        engine=engine,
    )


def sort_findings_by_score(findings: list[Any], descending: bool = True) -> list[Any]:
    """
    Sort findings by their final_score attribute.

    Args:
        findings: List of Finding objects with final_score attribute.
        descending: Sort descending (highest first) if True.

    Returns:
        Sorted list of findings.
    """
    return sorted(
        findings,
        key=lambda f: getattr(f, "final_score", 0) or 0,
        reverse=descending,
    )


def assign_scores_to_findings(
    findings: list[Any],
    engine: str | None = None,
    sort: bool = True,
) -> list[Any]:
    """
    Calculate and assign final scores to a list of findings.

    This function:
    1. Calculates final_score for each finding
    2. Assigns final_score to finding.final_score
    3. Assigns score_detail dict to finding.score_detail (if attribute exists)
    4. Optionally sorts by final_score (descending)

    Args:
        findings: List of Finding objects.
        engine: Default engine name (uses finding.source if not provided).
        sort: Whether to sort findings by score after assignment.

    Returns:
        List of findings with scores assigned (sorted if sort=True).
    """
    for finding in findings:
        # Determine engine for this finding
        finding_engine = engine
        if finding_engine is None and hasattr(finding, "source"):
            finding_engine = finding.source

        # Calculate score
        score = calculate_finding_score(finding, finding_engine)

        # Assign final_score
        if hasattr(finding, "final_score"):
            finding.final_score = score.total

        # Assign score_detail if the attribute exists
        if hasattr(finding, "score_detail"):
            finding.score_detail = score.to_dict()

        # Also store in metadata if available
        if hasattr(finding, "metadata") and isinstance(finding.metadata, dict):
            finding.metadata["final_score"] = score.to_dict()

    # Sort if requested
    if sort:
        findings = sort_findings_by_score(findings)

    return findings


# =============================================================================
# Module-level convenience
# =============================================================================

def get_score_weights() -> dict[str, float]:
    """Get current score component weights."""
    return {
        "severity": SEVERITY_WEIGHT,
        "exploitability": EXPLOITABILITY_WEIGHT,
        "confidence": CONFIDENCE_WEIGHT,
    }


def get_all_engine_weights() -> dict[str, float]:
    """Get all engine weights."""
    return dict(ENGINE_WEIGHTS)


def get_all_severity_scores() -> dict[str, float]:
    """Get all severity scores."""
    return dict(SEVERITY_SCORES)


def get_all_exploitability_scores() -> dict[str, float]:
    """Get all exploitability scores."""
    return dict(EXPLOITABILITY_SCORES)
