"""
Adversarial Verification Data Models

Defines data models for the three-role adversarial verification system.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class VerdictType(str, Enum):
    """Final verdict types from adversarial verification."""

    CONFIRMED = "confirmed"  # Attacker wins - vulnerability is real
    FALSE_POSITIVE = "false_positive"  # Defender wins - not a real issue
    NEEDS_REVIEW = "needs_review"  # Tie - needs human review
    CONDITIONAL = "conditional"  # Exploitable under specific conditions


class ArgumentStrength(str, Enum):
    """Strength rating for arguments."""

    WEAK = "weak"  # Speculative or easily countered
    MODERATE = "moderate"  # Plausible but not definitive
    STRONG = "strong"  # Clear evidence or PoC
    DEFINITIVE = "definitive"  # Irrefutable proof


class VerificationArgument(BaseModel):
    """An argument from attacker or defender."""

    role: str = Field(..., description="'attacker' or 'defender'")
    claim: str = Field(..., description="Main claim or assertion")
    evidence: list[str] = Field(
        default_factory=list,
        description="Supporting evidence (code snippets, logic)",
    )
    reasoning: str = Field(..., description="Detailed reasoning")
    strength: ArgumentStrength = Field(
        default=ArgumentStrength.MODERATE,
        description="Strength of the argument",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in the argument",
    )
    counter_arguments: list[str] = Field(
        default_factory=list,
        description="Potential counter-arguments to address",
    )

    # PoC-related fields (mainly for attacker)
    poc_code: str | None = Field(
        default=None,
        description="Proof of concept code if applicable",
    )
    poc_type: str | None = Field(
        default=None,
        description="Type of PoC (e.g., 'http_request', 'curl', 'python')",
    )
    exploitation_steps: list[str] = Field(
        default_factory=list,
        description="Steps to exploit the vulnerability",
    )
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Prerequisites for exploitation",
    )

    # Defense-related fields (mainly for defender)
    sanitizers_found: list[str] = Field(
        default_factory=list,
        description="Sanitization functions detected",
    )
    validation_checks: list[str] = Field(
        default_factory=list,
        description="Validation checks detected",
    )
    framework_protections: list[str] = Field(
        default_factory=list,
        description="Framework-level protections",
    )


class AdversarialVerdict(BaseModel):
    """Final verdict from the arbiter."""

    verdict: VerdictType = Field(..., description="Final judgment")
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in the verdict",
    )
    summary: str = Field(..., description="Brief summary of the decision")
    reasoning: str = Field(..., description="Detailed reasoning for the verdict")

    # Key factors in the decision
    attacker_strength: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Strength of attacker's arguments",
    )
    defender_strength: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Strength of defender's arguments",
    )

    # For conditional verdicts
    conditions: list[str] = Field(
        default_factory=list,
        description="Conditions for exploitation (if conditional)",
    )

    # Recommendations
    recommended_action: str = Field(
        default="review",
        description="Recommended action: 'fix', 'review', 'ignore', 'monitor'",
    )
    priority: str = Field(
        default="medium",
        description="Priority for action: 'critical', 'high', 'medium', 'low'",
    )


class VerificationResult(BaseModel):
    """Complete result of adversarial verification."""

    # Original finding info
    finding_id: str = Field(..., description="ID of the original finding")
    finding_type: str = Field(..., description="Type of vulnerability")
    finding_severity: str = Field(..., description="Original severity")
    finding_location: str = Field(..., description="File:line of the finding")

    # Arguments from both sides
    attacker_argument: VerificationArgument | None = Field(
        default=None,
        description="Attacker's argument",
    )
    defender_argument: VerificationArgument | None = Field(
        default=None,
        description="Defender's argument",
    )

    # Final verdict
    verdict: AdversarialVerdict | None = Field(
        default=None,
        description="Final verdict from arbiter",
    )

    # Round tracking
    rounds_completed: int = Field(
        default=0,
        description="Number of debate rounds completed",
    )
    debate_history: list[dict[str, Any]] = Field(
        default_factory=list,
        description="History of the debate",
    )

    # Metadata
    verification_started: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When verification started",
    )
    verification_completed: datetime | None = Field(
        default=None,
        description="When verification completed",
    )
    duration_seconds: float | None = Field(
        default=None,
        description="Total verification duration",
    )
    tokens_used: int = Field(
        default=0,
        description="Total tokens used",
    )

    def is_complete(self) -> bool:
        """Check if verification is complete."""
        return self.verdict is not None

    def to_summary(self) -> str:
        """Generate a one-line summary."""
        if self.verdict:
            return f"[{self.verdict.verdict.value.upper()}] {self.finding_type} at {self.finding_location} (confidence: {self.verdict.confidence:.0%})"
        return f"[PENDING] {self.finding_type} at {self.finding_location}"


class VerificationSession(BaseModel):
    """A verification session containing multiple findings."""

    session_id: str = Field(..., description="Unique session identifier")
    source_path: str = Field(..., description="Path that was scanned")
    results: list[VerificationResult] = Field(
        default_factory=list,
        description="Verification results for each finding",
    )

    # Statistics
    total_findings: int = Field(default=0, description="Total findings to verify")
    confirmed: int = Field(default=0, description="Confirmed vulnerabilities")
    false_positives: int = Field(default=0, description="False positives")
    needs_review: int = Field(default=0, description="Needs human review")
    conditional: int = Field(default=0, description="Conditional vulnerabilities")

    # Timing
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When session started",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="When session completed",
    )

    def add_result(self, result: VerificationResult) -> None:
        """Add a verification result and update statistics."""
        self.results.append(result)
        self.total_findings += 1

        if result.verdict:
            match result.verdict.verdict:
                case VerdictType.CONFIRMED:
                    self.confirmed += 1
                case VerdictType.FALSE_POSITIVE:
                    self.false_positives += 1
                case VerdictType.NEEDS_REVIEW:
                    self.needs_review += 1
                case VerdictType.CONDITIONAL:
                    self.conditional += 1

    def get_summary(self) -> dict[str, Any]:
        """Get summary statistics."""
        return {
            "total": self.total_findings,
            "confirmed": self.confirmed,
            "false_positives": self.false_positives,
            "needs_review": self.needs_review,
            "conditional": self.conditional,
            "confirmed_rate": (
                self.confirmed / self.total_findings if self.total_findings > 0 else 0
            ),
            "false_positive_rate": (
                self.false_positives / self.total_findings if self.total_findings > 0 else 0
            ),
        }
