"""
Adversarial Verification Data Models

Defines data models for the three-role adversarial verification system.
Enhanced with multi-round debate support.
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


class DebateRound(BaseModel):
    """A single round in the debate."""

    round_number: int = Field(..., description="Round number (1-indexed)")
    attacker_argument: "VerificationArgument" = Field(
        ..., description="Attacker's argument for this round"
    )
    defender_argument: "VerificationArgument" = Field(
        ..., description="Defender's argument for this round"
    )
    arbiter_verdict: "AdversarialVerdict | None" = Field(
        default=None, description="Arbiter's verdict for this round (if evaluated)"
    )
    continue_debate: bool = Field(
        default=False, description="Whether to continue to next round"
    )
    continue_reason: str | None = Field(
        default=None, description="Reason for continuing debate"
    )


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
    exploitation_barriers: list[str] = Field(
        default_factory=list,
        description="Barriers to exploitation",
    )
    false_positive_reasons: list[str] = Field(
        default_factory=list,
        description="Reasons why this might be a false positive",
    )

    # Round tracking for multi-round debates
    round_number: int = Field(
        default=1,
        description="Which round this argument belongs to",
    )
    is_rebuttal: bool = Field(
        default=False,
        description="Whether this is a rebuttal to previous argument",
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

    # Key factors that influenced the decision
    key_factors: list[str] = Field(
        default_factory=list,
        description="Key factors that influenced the decision",
    )

    # Round tracking
    round_number: int = Field(
        default=1,
        description="Which round this verdict belongs to",
    )

    def is_decisive(self) -> bool:
        """Check if this verdict is decisive (CONFIRMED/FALSE_POSITIVE with high confidence and large strength diff)."""
        # NEEDS_REVIEW is never decisive
        if self.verdict == VerdictType.NEEDS_REVIEW:
            return False
        # CONDITIONAL is not decisive (needs more context)
        if self.verdict == VerdictType.CONDITIONAL:
            return False
        # Low confidence is not decisive
        if self.confidence < 0.7:
            return False
        # Small strength difference is not decisive
        strength_diff = abs(self.attacker_strength - self.defender_strength)
        if strength_diff < 0.3:
            return False
        return True

    def should_continue_debate(self, strength_diff_threshold: float = 0.2, confidence_threshold: float = 0.6) -> tuple[bool, str]:
        """
        Determine if debate should continue based on this verdict.

        Args:
            strength_diff_threshold: Minimum strength difference to consider decisive
            confidence_threshold: Minimum confidence to consider decisive

        Returns:
            Tuple of (should_continue, reason)
        """
        # Don't continue if we have a decisive verdict
        if self.is_decisive():
            return False, f"Decisive verdict: {self.verdict.value} with {self.confidence:.0%} confidence"

        # Continue if NEEDS_REVIEW
        if self.verdict == VerdictType.NEEDS_REVIEW:
            return True, "Verdict is NEEDS_REVIEW - requires more debate"

        # Continue if strength difference is too small
        strength_diff = abs(self.attacker_strength - self.defender_strength)
        if strength_diff < strength_diff_threshold:
            return True, f"Strength difference too small ({strength_diff:.2f} < {strength_diff_threshold})"

        # Continue if confidence is low
        if self.confidence < confidence_threshold:
            return True, f"Low confidence ({self.confidence:.0%} < {confidence_threshold:.0%})"

        return False, "Sufficient confidence for decision"


class VerificationResult(BaseModel):
    """Complete result of adversarial verification."""

    # Original finding info
    finding_id: str = Field(..., description="ID of the original finding")
    finding_type: str = Field(..., description="Type of vulnerability")
    finding_severity: str = Field(..., description="Original severity")
    finding_location: str = Field(..., description="File:line of the finding")

    # Latest arguments from both sides (for backwards compatibility)
    attacker_argument: VerificationArgument | None = Field(
        default=None,
        description="Attacker's latest argument",
    )
    defender_argument: VerificationArgument | None = Field(
        default=None,
        description="Defender's latest argument",
    )

    # All debate rounds (for multi-round support)
    debate_rounds: list[DebateRound] = Field(
        default_factory=list,
        description="All debate rounds",
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
    max_rounds_reached: bool = Field(
        default=False,
        description="Whether max rounds was reached without decisive verdict",
    )
    debate_history: list[dict[str, Any]] = Field(
        default_factory=list,
        description="History of the debate (legacy format)",
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
            rounds_info = f" ({self.rounds_completed} round{'s' if self.rounds_completed > 1 else ''})"
            return f"[{self.verdict.verdict.value.upper()}] {self.finding_type} at {self.finding_location} (confidence: {self.verdict.confidence:.0%}){rounds_info}"
        return f"[PENDING] {self.finding_type} at {self.finding_location}"

    def get_all_attacker_arguments(self) -> list[VerificationArgument]:
        """Get all attacker arguments across all rounds."""
        return [r.attacker_argument for r in self.debate_rounds]

    def get_all_defender_arguments(self) -> list[VerificationArgument]:
        """Get all defender arguments across all rounds."""
        return [r.defender_argument for r in self.debate_rounds]

    def add_round(self, debate_round: DebateRound) -> None:
        """Add a debate round and update latest arguments."""
        self.debate_rounds.append(debate_round)
        self.attacker_argument = debate_round.attacker_argument
        self.defender_argument = debate_round.defender_argument
        self.rounds_completed = len(self.debate_rounds)

        # Also update legacy debate_history format
        self.debate_history.append({
            "round": debate_round.round_number,
            "attacker_claim": debate_round.attacker_argument.claim,
            "attacker_confidence": debate_round.attacker_argument.confidence,
            "attacker_strength": debate_round.attacker_argument.strength.value,
            "defender_claim": debate_round.defender_argument.claim,
            "defender_confidence": debate_round.defender_argument.confidence,
            "defender_strength": debate_round.defender_argument.strength.value,
            "continue_debate": debate_round.continue_debate,
            "continue_reason": debate_round.continue_reason,
        })


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

    # Multi-round statistics
    total_rounds: int = Field(default=0, description="Total debate rounds across all findings")
    avg_rounds_per_finding: float = Field(default=0.0, description="Average rounds per finding")
    max_rounds_used: int = Field(default=0, description="Max rounds used for any finding")

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

        # Update round statistics
        self.total_rounds += result.rounds_completed
        self.max_rounds_used = max(self.max_rounds_used, result.rounds_completed)
        self.avg_rounds_per_finding = self.total_rounds / self.total_findings

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
            "total_rounds": self.total_rounds,
            "avg_rounds_per_finding": round(self.avg_rounds_per_finding, 2),
            "max_rounds_used": self.max_rounds_used,
        }


class TriggerConditions(BaseModel):
    """Conditions that trigger additional debate rounds."""

    needs_review: bool = Field(
        default=True,
        description="Trigger when verdict is NEEDS_REVIEW",
    )
    strength_diff_threshold: float = Field(
        default=0.2,
        ge=0.0,
        le=1.0,
        description="Trigger when |attacker_strength - defender_strength| < threshold",
    )
    confidence_threshold: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Trigger when verdict confidence < threshold",
    )

    def should_continue(
        self,
        verdict: AdversarialVerdict,
    ) -> tuple[bool, str]:
        """
        Determine if debate should continue based on verdict.

        Args:
            verdict: The current verdict to evaluate.

        Returns:
            Tuple of (should_continue, reason)
        """
        reasons = []

        # Check NEEDS_REVIEW
        if self.needs_review and verdict.verdict == VerdictType.NEEDS_REVIEW:
            reasons.append("verdict is NEEDS_REVIEW")

        # Check strength difference
        strength_diff = abs(verdict.attacker_strength - verdict.defender_strength)
        if strength_diff < self.strength_diff_threshold:
            reasons.append(
                f"strength difference ({strength_diff:.2f}) < threshold ({self.strength_diff_threshold})"
            )

        # Check confidence
        if verdict.confidence < self.confidence_threshold:
            reasons.append(
                f"confidence ({verdict.confidence:.0%}) < threshold ({self.confidence_threshold:.0%})"
            )

        if reasons:
            return True, "; ".join(reasons)

        return False, "Decisive verdict reached"


# Update forward references
DebateRound.model_rebuild()
