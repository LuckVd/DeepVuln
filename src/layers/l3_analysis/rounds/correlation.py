"""
Correlation Models

Data structures for multi-source evidence correlation and verification.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from src.layers.l3_analysis.models import CodeLocation
from src.layers.l3_analysis.rounds.dataflow import DataFlowPath


class VerificationStatus(str, Enum):
    """
    Verification status for vulnerability candidates.

    Represents the final determination after correlation analysis.
    """

    CONFIRMED = "confirmed"           # Confirmed as real vulnerability
    LIKELY = "likely"                 # High probability of being vulnerability
    UNCERTAIN = "uncertain"           # Needs manual review
    FALSE_POSITIVE = "false_positive" # Confirmed as false positive
    NOT_EXPLOITABLE = "not_exploitable"  # Vulnerability exists but not exploitable


class EvidenceSource(str, Enum):
    """
    Source of evidence for vulnerability detection.
    """

    SEMGREP = "semgrep"      # Semgrep pattern matching
    CODEQL = "codeql"        # CodeQL data flow analysis
    AGENT = "agent"          # AI Agent deep audit
    MANUAL = "manual"        # Manual analysis
    CORRELATION = "correlation"  # Cross-source correlation


class EvidenceType(str, Enum):
    """
    Type of evidence collected.
    """

    PATTERN_MATCH = "pattern_match"       # Direct pattern match
    DATAFLOW_PATH = "dataflow_path"       # Complete data flow path
    TAINT_PROPAGATION = "taint_propagation"  # Taint spread analysis
    SANITIZER_DETECTED = "sanitizer_detected"  # Security control found
    AGENT_ANALYSIS = "agent_analysis"     # Agent reasoning result
    CODE_SNIPPET = "code_snippet"         # Relevant code snippet
    CVE_MATCH = "cve_match"               # Matches known CVE pattern
    EXPLOIT_SCENARIO = "exploit_scenario"  # Potential exploit path


class Evidence(BaseModel):
    """
    Single piece of evidence for a vulnerability candidate.
    """

    # Identity
    id: str = Field(..., description="Unique evidence identifier")

    # Source
    source: EvidenceSource = Field(..., description="Where this evidence came from")
    evidence_type: EvidenceType = Field(..., description="Type of evidence")

    # Content
    location: CodeLocation | None = Field(
        default=None,
        description="Code location if applicable",
    )
    content: str | None = Field(
        default=None,
        description="Evidence content/description",
    )
    code_snippet: str | None = Field(
        default=None,
        description="Relevant code snippet",
    )

    # Confidence
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in this evidence",
    )
    weight: float = Field(
        default=1.0,
        ge=0.0,
        le=2.0,
        description="Weight for aggregation (higher = more important)",
    )

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When evidence was collected",
    )

    def to_summary(self) -> str:
        """Get a one-line summary."""
        return f"[{self.source.value}] {self.evidence_type.value}: {self.confidence:.0%}"


class EvidenceChain(BaseModel):
    """
    Chain of evidence supporting a vulnerability candidate.

    Aggregates evidence from multiple sources to build a complete picture
    of the potential vulnerability.
    """

    # Identity
    id: str = Field(..., description="Unique chain identifier")
    candidate_id: str = Field(..., description="ID of related vulnerability candidate")

    # Evidence collection
    evidences: list[Evidence] = Field(
        default_factory=list,
        description="All collected evidence",
    )
    dataflow_paths: list[DataFlowPath] = Field(
        default_factory=list,
        description="Data flow paths found",
    )

    # Source tracking
    sources: list[EvidenceSource] = Field(
        default_factory=list,
        description="Unique sources that contributed evidence",
    )
    source_count: int = Field(default=0, description="Number of unique sources")

    # Aggregated metrics
    total_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Aggregated confidence across all evidence",
    )
    weighted_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Weighted confidence score",
    )

    # Consistency
    consistent: bool = Field(
        default=True,
        description="Whether all evidence points to same conclusion",
    )
    conflicts: list[str] = Field(
        default_factory=list,
        description="Description of any conflicting evidence",
    )

    # Status
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNCERTAIN,
        description="Current verification status",
    )

    # Timing
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When chain was created",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When chain was last updated",
    )

    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence to the chain."""
        self.evidences.append(evidence)
        if evidence.source not in self.sources:
            self.sources.append(evidence.source)
        self.source_count = len(self.sources)
        self._recalculate_confidence()
        self.updated_at = datetime.now(UTC)

    def add_dataflow_path(self, path: DataFlowPath) -> None:
        """Add a data flow path."""
        self.dataflow_paths.append(path)
        self.updated_at = datetime.now(UTC)

    def _recalculate_confidence(self) -> None:
        """Recalculate aggregated confidence scores."""
        if not self.evidences:
            self.total_confidence = 0.0
            self.weighted_confidence = 0.0
            return

        # Simple average
        self.total_confidence = sum(e.confidence for e in self.evidences) / len(self.evidences)

        # Weighted average
        total_weight = sum(e.weight for e in self.evidences)
        if total_weight > 0:
            self.weighted_confidence = (
                sum(e.confidence * e.weight for e in self.evidences) / total_weight
            )
        else:
            self.weighted_confidence = self.total_confidence

    def check_consistency(self) -> None:
        """Check for conflicts in evidence."""
        false_positive_evidence = [
            e for e in self.evidences
            if e.metadata.get("is_false_positive", False)
        ]
        confirmed_evidence = [
            e for e in self.evidences
            if e.confidence >= 0.8 and not e.metadata.get("is_false_positive", False)
        ]

        if false_positive_evidence and confirmed_evidence:
            self.consistent = False
            self.conflicts.append(
                f"Mixed signals: {len(false_positive_evidence)} evidence suggest FP, "
                f"{len(confirmed_evidence)} suggest real vulnerability"
            )
        else:
            self.consistent = True
            self.conflicts = []

    def get_evidence_by_source(self, source: EvidenceSource) -> list[Evidence]:
        """Get all evidence from a specific source."""
        return [e for e in self.evidences if e.source == source]

    def get_summary(self) -> str:
        """Get a summary of the evidence chain."""
        status = self.verification_status.value
        sources = ", ".join(s.value for s in self.sources)
        return f"[{status}] {len(self.evidences)} evidence from {sources} (confidence: {self.weighted_confidence:.0%})"

    def to_prompt_context(self) -> str:
        """Generate context for LLM prompt."""
        lines = [
            "## Evidence Chain",
            "",
            f"Candidate ID: {self.candidate_id}",
            f"Status: {self.verification_status.value}",
            f"Sources: {', '.join(s.value for s in self.sources)}",
            f"Confidence: {self.weighted_confidence:.0%}",
            "",
            f"### Evidence ({len(self.evidences)} items)",
        ]

        for i, evidence in enumerate(self.evidences, 1):
            lines.append(f"{i}. [{evidence.source.value}] {evidence.evidence_type.value}")
            if evidence.content:
                lines.append(f"   {evidence.content[:100]}")
            lines.append(f"   Confidence: {evidence.confidence:.0%}")

        if self.dataflow_paths:
            lines.append("")
            lines.append(f"### Data Flow Paths ({len(self.dataflow_paths)})")
            for path in self.dataflow_paths:
                lines.append(f"  - {path.get_summary()}")

        if not self.consistent:
            lines.append("")
            lines.append("### Conflicts")
            for conflict in self.conflicts:
                lines.append(f"  - {conflict}")

        return "\n".join(lines)


class CorrelationRule(BaseModel):
    """
    Rule for correlating evidence from multiple sources.
    """

    # Identity
    id: str = Field(..., description="Unique rule identifier")
    name: str = Field(..., description="Rule name")
    description: str | None = Field(default=None, description="Rule description")

    # Conditions
    required_sources: list[EvidenceSource] = Field(
        default_factory=list,
        description="Sources that must be present",
    )
    min_sources: int = Field(
        default=1,
        description="Minimum number of sources required",
    )
    required_evidence_types: list[EvidenceType] = Field(
        default_factory=list,
        description="Types of evidence required",
    )

    # Weights
    source_weights: dict[str, float] = Field(
        default_factory=dict,
        description="Weight for each source",
    )

    # Output
    if_matched: VerificationStatus = Field(
        default=VerificationStatus.LIKELY,
        description="Status if rule matches",
    )
    confidence_boost: float = Field(
        default=0.1,
        description="Confidence boost when rule matches",
    )

    def matches(self, chain: EvidenceChain) -> bool:
        """Check if this rule matches an evidence chain."""
        # Check minimum sources
        if chain.source_count < self.min_sources:
            return False

        # Check required sources
        for source in self.required_sources:
            if source not in chain.sources:
                return False

        # Check required evidence types
        if self.required_evidence_types:
            found_types = {e.evidence_type for e in chain.evidences}
            for req_type in self.required_evidence_types:
                if req_type not in found_types:
                    return False

        return True


class CorrelationResult(BaseModel):
    """
    Result of correlation analysis for a vulnerability candidate.
    """

    # Identity
    id: str = Field(..., description="Unique result identifier")
    candidate_id: str = Field(..., description="ID of analyzed candidate")

    # Evidence chain
    evidence_chain: EvidenceChain = Field(
        ...,
        description="The evidence chain analyzed",
    )

    # Correlation outcome
    correlated: bool = Field(
        default=False,
        description="Whether correlation was successful",
    )
    matched_rules: list[str] = Field(
        default_factory=list,
        description="IDs of rules that matched",
    )

    # Final determination
    final_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Final confidence after correlation",
    )
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNCERTAIN,
        description="Final verification status",
    )
    verdict: str | None = Field(
        default=None,
        description="Human-readable verdict",
    )
    verdict_reasons: list[str] = Field(
        default_factory=list,
        description="Reasons for the verdict",
    )

    # Recommendations
    needs_manual_review: bool = Field(
        default=False,
        description="Whether manual review is needed",
    )
    review_reasons: list[str] = Field(
        default_factory=list,
        description="Why manual review is needed",
    )

    # Timing
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When correlation was performed",
    )
    duration_seconds: float | None = Field(
        default=None,
        description="Time taken for correlation",
    )

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )

    def add_matched_rule(self, rule: CorrelationRule) -> None:
        """Record a matched rule."""
        self.matched_rules.append(rule.id)
        self.final_confidence = min(1.0, self.final_confidence + rule.confidence_boost)
        if rule.if_matched != VerificationStatus.UNCERTAIN:
            self.verification_status = rule.if_matched

    def set_verdict(
        self,
        status: VerificationStatus,
        verdict: str,
        reasons: list[str] | None = None,
    ) -> None:
        """Set the final verdict."""
        self.verification_status = status
        self.verdict = verdict
        self.verdict_reasons = reasons or []
        self.evidence_chain.verification_status = status

    def mark_for_review(self, reason: str) -> None:
        """Mark as needing manual review."""
        self.needs_manual_review = True
        self.review_reasons.append(reason)

    def get_summary(self) -> str:
        """Get a one-line summary."""
        status = self.verification_status.value
        correlated = "correlated" if self.correlated else "not correlated"
        return f"[{status}] {correlated}, {len(self.matched_rules)} rules matched (confidence: {self.final_confidence:.0%})"

    def to_prompt_context(self) -> str:
        """Generate context for LLM prompt."""
        lines = [
            "## Correlation Result",
            "",
            f"Candidate ID: {self.candidate_id}",
            f"Status: {self.verification_status.value}",
            f"Correlated: {'Yes' if self.correlated else 'No'}",
            f"Final Confidence: {self.final_confidence:.0%}",
        ]

        if self.verdict:
            lines.append(f"Verdict: {self.verdict}")

        if self.verdict_reasons:
            lines.append("")
            lines.append("### Reasons")
            for reason in self.verdict_reasons:
                lines.append(f"  - {reason}")

        if self.matched_rules:
            lines.append("")
            lines.append(f"### Matched Rules ({len(self.matched_rules)})")
            for rule_id in self.matched_rules:
                lines.append(f"  - {rule_id}")

        if self.needs_manual_review:
            lines.append("")
            lines.append("### Manual Review Required")
            for reason in self.review_reasons:
                lines.append(f"  - {reason}")

        return "\n".join(lines)


# Default correlation rules
DEFAULT_CORRELATION_RULES: list[CorrelationRule] = [
    CorrelationRule(
        id="multi-source-confirmation",
        name="Multi-Source Confirmation",
        description="Vulnerability confirmed by multiple sources",
        min_sources=2,
        if_matched=VerificationStatus.CONFIRMED,
        confidence_boost=0.2,
    ),
    CorrelationRule(
        id="codeql-agent-deep-confirm",
        name="CodeQL + Agent Deep Confirmation",
        description="Both CodeQL and Agent confirm the vulnerability",
        required_sources=[EvidenceSource.CODEQL, EvidenceSource.AGENT],
        required_evidence_types=[EvidenceType.DATAFLOW_PATH, EvidenceType.AGENT_ANALYSIS],
        if_matched=VerificationStatus.CONFIRMED,
        confidence_boost=0.3,
    ),
    CorrelationRule(
        id="sanitizer-detected",
        name="Sanitizer Detected",
        description="Effective sanitizer found in data flow",
        required_evidence_types=[EvidenceType.SANITIZER_DETECTED],
        if_matched=VerificationStatus.NOT_EXPLOITABLE,
        confidence_boost=0.0,
    ),
    CorrelationRule(
        id="cve-pattern-match",
        name="CVE Pattern Match",
        description="Matches known CVE pattern",
        required_evidence_types=[EvidenceType.CVE_MATCH],
        if_matched=VerificationStatus.LIKELY,
        confidence_boost=0.15,
    ),
    CorrelationRule(
        id="agent-false-positive",
        name="Agent False Positive Detection",
        description="Agent determined this is a false positive",
        required_sources=[EvidenceSource.AGENT],
        if_matched=VerificationStatus.FALSE_POSITIVE,
        confidence_boost=0.0,
    ),
]
