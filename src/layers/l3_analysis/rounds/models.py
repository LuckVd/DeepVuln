"""
Round Models

Data models for multi-round audit system.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.layers.l3_analysis.models import Finding, FindingType, SeverityLevel


class RoundStatus(str, Enum):
    """Status of an audit round."""

    PENDING = "pending"  # Round not started yet
    RUNNING = "running"  # Round is currently executing
    COMPLETED = "completed"  # Round completed successfully
    FAILED = "failed"  # Round failed with error
    SKIPPED = "skipped"  # Round was skipped (e.g., no targets)


class ConfidenceLevel(str, Enum):
    """Confidence level for vulnerability candidates."""

    HIGH = "high"  # Strong evidence, likely real vulnerability
    MEDIUM = "medium"  # Moderate evidence, needs verification
    LOW = "low"  # Weak evidence, may be false positive


class AnalysisDepth(str, Enum):
    """Depth of analysis for a candidate."""

    QUICK = "quick"  # Fast pattern matching (Semgrep only)
    STANDARD = "standard"  # Standard analysis (Semgrep + quick Agent)
    DEEP = "deep"  # Deep analysis (full Agent audit)
    EXHAUSTIVE = "exhaustive"  # Complete analysis (all engines, dataflow)


class VulnerabilityCandidate(BaseModel):
    """
    A vulnerability candidate from an audit round.

    Represents a potential vulnerability that may need further analysis
    in subsequent rounds.
    """

    # Identity
    id: str = Field(..., description="Unique candidate identifier")
    finding: Finding = Field(..., description="The underlying finding")

    # Classification
    confidence: ConfidenceLevel = Field(
        default=ConfidenceLevel.MEDIUM,
        description="Confidence level for this candidate",
    )
    analysis_depth: AnalysisDepth = Field(
        default=AnalysisDepth.QUICK,
        description="Depth of analysis performed",
    )

    # Round tracking
    discovered_in_round: int = Field(..., description="Round number where discovered")
    analyzed_in_rounds: list[int] = Field(
        default_factory=list,
        description="Round numbers where this was analyzed",
    )

    # Next steps
    needs_deep_analysis: bool = Field(
        default=False,
        description="Whether this needs deeper analysis",
    )
    needs_verification: bool = Field(
        default=False,
        description="Whether this needs verification (PoC)",
    )

    # Related context
    related_targets: list[str] = Field(
        default_factory=list,
        description="IDs of related audit targets",
    )
    related_candidates: list[str] = Field(
        default_factory=list,
        description="IDs of related candidates",
    )
    dataflow_path: list[str] | None = Field(
        default=None,
        description="Dataflow path if traced",
    )

    # Evidence
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Evidence collected during analysis",
    )

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this candidate was created",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this candidate was last updated",
    )

    def add_evidence(self, source: str, data: dict[str, Any]) -> None:
        """Add evidence from an analysis source."""
        self.evidence.append({
            "source": source,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": data,
        })
        self.updated_at = datetime.now(UTC)

    def mark_for_deep_analysis(self) -> None:
        """Mark this candidate for deep analysis."""
        self.needs_deep_analysis = True
        self.updated_at = datetime.now(UTC)

    def to_summary(self) -> str:
        """Generate a one-line summary."""
        return (
            f"[{self.confidence.value.upper()}] "
            f"{self.finding.title} "
            f"(Round {self.discovered_in_round})"
        )


class CoverageStats(BaseModel):
    """Statistics about code coverage during a round."""

    # File coverage
    total_files: int = Field(default=0, description="Total files in scope")
    scanned_files: int = Field(default=0, description="Files actually scanned")
    skipped_files: int = Field(default=0, description="Files skipped")

    # Line coverage
    total_lines: int = Field(default=0, description="Total lines of code")
    scanned_lines: int = Field(default=0, description="Lines analyzed")

    # Target coverage
    total_targets: int = Field(default=0, description="Total audit targets")
    analyzed_targets: int = Field(default=0, description="Targets analyzed")
    critical_targets_analyzed: int = Field(default=0, description="Critical targets analyzed")
    high_targets_analyzed: int = Field(default=0, description="High priority targets analyzed")

    # Entry point coverage
    entry_points_scanned: int = Field(default=0, description="Entry points scanned")
    http_endpoints_scanned: int = Field(default=0, description="HTTP endpoints scanned")
    rpc_endpoints_scanned: int = Field(default=0, description="RPC endpoints scanned")

    @property
    def file_coverage_percent(self) -> float:
        """Calculate file coverage percentage."""
        if self.total_files == 0:
            return 0.0
        return (self.scanned_files / self.total_files) * 100

    @property
    def target_coverage_percent(self) -> float:
        """Calculate target coverage percentage."""
        if self.total_targets == 0:
            return 0.0
        return (self.analyzed_targets / self.total_targets) * 100


class EngineStats(BaseModel):
    """Statistics for a single analysis engine."""

    engine: str = Field(..., description="Engine name")
    enabled: bool = Field(default=True, description="Whether engine was enabled")
    executed: bool = Field(default=False, description="Whether engine was executed")

    # Files/targets
    files_scanned: int = Field(default=0, description="Files scanned by this engine")
    targets_analyzed: int = Field(default=0, description="Targets analyzed")

    # Findings
    findings_count: int = Field(default=0, description="Total findings")
    candidates_count: int = Field(default=0, description="Candidates produced")

    # Timing
    start_time: datetime | None = Field(default=None, description="Engine start time")
    end_time: datetime | None = Field(default=None, description="Engine end time")
    duration_seconds: float | None = Field(default=None, description="Execution duration")

    # Errors
    errors: list[str] = Field(default_factory=list, description="Error messages")
    warnings: list[str] = Field(default_factory=list, description="Warning messages")

    # Resources
    tokens_used: int = Field(default=0, description="LLM tokens used (if applicable)")
    api_calls: int = Field(default=0, description="API calls made (if applicable)")

    def add_error(self, message: str) -> None:
        """Add an error message."""
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        """Add a warning message."""
        self.warnings.append(message)


class RoundResult(BaseModel):
    """
    Result of a single audit round.

    Contains all candidates and statistics from one round of analysis.
    """

    # Round info
    round_number: int = Field(..., description="Round number (1-indexed)")
    status: RoundStatus = Field(default=RoundStatus.PENDING, description="Round status")

    # Findings
    candidates: list[VulnerabilityCandidate] = Field(
        default_factory=list,
        description="Vulnerability candidates from this round",
    )
    total_candidates: int = Field(default=0, description="Total candidates count")

    # Candidates by confidence
    high_confidence_count: int = Field(default=0, description="High confidence candidates")
    medium_confidence_count: int = Field(default=0, description="Medium confidence candidates")
    low_confidence_count: int = Field(default=0, description="Low confidence candidates")

    # Next round planning
    next_round_candidates: list[str] = Field(
        default_factory=list,
        description="IDs of candidates needing analysis in next round",
    )
    skipped_targets: list[str] = Field(
        default_factory=list,
        description="Targets skipped in this round",
    )

    # Coverage
    coverage: CoverageStats = Field(
        default_factory=CoverageStats,
        description="Coverage statistics",
    )

    # Engine statistics
    engine_stats: dict[str, EngineStats] = Field(
        default_factory=dict,
        description="Statistics per engine",
    )

    # Timing
    started_at: datetime | None = Field(default=None, description="Round start time")
    completed_at: datetime | None = Field(default=None, description="Round end time")
    duration_seconds: float | None = Field(default=None, description="Round duration")

    # Errors
    errors: list[str] = Field(default_factory=list, description="Error messages")

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional round metadata",
    )

    def add_candidate(self, candidate: VulnerabilityCandidate) -> None:
        """Add a candidate and update statistics."""
        self.candidates.append(candidate)
        self.total_candidates += 1

        # Update confidence counts
        if candidate.confidence == ConfidenceLevel.HIGH:
            self.high_confidence_count += 1
        elif candidate.confidence == ConfidenceLevel.MEDIUM:
            self.medium_confidence_count += 1
        else:
            self.low_confidence_count += 1

    def get_candidates_by_severity(
        self,
        severities: list[SeverityLevel],
    ) -> list[VulnerabilityCandidate]:
        """Filter candidates by finding severity."""
        severity_values = [s.value for s in severities]
        return [
            c for c in self.candidates
            if c.finding.severity.value in severity_values
        ]

    def get_candidates_needing_deep_analysis(self) -> list[VulnerabilityCandidate]:
        """Get candidates that need deeper analysis."""
        return [c for c in self.candidates if c.needs_deep_analysis]

    def get_candidates_for_next_round(self) -> list[VulnerabilityCandidate]:
        """Get candidates that should be analyzed in next round."""
        return [c for c in self.candidates if c.id in self.next_round_candidates]

    def mark_completed(self) -> None:
        """Mark the round as completed."""
        self.status = RoundStatus.COMPLETED
        self.completed_at = datetime.now(UTC)
        if self.started_at:
            self.duration_seconds = (
                self.completed_at - self.started_at
            ).total_seconds()

    def mark_failed(self, error: str) -> None:
        """Mark the round as failed."""
        self.status = RoundStatus.FAILED
        self.errors.append(error)
        self.completed_at = datetime.now(UTC)
        if self.started_at:
            self.duration_seconds = (
                self.completed_at - self.started_at
            ).total_seconds()

    def to_summary(self) -> str:
        """Generate a summary of the round."""
        lines = [
            f"Round {self.round_number}: {self.status.value}",
            f"  Candidates: {self.total_candidates}",
            f"    High confidence: {self.high_confidence_count}",
            f"    Medium confidence: {self.medium_confidence_count}",
            f"    Low confidence: {self.low_confidence_count}",
            f"  Next round candidates: {len(self.next_round_candidates)}",
            f"  Coverage: {self.coverage.target_coverage_percent:.1f}% targets",
        ]
        if self.duration_seconds:
            lines.append(f"  Duration: {self.duration_seconds:.2f}s")
        return "\n".join(lines)


class AuditSession(BaseModel):
    """
    Complete audit session across all rounds.

    Tracks the entire multi-round audit process.
    """

    # Session info
    id: str = Field(..., description="Unique session identifier")
    project_name: str = Field(..., description="Project being audited")
    source_path: str = Field(..., description="Path to source code")

    # Status
    status: RoundStatus = Field(default=RoundStatus.PENDING, description="Session status")
    current_round: int = Field(default=0, description="Current round number")
    max_rounds: int = Field(default=3, description="Maximum rounds allowed")

    # Round results
    rounds: list[RoundResult] = Field(
        default_factory=list,
        description="Results from each round",
    )

    # Aggregated findings
    all_candidates: list[VulnerabilityCandidate] = Field(
        default_factory=list,
        description="All candidates across all rounds",
    )
    confirmed_vulnerabilities: list[VulnerabilityCandidate] = Field(
        default_factory=list,
        description="Confirmed vulnerabilities",
    )
    false_positives: list[VulnerabilityCandidate] = Field(
        default_factory=list,
        description="Confirmed false positives",
    )

    # Timing
    started_at: datetime | None = Field(default=None, description="Session start time")
    completed_at: datetime | None = Field(default=None, description="Session end time")
    duration_seconds: float | None = Field(default=None, description="Total duration")

    # Configuration
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Session configuration",
    )

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional session metadata",
    )

    def add_round(self, result: RoundResult) -> None:
        """Add a round result to the session."""
        self.rounds.append(result)
        self.current_round = result.round_number
        self.all_candidates.extend(result.candidates)

    def get_current_round(self) -> RoundResult | None:
        """Get the current round result."""
        if self.rounds:
            return self.rounds[-1]
        return None

    def should_continue(self) -> bool:
        """Check if audit should continue to next round."""
        if self.status in (RoundStatus.COMPLETED, RoundStatus.FAILED):
            return False
        if self.current_round >= self.max_rounds:
            return False

        # Check if there are candidates for next round
        current = self.get_current_round()
        if current and current.next_round_candidates:
            return True

        return False

    def get_statistics(self) -> dict[str, Any]:
        """Get overall session statistics."""
        return {
            "session_id": self.id,
            "project_name": self.project_name,
            "status": self.status.value,
            "rounds_completed": len(self.rounds),
            "total_candidates": len(self.all_candidates),
            "confirmed_vulnerabilities": len(self.confirmed_vulnerabilities),
            "false_positives": len(self.false_positives),
            "duration_seconds": self.duration_seconds,
        }

    def mark_completed(self) -> None:
        """Mark the session as completed."""
        self.status = RoundStatus.COMPLETED
        self.completed_at = datetime.now(UTC)
        if self.started_at:
            self.duration_seconds = (
                self.completed_at - self.started_at
            ).total_seconds()

    def to_summary(self) -> str:
        """Generate a summary of the audit session."""
        lines = [
            f"Audit Session: {self.project_name}",
            f"Status: {self.status.value}",
            f"Rounds: {len(self.rounds)}/{self.max_rounds}",
            "",
            "Findings:",
            f"  Total candidates: {len(self.all_candidates)}",
            f"  Confirmed: {len(self.confirmed_vulnerabilities)}",
            f"  False positives: {len(self.false_positives)}",
        ]
        if self.duration_seconds:
            lines.append(f"\nDuration: {self.duration_seconds:.2f}s")
        return "\n".join(lines)
