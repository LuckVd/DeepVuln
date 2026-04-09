"""Adjudication Service - P14-03.

This service wraps the CLI's adjudication and deduplication functionality
for use in the web service.

It integrates:
- ClusterBasedDeduplicator for semantic deduplication
- Exploitability-based adjudication logic
- Evidence strength assessment
- Report status application
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from src.layers.l3_analysis.deduplicator import (
    ASTDeduplicator,
    ClusterBasedDeduplicator,
    ClusterDeduplicatorConfig,
    DeduplicationResult,
)
from src.layers.l3_analysis.adjudication import (
    FinalStatus,
    AdjudicationResult as CLIAdjudicationResult,
    AdjudicationSummary as CLIAdjudicationSummary,
    apply_exploitability_override,
    get_exploitability_value,
    get_severity_value,
)
from src.layers.l3_analysis.models import Finding
from src.layers.l3_analysis.reporting import map_to_report_status


logger = logging.getLogger(__name__)


class ReportStatus(str, Enum):
    """Unified report status for findings (P4-05)."""
    PROCESSED = "processed"
    DUPLICATE = "duplicate"
    FALSE_POSITIVE = "false_positive"
    CONFIRMED = "confirmed"


@dataclass
class AdjudicationResult:
    """Result of adjudicating a single finding."""
    finding_id: str
    final_status: FinalStatus
    exploitability: Optional[str]
    severity: str
    override_applied: bool
    override_reason: str
    report_status: ReportStatus
    evidence_strength: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "finding_id": self.finding_id,
            "final_status": self.final_status.value,
            "exploitability": self.exploitability,
            "severity": self.severity,
            "override_applied": self.override_applied,
            "override_reason": self.override_reason,
            "report_status": self.report_status.value,
            "evidence_strength": self.evidence_strength,
        }


@dataclass
class AdjudicationSummary:
    """Summary of adjudication results for a batch."""
    total_findings: int = 0
    unique_findings: int = 0
    duplicates_removed: int = 0
    by_final_status: dict[str, int] = field(default_factory=dict)
    by_report_status: dict[str, int] = field(default_factory=dict)
    overrides_applied: int = 0
    evidence_strength: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "total_findings": self.total_findings,
            "unique_findings": self.unique_findings,
            "duplicates_removed": self.duplicates_removed,
            "by_final_status": self.by_final_status,
            "by_report_status": self.by_report_status,
            "overrides_applied": self.overrides_applied,
            "evidence_strength": self.evidence_strength,
        }


class AdjudicationService:
    """Service for adjudicating findings (P14-03).

    This service provides:
    1. Semantic deduplication using ClusterBasedDeduplicator
    2. Exploitability-based adjudication
    3. Evidence strength assessment
    4. Report status application
    """

    def __init__(
        self,
        enable_deduplication: bool = True,
        enable_adjudication: bool = True,
        cluster_distance_threshold: float = 0.3,
        llm_client: Optional[Any] = None,
    ):
        """Initialize the adjudication service.

        Args:
            enable_deduplication: Whether to enable semantic deduplication
            enable_adjudication: Whether to enable exploitability adjudication
            cluster_distance_threshold: Distance threshold for clustering (0-1)
            llm_client: Optional LLM client for semantic deduplication
        """
        self.enable_deduplication = enable_deduplication
        self.enable_adjudication = enable_adjudication

        # Initialize deduplicator
        self.deduplicator: Optional[ClusterBasedDeduplicator] = None
        if enable_deduplication:
            config = ClusterDeduplicatorConfig(
                distance_threshold=cluster_distance_threshold,
                enable_llm_dedup=llm_client is not None,
            )
            self.deduplicator = ClusterBasedDeduplicator(
                config=config,
                llm_client=llm_client,
            )
            logger.info(
                f"AdjudicationService: deduplication enabled "
                f"(threshold={cluster_distance_threshold}, llm={llm_client is not None})"
            )

        if enable_adjudication:
            logger.info("AdjudicationService: exploitability adjudication enabled")

    def deduplicate_findings(
        self,
        findings: list[Finding],
    ) -> tuple[list[Finding], DeduplicationResult]:
        """Remove duplicate findings using semantic deduplication.

        Args:
            findings: List of findings to deduplicate

        Returns:
            Tuple of (unique_findings, deduplication_result)
        """
        if not self.deduplicator or not findings:
            return findings, DeduplicationResult(
                unique_findings=findings,
                removed_count=0,
                merged_groups=0,
            )

        logger.info(f"Deduplicating {len(findings)} findings")

        # Run deduplication (deduplicator.deduplicate is now async)
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            # We're in an async context, we can't await here
            # This method shouldn't be called from async context
            logger.warning("deduplicate_findings() called from async context, returning all findings")
            result = DeduplicationResult(
                unique_findings=findings,
                removed_count=0,
                merged_groups=0,
            )
        except RuntimeError:
            # No running loop, we can use asyncio.run
            result = asyncio.run(self.deduplicator.deduplicate(findings))

        logger.info(
            f"Deduplication complete: {len(result.unique_findings)} unique, "
            f"{result.removed_count} duplicates removed, "
            f"{result.merged_groups} groups merged"
        )

        return result.unique_findings, result

    def adjudicate_finding(
        self,
        finding: Finding,
    ) -> AdjudicationResult:
        """Adjudicate a single finding based on exploitability.

        Args:
            finding: The finding to adjudicate

        Returns:
            AdjudicationResult with final status
        """
        if not self.enable_adjudication:
            # Default adjudication when disabled
            return AdjudicationResult(
                finding_id=finding.id,
                final_status=FinalStatus.CONDITIONAL,
                exploitability=None,
                severity=get_severity_value(finding),
                override_applied=False,
                override_reason="Adjudication disabled",
                report_status=ReportStatus.PROCESSED,
            )

        # Apply exploitability override
        cli_result = apply_exploitability_override(finding)

        # Apply report status
        report_status = map_to_report_status(finding)

        # Get evidence strength if available
        evidence_strength = None
        if hasattr(finding, "evidence_strength"):
            ev = finding.evidence_strength
            if hasattr(ev, "value"):
                evidence_strength = ev.value
            else:
                evidence_strength = str(ev).lower()

        return AdjudicationResult(
            finding_id=finding.id,
            final_status=cli_result.final_status,
            exploitability=cli_result.exploitability,
            severity=cli_result.severity,
            override_applied=cli_result.override_applied,
            override_reason=cli_result.override_reason,
            report_status=report_status,
            evidence_strength=evidence_strength,
        )

    async def adjudicate_findings_batch(
        self,
        findings: list[Finding],
    ) -> tuple[list[Finding], AdjudicationSummary]:
        """Adjudicate a batch of findings (async version for proper LLM token tracking).

        Args:
            findings: List of findings to adjudicate

        Returns:
            Tuple of (adjudicated_findings, summary)
        """
        summary = AdjudicationSummary()
        summary.total_findings = len(findings)

        # Step 1: Deduplicate
        unique_findings, dedup_result = self.deduplicate_findings(findings)
        summary.unique_findings = len(unique_findings)
        summary.duplicates_removed = dedup_result.removed_count

        # Step 2: Adjudicate each unique finding
        adjudicated_findings = []
        for finding in unique_findings:
            result = self.adjudicate_finding(finding)

            # Store result in finding metadata
            finding.metadata = finding.metadata or {}
            finding.metadata["adjudication"] = result.to_dict()

            # Update counters
            final_status = result.final_status.value
            summary.by_final_status[final_status] = (
                summary.by_final_status.get(final_status, 0) + 1
            )

            report_status = result.report_status.value
            summary.by_report_status[report_status] = (
                summary.by_report_status.get(report_status, 0) + 1
            )

            if result.override_applied:
                summary.overrides_applied += 1

            if result.evidence_strength:
                summary.evidence_strength[result.evidence_strength] = (
                    summary.evidence_strength.get(result.evidence_strength, 0) + 1
                )

            adjudicated_findings.append(finding)

        logger.info(
            f"Adjudication complete: {summary.total_findings} total, "
            f"{summary.unique_findings} unique, "
            f"{summary.overrides_applied} overrides applied"
        )

        return adjudicated_findings, summary


def create_adjudication_service(
    enable_deduplication: bool = True,
    enable_adjudication: bool = True,
    cluster_distance_threshold: float = 0.3,
    llm_client: Optional[Any] = None,
) -> AdjudicationService:
    """Factory function to create an AdjudicationService.

    Args:
        enable_deduplication: Whether to enable semantic deduplication
        enable_adjudication: Whether to enable exploitability adjudication
        cluster_distance_threshold: Distance threshold for clustering (0-1)
        llm_client: Optional LLM client for semantic deduplication

    Returns:
        Configured AdjudicationService instance
    """
    return AdjudicationService(
        enable_deduplication=enable_deduplication,
        enable_adjudication=enable_adjudication,
        cluster_distance_threshold=cluster_distance_threshold,
        llm_client=llm_client,
    )
