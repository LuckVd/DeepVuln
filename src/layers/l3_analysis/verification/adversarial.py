"""
Adversarial Verifier - Main controller for the three-role verification system.

This module orchestrates the adversarial verification process, coordinating
the attacker, defender, and arbiter roles to validate vulnerability findings.
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from ..llm.client import LLMClient
from ..models import Finding
from .arbiter import ArbiterVerifier
from .attacker import AttackerVerifier
from .defender import DefenderVerifier
from .models import (
    AdversarialVerdict,
    VerificationResult,
    VerificationSession,
    VerdictType,
)

logger = logging.getLogger(__name__)


class AdversarialVerifierConfig:
    """Configuration for adversarial verification."""

    def __init__(
        self,
        enabled: bool = True,
        max_rounds: int = 1,
        max_context_length: int = 4000,
        parallel_analysis: bool = True,
        skip_low_severity: bool = False,
        skip_info_findings: bool = True,
        confidence_threshold: float = 0.7,
        use_heuristic_fallback: bool = True,
    ):
        """
        Initialize configuration.

        Args:
            enabled: Whether adversarial verification is enabled.
            max_rounds: Maximum debate rounds (currently only 1 supported).
            max_context_length: Maximum code context for analysis.
            parallel_analysis: Run attacker and defender in parallel.
            skip_low_severity: Skip verification for low severity findings.
            skip_info_findings: Skip verification for info-level findings.
            confidence_threshold: Minimum confidence to accept verdict.
            use_heuristic_fallback: Use heuristics if LLM fails.
        """
        self.enabled = enabled
        self.max_rounds = max_rounds
        self.max_context_length = max_context_length
        self.parallel_analysis = parallel_analysis
        self.skip_low_severity = skip_low_severity
        self.skip_info_findings = skip_info_findings
        self.confidence_threshold = confidence_threshold
        self.use_heuristic_fallback = use_heuristic_fallback


class AdversarialVerifier:
    """
    Main controller for adversarial verification.

    Coordinates the three-role verification process:
    1. Attacker analyzes exploitability
    2. Defender analyzes mitigations
    3. Arbiter makes final judgment
    """

    def __init__(
        self,
        llm_client: LLMClient,
        config: AdversarialVerifierConfig | None = None,
    ):
        """
        Initialize the adversarial verifier.

        Args:
            llm_client: LLM client for analysis.
            config: Configuration options.
        """
        self.llm_client = llm_client
        self.config = config or AdversarialVerifierConfig()

        # Initialize role verifiers
        self.attacker = AttackerVerifier(
            llm_client=llm_client,
            max_context_length=self.config.max_context_length,
        )
        self.defender = DefenderVerifier(
            llm_client=llm_client,
            max_context_length=self.config.max_context_length,
        )
        self.arbiter = ArbiterVerifier(
            llm_client=llm_client,
            use_heuristic_fallback=self.config.use_heuristic_fallback,
        )

    async def verify_finding(
        self,
        finding: Finding | dict[str, Any],
        code_context: str,
        related_code: str | None = None,
    ) -> VerificationResult:
        """
        Verify a single vulnerability finding.

        Args:
            finding: The vulnerability finding to verify.
            code_context: The vulnerable code snippet.
            related_code: Additional context code.

        Returns:
            VerificationResult with the verification outcome.
        """
        # Convert Finding to dict if needed
        if isinstance(finding, Finding):
            finding_dict = {
                "id": finding.id,
                "type": finding.rule_id or "unknown",
                "severity": finding.severity.value,
                "title": finding.title,
                "description": finding.description,
                "location": finding.location.to_display(),
                "code_snippet": finding.location.snippet,
                "dataflow": finding.metadata.get("dataflow"),
                "attack_surface": finding.metadata.get("attack_surface"),
                "user_controlled": finding.metadata.get("user_controlled"),
                "cwe": finding.cwe,
                "language": finding.metadata.get("language", ""),
            }
            finding_id = finding.id
        else:
            finding_dict = finding
            finding_id = finding.get("id", str(uuid.uuid4())[:8])

        # Check if we should skip verification
        if self._should_skip(finding_dict):
            return self._create_skipped_result(finding_dict, finding_id)

        # Initialize result
        result = VerificationResult(
            finding_id=finding_id,
            finding_type=finding_dict.get("type", "unknown"),
            finding_severity=finding_dict.get("severity", "medium"),
            finding_location=finding_dict.get("location", "unknown"),
        )

        start_time = datetime.now(UTC)

        try:
            # Run attacker and defender analysis
            if self.config.parallel_analysis:
                # Parallel execution
                attacker_task = self.attacker.analyze(
                    finding=finding_dict,
                    code_context=code_context,
                    related_code=related_code,
                )
                defender_task = self.defender.analyze(
                    finding=finding_dict,
                    code_context=code_context,
                    related_code=related_code,
                )

                attacker_arg, defender_arg = await asyncio.gather(
                    attacker_task, defender_task
                )
            else:
                # Sequential execution
                attacker_arg = await self.attacker.analyze(
                    finding=finding_dict,
                    code_context=code_context,
                    related_code=related_code,
                )
                defender_arg = await self.defender.analyze(
                    finding=finding_dict,
                    code_context=code_context,
                    related_code=related_code,
                    attacker_argument=attacker_arg.model_dump(),
                )

            result.attacker_argument = attacker_arg
            result.defender_argument = defender_arg

            # Record debate round
            result.debate_history.append({
                "round": 1,
                "attacker_claim": attacker_arg.claim,
                "attacker_confidence": attacker_arg.confidence,
                "defender_claim": defender_arg.claim,
                "defender_confidence": defender_arg.confidence,
            })
            result.rounds_completed = 1

            # Run arbiter evaluation
            verdict = await self.arbiter.evaluate(
                finding=finding_dict,
                attacker_argument=attacker_arg,
                defender_argument=defender_arg,
            )
            result.verdict = verdict

        except Exception as e:
            logger.error(f"Verification failed for {finding_id}: {e}")
            # Create error verdict
            result.verdict = AdversarialVerdict(
                verdict=VerdictType.NEEDS_REVIEW,
                confidence=0.0,
                summary="Verification process failed",
                reasoning=str(e),
                recommended_action="review",
                priority="medium",
            )

        # Record timing
        end_time = datetime.now(UTC)
        result.verification_completed = end_time
        result.duration_seconds = (end_time - start_time).total_seconds()

        return result

    async def verify_findings(
        self,
        findings: list[Finding | dict[str, Any]],
        source_path: str,
        code_fetcher: Callable | None = None,
    ) -> VerificationSession:
        """
        Verify multiple vulnerability findings.

        Args:
            findings: List of findings to verify.
            source_path: Path to the source code.
            code_fetcher: Optional function to fetch code for each finding.

        Returns:
            VerificationSession with all results.
        """
        session = VerificationSession(
            session_id=str(uuid.uuid4())[:12],
            source_path=source_path,
        )

        for finding in findings:
            # Get code context
            if code_fetcher:
                code_context, related_code = await code_fetcher(finding)
            else:
                code_context = self._get_default_code_context(finding)
                related_code = None

            result = await self.verify_finding(
                finding=finding,
                code_context=code_context,
                related_code=related_code,
            )
            session.add_result(result)

        session.completed_at = datetime.now(UTC)
        return session

    def _should_skip(self, finding: dict[str, Any]) -> bool:
        """Check if verification should be skipped for this finding."""
        if not self.config.enabled:
            return True

        severity = finding.get("severity", "medium").lower()

        if self.config.skip_info_findings and severity == "info":
            return True

        if self.config.skip_low_severity and severity == "low":
            return True

        # Skip suspicious code findings (low confidence)
        is_suspicious = finding.get("metadata", {}).get("is_suspicious", False)
        if is_suspicious:
            return True

        return False

    def _create_skipped_result(
        self,
        finding: dict[str, Any],
        finding_id: str,
    ) -> VerificationResult:
        """Create a result for skipped findings."""
        severity = finding.get("severity", "medium").lower()

        if severity == "info":
            reason = "Info-level findings are skipped"
        elif severity == "low":
            reason = "Low severity findings are skipped"
        elif finding.get("metadata", {}).get("is_suspicious"):
            reason = "Suspicious code findings are skipped"
        else:
            reason = "Verification disabled"

        return VerificationResult(
            finding_id=finding_id,
            finding_type=finding.get("type", "unknown"),
            finding_severity=severity,
            finding_location=finding.get("location", "unknown"),
            verdict=AdversarialVerdict(
                verdict=VerdictType.NEEDS_REVIEW,
                confidence=0.0,
                summary="Skipped verification",
                reasoning=reason,
                recommended_action="review" if severity in ["high", "critical"] else "ignore",
                priority="low",
            ),
            rounds_completed=0,
        )

    def _get_default_code_context(self, finding: Finding | dict[str, Any]) -> str:
        """Get default code context from finding."""
        if isinstance(finding, Finding):
            snippet = finding.location.snippet or ""
            description = finding.description
        else:
            snippet = finding.get("code_snippet", "")
            description = finding.get("description", "")

        if snippet:
            return snippet

        # Fall back to description
        return f"# Code context not available\n# Description: {description}"

    def get_statistics(self, session: VerificationSession) -> dict[str, Any]:
        """
        Get statistics from a verification session.

        Args:
            session: The verification session.

        Returns:
            Statistics dictionary.
        """
        stats = session.get_summary()

        # Add additional analysis
        total_tokens = sum(r.tokens_used for r in session.results)
        avg_duration = (
            sum(r.duration_seconds or 0 for r in session.results) / len(session.results)
            if session.results else 0
        )

        stats["total_tokens_used"] = total_tokens
        stats["avg_verification_time"] = avg_duration

        # Severity breakdown of confirmed
        confirmed_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for result in session.results:
            if result.verdict and result.verdict.verdict == VerdictType.CONFIRMED:
                sev = result.finding_severity.lower()
                if sev in confirmed_by_severity:
                    confirmed_by_severity[sev] += 1
        stats["confirmed_by_severity"] = confirmed_by_severity

        return stats

    def format_session_report(self, session: VerificationSession) -> str:
        """
        Format a verification session as a report.

        Args:
            session: The verification session.

        Returns:
            Formatted report string.
        """
        stats = self.get_statistics(session)

        lines = [
            "# Adversarial Verification Report",
            "",
            f"**Session ID:** {session.session_id}",
            f"**Source:** {session.source_path}",
            f"**Started:** {session.started_at.isoformat()}",
            f"**Completed:** {session.completed_at.isoformat() if session.completed_at else 'N/A'}",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Findings | {stats['total']} |",
            f"| Confirmed | {stats['confirmed']} |",
            f"| False Positives | {stats['false_positives']} |",
            f"| Needs Review | {stats['needs_review']} |",
            f"| Conditional | {stats['conditional']} |",
            f"| Confirmed Rate | {stats['confirmed_rate']:.1%} |",
            f"| False Positive Rate | {stats['false_positive_rate']:.1%} |",
            "",
            "## Confirmed by Severity",
            "",
        ]

        for sev, count in stats.get("confirmed_by_severity", {}).items():
            if count > 0:
                lines.append(f"- **{sev.upper()}**: {count}")

        lines.extend([
            "",
            "## Detailed Results",
            "",
        ])

        # Sort by verdict priority
        verdict_order = {
            VerdictType.CONFIRMED: 0,
            VerdictType.CONDITIONAL: 1,
            VerdictType.NEEDS_REVIEW: 2,
            VerdictType.FALSE_POSITIVE: 3,
        }

        sorted_results = sorted(
            session.results,
            key=lambda r: verdict_order.get(r.verdict.verdict if r.verdict else VerdictType.NEEDS_REVIEW, 99),
        )

        for result in sorted_results:
            if result.verdict:
                lines.extend([
                    f"### {result.finding_type} at {result.finding_location}",
                    "",
                    f"- **Verdict:** {result.verdict.verdict.value.upper()}",
                    f"- **Confidence:** {result.verdict.confidence:.0%}",
                    f"- **Priority:** {result.verdict.priority.upper()}",
                    f"- **Action:** {result.verdict.recommended_action}",
                    "",
                    f"**Summary:** {result.verdict.summary}",
                    "",
                ])

        return "\n".join(lines)


async def create_verifier(
    llm_client: LLMClient,
    config: dict[str, Any] | None = None,
) -> AdversarialVerifier:
    """
    Factory function to create an adversarial verifier.

    Args:
        llm_client: LLM client for analysis.
        config: Optional configuration dictionary.

    Returns:
        Configured AdversarialVerifier instance.
    """
    if config:
        verifier_config = AdversarialVerifierConfig(**config)
    else:
        verifier_config = AdversarialVerifierConfig()

    return AdversarialVerifier(llm_client=llm_client, config=verifier_config)
