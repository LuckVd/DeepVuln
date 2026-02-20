"""
Round Three Executor - Correlation Verification

Third round of multi-round audit: correlation and final verification.
"""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.rounds.correlation import (
    CorrelationResult,
    CorrelationRule,
    DEFAULT_CORRELATION_RULES,
    EvidenceChain,
    VerificationStatus,
)
from src.layers.l3_analysis.rounds.evidence_builder import EvidenceChainBuilder
from src.layers.l3_analysis.rounds.models import (
    AnalysisDepth,
    AuditSession,
    ConfidenceLevel,
    CoverageStats,
    EngineStats,
    RoundResult,
    RoundStatus,
    VulnerabilityCandidate,
)
from src.layers.l3_analysis.strategy.models import AuditStrategy


class RoundThreeExecutor:
    """
    Third round executor: Correlation Verification.

    This round performs:
    1. Multi-source evidence aggregation
    2. Cross-verification between sources
    3. Pattern matching against known vulnerabilities
    4. Final vulnerability determination
    """

    # Confidence threshold for auto-confirmation
    AUTO_CONFIRM_THRESHOLD = 0.85

    # Confidence threshold for auto-fp
    AUTO_FP_THRESHOLD = 0.25

    def __init__(
        self,
        source_path: Path,
        agent_executor: Any | None = None,
        correlation_rules: list[CorrelationRule] | None = None,
        evidence_builder: EvidenceChainBuilder | None = None,
    ):
        """
        Initialize the round three executor.

        Args:
            source_path: Path to source code.
            agent_executor: Async function to execute Agent verification.
            correlation_rules: Custom correlation rules (uses defaults if None).
            evidence_builder: Custom evidence chain builder (creates one if None).
        """
        self.logger = get_logger(__name__)
        self.source_path = source_path
        self._agent_executor = agent_executor
        self._correlation_rules = correlation_rules or DEFAULT_CORRELATION_RULES
        self._evidence_builder = evidence_builder or EvidenceChainBuilder(source_path)

    async def execute(
        self,
        strategy: AuditStrategy,
        previous_round: RoundResult | None = None,
    ) -> RoundResult:
        """
        Execute round three: Correlation Verification.

        Args:
            strategy: Audit strategy with targets.
            previous_round: Result from round two (contains deep analysis results).

        Returns:
            Round result with final vulnerability determinations.
        """
        self.logger.info("Starting Round 3: Correlation Verification")

        # Initialize round result
        round_result = RoundResult(
            round_number=3,
            status=RoundStatus.RUNNING,
            started_at=datetime.now(UTC),
        )

        # Initialize coverage stats
        coverage = CoverageStats(
            total_targets=strategy.total_targets,
        )

        try:
            # Get candidates from round two
            if not previous_round or not previous_round.candidates:
                self.logger.info("No candidates from round two, skipping correlation")
                round_result.mark_completed()
                return round_result

            candidates = previous_round.get_candidates_for_next_round()
            self.logger.info(f"Processing {len(candidates)} candidates for correlation")

            # Phase 1: Build evidence chains
            correlation_stats = await self._build_evidence_chains(
                candidates, round_result, coverage
            )

            # Phase 2: Apply correlation rules
            rule_stats = await self._apply_correlation_rules(
                candidates, round_result, coverage
            )

            # Phase 3: Final determination
            self._make_final_determinations(candidates, round_result)

            # Update engine stats
            round_result.engine_stats["correlation"] = correlation_stats
            round_result.engine_stats["rules"] = rule_stats

            # Phase 4: Categorize final results
            self._categorize_results(round_result)

            # Update coverage
            round_result.coverage = coverage

            # Mark completed
            round_result.mark_completed()

            self.logger.info(
                f"Round 3 completed: {round_result.total_candidates} candidates, "
                f"{len(round_result.candidates)} verified"
            )

        except Exception as e:
            self.logger.error(f"Round 3 failed: {e}")
            round_result.mark_failed(str(e))

        return round_result

    async def _build_evidence_chains(
        self,
        candidates: list[VulnerabilityCandidate],
        round_result: RoundResult,
        coverage: CoverageStats,
    ) -> EngineStats:
        """Build evidence chains from candidate data using EvidenceChainBuilder."""
        self.logger.info("Phase 1: Building Evidence Chains")

        stats = EngineStats(
            engine="evidence_builder",
            enabled=True,
            start_time=datetime.now(UTC),
        )

        try:
            stats.executed = True

            for candidate in candidates:
                try:
                    # Use EvidenceChainBuilder to build the chain
                    chain = self._evidence_builder.build_chain(candidate)

                    # Store chain in candidate metadata
                    if "correlation" not in candidate.metadata:
                        candidate.metadata["correlation"] = {}
                    candidate.metadata["correlation"]["evidence_chain"] = chain.model_dump()

                    candidate.analyzed_in_rounds.append(3)
                    stats.findings_count += 1

                except Exception as e:
                    self.logger.warning(
                        f"Evidence chain building failed for candidate {candidate.id}: {e}"
                    )
                    stats.add_warning(f"Candidate {candidate.id}: {e}")

            stats.candidates_count = len(candidates)
            coverage.analyzed_targets += len(candidates)

        except Exception as e:
            self.logger.error(f"Evidence chain building failed: {e}")
            stats.add_error(str(e))

        stats.end_time = datetime.now(UTC)
        if stats.start_time:
            stats.duration_seconds = (
                stats.end_time - stats.start_time
            ).total_seconds()

        return stats

    async def _apply_correlation_rules(
        self,
        candidates: list[VulnerabilityCandidate],
        round_result: RoundResult,
        coverage: CoverageStats,
    ) -> EngineStats:
        """Apply correlation rules to evidence chains."""
        self.logger.info("Phase 2: Applying Correlation Rules")

        stats = EngineStats(
            engine="correlation_rules",
            enabled=True,
            start_time=datetime.now(UTC),
        )

        try:
            stats.executed = True

            for candidate in candidates:
                try:
                    # Get evidence chain
                    chain_data = candidate.metadata.get("correlation", {}).get("evidence_chain")
                    if not chain_data:
                        continue

                    chain = EvidenceChain(**chain_data)

                    # Create correlation result
                    result = CorrelationResult(
                        id=f"corr-{uuid.uuid4().hex[:8]}",
                        candidate_id=candidate.id,
                        evidence_chain=chain,
                    )

                    # Apply each rule
                    for rule in self._correlation_rules:
                        if rule.matches(chain):
                            result.add_matched_rule(rule)
                            self.logger.debug(
                                f"Rule '{rule.name}' matched for candidate {candidate.id}"
                            )

                    # Store result
                    candidate.metadata["correlation"]["result"] = result.model_dump()
                    stats.findings_count += 1

                except Exception as e:
                    self.logger.warning(
                        f"Correlation rules failed for candidate {candidate.id}: {e}"
                    )
                    stats.add_warning(f"Candidate {candidate.id}: {e}")

            stats.candidates_count = len(candidates)

        except Exception as e:
            self.logger.error(f"Correlation rules failed: {e}")
            stats.add_error(str(e))

        stats.end_time = datetime.now(UTC)
        if stats.start_time:
            stats.duration_seconds = (
                stats.end_time - stats.start_time
            ).total_seconds()

        return stats

    def _make_final_determinations(
        self,
        candidates: list[VulnerabilityCandidate],
        round_result: RoundResult,
    ) -> None:
        """Make final vulnerability determinations."""
        self.logger.info("Phase 3: Making Final Determinations")

        for candidate in candidates:
            correlation_data = candidate.metadata.get("correlation", {})
            result_data = correlation_data.get("result")
            chain_data = correlation_data.get("evidence_chain")

            if not result_data or not chain_data:
                # No correlation performed, keep existing status
                continue

            result = CorrelationResult(**result_data)
            chain = EvidenceChain(**chain_data)

            # Determine final status based on correlation
            final_status = self._determine_status(result, chain)
            result.verification_status = final_status

            # Calculate final confidence
            final_confidence = self._calculate_final_confidence(result, chain)
            result.final_confidence = final_confidence

            # Generate verdict
            verdict, reasons = self._generate_verdict(final_status, result, chain)
            result.verdict = verdict
            result.verdict_reasons = reasons

            # Check if manual review needed
            if final_status == VerificationStatus.UNCERTAIN:
                result.needs_manual_review = True
                result.review_reasons.append("Confidence below auto-determination threshold")

            # Update candidate
            candidate.metadata["correlation"]["result"] = result.model_dump()

            # Map verification status back to confidence level
            if final_status == VerificationStatus.CONFIRMED:
                candidate.confidence = ConfidenceLevel.HIGH
            elif final_status == VerificationStatus.LIKELY:
                candidate.confidence = ConfidenceLevel.HIGH
            elif final_status == VerificationStatus.FALSE_POSITIVE:
                candidate.confidence = ConfidenceLevel.LOW
            elif final_status == VerificationStatus.NOT_EXPLOITABLE:
                candidate.confidence = ConfidenceLevel.LOW
            # UNCERTAIN keeps existing confidence

    def _determine_status(
        self,
        result: CorrelationResult,
        chain: EvidenceChain,
    ) -> VerificationStatus:
        """Determine final verification status."""
        # If any rule set a specific status, use it
        if result.verification_status != VerificationStatus.UNCERTAIN:
            return result.verification_status

        # Check for explicit false positive evidence
        for evidence in chain.evidences:
            if evidence.metadata.get("is_false_positive"):
                return VerificationStatus.FALSE_POSITIVE

        # Check for sanitizer in dataflow
        for path in chain.dataflow_paths:
            if path.has_effective_sanitizer:
                return VerificationStatus.NOT_EXPLOITABLE

        # Use confidence-based determination
        if chain.weighted_confidence >= self.AUTO_CONFIRM_THRESHOLD:
            return VerificationStatus.CONFIRMED
        elif chain.weighted_confidence >= 0.6:
            return VerificationStatus.LIKELY
        elif chain.weighted_confidence <= self.AUTO_FP_THRESHOLD:
            return VerificationStatus.FALSE_POSITIVE

        return VerificationStatus.UNCERTAIN

    def _calculate_final_confidence(
        self,
        result: CorrelationResult,
        chain: EvidenceChain,
    ) -> float:
        """Calculate final confidence score."""
        base_confidence = chain.weighted_confidence

        # Boost for multiple sources
        if chain.source_count >= 3:
            base_confidence = min(1.0, base_confidence + 0.1)
        elif chain.source_count >= 2:
            base_confidence = min(1.0, base_confidence + 0.05)

        # Boost for matched rules
        base_confidence = min(1.0, base_confidence + len(result.matched_rules) * 0.05)

        # Penalty for conflicts
        if not chain.consistent:
            base_confidence = max(0.0, base_confidence - 0.15)

        # Boost for complete dataflow
        complete_paths = sum(1 for p in chain.dataflow_paths if p.is_complete)
        if complete_paths > 0:
            base_confidence = min(1.0, base_confidence + 0.1)

        return base_confidence

    def _generate_verdict(
        self,
        status: VerificationStatus,
        result: CorrelationResult,
        chain: EvidenceChain,
    ) -> tuple[str, list[str]]:
        """Generate human-readable verdict."""
        reasons = []

        if status == VerificationStatus.CONFIRMED:
            verdict = "Confirmed vulnerability"
            if chain.source_count >= 2:
                reasons.append(f"Confirmed by {chain.source_count} independent sources")
            if chain.dataflow_paths:
                reasons.append(f"Found {len(chain.dataflow_paths)} data flow paths")
            if result.matched_rules:
                reasons.append(f"Matched {len(result.matched_rules)} correlation rules")

        elif status == VerificationStatus.LIKELY:
            verdict = "Likely vulnerability"
            reasons.append(f"Evidence confidence: {chain.weighted_confidence:.0%}")
            reasons.append("Manual verification recommended")

        elif status == VerificationStatus.FALSE_POSITIVE:
            verdict = "False positive"
            for evidence in chain.evidences:
                if evidence.metadata.get("is_false_positive"):
                    reasons.append(f"Identified as FP by {evidence.source.value}")
            if not reasons:
                reasons.append("Low confidence across all sources")

        elif status == VerificationStatus.NOT_EXPLOITABLE:
            verdict = "Not exploitable"
            reasons.append("Effective sanitizer detected in data flow")

        else:  # UNCERTAIN
            verdict = "Requires manual review"
            reasons.append(f"Evidence confidence: {chain.weighted_confidence:.0%}")
            reasons.append("Insufficient evidence for auto-determination")

        return verdict, reasons

    def _categorize_results(self, round_result: RoundResult) -> None:
        """Categorize candidates into final groups."""
        confirmed = []
        likely = []
        uncertain = []
        false_positive = []
        not_exploitable = []

        for candidate in round_result.candidates:
            result_data = candidate.metadata.get("correlation", {}).get("result")
            if not result_data:
                uncertain.append(candidate)
                continue

            status = VerificationStatus(result_data.get("verification_status", "uncertain"))

            if status == VerificationStatus.CONFIRMED:
                confirmed.append(candidate)
            elif status == VerificationStatus.LIKELY:
                likely.append(candidate)
            elif status == VerificationStatus.FALSE_POSITIVE:
                false_positive.append(candidate)
            elif status == VerificationStatus.NOT_EXPLOITABLE:
                not_exploitable.append(candidate)
            else:
                uncertain.append(candidate)

        # Store categories in metadata
        round_result.metadata["categories"] = {
            "confirmed": len(confirmed),
            "likely": len(likely),
            "uncertain": len(uncertain),
            "false_positive": len(false_positive),
            "not_exploitable": len(not_exploitable),
        }

        # Candidates marked as confirmed or likely should be in final results
        round_result.next_round_candidates = [
            c.id for c in confirmed + likely
        ]

        self.logger.info(
            f"Results: {len(confirmed)} confirmed, {len(likely)} likely, "
            f"{len(uncertain)} uncertain, {len(false_positive)} FP, "
            f"{len(not_exploitable)} not exploitable"
        )
