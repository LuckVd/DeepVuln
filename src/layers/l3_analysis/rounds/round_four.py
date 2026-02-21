"""
Round Four Executor - Exploitability Verification

Fourth round of multi-round audit: verify vulnerability exploitability
and calibrate severity based on real-world attack feasibility.
"""

import uuid
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.models import Finding, SeverityLevel
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
from src.layers.l3_analysis.task.context_builder import (
    CallChainInfo,
    ContextBuilder,
    DataFlowMarker,
)


class ExploitabilityStatus(str, Enum):
    """Status of exploitability verification."""

    EXPLOITABLE = "exploitable"  # Can be exploited in real attack
    CONDITIONAL = "conditional"  # Exploitable under specific conditions
    UNLIKELY = "unlikely"  # Unlikely to be exploitable
    NOT_EXPLOITABLE = "not_exploitable"  # Cannot be exploited
    NEEDS_REVIEW = "needs_review"  # Needs manual review


class SeverityAdjustment(BaseModel):
    """Record of a severity adjustment."""

    original_severity: SeverityLevel
    adjusted_severity: SeverityLevel
    reason: str
    factors: list[str] = Field(default_factory=list)


class ExploitabilityResult(BaseModel):
    """Result of exploitability verification for a single finding."""

    finding_id: str
    status: ExploitabilityStatus
    confidence: float = Field(ge=0.0, le=1.0)

    # Analysis results
    is_entry_point: bool = False
    entry_point_type: str | None = None
    is_user_controlled: bool = False
    data_source_type: str | None = None
    prerequisites: list[str] = Field(default_factory=list)

    # Severity adjustment
    severity_adjustment: SeverityAdjustment | None = None

    # Evidence
    call_chain: CallChainInfo | None = None
    data_flow_markers: list[DataFlowMarker] = Field(default_factory=list)

    # Reasoning
    reasoning: str = ""

    # Metadata
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RoundFourExecutor:
    """
    Fourth round executor: Exploitability Verification.

    This round performs:
    1. Attack surface analysis (is code reachable?)
    2. Data source verification (is input user-controlled?)
    3. Prerequisite analysis (what conditions must be met?)
    4. Severity calibration (adjust based on real-world feasibility)
    """

    # Confidence threshold for auto-confirmation
    AUTO_CONFIRM_THRESHOLD = 0.85

    # Confidence threshold for auto-false-positive
    AUTO_FP_THRESHOLD = 0.25

    # Severity downgrade rules
    DOWNGRADE_RULES = {
        "no_entry_point": {
            "new_severity": SeverityLevel.INFO,
            "reason": "Code is not reachable from external entry points",
        },
        "internal_config_source": {
            "new_severity": SeverityLevel.LOW,
            "reason": "Input comes from internal configuration, not user",
        },
        "trusted_source": {
            "new_severity": SeverityLevel.LOW,
            "reason": "Input comes from trusted internal source",
        },
        "requires_auth": {
            "new_severity": None,  # Downgrade by one level
            "reason": "Exploitation requires authentication",
        },
        "requires_admin": {
            "new_severity": SeverityLevel.LOW,
            "reason": "Exploitation requires administrative privileges",
        },
        "framework_internal": {
            "new_severity": SeverityLevel.INFO,
            "reason": "This is internal framework code, not directly exploitable",
        },
        "rare_conditions": {
            "new_severity": None,  # Downgrade by one level
            "reason": "Exploitation requires rare/specific conditions",
        },
    }

    def __init__(
        self,
        source_path: Path,
        context_builder: ContextBuilder | None = None,
    ):
        """
        Initialize the round four executor.

        Args:
            source_path: Path to source code.
            context_builder: Context builder instance (creates one if None).
        """
        self.logger = get_logger(__name__)
        self.source_path = source_path
        self._context_builder = context_builder or ContextBuilder()

    async def execute(
        self,
        strategy: AuditStrategy,
        previous_round: RoundResult | None = None,
    ) -> RoundResult:
        """
        Execute round four: Exploitability Verification.

        Args:
            strategy: Audit strategy with targets.
            previous_round: Result from round three (contains candidates).

        Returns:
            Round result with verified/adjusted findings.
        """
        self.logger.info("Starting Round 4: Exploitability Verification")

        # Initialize round result
        round_result = RoundResult(
            round_number=4,
            status=RoundStatus.RUNNING,
            started_at=datetime.now(UTC),
        )

        # Initialize coverage stats
        coverage = CoverageStats(
            total_targets=strategy.total_targets,
        )

        # Initialize engine stats
        engine_stats = EngineStats(
            engine="exploitability-verifier",
            enabled=True,
            executed=True,
            start_time=datetime.now(UTC),
        )

        try:
            # Get candidates from previous round
            if not previous_round or not previous_round.candidates:
                self.logger.info("No candidates to verify in Round 4")
                round_result.status = RoundStatus.SKIPPED
                round_result.mark_completed()
                return round_result

            candidates = previous_round.candidates
            coverage.total_targets = len(candidates)

            self.logger.info(f"Verifying exploitability for {len(candidates)} candidates")

            # Process each candidate
            for candidate in candidates:
                try:
                    result = await self._verify_exploitability(candidate)

                    # Update candidate based on result
                    self._apply_verification_result(candidate, result)

                    # Add to round result
                    round_result.add_candidate(candidate)
                    coverage.analyzed_targets += 1

                    # Track for next round if needed
                    if result.status == ExploitabilityStatus.NEEDS_REVIEW:
                        round_result.next_round_candidates.append(candidate.id)

                except Exception as e:
                    self.logger.warning(f"Error verifying {candidate.id}: {e}")
                    candidate.add_evidence("exploitability_verification", {
                        "error": str(e),
                        "status": "error",
                    })

            # Update engine stats
            engine_stats.end_time = datetime.now(UTC)
            engine_stats.duration_seconds = (
                engine_stats.end_time - engine_stats.start_time
            ).total_seconds()
            engine_stats.targets_analyzed = coverage.analyzed_targets

            # Complete round
            round_result.coverage = coverage
            round_result.engine_stats["exploitability-verifier"] = engine_stats
            round_result.mark_completed()

            self.logger.info(
                f"Round 4 completed: {coverage.analyzed_targets} verified, "
                f"{len(round_result.next_round_candidates)} need manual review"
            )

            return round_result

        except Exception as e:
            self.logger.error(f"Round 4 failed: {e}")
            round_result.mark_failed(str(e))
            return round_result

    async def _verify_exploitability(
        self,
        candidate: VulnerabilityCandidate,
    ) -> ExploitabilityResult:
        """
        Verify exploitability of a single vulnerability candidate.

        Args:
            candidate: The vulnerability candidate to verify.

        Returns:
            ExploitabilityResult with verification details.
        """
        finding = candidate.finding
        location = finding.location

        # Get call chain analysis
        call_chain = self._context_builder.analyze_call_chain(
            source_path=self.source_path,
            file_path=location.file,
            function_name=self._extract_function_name(location.snippet or ""),
        )

        # Get data flow analysis
        data_flow = self._context_builder.analyze_data_flow(
            source_path=self.source_path,
            file_path=location.file,
            function_name=self._extract_function_name(location.snippet or ""),
        )

        # Determine exploitability
        status, confidence, reasoning = self._assess_exploitability(
            call_chain=call_chain,
            data_flow=data_flow,
            finding=finding,
        )

        # Determine severity adjustment
        severity_adjustment = self._calculate_severity_adjustment(
            original_severity=finding.severity,
            call_chain=call_chain,
            data_flow=data_flow,
            status=status,
        )

        return ExploitabilityResult(
            finding_id=finding.id,
            status=status,
            confidence=confidence,
            is_entry_point=call_chain.is_entry_point if call_chain else False,
            entry_point_type=call_chain.entry_point_type if call_chain else None,
            is_user_controlled=self._has_user_controlled_data(data_flow),
            data_source_type=self._get_primary_data_source(data_flow),
            prerequisites=self._extract_prerequisites(call_chain, data_flow),
            severity_adjustment=severity_adjustment,
            call_chain=call_chain,
            data_flow_markers=data_flow,
            reasoning=reasoning,
        )

    def _assess_exploitability(
        self,
        call_chain: CallChainInfo | None,
        data_flow: list[DataFlowMarker],
        finding: Finding,
    ) -> tuple[ExploitabilityStatus, float, str]:
        """
        Assess the exploitability of a finding.

        Returns:
            Tuple of (status, confidence, reasoning).
        """
        reasoning_parts = []

        # Check 1: Is this code reachable from external entry points?
        if call_chain:
            if call_chain.is_entry_point:
                reasoning_parts.append(
                    f"Code IS an external entry point ({call_chain.entry_point_type})."
                )
            elif call_chain.callers:
                reasoning_parts.append(
                    f"Code is called by {len(call_chain.callers)} other functions."
                )
                # Check if any caller is an entry point
                has_entry_caller = any(
                    self._is_entry_caller(c) for c in call_chain.callers
                )
                if not has_entry_caller:
                    reasoning_parts.append("No external entry points found in call chain.")
            else:
                reasoning_parts.append("No external callers found - may be internal/dead code.")
        else:
            reasoning_parts.append("Could not determine call chain.")

        # Check 2: Is the input user-controlled?
        user_controlled = self._has_user_controlled_data(data_flow)
        if user_controlled:
            reasoning_parts.append("Input appears to be USER-CONTROLLED.")
        else:
            sources = [m.source_type for m in data_flow]
            if "config" in sources:
                reasoning_parts.append("Input comes from CONFIGURATION (not user-controlled).")
            elif "trusted" in sources:
                reasoning_parts.append("Input comes from TRUSTED source.")
            elif not data_flow:
                reasoning_parts.append("Could not determine data sources.")

        # Check 3: Determine final status
        if not call_chain or (not call_chain.is_entry_point and not call_chain.callers):
            # No entry point found
            return (
                ExploitabilityStatus.NOT_EXPLOITABLE,
                0.2,
                " | ".join(reasoning_parts) + " | Severity should be INFO."
            )

        if not user_controlled:
            # Input not user-controlled
            if call_chain.is_entry_point:
                return (
                    ExploitabilityStatus.UNLIKELY,
                    0.4,
                    " | ".join(reasoning_parts) + " | Entry point exists but input is not user-controlled."
                )
            else:
                return (
                    ExploitabilityStatus.NOT_EXPLOITABLE,
                    0.25,
                    " | ".join(reasoning_parts) + " | No user-controlled input path found."
                )

        if call_chain.is_entry_point and user_controlled:
            return (
                ExploitabilityStatus.EXPLOITABLE,
                0.85,
                " | ".join(reasoning_parts) + " | REAL VULNERABILITY - externally reachable with user input."
            )

        # Default: needs review
        return (
            ExploitabilityStatus.NEEDS_REVIEW,
            0.5,
            " | ".join(reasoning_parts) + " | Could not determine exploitability - needs manual review."
        )

    def _calculate_severity_adjustment(
        self,
        original_severity: SeverityLevel,
        call_chain: CallChainInfo | None,
        data_flow: list[DataFlowMarker],
        status: ExploitabilityStatus,
    ) -> SeverityAdjustment | None:
        """
        Calculate severity adjustment based on exploitability analysis.

        Returns:
            SeverityAdjustment if adjustment is needed, None otherwise.
        """
        factors = []
        new_severity = original_severity
        reason = ""

        # Factor 1: No entry point
        if call_chain and not call_chain.is_entry_point and not call_chain.callers:
            rule = self.DOWNGRADE_RULES["no_entry_point"]
            new_severity = rule["new_severity"]
            reason = rule["reason"]
            factors.append("no_entry_point")

        # Factor 2: Internal config source
        elif self._has_only_config_sources(data_flow):
            rule = self.DOWNGRADE_RULES["internal_config_source"]
            new_severity = rule["new_severity"]
            reason = rule["reason"]
            factors.append("internal_config_source")

        # Factor 3: Trusted source
        elif self._has_only_trusted_sources(data_flow):
            rule = self.DOWNGRADE_RULES["trusted_source"]
            new_severity = rule["new_severity"]
            reason = rule["reason"]
            factors.append("trusted_source")

        # Factor 4: Based on exploitability status
        elif status == ExploitabilityStatus.NOT_EXPLOITABLE:
            new_severity = SeverityLevel.INFO
            reason = "Vulnerability is not exploitable"
            factors.append("not_exploitable")
        elif status == ExploitabilityStatus.UNLIKELY:
            new_severity = self._downgrade_one_level(original_severity)
            reason = "Exploitation is unlikely"
            factors.append("unlikely_exploitation")

        # No adjustment needed
        if new_severity == original_severity:
            return None

        return SeverityAdjustment(
            original_severity=original_severity,
            adjusted_severity=new_severity,
            reason=reason,
            factors=factors,
        )

    def _apply_verification_result(
        self,
        candidate: VulnerabilityCandidate,
        result: ExploitabilityResult,
    ) -> None:
        """Apply verification result to a candidate."""
        # Add evidence
        candidate.add_evidence("exploitability_verification", {
            "status": result.status.value,
            "confidence": result.confidence,
            "is_entry_point": result.is_entry_point,
            "is_user_controlled": result.is_user_controlled,
            "reasoning": result.reasoning,
        })

        # Apply severity adjustment
        if result.severity_adjustment:
            adj = result.severity_adjustment
            candidate.finding.severity = adj.adjusted_severity
            candidate.finding.metadata = candidate.finding.metadata or {}
            candidate.finding.metadata["severity_adjustment"] = {
                "original": adj.original_severity.value,
                "adjusted": adj.adjusted_severity.value,
                "reason": adj.reason,
                "factors": adj.factors,
            }

            self.logger.info(
                f"Adjusted severity for {candidate.finding.title}: "
                f"{adj.original_severity.value} -> {adj.adjusted_severity.value} "
                f"({adj.reason})"
            )

        # Update confidence
        if result.confidence >= 0.8:
            candidate.confidence = ConfidenceLevel.HIGH
        elif result.confidence >= 0.5:
            candidate.confidence = ConfidenceLevel.MEDIUM
        else:
            candidate.confidence = ConfidenceLevel.LOW

        # Mark for verification if needed
        candidate.needs_verification = (
            result.status == ExploitabilityStatus.NEEDS_REVIEW
        )

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _extract_function_name(self, code_snippet: str) -> str | None:
        """Extract function name from code snippet."""
        import re

        # Try to find function definition
        patterns = [
            r'def\s+(\w+)\s*\(',  # Python
            r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\(',  # Java
            r'function\s+(\w+)\s*\(',  # JavaScript
            r'func\s+(\w+)\s*\(',  # Go
        ]

        for pattern in patterns:
            match = re.search(pattern, code_snippet)
            if match:
                return match.group(1)

        return None

    def _has_user_controlled_data(self, data_flow: list[DataFlowMarker]) -> bool:
        """Check if any data flow marker indicates user-controlled input."""
        return any(m.source_type == "user_input" for m in data_flow)

    def _get_primary_data_source(self, data_flow: list[DataFlowMarker]) -> str | None:
        """Get the primary data source type."""
        if not data_flow:
            return None

        # Priority: user_input > config > trusted > internal
        priority = ["user_input", "config", "trusted", "internal"]
        for source_type in priority:
            if any(m.source_type == source_type for m in data_flow):
                return source_type

        return data_flow[0].source_type if data_flow else None

    def _has_only_config_sources(self, data_flow: list[DataFlowMarker]) -> bool:
        """Check if all data sources are configuration."""
        if not data_flow:
            return False
        return all(m.source_type in ("config", "internal") for m in data_flow)

    def _has_only_trusted_sources(self, data_flow: list[DataFlowMarker]) -> bool:
        """Check if all data sources are trusted."""
        if not data_flow:
            return False
        return all(m.source_type in ("trusted", "internal") for m in data_flow)

    def _is_entry_caller(self, caller: dict[str, str]) -> bool:
        """Check if a caller function is an entry point."""
        # Common entry point patterns
        entry_patterns = [
            "main", "handle", "process", "execute", "run",
            "onMessage", "onRequest", "doGet", "doPost",
            "controller", "handler", "endpoint",
        ]
        name = caller.get("name", "").lower()
        return any(p in name for p in entry_patterns)

    def _extract_prerequisites(
        self,
        call_chain: CallChainInfo | None,
        data_flow: list[DataFlowMarker],
    ) -> list[str]:
        """Extract prerequisites for exploitation."""
        prerequisites = []

        if call_chain and not call_chain.is_entry_point:
            prerequisites.append("Must reach internal function through call chain")

        if data_flow:
            for marker in data_flow:
                if marker.source_type == "config":
                    prerequisites.append("Must control configuration values")
                elif marker.source_type == "trusted":
                    prerequisites.append("Must compromise trusted data source")

        return prerequisites

    def _downgrade_one_level(self, severity: SeverityLevel) -> SeverityLevel:
        """Downgrade severity by one level."""
        downgrade_map = {
            SeverityLevel.CRITICAL: SeverityLevel.HIGH,
            SeverityLevel.HIGH: SeverityLevel.MEDIUM,
            SeverityLevel.MEDIUM: SeverityLevel.LOW,
            SeverityLevel.LOW: SeverityLevel.INFO,
            SeverityLevel.INFO: SeverityLevel.INFO,
        }
        return downgrade_map.get(severity, severity)
