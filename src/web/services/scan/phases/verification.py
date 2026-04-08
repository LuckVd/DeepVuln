"""Verification phase.

This phase handles LLM verification of findings.
"""

from typing import Any
import logging


from .base import ScanPhase, PhaseResult

logger = logging.getLogger(__name__)


class VerificationPhase(ScanPhase):
    """Verification phase (L4).

    This phase verifies findings using LLM analysis.
    """

    def __init__(self):
        super().__init__(
            name="L4_verification",
            description="Exploitability Verification",
        )

    async def execute(
        self,
        context: "ScanContext",  # noqa: F821
    ) -> PhaseResult:
        """Execute verification phase.

        Args:
            context: Scan context

        Returns:
            Phase result with verified findings
        """
        if not context.config.llm_verify:
            # Skip verification if not enabled
            logger.info("LLM verification disabled, skipping")
            return PhaseResult(success=True, findings=context.findings)

        if not context.findings:
            logger.info("No findings to verify")
            return PhaseResult(success=True, findings=[])

        # Import verification executor
        from src.layers.l3_analysis.rounds.round_four import RoundFourExecutor
        from src.layers.l3_analysis.llm.openai_client import OpenAIClient
        from src.layers.l3_analysis.rounds.models import VulnerabilityCandidate, ConfidenceLevel
        from src.core.config import get_llm_config, get_openai_config
        from datetime import UTC, datetime
        import uuid

        # Initialize LLM client
        try:
            llm_config = get_llm_config()
            openai_config = get_openai_config()
            llm_client = OpenAIClient(
                model=context.config.model or "gpt-4",
                api_key=openai_config.get("api_key"),
                base_url=openai_config.get("base_url"),
                max_tokens=llm_config.get("max_tokens", 4096),
            )
        except Exception as e:
            logger.warning(f"Failed to initialize LLM client for verification: {e}")
            # Return findings without verification
            return PhaseResult(success=True, findings=context.findings)

        # Get attack surface report from preparation phase
        surface_report = context.data.get("attack_surface")  # type: ignore
        codeql_findings = [
            f for f in context.findings
            if f.get("engine") == "codeql"
        ]

        # Create executor
        executor = RoundFourExecutor(
            source_path=context.source_path,
            llm_client=llm_client,
            enable_llm_assessment=True,
            attack_surface_report=surface_report,
            codeql_results=codeql_findings,
        )

        verified_findings = []
        total_tokens = 0

        # Verify each finding
        for finding in context.findings:
            if context.is_cancelled():
                break

            try:
                # Create candidate
                candidate = VulnerabilityCandidate(
                    id=str(uuid.uuid4())[:8],
                    finding=finding,
                    confidence=ConfidenceLevel.MEDIUM,
                    discovered_in_round=1,
                )

                # Verify exploitability
                verify_result = await executor._verify_exploitability(candidate)

                # Update finding with verification result
                if verify_result and verify_result.exploitable:
                    finding["verified"] = True
                    finding["exploitability"] = verify_result.exploitable.value
                    finding["confidence"] = verify_result.confidence.value
                    verified_findings.append(finding)
                    total_tokens += verify_result.tokens_used or 0
                else:
                    # Still include but mark as unverified
                    finding["verified"] = False
                    verified_findings.append(finding)

            except Exception as e:
                logger.error(f"Failed to verify finding: {e}")
                verified_findings.append(finding)

        # Update verified count
        context.statistics.verified_count = sum(
            1 for f in verified_findings if f.get("verified")
        )

        return PhaseResult(
            success=True,
            findings=verified_findings,
            tokens_used=total_tokens,
        )
