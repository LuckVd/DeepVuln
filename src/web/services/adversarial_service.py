"""Adversarial Service - P14-04.

This service wraps the CLI's adversarial verification functionality
for use in the web service.

It integrates:
- AdversarialVerifier for multi-role verification (attacker/defender/arbiter)
- Multi-round debates with strategy evolution
- Per-round timeout handling
- WebSocket real-time progress updates
"""

import asyncio
import logging
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from src.layers.l3_analysis.verification.adversarial import (
    AdversarialVerifier,
    AdversarialVerifierConfig,
    TriggerConditions,
)
from src.layers.l3_analysis.verification.models import (
    AdversarialVerdict,
    VerificationResult,
    VerificationSession,
)
from src.layers.l3_analysis.llm.client import LLMClient
from src.layers.l3_analysis.models import Finding


logger = logging.getLogger(__name__)


class AdversarialStatus(str, Enum):
    """Status of adversarial verification for a finding."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNCERTAIN = "uncertain"
    TIMEOUT = "timeout"


class DebateRound:
    """Information about a single debate round."""

    def __init__(
        self,
        round_number: int,
        role: str,
        content: str,
        timestamp: datetime,
        confidence: float = 0.5,
    ):
        self.round_number = round_number
        self.role = role  # "attacker", "defender", or "arbiter"
        self.content = content
        self.timestamp = timestamp
        self.confidence = confidence

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for WebSocket/JSON."""
        return {
            "round": self.round_number,
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "confidence": self.confidence,
        }


class AdversarialService:
    """Service for adversarial verification (P14-04).

    This service provides:
    1. Multi-round adversarial debates
    2. Per-round timeout handling
    3. Real-time progress updates via callback
    4. Strategy evolution across rounds
    """

    # Default timeout per round (seconds)
    DEFAULT_ROUND_TIMEOUT = 180  # 3 minutes

    def __init__(
        self,
        llm_client: LLMClient,
        max_rounds: int = 5,
        round_timeout: int = DEFAULT_ROUND_TIMEOUT,
        progress_callback: Optional[Callable[[str, dict[str, Any]], None]] = None,
    ):
        """Initialize the adversarial service.

        Args:
            llm_client: LLM client for AI-based verification
            max_rounds: Maximum number of debate rounds (default 5)
            round_timeout: Timeout per round in seconds (default 180)
            progress_callback: Optional callback for real-time updates
        """
        self.llm_client = llm_client
        self.max_rounds = max_rounds
        self.round_timeout = round_timeout
        self.progress_callback = progress_callback

        # Create verifier configuration
        self.config = AdversarialVerifierConfig(
            enabled=True,
            max_rounds=max_rounds,
            parallel_analysis=True,
            sequential_rebuttal=True,
            confidence_threshold=0.7,
        )

        # Create the verifier
        self.verifier = AdversarialVerifier(
            llm_client=llm_client,
            config=self.config,
        )

        logger.info(
            f"AdversarialService initialized: max_rounds={max_rounds}, "
            f"round_timeout={round_timeout}s"
        )

    async def verify_finding(
        self,
        finding: Finding,
        source_path: Path,
    ) -> dict[str, Any]:
        """Verify a single finding using adversarial debate.

        Args:
            finding: The finding to verify
            source_path: Path to source code for context

        Returns:
            Dictionary with verification results including:
                - status: Final adversarial status
                - confidence: Confidence in the verdict
                - rounds: List of debate rounds
                - verdict: Final verdict details
                - timeout: Whether verification timed out
        """
        finding_id = finding.id or "unknown"
        logger.info(f"Starting adversarial verification for finding {finding_id}")

        rounds = []
        timeout_occurred = False

        try:
            # Run verification with timeout
            result = await asyncio.wait_for(
                self._run_verification_with_callbacks(finding, source_path, rounds),
                timeout=self.round_timeout * self.max_rounds,
            )
        except asyncio.TimeoutError:
            logger.warning(f"Adversarial verification timed out for finding {finding_id}")
            timeout_occurred = True

            # Create timeout result
            result = {
                "status": AdversarialStatus.UNCERTAIN,
                "confidence": 0.3,
                "reasoning": f"Verification timed out after {self.max_rounds} rounds",
                "verdict": AdversarialVerdict.UNCERTAIN,
            }

        # Determine final status
        if timeout_occurred:
            status = AdversarialStatus.TIMEOUT
        elif result.get("verdict") == AdversarialVerdict.CONFIRMED:
            status = AdversarialStatus.CONFIRMED
        elif result.get("verdict") == AdversarialVerdict.REJECTED:
            status = AdversarialStatus.REJECTED
        else:
            status = AdversarialStatus.UNCERTAIN

        return {
            "finding_id": finding_id,
            "status": status.value,
            "confidence": result.get("confidence", 0.5),
            "rounds": [r.to_dict() for r in rounds],
            "rounds_count": len(rounds),
            "verdict": result.get("verdict", AdversarialVerdict.UNCERTAIN).value
            if result.get("verdict") else None,
            "reasoning": result.get("reasoning", ""),
            "timeout": timeout_occurred,
        }

    async def _run_verification_with_callbacks(
        self,
        finding: Finding,
        source_path: Path,
        rounds: list[DebateRound],
    ) -> dict[str, Any]:
        """Run verification with progress callbacks.

        This wraps the verifier and sends callbacks for each round.

        Args:
            finding: The finding to verify
            source_path: Path to source code
            rounds: List to collect debate rounds (output parameter)

        Returns:
            Verification result dict
        """
        # Extract code context from source file
        code_context = ""
        related_code = ""

        if source_path.exists():
            try:
                # Read the source file and extract relevant context
                with open(source_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()

                # Get the line number from finding location
                if hasattr(finding, 'location') and finding.location:
                    line_num = finding.location.start_line if hasattr(finding.location, 'start_line') else None

                    if line_num:
                        lines = file_content.split('\n')
                        # Extract context around the finding (up to 50 lines)
                        context_start = max(0, line_num - 10)
                        context_end = min(len(lines), line_num + 40)
                        code_context = '\n'.join(lines[context_start:context_end])

                        # Extract additional related code (before context)
                        if context_start > 0:
                            related_code = '\n'.join(lines[max(0, context_start - 30):context_start])
                    else:
                        # No line number, use entire file
                        code_context = file_content[:5000]  # Limit to 5000 chars
            except Exception as e:
                logger.warning(f"Failed to read source file {source_path}: {e}")
                code_context = finding.location.snippet if hasattr(finding, 'location') and finding.location.snippet else ""
        else:
            # File doesn't exist, use snippet from finding
            code_context = finding.location.snippet if hasattr(finding, 'location') and finding.location.snippet else ""

        # Run verification with correct API signature
        result_obj = await self.verifier.verify_finding(
            finding=finding,
            code_context=code_context,
            related_code=related_code if related_code else None,
        )

        # Create a mock session-like structure for compatibility
        session = type('obj', (object,), {
            'rounds': [],
            'result': result_obj,
        })()

        # Extract rounds from session
        if session and hasattr(session, 'rounds'):
            for i, round_obj in enumerate(session.rounds):
                debate_round = DebateRound(
                    round_number=i + 1,
                    role=round_obj.role if hasattr(round_obj, 'role') else "unknown",
                    content=round_obj.content if hasattr(round_obj, 'content') else "",
                    timestamp=datetime.now(UTC),
                    confidence=round_obj.confidence if hasattr(round_obj, 'confidence') else 0.5,
                )
                rounds.append(debate_round)

                # Send progress callback
                if self.progress_callback:
                    self.progress_callback("adversarial_round", {
                        "finding_id": finding.id,
                        "round": i + 1,
                        "role": debate_round.role,
                        "content": debate_round.content[:200],  # Truncate for callback
                        "confidence": debate_round.confidence,
                    })

        # Build result from session
        if session and hasattr(session, 'result'):
            result_obj = session.result
            return {
                "verdict": result_obj.verdict if hasattr(result_obj, 'verdict') else None,
                "confidence": result_obj.confidence if hasattr(result_obj, 'confidence') else 0.5,
                "reasoning": result_obj.reasoning if hasattr(result_obj, 'reasoning') else "",
            }

        return {
            "verdict": AdversarialVerdict.UNCERTAIN,
            "confidence": 0.5,
            "reasoning": "Verification completed with no clear verdict",
        }

    async def verify_findings_batch(
        self,
        findings: list[Finding],
        source_path: Path,
        max_concurrent: int = 2,
    ) -> dict[str, dict[str, Any]]:
        """Verify multiple findings in batch.

        Args:
            findings: List of findings to verify
            source_path: Path to source code
            max_concurrent: Maximum concurrent verifications (default 2)

        Returns:
            Dictionary mapping finding_id to verification result
        """
        results = {}

        # Process in batches to control concurrency
        for i in range(0, len(findings), max_concurrent):
            batch = findings[i:i + max_concurrent]
            tasks = [
                self.verify_finding(f, source_path)
                for f in batch
            ]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for finding, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Error verifying finding {finding.id}: {result}")
                    results[finding.id] = {
                        "finding_id": finding.id,
                        "status": AdversarialStatus.UNCERTAIN.value,
                        "confidence": 0.1,
                        "error": str(result),
                        "timeout": False,
                    }
                else:
                    results[finding.id] = result

        logger.info(f"Verified {len(results)} findings with adversarial debate")
        return results

    def should_verify_finding(self, finding: Finding) -> bool:
        """Check if a finding should undergo adversarial verification.

        Args:
            finding: The finding to check

        Returns:
            True if the finding should be verified
        """
        from src.layers.l3_analysis.models import SeverityLevel

        # Skip info findings by default
        if finding.severity == SeverityLevel.INFO:
            return False

        # Skip findings with very low confidence
        if finding.confidence and finding.confidence < 0.3:
            return False

        return True


def create_adversarial_service(
    llm_client: Optional[LLMClient] = None,
    max_rounds: int = 5,
    round_timeout: int = 180,
    progress_callback: Optional[Callable[[str, dict[str, Any]], None]] = None,
    db_session_factory: Optional[Callable[[], AsyncSession]] = None,
) -> AdversarialService:
    """Factory function to create an AdversarialService.

    Args:
        llm_client: Optional LLM client for AI-based verification.
                     If not provided, will try to load from database.
        max_rounds: Maximum number of debate rounds (default 5)
        round_timeout: Timeout per round in seconds (default 180)
        progress_callback: Optional callback for real-time updates
        db_session_factory: Optional factory function for creating DB sessions

    Returns:
        Configured AdversarialService instance

    Raises:
        ValueError: If no LLM client is available and cannot load from database
    """
    # If no LLM client provided, try to load from database
    if llm_client is None:
        if db_session_factory is None:
            raise ValueError("Either llm_client or db_session_factory must be provided")

        from src.web.services.llm_config_service import LLMConfigService

        # Get verification config from database
        import asyncio

        async def _get_verification_client() -> LLMClient:
            async with db_session_factory() as db:
                llm_config = await LLMConfigService.get_verification_config(db)
                if llm_config is None:
                    raise ValueError("No verification LLM config found in database")
                return LLMConfigService.create_llm_client(llm_config)

        # Note: This should be called from an async context
        # For now, we'll require the caller to provide the client
        raise ValueError(
            "LLM client must be provided for adversarial verification. "
            "Please configure a 'verification' type LLM config in settings."
        )

    return AdversarialService(
        llm_client=llm_client,
        max_rounds=max_rounds,
        round_timeout=round_timeout,
        progress_callback=progress_callback,
    )


async def create_adversarial_service_from_db(
    db_session_factory: Callable[[], AsyncSession],
    max_rounds: int = 5,
    round_timeout: int = 180,
    progress_callback: Optional[Callable[[str, dict[str, Any]], None]] = None,
) -> Optional[AdversarialService]:
    """Factory function to create an AdversarialService from database config.

    Args:
        db_session_factory: Factory function for creating DB sessions
        max_rounds: Maximum number of debate rounds (default 5)
        round_timeout: Timeout per round in seconds (default 180)
        progress_callback: Optional callback for real-time updates

    Returns:
        Configured AdversarialService instance, or None if no config found
    """
    from src.web.services.llm_config_service import LLMConfigService

    async with db_session_factory() as db:
        llm_config = await LLMConfigService.get_verification_config(db)
        if llm_config is None:
            logger.warning("No verification LLM config found in database")
            return None

        llm_client = LLMConfigService.create_llm_client(llm_config)
        logger.info(f"Created adversarial service with config: {llm_config.name}")

        return AdversarialService(
            llm_client=llm_client,
            max_rounds=max_rounds,
            round_timeout=round_timeout,
            progress_callback=progress_callback,
        )
