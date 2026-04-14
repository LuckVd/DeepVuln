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
        language: str = "zh",
    ):
        """Initialize the adversarial service.

        Args:
            llm_client: LLM client for AI-based verification
            max_rounds: Maximum number of debate rounds (default 5)
            round_timeout: Timeout per round in seconds (default 180)
            progress_callback: Optional callback for real-time updates
            language: Output language for debate content ("en" or "zh", default "zh")
        """
        self.llm_client = llm_client
        self.max_rounds = max_rounds
        self.round_timeout = round_timeout
        self.progress_callback = progress_callback
        self.language = language

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
            language=language,
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
                "verdict": None,
            }

        # Determine final status
        if timeout_occurred:
            status = AdversarialStatus.TIMEOUT
        else:
            from src.layers.l3_analysis.verification.models import VerdictType
            verdict_obj = result.get("verdict")
            if verdict_obj and hasattr(verdict_obj, 'verdict'):
                vtype = verdict_obj.verdict
            elif verdict_obj and hasattr(verdict_obj, 'value'):
                vtype = verdict_obj
            else:
                vtype = None

            if vtype == VerdictType.CONFIRMED:
                status = AdversarialStatus.CONFIRMED
            elif vtype == VerdictType.FALSE_POSITIVE:
                status = AdversarialStatus.REJECTED
            else:
                status = AdversarialStatus.UNCERTAIN

        # Serialize full verdict data
        verdict_obj = result.get("verdict")
        verdict_data = None
        if verdict_obj and hasattr(verdict_obj, 'model_dump'):
            verdict_data = verdict_obj.model_dump()
            # Convert enums to strings for JSON serialization
            if 'verdict' in verdict_data and hasattr(verdict_data['verdict'], 'value'):
                verdict_data['verdict'] = verdict_data['verdict'].value
        elif verdict_obj and hasattr(verdict_obj, 'value'):
            verdict_data = {"verdict": verdict_obj.value}

        # Serialize full debate rounds from VerificationResult
        full_rounds = []
        debate_rounds = result.get("debate_rounds", [])
        for dr in debate_rounds:
            round_data: dict[str, Any] = {
                "round_number": getattr(dr, 'round_number', 0),
            }
            # Attacker argument
            attacker = getattr(dr, 'attacker_argument', None)
            if attacker and hasattr(attacker, 'model_dump'):
                a_data = attacker.model_dump()
                if 'strength' in a_data and hasattr(a_data['strength'], 'value'):
                    a_data['strength'] = a_data['strength'].value
                round_data["attacker_argument"] = a_data
            # Defender argument
            defender = getattr(dr, 'defender_argument', None)
            if defender and hasattr(defender, 'model_dump'):
                d_data = defender.model_dump()
                if 'strength' in d_data and hasattr(d_data['strength'], 'value'):
                    d_data['strength'] = d_data['strength'].value
                round_data["defender_argument"] = d_data
            # Arbiter verdict
            arbiter = getattr(dr, 'arbiter_verdict', None)
            if arbiter and hasattr(arbiter, 'model_dump'):
                av_data = arbiter.model_dump()
                if 'verdict' in av_data and hasattr(av_data['verdict'], 'value'):
                    av_data['verdict'] = av_data['verdict'].value
                round_data["arbiter_verdict"] = av_data
            # Continue info
            if hasattr(dr, 'continue_debate'):
                round_data["continue_debate"] = dr.continue_debate
            if hasattr(dr, 'continue_reason') and dr.continue_reason:
                round_data["continue_reason"] = dr.continue_reason
            full_rounds.append(round_data)

        return {
            "finding_id": finding_id,
            "status": status.value,
            "confidence": result.get("confidence", 0.5),
            "rounds": full_rounds if full_rounds else [r.to_dict() for r in rounds],
            "rounds_count": len(full_rounds) if full_rounds else len(rounds),
            "verdict": verdict_data,
            "reasoning": result.get("reasoning", ""),
            "timeout": timeout_occurred,
            "duration_seconds": result.get("duration_seconds", 0),
            "tokens_used": result.get("tokens_used", 0),
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
        # Resolve actual source file path from finding location
        actual_file_path = source_path
        if hasattr(finding, 'location') and finding.location:
            file_name = getattr(finding.location, 'file', '')
            if file_name:
                candidate = Path(source_path) / file_name
                if candidate.is_file():
                    actual_file_path = candidate
                    logger.debug(f"Resolved finding file: {actual_file_path}")
                else:
                    # Try without leading slash
                    candidate2 = Path(source_path) / file_name.lstrip('/')
                    if candidate2.is_file():
                        actual_file_path = candidate2

        # Extract code context from source file
        code_context = ""
        related_code = ""

        if actual_file_path.is_file():
            try:
                # Read the source file and extract relevant context
                with open(actual_file_path, 'r', encoding='utf-8') as f:
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
                logger.warning(f"Failed to read source file {actual_file_path}: {e}")
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

        # Extract debate rounds from VerificationResult
        debate_rounds = getattr(result_obj, 'debate_rounds', []) or []
        logger.info(f"Finding {finding.id}: extracted {len(debate_rounds)} debate rounds from VerificationResult (callback={'yes' if self.progress_callback else 'no'})")
        for dr in debate_rounds:
            round_num = getattr(dr, 'round_number', 0)
            total_rounds = len(debate_rounds)

            # Common finding info (Finding model uses 'type' not 'vuln_type', 'location.file' not 'file_path')
            finding_id = finding.id or "unknown"
            finding_title = getattr(finding, 'title', '') or ''
            vuln_type = str(getattr(finding, 'type', '') or '')
            severity = str(getattr(finding, 'severity', '') or '')
            file_path = ''
            if hasattr(finding, 'location') and finding.location:
                file_path = getattr(finding.location, 'file', '') or ''

            # --- Attacker argument ---
            attacker = getattr(dr, 'attacker_argument', None)
            if attacker:
                rounds.append(DebateRound(
                    round_number=round_num,
                    role="attacker",
                    content=getattr(attacker, 'claim', ''),
                    timestamp=datetime.now(UTC),
                    confidence=getattr(attacker, 'confidence', 0.5),
                ))
                if self.progress_callback:
                    try:
                        # Build detail dict with full data for expandable card
                        attacker_detail = {
                            "evidence": getattr(attacker, 'evidence', []) or [],
                            "reasoning": getattr(attacker, 'reasoning', '') or '',
                            "poc_code": getattr(attacker, 'poc_code', None),
                            "poc_type": getattr(attacker, 'poc_type', None),
                            "exploitation_steps": getattr(attacker, 'exploitation_steps', []) or [],
                            "prerequisites": getattr(attacker, 'prerequisites', []) or [],
                            "counter_arguments": getattr(attacker, 'counter_arguments', []) or [],
                            "is_rebuttal": getattr(attacker, 'is_rebuttal', False),
                        }
                        self.progress_callback("adversarial_round", {
                            "finding_id": finding_id,
                            "finding_title": finding_title,
                            "vuln_type": vuln_type,
                            "severity": severity,
                            "file_path": file_path,
                            "round": round_num,
                            "total_rounds": total_rounds,
                            "role": "attacker",
                            "claim": getattr(attacker, 'claim', ''),
                            "evidence": str(getattr(attacker, 'evidence', ''))[:300],
                            "strength": str(getattr(attacker, 'strength', '')),
                            "confidence": getattr(attacker, 'confidence', 0.5),
                            "detail": attacker_detail,
                        })
                    except Exception as e:
                        logger.error(f"Adversarial callback error: {e}")

            # --- Defender argument ---
            defender = getattr(dr, 'defender_argument', None)
            if defender:
                rounds.append(DebateRound(
                    round_number=round_num,
                    role="defender",
                    content=getattr(defender, 'claim', ''),
                    timestamp=datetime.now(UTC),
                    confidence=getattr(defender, 'confidence', 0.5),
                ))
                if self.progress_callback:
                    try:
                        # Build detail dict with full data for expandable card
                        defender_detail = {
                            "evidence": getattr(defender, 'evidence', []) or [],
                            "reasoning": getattr(defender, 'reasoning', '') or '',
                            "sanitizers_found": getattr(defender, 'sanitizers_found', []) or [],
                            "validation_checks": getattr(defender, 'validation_checks', []) or [],
                            "framework_protections": getattr(defender, 'framework_protections', []) or [],
                            "exploitation_barriers": getattr(defender, 'exploitation_barriers', []) or [],
                            "false_positive_reasons": getattr(defender, 'false_positive_reasons', []) or [],
                            "counter_arguments": getattr(defender, 'counter_arguments', []) or [],
                            "is_rebuttal": getattr(defender, 'is_rebuttal', False),
                        }
                        self.progress_callback("adversarial_round", {
                            "finding_id": finding_id,
                            "finding_title": finding_title,
                            "vuln_type": vuln_type,
                            "severity": severity,
                            "file_path": file_path,
                            "round": round_num,
                            "total_rounds": total_rounds,
                            "role": "defender",
                            "claim": getattr(defender, 'claim', ''),
                            "evidence": str(getattr(defender, 'evidence', ''))[:300],
                            "strength": str(getattr(defender, 'strength', '')),
                            "confidence": getattr(defender, 'confidence', 0.5),
                            "detail": defender_detail,
                        })
                    except Exception as e:
                        logger.error(f"Adversarial defender callback error: {e}")

            # --- Arbiter verdict ---
            arbiter = getattr(dr, 'arbiter_verdict', None)
            if arbiter:
                rounds.append(DebateRound(
                    round_number=round_num,
                    role="judge",
                    content=getattr(arbiter, 'reasoning', ''),
                    timestamp=datetime.now(UTC),
                    confidence=getattr(arbiter, 'confidence', 0.5),
                ))
                if self.progress_callback:
                    try:
                        # Build detail dict with full data for expandable card
                        judge_detail = {
                            "summary": getattr(arbiter, 'summary', '') or '',
                            "reasoning": getattr(arbiter, 'reasoning', '') or '',
                            "attacker_strength": getattr(arbiter, 'attacker_strength', 0),
                            "defender_strength": getattr(arbiter, 'defender_strength', 0),
                            "conditions": getattr(arbiter, 'conditions', []) or [],
                            "key_factors": getattr(arbiter, 'key_factors', []) or [],
                            "priority": str(getattr(arbiter, 'priority', '')),
                        }
                        self.progress_callback("adversarial_round", {
                            "finding_id": finding_id,
                            "finding_title": finding_title,
                            "vuln_type": vuln_type,
                            "severity": severity,
                            "file_path": file_path,
                            "round": round_num,
                            "total_rounds": total_rounds,
                            "role": "judge",
                            "claim": getattr(arbiter, 'summary', '') or getattr(arbiter, 'reasoning', ''),
                            "verdict": str(getattr(arbiter, 'verdict', '')),
                            "confidence": getattr(arbiter, 'confidence', 0.5),
                            "recommended_action": str(getattr(arbiter, 'recommended_action', '')),
                            "detail": judge_detail,
                        })
                    except Exception as e:
                        logger.error(f"Adversarial judge callback error: {e}")

        # Build result from VerificationResult
        final_verdict = getattr(result_obj, 'verdict', None)
        return {
            "verdict": final_verdict,
            "confidence": getattr(final_verdict, 'confidence', 0.5) if final_verdict else 0.5,
            "reasoning": getattr(final_verdict, 'reasoning', '') if final_verdict else "",
            "rounds_completed": getattr(result_obj, 'rounds_completed', 0),
            "duration_seconds": getattr(result_obj, 'duration_seconds', 0),
            "tokens_used": getattr(result_obj, 'tokens_used', 0),
            "debate_rounds": getattr(result_obj, 'debate_rounds', []),
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
    language: str = "zh",
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

        # Caller must provide the LLM client
        raise ValueError(
            "LLM client must be provided for adversarial verification. "
            "Please configure a 'verification' type LLM config in settings."
        )

    return AdversarialService(
        llm_client=llm_client,
        max_rounds=max_rounds,
        round_timeout=round_timeout,
        progress_callback=progress_callback,
        language=language,
    )


async def create_adversarial_service_from_db(
    db_session_factory: Callable[[], AsyncSession],
    max_rounds: int = 5,
    round_timeout: int = 180,
    progress_callback: Optional[Callable[[str, dict[str, Any]], None]] = None,
    llm_client=None,  # P18-Bugfix: 支持传入现有的 llm_client 以正确统计 token
    language: str = "zh",
) -> Optional[AdversarialService]:
    """Factory function to create an AdversarialService from database config.

    Args:
        db_session_factory: Factory function for creating DB sessions
        max_rounds: Maximum number of debate rounds (default 5)
        round_timeout: Timeout per round in seconds (default 180)
        progress_callback: Optional callback for real-time updates
        llm_client: Optional existing LLM client to reuse (P18-Bugfix)

    Returns:
        Configured AdversarialService instance, or None if no config found
    """
    from src.web.services.llm_config_service import LLMConfigService

    async with db_session_factory() as db:
        llm_config = await LLMConfigService.get_verification_config(db)
        if llm_config is None:
            logger.warning("No verification LLM config found in database")
            return None

        # P18-Bugfix: 如果没有提供 llm_client，则创建新的
        if llm_client is None:
            llm_client = LLMConfigService.create_llm_client(llm_config)
            logger.info(f"Created new LLM client for adversarial service with config: {llm_config.name}")
        else:
            logger.info(f"Reusing existing LLM client for adversarial service with config: {llm_config.name}")

        return AdversarialService(
            llm_client=llm_client,
            max_rounds=max_rounds,
            round_timeout=round_timeout,
            progress_callback=progress_callback,
            language=language,
        )
