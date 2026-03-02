"""
Arbiter Verifier - Evaluates arguments and makes final judgment.

This role acts as an impartial judge, evaluating the arguments from both
attacker and defender to make a final determination about exploitability.

Enhanced with multi-round debate support (debate history evaluation).
"""

import json
import logging
from typing import Any

from ..llm.client import LLMClient, LLMError
from ..prompts.adversarial import ARBITER_SYSTEM_PROMPT, get_arbiter_user_prompt
from .models import (
    AdversarialVerdict,
    DebateRound,
    TriggerConditions,
    VerificationArgument,
    VerdictType,
)

logger = logging.getLogger(__name__)


class ArbiterVerifier:
    """
    Arbiter role in adversarial verification.

    Evaluates arguments from attacker and defender to make a final judgment:
    - CONFIRMED: Vulnerability is real and exploitable
    - FALSE_POSITIVE: Not a real vulnerability
    - NEEDS_REVIEW: Cannot determine, needs human review
    - CONDITIONAL: Exploitable under specific conditions

    In multi-round debates, considers all rounds of debate history.
    """

    # Thresholds for automatic decisions
    CONFIDENCE_THRESHOLD_HIGH = 0.8
    CONFIDENCE_THRESHOLD_LOW = 0.3
    STRENGTH_DIFF_THRESHOLD = 0.4

    def __init__(
        self,
        llm_client: LLMClient,
        use_heuristic_fallback: bool = True,
        strict_mode: bool = False,
        trigger_conditions: TriggerConditions | None = None,
    ):
        """
        Initialize the arbiter verifier.

        Args:
            llm_client: LLM client for generating verdicts.
            use_heuristic_fallback: Whether to use heuristics if LLM fails.
            strict_mode: If True, require high confidence for definitive verdicts.
            trigger_conditions: Conditions for triggering additional debate rounds.
        """
        self.llm_client = llm_client
        self.use_heuristic_fallback = use_heuristic_fallback
        self.strict_mode = strict_mode
        self.trigger_conditions = trigger_conditions or TriggerConditions()

    async def evaluate(
        self,
        finding: dict[str, Any],
        attacker_argument: VerificationArgument,
        defender_argument: VerificationArgument,
        debate_history: list[dict[str, Any]] | None = None,
        round_number: int = 1,
    ) -> AdversarialVerdict:
        """
        Evaluate arguments and make a final judgment.

        Args:
            finding: The original vulnerability finding.
            attacker_argument: Attacker's argument (latest).
            defender_argument: Defender's argument (latest).
            debate_history: History of previous debate rounds.
            round_number: Current round number.

        Returns:
            AdversarialVerdict with final judgment.
        """
        # Build prompt with debate history
        user_prompt = get_arbiter_user_prompt(
            finding=finding,
            attacker_argument=attacker_argument.model_dump(),
            defender_argument=defender_argument.model_dump(),
            debate_history=debate_history,
        )

        try:
            # Call LLM
            response = await self.llm_client.complete_with_context(
                system_prompt=ARBITER_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )

            # Parse response
            result = self._parse_response(response.content)

            # Build verdict
            return self._build_verdict(result, round_number=round_number)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse arbiter response as JSON: {e}")
            if self.use_heuristic_fallback:
                return self._heuristic_verdict(
                    finding=finding,
                    attacker_argument=attacker_argument,
                    defender_argument=defender_argument,
                    round_number=round_number,
                )
            return self._create_error_verdict(
                f"JSON parsing error: {e}",
                round_number=round_number,
            )

        except LLMError as e:
            logger.error(f"LLM error in arbiter evaluation: {e}")
            if self.use_heuristic_fallback:
                return self._heuristic_verdict(
                    finding=finding,
                    attacker_argument=attacker_argument,
                    defender_argument=defender_argument,
                    round_number=round_number,
                )
            return self._create_error_verdict(
                str(e),
                round_number=round_number,
            )

    async def evaluate_rounds(
        self,
        finding: dict[str, Any],
        debate_rounds: list[DebateRound],
    ) -> AdversarialVerdict:
        """
        Evaluate all debate rounds and make a final judgment.

        This is used for multi-round debates where the arbiter considers
        the entire debate history.

        Args:
            finding: The original vulnerability finding.
            debate_rounds: All debate rounds.

        Returns:
            AdversarialVerdict with final judgment.
        """
        if not debate_rounds:
            return self._create_error_verdict("No debate rounds to evaluate", round_number=0)

        # Get latest arguments
        latest_round = debate_rounds[-1]
        attacker_argument = latest_round.attacker_argument
        defender_argument = latest_round.defender_argument

        # Build debate history for prompt
        debate_history = []
        for r in debate_rounds[:-1]:  # Exclude current round
            debate_history.append({
                "round": r.round_number,
                "attacker_claim": r.attacker_argument.claim,
                "attacker_confidence": r.attacker_argument.confidence,
                "defender_claim": r.defender_argument.claim,
                "defender_confidence": r.defender_argument.confidence,
            })

        return await self.evaluate(
            finding=finding,
            attacker_argument=attacker_argument,
            defender_argument=defender_argument,
            debate_history=debate_history if debate_history else None,
            round_number=len(debate_rounds),
        )

    def should_continue_debate(
        self,
        verdict: AdversarialVerdict,
        current_round: int,
        max_rounds: int,
    ) -> tuple[bool, str]:
        """
        Determine if debate should continue based on verdict and round count.

        Args:
            verdict: The current verdict.
            current_round: Current round number.
            max_rounds: Maximum allowed rounds.

        Returns:
            Tuple of (should_continue, reason).
        """
        # Check if max rounds reached
        if current_round >= max_rounds:
            return False, f"Maximum rounds ({max_rounds}) reached"

        # Use trigger conditions to determine if we should continue
        return self.trigger_conditions.should_continue(verdict)

    def _parse_response(self, content: str) -> dict[str, Any]:
        """Parse LLM response content to JSON."""
        content = content.strip()

        # Try to extract JSON from markdown code blocks
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        return json.loads(content)

    def _build_verdict(
        self,
        result: dict[str, Any],
        round_number: int = 1,
    ) -> AdversarialVerdict:
        """Build an AdversarialVerdict from parsed result."""
        # Map verdict string to enum
        verdict_str = result.get("verdict", "needs_review").lower()
        verdict_map = {
            "confirmed": VerdictType.CONFIRMED,
            "false_positive": VerdictType.FALSE_POSITIVE,
            "needs_review": VerdictType.NEEDS_REVIEW,
            "conditional": VerdictType.CONDITIONAL,
        }
        verdict = verdict_map.get(verdict_str, VerdictType.NEEDS_REVIEW)

        # Validate confidence
        confidence = float(result.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))

        # In strict mode, require high confidence for definitive verdicts
        if self.strict_mode and confidence < self.CONFIDENCE_THRESHOLD_HIGH:
            if verdict in [VerdictType.CONFIRMED, VerdictType.FALSE_POSITIVE]:
                verdict = VerdictType.NEEDS_REVIEW

        return AdversarialVerdict(
            verdict=verdict,
            confidence=confidence,
            summary=result.get("summary", ""),
            reasoning=result.get("reasoning", ""),
            attacker_strength=float(result.get("attacker_strength", 0.5)),
            defender_strength=float(result.get("defender_strength", 0.5)),
            conditions=result.get("conditions", []),
            recommended_action=result.get("recommended_action", "review"),
            priority=result.get("priority", "medium"),
            key_factors=result.get("key_factors", []),
            round_number=round_number,
        )

    def _create_error_verdict(
        self,
        error_message: str,
        round_number: int = 1,
    ) -> AdversarialVerdict:
        """Create an error verdict when LLM fails."""
        return AdversarialVerdict(
            verdict=VerdictType.NEEDS_REVIEW,
            confidence=0.0,
            summary="Failed to evaluate arguments",
            reasoning=error_message,
            recommended_action="review",
            priority="medium",
            round_number=round_number,
        )

    def _heuristic_verdict(
        self,
        finding: dict[str, Any],
        attacker_argument: VerificationArgument,
        defender_argument: VerificationArgument,
        round_number: int = 1,
    ) -> AdversarialVerdict:
        """
        Generate a heuristic verdict based on argument strengths.

        This is used as a fallback when LLM fails.

        Args:
            finding: The original finding.
            attacker_argument: Attacker's argument.
            defender_argument: Defender's argument.
            round_number: Current round number.

        Returns:
            Heuristic verdict.
        """
        # Calculate strength scores
        attacker_score = self._calculate_argument_strength(attacker_argument)
        defender_score = self._calculate_argument_strength(defender_argument)

        # Calculate difference
        strength_diff = abs(attacker_score - defender_score)
        stronger_side = "attacker" if attacker_score > defender_score else "defender"

        # Determine verdict based on strengths
        if strength_diff >= self.STRENGTH_DIFF_THRESHOLD:
            # Clear winner
            if stronger_side == "attacker":
                verdict = VerdictType.CONFIRMED
                summary = "Attacker provides stronger evidence of exploitability"
            else:
                verdict = VerdictType.FALSE_POSITIVE
                summary = "Defender provides stronger evidence of mitigation"
        elif attacker_score > 0.6 and defender_score < 0.4:
            # Attacker has moderate strength, defender weak
            verdict = VerdictType.CONFIRMED
            summary = "Attacker shows plausible exploit path with weak counter-argument"
        elif defender_score > 0.6 and attacker_score < 0.4:
            # Defender has moderate strength, attacker weak
            verdict = VerdictType.FALSE_POSITIVE
            summary = "Defender shows effective mitigations with weak attack argument"
        elif attacker_score > 0.5 and defender_score > 0.5:
            # Both sides have some strength
            verdict = VerdictType.CONDITIONAL
            summary = "Both sides present valid arguments - may be exploitable under specific conditions"
        else:
            # Neither side is convincing
            verdict = VerdictType.NEEDS_REVIEW
            summary = "Unable to determine - requires manual security review"

        # Calculate confidence
        confidence = min(strength_diff + 0.3, 0.8)

        # Determine priority based on original severity and verdict
        original_severity = finding.get("severity", "medium").lower()
        if verdict == VerdictType.CONFIRMED:
            if original_severity in ["critical", "high"]:
                priority = "critical"
            else:
                priority = "high"
        elif verdict == VerdictType.CONDITIONAL:
            priority = "high" if original_severity in ["critical", "high"] else "medium"
        elif verdict == VerdictType.NEEDS_REVIEW:
            priority = "medium"
        else:
            priority = "low"

        # Determine recommended action
        action_map = {
            VerdictType.CONFIRMED: "fix",
            VerdictType.FALSE_POSITIVE: "ignore",
            VerdictType.NEEDS_REVIEW: "review",
            VerdictType.CONDITIONAL: "monitor",
        }

        return AdversarialVerdict(
            verdict=verdict,
            confidence=confidence,
            summary=summary,
            reasoning=f"Heuristic evaluation (round {round_number}): attacker strength={attacker_score:.2f}, defender strength={defender_score:.2f}",
            attacker_strength=attacker_score,
            defender_strength=defender_score,
            conditions=attacker_argument.prerequisites if verdict == VerdictType.CONDITIONAL else [],
            recommended_action=action_map[verdict],
            priority=priority,
            key_factors=[
                f"Attacker confidence: {attacker_argument.confidence:.0%}",
                f"Defender confidence: {defender_argument.confidence:.0%}",
                f"Strength difference: {strength_diff:.2f}",
            ],
            round_number=round_number,
        )

    def _calculate_argument_strength(self, argument: VerificationArgument) -> float:
        """
        Calculate a strength score for an argument.

        Args:
            argument: The argument to evaluate.

        Returns:
            Strength score between 0.0 and 1.0.
        """
        score = argument.confidence

        # Adjust based on strength enum
        strength_multipliers = {
            "weak": 0.6,
            "moderate": 0.8,
            "strong": 1.0,
            "definitive": 1.2,
        }
        score *= strength_multipliers.get(argument.strength.value, 0.8)

        # Adjust based on evidence count
        if argument.evidence:
            score += 0.05 * min(len(argument.evidence), 4)

        # Adjust based on specific content
        if argument.role == "attacker":
            # Attacker-specific bonuses
            if argument.poc_code:
                score += 0.15
            if argument.exploitation_steps:
                score += 0.05 * min(len(argument.exploitation_steps), 3)
            if argument.prerequisites:
                # Having prerequisites means it's more realistic
                score += 0.05
        else:
            # Defender-specific bonuses
            if argument.sanitizers_found:
                score += 0.1 * min(len(argument.sanitizers_found), 3)
            if argument.validation_checks:
                score += 0.05 * min(len(argument.validation_checks), 3)
            if argument.framework_protections:
                score += 0.1 * min(len(argument.framework_protections), 2)

        # Clamp score
        return max(0.0, min(1.0, score))

    def get_verdict_explanation(self, verdict: AdversarialVerdict) -> str:
        """
        Generate a human-readable explanation of the verdict.

        Args:
            verdict: The verdict to explain.

        Returns:
            Human-readable explanation.
        """
        verdict_explanations = {
            VerdictType.CONFIRMED: """
This vulnerability has been CONFIRMED as exploitable. The attacker provided compelling
evidence of a working exploit path, and the defender could not demonstrate adequate
mitigations. Immediate remediation is recommended.
""".strip(),
            VerdictType.FALSE_POSITIVE: """
This finding has been determined to be a FALSE POSITIVE. The defender demonstrated
effective security controls (sanitization, validation, or framework protections)
that prevent exploitation. No immediate action is required.
""".strip(),
            VerdictType.NEEDS_REVIEW: """
This finding requires MANUAL REVIEW. The automated analysis could not reach a
definitive conclusion. A security expert should review the code and context to
determine if this is a real vulnerability.
""".strip(),
            VerdictType.CONDITIONAL: """
This vulnerability is CONDITIONALLY exploitable. Under certain conditions or
configurations, exploitation may be possible. Review the specific conditions
and assess your environment's risk.
""".strip(),
        }

        base_explanation = verdict_explanations.get(verdict.verdict, "Unknown verdict")

        round_info = f"\n\n**Debate Rounds:** {verdict.round_number}" if verdict.round_number > 1 else ""

        key_factors_text = ""
        if verdict.key_factors:
            key_factors_text = "\n\n**Key Factors:**\n" + "\n".join(f"- {f}" for f in verdict.key_factors)

        return f"""
{base_explanation}

**Summary:** {verdict.summary}

**Confidence:** {verdict.confidence:.0%}

**Recommended Action:** {verdict.recommended_action.upper()}
**Priority:** {verdict.priority.upper()}
{round_info}
{key_factors_text}

**Reasoning:**
{verdict.reasoning}

**Strength Assessment:**
- Attacker: {verdict.attacker_strength:.0%}
- Defender: {verdict.defender_strength:.0%}
""".strip()
