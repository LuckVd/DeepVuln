"""
Arbiter Verifier - Evaluates arguments and makes final judgment.

This role acts as an impartial judge, evaluating the arguments from both
attacker and defender to make a final determination about exploitability.
"""

import json
import logging
from typing import Any

from ..llm.client import LLMClient, LLMError
from ..prompts.adversarial import ARBITER_SYSTEM_PROMPT, get_arbiter_user_prompt
from .models import (
    AdversarialVerdict,
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
    ):
        """
        Initialize the arbiter verifier.

        Args:
            llm_client: LLM client for generating verdicts.
            use_heuristic_fallback: Whether to use heuristics if LLM fails.
            strict_mode: If True, require high confidence for definitive verdicts.
        """
        self.llm_client = llm_client
        self.use_heuristic_fallback = use_heuristic_fallback
        self.strict_mode = strict_mode

    async def evaluate(
        self,
        finding: dict[str, Any],
        attacker_argument: VerificationArgument,
        defender_argument: VerificationArgument,
    ) -> AdversarialVerdict:
        """
        Evaluate arguments and make a final judgment.

        Args:
            finding: The original vulnerability finding.
            attacker_argument: Attacker's argument.
            defender_argument: Defender's argument.

        Returns:
            AdversarialVerdict with final judgment.
        """
        # Build prompt
        user_prompt = get_arbiter_user_prompt(
            finding=finding,
            attacker_argument=attacker_argument.model_dump(),
            defender_argument=defender_argument.model_dump(),
        )

        try:
            # Call LLM
            response = await self.llm_client.complete_with_context(
                system_prompt=ARBITER_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )

            # Parse response
            content = response.content.strip()

            # Try to extract JSON from markdown code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            result = json.loads(content)

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
            )

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse arbiter response as JSON: {e}")
            if self.use_heuristic_fallback:
                return self._heuristic_verdict(
                    finding=finding,
                    attacker_argument=attacker_argument,
                    defender_argument=defender_argument,
                )
            return AdversarialVerdict(
                verdict=VerdictType.NEEDS_REVIEW,
                confidence=0.0,
                summary="Failed to parse LLM response",
                reasoning=f"JSON parsing error: {e}",
                recommended_action="review",
                priority="medium",
            )

        except LLMError as e:
            logger.error(f"LLM error in arbiter evaluation: {e}")
            if self.use_heuristic_fallback:
                return self._heuristic_verdict(
                    finding=finding,
                    attacker_argument=attacker_argument,
                    defender_argument=defender_argument,
                )
            return AdversarialVerdict(
                verdict=VerdictType.NEEDS_REVIEW,
                confidence=0.0,
                summary="LLM error during evaluation",
                reasoning=str(e),
                recommended_action="review",
                priority="medium",
            )

    def _heuristic_verdict(
        self,
        finding: dict[str, Any],
        attacker_argument: VerificationArgument,
        defender_argument: VerificationArgument,
    ) -> AdversarialVerdict:
        """
        Generate a heuristic verdict based on argument strengths.

        This is used as a fallback when LLM fails.

        Args:
            finding: The original finding.
            attacker_argument: Attacker's argument.
            defender_argument: Defender's argument.

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
            reasoning=f"Heuristic evaluation: attacker strength={attacker_score:.2f}, defender strength={defender_score:.2f}",
            attacker_strength=attacker_score,
            defender_strength=defender_score,
            conditions=attacker_argument.prerequisites if verdict == VerdictType.CONDITIONAL else [],
            recommended_action=action_map[verdict],
            priority=priority,
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

        return f"""
{base_explanation}

**Summary:** {verdict.summary}

**Confidence:** {verdict.confidence:.0%}

**Recommended Action:** {verdict.recommended_action.upper()}
**Priority:** {verdict.priority.upper()}

**Reasoning:**
{verdict.reasoning}

**Strength Assessment:**
- Attacker: {verdict.attacker_strength:.0%}
- Defender: {verdict.defender_strength:.0%}
""".strip()
