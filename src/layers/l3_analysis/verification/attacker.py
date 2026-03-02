"""
Attacker Verifier - Attempts to construct PoCs and prove exploitability.

This role analyzes vulnerability candidates from an attacker's perspective,
constructing proof-of-concept exploits and identifying attack paths.

Enhanced with multi-round debate support (rebuttal capability).
"""

import json
import logging
from typing import Any

from ..llm.client import LLMClient, LLMError
from ..prompts.adversarial import (
    ATTACKER_SYSTEM_PROMPT,
    get_attacker_rebuttal_prompt,
    get_attacker_user_prompt,
)
from .models import ArgumentStrength, VerificationArgument

logger = logging.getLogger(__name__)


class AttackerVerifier:
    """
    Attacker role in adversarial verification.

    Attempts to prove that a vulnerability is real and exploitable by:
    - Constructing proof-of-concept exploits
    - Identifying complete attack paths
    - Finding bypass techniques for defenses

    In multi-round debates, can rebut defender's arguments.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        max_context_length: int = 4000,
        include_bypass_db: bool = True,
    ):
        """
        Initialize the attacker verifier.

        Args:
            llm_client: LLM client for generating arguments.
            max_context_length: Maximum code context length.
            include_bypass_db: Whether to include bypass technique reference.
        """
        self.llm_client = llm_client
        self.max_context_length = max_context_length
        self.include_bypass_db = include_bypass_db

    async def analyze(
        self,
        finding: dict[str, Any],
        code_context: str,
        related_code: str | None = None,
        round_number: int = 1,
    ) -> VerificationArgument:
        """
        Analyze a vulnerability from an attacker's perspective.

        Args:
            finding: The vulnerability finding to analyze.
            code_context: The vulnerable code snippet.
            related_code: Additional context code.
            round_number: Current debate round number.

        Returns:
            VerificationArgument with attacker's analysis.
        """
        # Truncate code if needed
        if len(code_context) > self.max_context_length:
            code_context = code_context[: self.max_context_length] + "\n... (truncated)"

        # Build prompt
        user_prompt = get_attacker_user_prompt(
            finding=finding,
            code_context=code_context,
            related_code=related_code,
        )

        try:
            # Call LLM
            response = await self.llm_client.complete_with_context(
                system_prompt=ATTACKER_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )

            # Parse response
            result = self._parse_response(response.content)

            # Build argument
            return self._build_argument(result, round_number=round_number, is_rebuttal=False)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse attacker response as JSON: {e}")
            return self._create_error_argument(
                f"LLM response parsing failed: {e}",
                round_number=round_number,
            )

        except LLMError as e:
            logger.error(f"LLM error in attacker analysis: {e}")
            return self._create_error_argument(
                str(e),
                round_number=round_number,
            )

    async def rebut(
        self,
        finding: dict[str, Any],
        code_context: str,
        defender_argument: VerificationArgument,
        previous_attacker_argument: VerificationArgument,
    ) -> VerificationArgument:
        """
        Rebut the defender's counter-argument.

        This is used in multi-round debates to respond to the defender's
        claims and strengthen the attacker's case.

        Args:
            finding: The vulnerability finding.
            code_context: The vulnerable code snippet.
            defender_argument: The defender's counter-argument.
            previous_attacker_argument: The attacker's previous argument.

        Returns:
            VerificationArgument with attacker's rebuttal.
        """
        round_number = previous_attacker_argument.round_number + 1

        # Truncate code if needed
        if len(code_context) > self.max_context_length:
            code_context = code_context[: self.max_context_length] + "\n... (truncated)"

        # Build rebuttal prompt
        user_prompt = get_attacker_rebuttal_prompt(
            finding=finding,
            code_context=code_context,
            defender_argument=defender_argument.model_dump(),
            previous_attacker_argument=previous_attacker_argument.model_dump(),
        )

        try:
            # Call LLM with the same system prompt (attacker mindset)
            response = await self.llm_client.complete_with_context(
                system_prompt=ATTACKER_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )

            # Parse response
            result = self._parse_response(response.content)

            # Build argument with rebuttal flag
            return self._build_argument(result, round_number=round_number, is_rebuttal=True)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse attacker rebuttal as JSON: {e}")
            return self._create_error_argument(
                f"LLM response parsing failed: {e}",
                round_number=round_number,
                is_rebuttal=True,
            )

        except LLMError as e:
            logger.error(f"LLM error in attacker rebuttal: {e}")
            return self._create_error_argument(
                str(e),
                round_number=round_number,
                is_rebuttal=True,
            )

    def _parse_response(self, content: str) -> dict[str, Any]:
        """Parse LLM response content to JSON."""
        content = content.strip()

        # Try to extract JSON from markdown code blocks
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        return json.loads(content)

    def _build_argument(
        self,
        result: dict[str, Any],
        round_number: int = 1,
        is_rebuttal: bool = False,
    ) -> VerificationArgument:
        """Build a VerificationArgument from parsed result."""
        # Map strength string to enum
        strength_str = result.get("strength", "moderate").lower()
        strength_map = {
            "weak": ArgumentStrength.WEAK,
            "moderate": ArgumentStrength.MODERATE,
            "strong": ArgumentStrength.STRONG,
            "definitive": ArgumentStrength.DEFINITIVE,
        }
        strength = strength_map.get(strength_str, ArgumentStrength.MODERATE)

        return VerificationArgument(
            role="attacker",
            claim=result.get("claim", "This vulnerability is exploitable"),
            evidence=result.get("evidence", []),
            reasoning=result.get("reasoning", ""),
            strength=strength,
            confidence=float(result.get("confidence", 0.5)),
            counter_arguments=result.get("counter_arguments", []),
            poc_code=result.get("poc_code"),
            poc_type=result.get("poc_type"),
            exploitation_steps=result.get("exploitation_steps", []),
            prerequisites=result.get("prerequisites", []),
            round_number=round_number,
            is_rebuttal=is_rebuttal,
        )

    def _create_error_argument(
        self,
        error_message: str,
        round_number: int = 1,
        is_rebuttal: bool = False,
    ) -> VerificationArgument:
        """Create an error argument when LLM fails."""
        return VerificationArgument(
            role="attacker",
            claim="Unable to construct argument due to error",
            evidence=[],
            reasoning=error_message,
            strength=ArgumentStrength.WEAK,
            confidence=0.0,
            counter_arguments=[],
            round_number=round_number,
            is_rebuttal=is_rebuttal,
        )

    def get_quick_assessment(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Get a quick heuristic assessment without LLM.

        This provides initial confidence based on known patterns.

        Args:
            finding: The vulnerability finding.

        Returns:
            Quick assessment with initial confidence and patterns.
        """
        vuln_type = finding.get("type", "")
        confidence = 0.5  # Base confidence

        # Adjust based on vulnerability type
        high_severity_types = ["sql_injection", "command_injection", "code_injection", "rce"]
        if vuln_type in high_severity_types:
            confidence += 0.1

        # Check for code patterns that suggest exploitability
        code_snippet = finding.get("code_snippet", "") or finding.get("description", "")
        dangerous_patterns = [
            ("user_controlled", True, 0.15),
            ("no sanitization", True, 0.1),
            ("direct input", True, 0.1),
            ("prepared statement", False, -0.2),
            ("parameterized", False, -0.2),
            ("sanitize", False, -0.15),
            ("validate", False, -0.1),
            ("escape", False, -0.1),
        ]

        for pattern, is_dangerous, adjustment in dangerous_patterns:
            if pattern.lower() in code_snippet.lower():
                confidence += adjustment

        # Check data flow completeness
        dataflow = finding.get("dataflow", "")
        if dataflow and "->" in dataflow:
            confidence += 0.05

        # Check attack surface
        attack_surface = finding.get("attack_surface", "")
        if attack_surface and attack_surface != "internal":
            confidence += 0.1

        # Clamp confidence
        confidence = max(0.0, min(1.0, confidence))

        return {
            "initial_confidence": confidence,
            "vulnerability_type": vuln_type,
            "has_dataflow": bool(dataflow),
            "external_attack_surface": attack_surface != "internal" if attack_surface else False,
            "user_controlled": finding.get("user_controlled", False),
        }
