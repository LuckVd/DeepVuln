"""
Enhanced Adversarial Verification with Multi-Round Evolution.

This module provides the enhanced adversarial verification system that extends
the base three-role debate system with:
- Multi-round dynamic adversarial evolution
- Strategy learning and evolution
- Convergence detection
- Rule extraction from successful verifications
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Any, Callable

from ..llm.client import LLMClient
from ..models import Finding
from .adversarial import AdversarialVerifier, AdversarialVerifierConfig
from .convergence import ConvergenceChecker, ConvergenceConfig, ConvergenceResult
from .models import (
    AdversarialVerdict,
    DebateRound,
    VerificationArgument,
    VerificationResult,
    VerificationSession,
    VerdictType,
)
from .strategy_library import (
    AttackStrategy,
    DefenseStrategy,
    StrategyLibrary,
    StrategyType,
    create_attacker_library,
    create_defender_library,
)

logger = logging.getLogger(__name__)


class EnhancedVerificationConfig:
    """Configuration for enhanced adversarial verification."""

    def __init__(
        self,
        # Base config
        enabled: bool = True,
        max_rounds: int = 5,
        max_context_length: int = 4000,
        parallel_analysis: bool = True,
        sequential_rebuttal: bool = True,
        # Enhanced features
        enable_evolution: bool = True,
        enable_learning: bool = True,
        enable_rule_extraction: bool = True,
        # Convergence
        confidence_threshold: float = 0.85,
        strength_diff_threshold: float = 0.35,
        strategy_stability_rounds: int = 2,
        # Strategy libraries
        attacker_library: StrategyLibrary | None = None,
        defender_library: StrategyLibrary | None = None,
        # Limits
        max_tokens_per_finding: int = 50000,
        # Filtering (for compatibility with base config)
        skip_low_severity: bool = False,
        skip_info_findings: bool = True,
        skip_low_confidence: bool = True,
        min_confidence_to_verify: float = 0.3,
    ):
        """
        Initialize enhanced verification config.

        Args:
            enabled: Whether enhanced verification is enabled.
            max_rounds: Maximum debate rounds.
            max_context_length: Maximum code context length.
            parallel_analysis: Run initial analysis in parallel.
            sequential_rebuttal: Run rebuttals sequentially.
            enable_evolution: Enable strategy evolution.
            enable_learning: Enable learning from failures/successes.
            enable_rule_extraction: Enable rule extraction from successes.
            confidence_threshold: Confidence threshold for convergence.
            strength_diff_threshold: Strength difference threshold.
            strategy_stability_rounds: Rounds without new strategies to consider stable.
            attacker_library: Pre-configured attacker strategy library.
            defender_library: Pre-configured defender strategy library.
            max_tokens_per_finding: Maximum tokens per finding.
            skip_low_severity: Skip verification for low severity findings.
            skip_info_findings: Skip verification for info-level findings.
            skip_low_confidence: Skip verification for low confidence findings.
            min_confidence_to_verify: Minimum confidence to trigger verification.
        """
        self.enabled = enabled
        self.max_rounds = max_rounds
        self.max_context_length = max_context_length
        self.parallel_analysis = parallel_analysis
        self.sequential_rebuttal = sequential_rebuttal
        self.enable_evolution = enable_evolution
        self.enable_learning = enable_learning
        self.enable_rule_extraction = enable_rule_extraction
        self.confidence_threshold = confidence_threshold
        self.strength_diff_threshold = strength_diff_threshold
        self.strategy_stability_rounds = strategy_stability_rounds
        self.max_tokens_per_finding = max_tokens_per_finding
        self.skip_low_severity = skip_low_severity
        self.skip_info_findings = skip_info_findings
        self.skip_low_confidence = skip_low_confidence
        self.min_confidence_to_verify = min_confidence_to_verify

        # Initialize strategy libraries
        self.attacker_library = attacker_library or create_attacker_library()
        self.defender_library = defender_library or create_defender_library()


class EnhancedAdversarialVerification:
    """
    Enhanced adversarial verification with multi-round evolution.

    This class extends the base AdversarialVerifier with:
    1. Strategy libraries for attackers and defenders
    2. Strategy evolution across rounds
    3. Learning from failures and successes
    4. Convergence detection
    5. Rule extraction for future use
    """

    def __init__(
        self,
        llm_client: LLMClient,
        config: EnhancedVerificationConfig | None = None,
    ):
        """
        Initialize enhanced adversarial verification.

        Args:
            llm_client: LLM client for analysis.
            config: Configuration options.
        """
        self.llm_client = llm_client
        self.config = config or EnhancedVerificationConfig()

        # Initialize base verifier
        base_config = AdversarialVerifierConfig(
            enabled=self.config.enabled,
            max_rounds=self.config.max_rounds,
            max_context_length=self.config.max_context_length,
            parallel_analysis=self.config.parallel_analysis,
            sequential_rebuttal=self.config.sequential_rebuttal,
        )
        self.base_verifier = AdversarialVerifier(
            llm_client=llm_client,
            config=base_config,
        )

        # Strategy libraries
        self.attacker_library = self.config.attacker_library
        self.defender_library = self.config.defender_library

        # Convergence checker
        convergence_config = ConvergenceConfig(
            max_rounds=self.config.max_rounds,
            confidence_threshold=self.config.confidence_threshold,
            strength_diff_threshold=self.config.strength_diff_threshold,
            strategy_stability_rounds=self.config.strategy_stability_rounds,
            max_tokens_per_finding=self.config.max_tokens_per_finding,
        )
        self.convergence_checker = ConvergenceChecker(config=convergence_config)

        # Track extracted rules
        self.extracted_rules: list[dict[str, Any]] = []

        # Statistics
        self._stats = {
            "total_verifications": 0,
            "total_rounds": 0,
            "evolved_strategies": 0,
            "rules_extracted": 0,
        }

    async def verify_finding(
        self,
        finding: Finding | dict[str, Any],
        code_context: str,
        related_code: str | None = None,
    ) -> VerificationResult:
        """
        Verify a vulnerability finding with enhanced multi-round evolution.

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

        # Initialize result
        result = VerificationResult(
            finding_id=finding_id,
            finding_type=finding_dict.get("type", "unknown"),
            finding_severity=finding_dict.get("severity", "medium"),
            finding_location=finding_dict.get("location", "unknown"),
        )

        start_time = datetime.now(UTC)
        self.convergence_checker.reset()

        try:
            # Run enhanced multi-round verification
            await self._run_enhanced_debate(
                finding=finding_dict,
                code_context=code_context,
                related_code=related_code,
                result=result,
            )

            # Extract rules if verification was successful
            if self.config.enable_rule_extraction and result.verdict:
                self._extract_rules(result)

        except Exception as e:
            logger.error(f"Enhanced verification failed for {finding_id}: {e}")
            result.verdict = AdversarialVerdict(
                verdict=VerdictType.NEEDS_REVIEW,
                confidence=0.0,
                summary="Enhanced verification process failed",
                reasoning=str(e),
                recommended_action="review",
                priority="medium",
            )

        # Record timing
        end_time = datetime.now(UTC)
        result.verification_completed = end_time
        result.duration_seconds = (end_time - start_time).total_seconds()

        # Update statistics
        self._stats["total_verifications"] += 1
        self._stats["total_rounds"] += result.rounds_completed

        return result

    async def _run_enhanced_debate(
        self,
        finding: dict[str, Any],
        code_context: str,
        related_code: str | None,
        result: VerificationResult,
    ) -> None:
        """
        Run enhanced multi-round debate with evolution.

        Args:
            finding: The vulnerability finding.
            code_context: The vulnerable code snippet.
            related_code: Additional context code.
            result: The result object to update.
        """
        current_round = 0
        continue_debate = True

        # Get initial strategies from libraries
        vulnerability_type = finding.get("type", "unknown")
        attack_strategies = self.attacker_library.get_best_attack_strategies(
            vulnerability_type=vulnerability_type,
            top_n=3,
        )
        defense_strategies = self.defender_library.get_best_defense_strategies(
            vulnerability_type=vulnerability_type,
            top_n=3,
        )

        while continue_debate and current_round < self.config.max_rounds:
            current_round += 1
            logger.info(f"Starting enhanced debate round {current_round}/{self.config.max_rounds}")

            # Evolve strategies (except round 1)
            if current_round > 1 and self.config.enable_evolution:
                attack_strategies, defense_strategies = await self._evolve_strategies(
                    finding=finding,
                    code_context=code_context,
                    previous_round=result.debate_rounds[-1] if result.debate_rounds else None,
                    vulnerability_type=vulnerability_type,
                )
                self._stats["evolved_strategies"] += 1

            # Run debate round
            if current_round == 1:
                attacker_arg, defender_arg = await self.base_verifier._run_round_1(
                    finding=finding,
                    code_context=code_context,
                    related_code=related_code,
                )
            else:
                attacker_arg, defender_arg = await self.base_verifier._run_rebuttal_round(
                    finding=finding,
                    code_context=code_context,
                    previous_attacker=result.debate_rounds[-1].attacker_argument,
                    previous_defender=result.debate_rounds[-1].defender_argument,
                    round_number=current_round,
                )

            # Enhance arguments with strategy context
            if attack_strategies:
                attacker_arg = self._enhance_attacker_argument(
                    argument=attacker_arg,
                    strategies=attack_strategies,
                    round_number=current_round,
                )
            if defense_strategies:
                defender_arg = self._enhance_defender_argument(
                    argument=defender_arg,
                    strategies=defense_strategies,
                    round_number=current_round,
                )

            # Arbiter evaluates
            verdict = await self.base_verifier.arbiter.evaluate(
                finding=finding,
                attacker_argument=attacker_arg,
                defender_argument=defender_arg,
                debate_history=result.debate_history,
                round_number=current_round,
            )

            # Create debate round
            debate_round = DebateRound(
                round_number=current_round,
                attacker_argument=attacker_arg,
                defender_argument=defender_arg,
                arbiter_verdict=verdict,
            )

            # Check convergence
            convergence_result = self.convergence_checker.record_round(
                verdict=verdict,
                attacker_strategy=attack_strategies[0] if attack_strategies else None,
                defender_strategy=defense_strategies[0] if defense_strategies else None,
            )

            debate_round.continue_debate = not convergence_result.should_converge
            debate_round.continue_reason = convergence_result.message

            # Add round to result
            result.add_round(debate_round)
            result.verdict = verdict

            logger.info(
                f"Round {current_round} complete: {verdict.verdict.value} "
                f"(confidence: {verdict.confidence:.0%}), "
                f"converge: {convergence_result.should_converge} ({convergence_result.reason.value})"
            )

            # Learn from this round
            if self.config.enable_learning:
                self._learn_from_round(
                    finding=finding,
                    round_data=debate_round,
                    attack_strategy=attack_strategies[0] if attack_strategies else None,
                    defense_strategy=defense_strategies[0] if defense_strategies else None,
                )

            # Check if we should continue
            continue_debate = not convergence_result.should_converge

        # Mark if max rounds reached
        if current_round >= self.config.max_rounds:
            result.max_rounds_reached = True
            logger.info(f"Max rounds ({self.config.max_rounds}) reached")

    async def _evolve_strategies(
        self,
        finding: dict[str, Any],
        code_context: str,
        previous_round: DebateRound | None,
        vulnerability_type: str,
    ) -> tuple[list[AttackStrategy], list[DefenseStrategy]]:
        """
        Evolve strategies based on previous round results.

        Args:
            finding: The vulnerability finding.
            code_context: The vulnerable code snippet.
            previous_round: Previous debate round (if any).
            vulnerability_type: Type of vulnerability.

        Returns:
            Tuple of (evolved_attack_strategies, evolved_defense_strategies).
        """
        # Get lessons from failures
        lessons = self.attacker_library.get_lessons_from_failures(
            vulnerability_type=vulnerability_type,
            limit=5,
        )

        # Get success patterns
        attack_patterns = self.attacker_library.get_success_patterns(
            vulnerability_type=vulnerability_type,
            limit=5,
        )
        defense_patterns = self.defender_library.get_success_patterns(
            vulnerability_type=vulnerability_type,
            limit=5,
        )

        # Get applicable bypass techniques
        bypasses = self.attacker_library.get_applicable_bypasses(
            scenario=vulnerability_type,
            top_n=3,
        )

        # Create evolved attack strategy
        evolved_attack = AttackStrategy(
            strategy_id=f"evolved_attack_{uuid.uuid4().hex[:8]}",
            vulnerability_type=vulnerability_type,
            generation=self._get_next_generation(self.attacker_library),
            bypass_techniques=bypasses[:2] if bypasses else [],
            confidence=0.6,
            mutations=[f"learned_from: {lesson[:50]}" for lesson in lessons[:2]],
        )

        # Create evolved defense strategy
        evolved_defense = DefenseStrategy(
            strategy_id=f"evolved_defense_{uuid.uuid4().hex[:8]}",
            vulnerability_type=vulnerability_type,
            generation=self._get_next_generation(self.defender_library),
            confidence=0.6,
            mutations=[f"pattern: {pattern[:50]}" for pattern in defense_patterns[:2]],
        )

        # Get existing strategies
        attack_strategies = self.attacker_library.get_best_attack_strategies(
            vulnerability_type=vulnerability_type,
            top_n=2,
        )
        defense_strategies = self.defender_library.get_best_defense_strategies(
            vulnerability_type=vulnerability_type,
            top_n=2,
        )

        # Add evolved strategies to front
        attack_strategies = [evolved_attack] + attack_strategies[:2]
        defense_strategies = [evolved_defense] + defense_strategies[:2]

        # Add to libraries
        self.attacker_library.add_attack_strategy(evolved_attack)
        self.defender_library.add_defense_strategy(evolved_defense)

        return attack_strategies, defense_strategies

    def _get_next_generation(self, library: StrategyLibrary) -> int:
        """Get the next generation number for a library."""
        if library.strategy_type == StrategyType.ATTACK:
            if not library.attack_strategies:
                return 1
            return max(s.generation for s in library.attack_strategies) + 1
        else:
            if not library.defense_strategies:
                return 1
            return max(s.generation for s in library.defense_strategies) + 1

    def _enhance_attacker_argument(
        self,
        argument: VerificationArgument,
        strategies: list[AttackStrategy],
        round_number: int,
    ) -> VerificationArgument:
        """Enhance attacker argument with strategy insights."""
        if not strategies:
            return argument

        strategy = strategies[0]

        # Add bypass techniques to exploitation steps
        for bt in strategy.bypass_techniques[:2]:
            if bt.name not in argument.exploitation_steps:
                argument.exploitation_steps.append(f"Try {bt.name}: {bt.description}")

        # Update confidence based on strategy fitness
        if strategy.fitness_score > 0.5:
            argument.confidence = min(1.0, argument.confidence * (1 + strategy.fitness_score * 0.2))

        argument.round_number = round_number
        return argument

    def _enhance_defender_argument(
        self,
        argument: VerificationArgument,
        strategies: list[DefenseStrategy],
        round_number: int,
    ) -> VerificationArgument:
        """Enhance defender argument with strategy insights."""
        if not strategies:
            return argument

        strategy = strategies[0]

        # Add multi-layer defense suggestions
        for layer in strategy.multi_layer_defense[:2]:
            if layer not in argument.framework_protections:
                argument.framework_protections.append(layer)

        # Update confidence based on strategy fitness
        if strategy.fitness_score > 0.5:
            argument.confidence = min(1.0, argument.confidence * (1 + strategy.fitness_score * 0.2))

        argument.round_number = round_number
        return argument

    def _learn_from_round(
        self,
        finding: dict[str, Any],
        round_data: DebateRound,
        attack_strategy: AttackStrategy | None,
        defense_strategy: DefenseStrategy | None,
    ) -> None:
        """Learn from a debate round."""
        verdict = round_data.arbiter_verdict
        if not verdict:
            return

        finding_id = finding.get("id", "unknown")

        # Record success/failure based on verdict
        if verdict.verdict == VerdictType.CONFIRMED:
            # Attacker succeeded
            if attack_strategy:
                attack_strategy.record_use(success=True)
                self.attacker_library.record_success(
                    strategy_id=attack_strategy.strategy_id,
                    approach=round_data.attacker_argument.claim,
                    why_it_worked=round_data.attacker_argument.reasoning,
                    patterns=round_data.attacker_argument.exploitation_steps,
                    finding_id=finding_id,
                )
            if defense_strategy:
                defense_strategy.record_use(success=False)

        elif verdict.verdict == VerdictType.FALSE_POSITIVE:
            # Defender succeeded
            if defense_strategy:
                defense_strategy.record_use(success=True)
                self.defender_library.record_success(
                    strategy_id=defense_strategy.strategy_id,
                    approach=round_data.defender_argument.claim,
                    why_it_worked=round_data.defender_argument.reasoning,
                    patterns=round_data.defender_argument.sanitizers_found,
                    finding_id=finding_id,
                )
            if attack_strategy:
                attack_strategy.record_use(success=False)
                self.attacker_library.record_failure(
                    strategy_id=attack_strategy.strategy_id,
                    attack_path=round_data.attacker_argument.claim,
                    failure_reason=round_data.defender_argument.claim,
                    defense_that_blocked=round_data.defender_argument.sanitizers_found[0]
                    if round_data.defender_argument.sanitizers_found else None,
                    finding_id=finding_id,
                )

    def _extract_rules(self, result: VerificationResult) -> None:
        """Extract rules from a successful verification."""
        if not result.verdict:
            return

        # Only extract rules from confirmed vulnerabilities
        if result.verdict.verdict != VerdictType.CONFIRMED:
            return

        # Extract attack pattern as rule
        if result.attacker_argument:
            rule = {
                "rule_id": f"extracted_{uuid.uuid4().hex[:8]}",
                "vulnerability_type": result.finding_type,
                "source": "enhanced_adversarial_verification",
                "attack_pattern": result.attacker_argument.claim,
                "exploitation_steps": result.attacker_argument.exploitation_steps,
                "confidence": result.verdict.confidence,
                "rounds_to_confirm": result.rounds_completed,
                "extracted_at": datetime.now(UTC).isoformat(),
            }
            self.extracted_rules.append(rule)
            self._stats["rules_extracted"] += 1

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
                code_context = self.base_verifier._get_default_code_context(finding)
                related_code = None

            result = await self.verify_finding(
                finding=finding,
                code_context=code_context,
                related_code=related_code,
            )
            session.add_result(result)

        session.completed_at = datetime.now(UTC)
        return session

    def get_statistics(self) -> dict[str, Any]:
        """Get verification statistics."""
        return {
            **self._stats,
            "attacker_library": self.attacker_library.get_statistics(),
            "defender_library": self.defender_library.get_statistics(),
            "extracted_rules_count": len(self.extracted_rules),
        }

    def get_extracted_rules(self) -> list[dict[str, Any]]:
        """Get all extracted rules."""
        return self.extracted_rules.copy()


async def create_enhanced_verifier(
    llm_client: LLMClient,
    config: dict[str, Any] | None = None,
) -> EnhancedAdversarialVerification:
    """
    Factory function to create an enhanced adversarial verifier.

    Args:
        llm_client: LLM client for analysis.
        config: Optional configuration dictionary.

    Returns:
        Configured EnhancedAdversarialVerification instance.
    """
    if config:
        # Create strategy libraries if provided
        attacker_library = None
        defender_library = None

        if "attacker_library_id" in config:
            attacker_library = create_attacker_library(config.pop("attacker_library_id"))
        if "defender_library_id" in config:
            defender_library = create_defender_library(config.pop("defender_library_id"))

        verifier_config = EnhancedVerificationConfig(
            attacker_library=attacker_library,
            defender_library=defender_library,
            **config,
        )
    else:
        verifier_config = EnhancedVerificationConfig()

    return EnhancedAdversarialVerification(
        llm_client=llm_client,
        config=verifier_config,
    )
