"""
Strategy Library for Enhanced Adversarial Verification.

This module provides the strategy storage and evolution mechanisms for
attackers and defenders in the enhanced multi-round adversarial verification
system.

Key Features:
- Strategy storage and retrieval
- Strategy evolution (selection, crossover, mutation)
- Historical failure learning
- Success pattern extraction
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class StrategyType(str, Enum):
    """Types of strategies."""

    ATTACK = "attack"
    DEFENSE = "defense"


class BypassTechnique(BaseModel):
    """A bypass technique for attackers."""

    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="How this technique works")
    applicable_scenarios: list[str] = Field(
        default_factory=list,
        description="Scenarios where this technique applies",
    )
    success_rate: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Historical success rate",
    )
    usage_count: int = Field(default=0, description="Number of times used")
    success_count: int = Field(default=0, description="Number of successful uses")
    examples: list[str] = Field(
        default_factory=list,
        description="Example applications",
    )

    def record_use(self, success: bool) -> None:
        """Record a usage of this technique."""
        self.usage_count += 1
        if success:
            self.success_count += 1
        self.success_rate = self.success_count / self.usage_count


class AttackChainTemplate(BaseModel):
    """A template for multi-step attack chains."""

    name: str = Field(..., description="Chain template name")
    steps: list[str] = Field(
        ...,
        description="Ordered list of attack steps",
    )
    vulnerability_types: list[str] = Field(
        default_factory=list,
        description="Applicable vulnerability types",
    )
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Prerequisites for this chain",
    )
    success_rate: float = Field(default=0.5, ge=0.0, le=1.0)
    usage_count: int = Field(default=0)
    success_count: int = Field(default=0)

    def record_use(self, success: bool) -> None:
        """Record a usage of this chain."""
        self.usage_count += 1
        if success:
            self.success_count += 1
        self.success_rate = self.success_count / self.usage_count


class EntryPoint(BaseModel):
    """An attack entry point."""

    path: str = Field(..., description="Entry point path (URL, function, etc.)")
    entry_type: str = Field(
        ...,
        description="Type: http, rpc, mq, cron, function, etc.",
    )
    parameters: list[str] = Field(
        default_factory=list,
        description="User-controllable parameters",
    )
    risk_level: str = Field(
        default="medium",
        description="Risk level: low, medium, high, critical",
    )
    discovered_in_round: int = Field(default=1, description="Round when discovered")
    successful_exploits: int = Field(default=0, description="Times successfully exploited")


class AttackStrategy(BaseModel):
    """A complete attack strategy."""

    strategy_id: str = Field(..., description="Unique strategy identifier")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this strategy was created",
    )

    # Core components
    entry_point: EntryPoint | None = Field(
        default=None,
        description="Target entry point",
    )
    bypass_techniques: list[BypassTechnique] = Field(
        default_factory=list,
        description="Bypass techniques to apply",
    )
    attack_chain: AttackChainTemplate | None = Field(
        default=None,
        description="Attack chain to execute",
    )

    # Strategy metadata
    vulnerability_type: str = Field(
        default="unknown",
        description="Target vulnerability type",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in this strategy",
    )

    # Evolution tracking
    generation: int = Field(default=1, description="Evolution generation")
    parent_ids: list[str] = Field(
        default_factory=list,
        description="Parent strategy IDs (for crossover)",
    )
    mutations: list[str] = Field(
        default_factory=list,
        description="Mutations applied to create this strategy",
    )

    # Performance tracking
    usage_count: int = Field(default=0, description="Times this strategy was used")
    success_count: int = Field(default=0, description="Times this strategy succeeded")
    fitness_score: float = Field(default=0.5, ge=0.0, le=1.0)

    def calculate_fitness(self) -> float:
        """Calculate fitness score based on performance."""
        if self.usage_count == 0:
            return 0.5  # Default for untested strategies

        # Success rate component (60%)
        success_rate = self.success_count / self.usage_count

        # Confidence component (20%)
        confidence_component = self.confidence

        # Complexity penalty (20%) - simpler strategies are preferred
        complexity = len(self.bypass_techniques) + (len(self.attack_chain.steps) if self.attack_chain else 0)
        complexity_penalty = max(0, 1 - complexity * 0.1)

        self.fitness_score = (
            0.6 * success_rate +
            0.2 * confidence_component +
            0.2 * complexity_penalty
        )
        return self.fitness_score


class DefenseMechanism(BaseModel):
    """A defense mechanism."""

    name: str = Field(..., description="Mechanism name")
    mechanism_type: str = Field(
        ...,
        description="Type: sanitizer, validator, framework_protection, etc.",
    )
    location: str = Field(..., description="Where this defense is applied")
    effectiveness: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="How effective this defense is",
    )
    bypasses_known: list[str] = Field(
        default_factory=list,
        description="Known bypass techniques",
    )
    usage_count: int = Field(default=0)
    block_count: int = Field(default=0, description="Attacks blocked")

    def record_use(self, blocked_attack: bool) -> None:
        """Record a defense usage."""
        self.usage_count += 1
        if blocked_attack:
            self.block_count += 1
        self.effectiveness = self.block_count / self.usage_count


class PredictedAttack(BaseModel):
    """A predicted attack pattern."""

    attack_type: str = Field(..., description="Predicted attack type")
    trigger_conditions: list[str] = Field(
        default_factory=list,
        description="Conditions that might trigger this attack",
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Indicators that this attack might occur",
    )
    suggested_defense: str = Field(
        default="",
        description="Suggested defense against this attack",
    )
    prediction_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )
    times_predicted: int = Field(default=0)
    times_occurred: int = Field(default=0, description="Times this prediction came true")

    def record_outcome(self, occurred: bool) -> None:
        """Record whether this prediction came true."""
        self.times_predicted += 1
        if occurred:
            self.times_occurred += 1
        self.prediction_confidence = self.times_occurred / self.times_predicted


class DefenseStrategy(BaseModel):
    """A complete defense strategy."""

    strategy_id: str = Field(..., description="Unique strategy identifier")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this strategy was created",
    )

    # Core components
    existing_defenses: list[DefenseMechanism] = Field(
        default_factory=list,
        description="Existing defense mechanisms",
    )
    predicted_attacks: list[PredictedAttack] = Field(
        default_factory=list,
        description="Predicted attack patterns",
    )
    multi_layer_defense: list[str] = Field(
        default_factory=list,
        description="Multi-layer defense suggestions",
    )

    # Strategy metadata
    vulnerability_type: str = Field(
        default="unknown",
        description="Target vulnerability type",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )

    # Evolution tracking
    generation: int = Field(default=1)
    parent_ids: list[str] = Field(default_factory=list)
    mutations: list[str] = Field(default_factory=list)

    # Performance tracking
    usage_count: int = Field(default=0)
    block_count: int = Field(default=0, description="Attacks blocked using this strategy")
    fitness_score: float = Field(default=0.5, ge=0.0, le=1.0)

    def calculate_fitness(self) -> float:
        """Calculate fitness score based on performance."""
        if self.usage_count == 0:
            return 0.5

        # Block rate component (60%)
        block_rate = self.block_count / self.usage_count

        # Confidence component (20%)
        confidence_component = self.confidence

        # Defense depth component (20%) - more layers is better
        defense_depth = min(1.0, len(self.multi_layer_defense) * 0.2)

        self.fitness_score = (
            0.6 * block_rate +
            0.2 * confidence_component +
            0.2 * defense_depth
        )
        return self.fitness_score


class FailureRecord(BaseModel):
    """Record of a failed attack attempt."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    strategy_id: str = Field(..., description="Strategy that failed")
    attack_path: str = Field(..., description="Attack path attempted")
    failure_reason: str = Field(..., description="Why it failed")
    defense_that_blocked: str | None = Field(
        default=None,
        description="Defense that blocked this attack",
    )
    lesson_learned: str = Field(..., description="What was learned from this failure")
    related_finding_id: str | None = Field(default=None)


class SuccessRecord(BaseModel):
    """Record of a successful attack or defense."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    strategy_id: str = Field(..., description="Strategy that succeeded")
    approach: str = Field(..., description="What approach worked")
    why_it_worked: str = Field(..., description="Why this approach succeeded")
    patterns_identified: list[str] = Field(
        default_factory=list,
        description="Patterns that can be reused",
    )
    related_finding_id: str | None = Field(default=None)


class StrategyLibrary(BaseModel):
    """
    Library for storing and managing strategies.

    Supports both attacker and defender strategies with:
    - Strategy storage and retrieval
    - Performance tracking
    - Evolution support
    - Historical learning
    """

    library_id: str = Field(..., description="Unique library identifier")
    strategy_type: StrategyType = Field(..., description="Attack or defense library")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Attack strategies (for attacker library)
    attack_strategies: list[AttackStrategy] = Field(default_factory=list)
    bypass_techniques: list[BypassTechnique] = Field(default_factory=list)
    attack_chains: list[AttackChainTemplate] = Field(default_factory=list)
    known_entry_points: list[EntryPoint] = Field(default_factory=list)

    # Defense strategies (for defender library)
    defense_strategies: list[DefenseStrategy] = Field(default_factory=list)
    defense_mechanisms: list[DefenseMechanism] = Field(default_factory=list)
    predicted_attacks: list[PredictedAttack] = Field(default_factory=list)

    # Learning records
    failure_records: list[FailureRecord] = Field(default_factory=list)
    success_records: list[SuccessRecord] = Field(default_factory=list)

    # Configuration
    max_strategies: int = Field(default=100, description="Maximum strategies to keep")
    max_history: int = Field(default=500, description="Maximum history records")

    # Statistics
    total_rounds: int = Field(default=0)
    total_successes: int = Field(default=0)
    total_failures: int = Field(default=0)

    def add_attack_strategy(self, strategy: AttackStrategy) -> None:
        """Add an attack strategy to the library."""
        self.attack_strategies.append(strategy)
        self._prune_strategies()
        self.updated_at = datetime.now(UTC)

    def add_defense_strategy(self, strategy: DefenseStrategy) -> None:
        """Add a defense strategy to the library."""
        self.defense_strategies.append(strategy)
        self._prune_strategies()
        self.updated_at = datetime.now(UTC)

    def record_failure(
        self,
        strategy_id: str,
        attack_path: str,
        failure_reason: str,
        defense_that_blocked: str | None = None,
        finding_id: str | None = None,
    ) -> None:
        """Record a failed attack attempt."""
        # Extract lesson learned
        lesson = self._extract_lesson(attack_path, failure_reason, defense_that_blocked)

        record = FailureRecord(
            strategy_id=strategy_id,
            attack_path=attack_path,
            failure_reason=failure_reason,
            defense_that_blocked=defense_that_blocked,
            lesson_learned=lesson,
            related_finding_id=finding_id,
        )
        self.failure_records.append(record)
        self.total_failures += 1

        # Prune history if needed
        if len(self.failure_records) > self.max_history:
            self.failure_records = self.failure_records[-self.max_history:]

        self.updated_at = datetime.now(UTC)

    def record_success(
        self,
        strategy_id: str,
        approach: str,
        why_it_worked: str,
        patterns: list[str] | None = None,
        finding_id: str | None = None,
    ) -> None:
        """Record a successful attack or defense."""
        record = SuccessRecord(
            strategy_id=strategy_id,
            approach=approach,
            why_it_worked=why_it_worked,
            patterns_identified=patterns or [],
            related_finding_id=finding_id,
        )
        self.success_records.append(record)
        self.total_successes += 1

        # Prune history if needed
        if len(self.success_records) > self.max_history:
            self.success_records = self.success_records[-self.max_history:]

        self.updated_at = datetime.now(UTC)

    def get_best_attack_strategies(
        self,
        vulnerability_type: str | None = None,
        top_n: int = 5,
    ) -> list[AttackStrategy]:
        """Get the best attack strategies, optionally filtered by vulnerability type."""
        strategies = self.attack_strategies

        if vulnerability_type:
            strategies = [
                s for s in strategies
                if s.vulnerability_type == vulnerability_type or s.vulnerability_type == "unknown"
            ]

        # Sort by fitness score
        sorted_strategies = sorted(
            strategies,
            key=lambda s: s.calculate_fitness(),
            reverse=True,
        )

        return sorted_strategies[:top_n]

    def get_best_defense_strategies(
        self,
        vulnerability_type: str | None = None,
        top_n: int = 5,
    ) -> list[DefenseStrategy]:
        """Get the best defense strategies, optionally filtered by vulnerability type."""
        strategies = self.defense_strategies

        if vulnerability_type:
            strategies = [
                s for s in strategies
                if s.vulnerability_type == vulnerability_type or s.vulnerability_type == "unknown"
            ]

        # Sort by fitness score
        sorted_strategies = sorted(
            strategies,
            key=lambda s: s.calculate_fitness(),
            reverse=True,
        )

        return sorted_strategies[:top_n]

    def get_applicable_bypasses(
        self,
        scenario: str,
        top_n: int = 5,
    ) -> list[BypassTechnique]:
        """Get bypass techniques applicable to a scenario."""
        applicable = [
            bt for bt in self.bypass_techniques
            if scenario.lower() in " ".join(bt.applicable_scenarios).lower()
            or not bt.applicable_scenarios  # General techniques
        ]

        # Sort by success rate
        sorted_bypasses = sorted(applicable, key=lambda bt: bt.success_rate, reverse=True)
        return sorted_bypasses[:top_n]

    def get_lessons_from_failures(
        self,
        vulnerability_type: str | None = None,
        limit: int = 10,
    ) -> list[str]:
        """Get lessons learned from past failures."""
        records = self.failure_records

        # Get recent failures
        recent = sorted(records, key=lambda r: r.timestamp, reverse=True)[:limit * 2]

        lessons = [r.lesson_learned for r in recent]
        return list(set(lessons))[:limit]  # Deduplicate and limit

    def get_success_patterns(
        self,
        vulnerability_type: str | None = None,
        limit: int = 10,
    ) -> list[str]:
        """Get patterns from successful strategies."""
        records = self.success_records

        recent = sorted(records, key=lambda r: r.timestamp, reverse=True)[:limit * 2]

        patterns = []
        for r in recent:
            patterns.extend(r.patterns_identified)

        return list(set(patterns))[:limit]

    def _extract_lesson(
        self,
        attack_path: str,
        failure_reason: str,
        defense_that_blocked: str | None,
    ) -> str:
        """Extract a lesson from a failure."""
        lesson_parts = [f"Failed: {attack_path}"]

        if defense_that_blocked:
            lesson_parts.append(f"Blocked by: {defense_that_blocked}")

        lesson_parts.append(f"Reason: {failure_reason}")
        lesson_parts.append("Avoid this approach or find alternative")

        return " | ".join(lesson_parts)

    def _prune_strategies(self) -> None:
        """Remove low-performing strategies if over limit."""
        if self.strategy_type == StrategyType.ATTACK:
            if len(self.attack_strategies) > self.max_strategies:
                # Keep top performers
                sorted_strategies = sorted(
                    self.attack_strategies,
                    key=lambda s: s.fitness_score,
                    reverse=True,
                )
                self.attack_strategies = sorted_strategies[:self.max_strategies]

        elif self.strategy_type == StrategyType.DEFENSE:
            if len(self.defense_strategies) > self.max_strategies:
                sorted_strategies = sorted(
                    self.defense_strategies,
                    key=lambda s: s.fitness_score,
                    reverse=True,
                )
                self.defense_strategies = sorted_strategies[:self.max_strategies]

    def get_statistics(self) -> dict[str, Any]:
        """Get library statistics."""
        return {
            "library_id": self.library_id,
            "strategy_type": self.strategy_type.value,
            "attack_strategies": len(self.attack_strategies),
            "defense_strategies": len(self.defense_strategies),
            "bypass_techniques": len(self.bypass_techniques),
            "attack_chains": len(self.attack_chains),
            "entry_points": len(self.known_entry_points),
            "defense_mechanisms": len(self.defense_mechanisms),
            "failure_records": len(self.failure_records),
            "success_records": len(self.success_records),
            "total_rounds": self.total_rounds,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "success_rate": (
                self.total_successes / (self.total_successes + self.total_failures)
                if (self.total_successes + self.total_failures) > 0
                else 0.0
            ),
        }


def create_attacker_library(library_id: str = "attacker_default") -> StrategyLibrary:
    """Create a default attacker strategy library with common techniques."""
    library = StrategyLibrary(
        library_id=library_id,
        strategy_type=StrategyType.ATTACK,
    )

    # Add common bypass techniques
    default_bypasses = [
        BypassTechnique(
            name="case_variation",
            description="Use case variations to bypass case-sensitive checks",
            applicable_scenarios=["input_validation", "waf_bypass"],
            success_rate=0.6,
            examples=["AdMiN", "SeLeCt"],
        ),
        BypassTechnique(
            name="encoding_bypass",
            description="Use URL encoding, double encoding, or hex encoding",
            applicable_scenarios=["input_validation", "waf_bypass", "filter_bypass"],
            success_rate=0.5,
            examples=["%41%42%43", "&#x41;"],
        ),
        BypassTechnique(
            name="null_byte_injection",
            description="Inject null bytes to truncate strings",
            applicable_scenarios=["file_upload", "path_traversal", "extension_bypass"],
            success_rate=0.4,
            examples=["file.php%00.jpg", "path/../../../etc/passwd%00"],
        ),
        BypassTechnique(
            name="comment_injection",
            description="Use comments to break up patterns",
            applicable_scenarios=["sql_injection", "xss"],
            success_rate=0.5,
            examples=["SEL/**/ECT", "<scr<!-->ipt>"],
        ),
        BypassTechnique(
            name="parameter_pollution",
            description="Use multiple parameters with same name",
            applicable_scenarios=["input_validation", "parameter_tampering"],
            success_rate=0.4,
            examples=["?id=1&id=2", "?file=a.txt&file=b.txt"],
        ),
    ]
    library.bypass_techniques = default_bypasses

    # Add default attack chain templates
    default_chains = [
        AttackChainTemplate(
            name="sqli_data_exfil",
            steps=["inject_sql", "bypass_waf", "extract_data", "exfiltrate"],
            vulnerability_types=["sql_injection"],
            prerequisites=["user_input_in_sql", "no_prepared_statements"],
            success_rate=0.6,
        ),
        AttackChainTemplate(
            name="xss_session_hijack",
            steps=["inject_script", "bypass_filter", "steal_cookie", "hijack_session"],
            vulnerability_types=["xss", "dom_xss", "stored_xss"],
            prerequisites=["user_input_in_html", "no_output_encoding"],
            success_rate=0.5,
        ),
        AttackChainTemplate(
            name="auth_bypass_privilege_escalation",
            steps=["bypass_auth", "escalate_privileges", "access_admin", "persist_access"],
            vulnerability_types=["auth_bypass", "privilege_escalation", "idor"],
            prerequisites=["weak_auth", "missing_authz_checks"],
            success_rate=0.4,
        ),
    ]
    library.attack_chains = default_chains

    return library


def create_defender_library(library_id: str = "defender_default") -> StrategyLibrary:
    """Create a default defender strategy library with common defenses."""
    library = StrategyLibrary(
        library_id=library_id,
        strategy_type=StrategyType.DEFENSE,
    )

    # Add common defense mechanisms
    default_defenses = [
        DefenseMechanism(
            name="parameterized_queries",
            mechanism_type="sanitizer",
            location="database_layer",
            effectiveness=0.95,
            bypasses_known=["second_order_sqli"],
        ),
        DefenseMechanism(
            name="output_encoding",
            mechanism_type="sanitizer",
            location="output_layer",
            effectiveness=0.9,
            bypasses_known=["improper_context"],
        ),
        DefenseMechanism(
            name="input_validation",
            mechanism_type="validator",
            location="input_layer",
            effectiveness=0.7,
            bypasses_known=["encoding_bypass", "case_variation"],
        ),
        DefenseMechanism(
            name="csrf_token",
            mechanism_type="framework_protection",
            location="form_handler",
            effectiveness=0.85,
            bypasses_known=["token_leakage", "referer_bypass"],
        ),
        DefenseMechanism(
            name="content_security_policy",
            mechanism_type="framework_protection",
            location="http_header",
            effectiveness=0.8,
            bypasses_known=["misconfiguration", "unsafe_inline"],
        ),
    ]
    library.defense_mechanisms = default_defenses

    # Add predicted attack patterns
    default_predictions = [
        PredictedAttack(
            attack_type="sql_injection",
            trigger_conditions=["user_input_in_query", "string_concatenation"],
            indicators=["dynamic_sql", "raw_queries"],
            suggested_defense="Use parameterized queries",
            prediction_confidence=0.8,
        ),
        PredictedAttack(
            attack_type="xss",
            trigger_conditions=["user_input_in_html", "dom_manipulation"],
            indicators=["innerHTML", "document.write"],
            suggested_defense="Apply output encoding",
            prediction_confidence=0.75,
        ),
        PredictedAttack(
            attack_type="path_traversal",
            trigger_conditions=["user_input_in_path", "file_operations"],
            indicators=["file_read", "file_include"],
            suggested_defense="Validate and sanitize file paths",
            prediction_confidence=0.7,
        ),
    ]
    library.predicted_attacks = default_predictions

    return library
