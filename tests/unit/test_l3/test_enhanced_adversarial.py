"""
Tests for Enhanced Adversarial Verification.

Tests cover:
- Strategy library operations
- Convergence checking
- Enhanced verification workflow
- Strategy evolution
- Learning mechanisms
"""

import pytest
from datetime import datetime, UTC

from src.layers.l3_analysis.verification.strategy_library import (
    AttackChainTemplate,
    AttackStrategy,
    BypassTechnique,
    DefenseMechanism,
    DefenseStrategy,
    EntryPoint,
    FailureRecord,
    PredictedAttack,
    StrategyLibrary,
    StrategyType,
    SuccessRecord,
    create_attacker_library,
    create_defender_library,
)
from src.layers.l3_analysis.verification.convergence import (
    ConvergenceChecker,
    ConvergenceConfig,
    ConvergenceReason,
    ConvergenceResult,
    ConvergenceState,
    RoundSummary,
)
from src.layers.l3_analysis.verification.models import (
    AdversarialVerdict,
    VerdictType,
)


# =============================================================================
# Strategy Library Tests
# =============================================================================

class TestBypassTechnique:
    """Tests for BypassTechnique."""

    def test_create_bypass_technique(self):
        """Test creating a bypass technique."""
        bt = BypassTechnique(
            name="case_variation",
            description="Use case variations to bypass checks",
            applicable_scenarios=["input_validation", "waf_bypass"],
            success_rate=0.6,
        )
        assert bt.name == "case_variation"
        assert bt.success_rate == 0.6
        assert bt.usage_count == 0
        assert bt.success_count == 0

    def test_record_use_success(self):
        """Test recording successful use."""
        bt = BypassTechnique(
            name="encoding_bypass",
            description="URL encoding bypass",
            success_rate=0.5,
        )
        bt.record_use(success=True)
        assert bt.usage_count == 1
        assert bt.success_count == 1
        assert bt.success_rate == 1.0

    def test_record_use_failure(self):
        """Test recording failed use."""
        bt = BypassTechnique(
            name="null_byte",
            description="Null byte injection",
            success_rate=0.5,
        )
        bt.record_use(success=False)
        assert bt.usage_count == 1
        assert bt.success_count == 0
        assert bt.success_rate == 0.0

    def test_record_multiple_uses(self):
        """Test recording multiple uses."""
        bt = BypassTechnique(name="test", description="test")
        bt.record_use(True)
        bt.record_use(True)
        bt.record_use(False)
        assert bt.usage_count == 3
        assert bt.success_count == 2
        assert bt.success_rate == pytest.approx(2/3)


class TestAttackChainTemplate:
    """Tests for AttackChainTemplate."""

    def test_create_chain(self):
        """Test creating an attack chain."""
        chain = AttackChainTemplate(
            name="sqli_data_exfil",
            steps=["inject_sql", "bypass_waf", "extract_data"],
            vulnerability_types=["sql_injection"],
            success_rate=0.6,
        )
        assert chain.name == "sqli_data_exfil"
        assert len(chain.steps) == 3
        assert chain.usage_count == 0

    def test_record_chain_use(self):
        """Test recording chain usage."""
        chain = AttackChainTemplate(
            name="test_chain",
            steps=["step1", "step2"],
        )
        chain.record_use(success=True)
        chain.record_use(success=False)
        assert chain.usage_count == 2
        assert chain.success_count == 1
        assert chain.success_rate == 0.5


class TestAttackStrategy:
    """Tests for AttackStrategy."""

    def test_create_strategy(self):
        """Test creating an attack strategy."""
        strategy = AttackStrategy(
            strategy_id="test_attack_001",
            vulnerability_type="sql_injection",
            confidence=0.7,
        )
        assert strategy.strategy_id == "test_attack_001"
        assert strategy.vulnerability_type == "sql_injection"
        assert strategy.generation == 1
        assert len(strategy.parent_ids) == 0

    def test_calculate_fitness_no_usage(self):
        """Test fitness calculation with no usage."""
        strategy = AttackStrategy(
            strategy_id="test",
            vulnerability_type="xss",
        )
        fitness = strategy.calculate_fitness()
        assert fitness == 0.5  # Default for untested

    def test_calculate_fitness_with_usage(self):
        """Test fitness calculation with usage."""
        strategy = AttackStrategy(
            strategy_id="test",
            vulnerability_type="xss",
            confidence=0.8,
        )
        strategy.usage_count = 10
        strategy.success_count = 7
        fitness = strategy.calculate_fitness()
        # 0.6 * 0.7 (success rate) + 0.2 * 0.8 (confidence) + 0.2 * 1.0 (no complexity)
        assert 0.5 < fitness < 0.8

    def test_strategy_with_bypasses(self):
        """Test strategy with bypass techniques."""
        bt = BypassTechnique(name="encoding", description="URL encoding")
        strategy = AttackStrategy(
            strategy_id="test",
            vulnerability_type="xss",
            bypass_techniques=[bt],
        )
        assert len(strategy.bypass_techniques) == 1


class TestDefenseStrategy:
    """Tests for DefenseStrategy."""

    def test_create_defense_strategy(self):
        """Test creating a defense strategy."""
        strategy = DefenseStrategy(
            strategy_id="def_001",
            vulnerability_type="sql_injection",
            confidence=0.8,
        )
        assert strategy.strategy_id == "def_001"
        assert strategy.vulnerability_type == "sql_injection"

    def test_calculate_fitness(self):
        """Test defense fitness calculation."""
        strategy = DefenseStrategy(
            strategy_id="test",
            vulnerability_type="xss",
            confidence=0.7,
            multi_layer_defense=["input_validation", "output_encoding"],
        )
        strategy.usage_count = 10
        strategy.block_count = 8
        fitness = strategy.calculate_fitness()
        assert fitness > 0.5


class TestStrategyLibrary:
    """Tests for StrategyLibrary."""

    def test_create_attacker_library(self):
        """Test creating an attacker library."""
        library = StrategyLibrary(
            library_id="test_attacker",
            strategy_type=StrategyType.ATTACK,
        )
        assert library.strategy_type == StrategyType.ATTACK
        assert len(library.attack_strategies) == 0

    def test_add_attack_strategy(self):
        """Test adding an attack strategy."""
        library = StrategyLibrary(
            library_id="test",
            strategy_type=StrategyType.ATTACK,
        )
        strategy = AttackStrategy(
            strategy_id="test_001",
            vulnerability_type="xss",
        )
        library.add_attack_strategy(strategy)
        assert len(library.attack_strategies) == 1

    def test_record_failure(self):
        """Test recording a failure."""
        library = StrategyLibrary(
            library_id="test",
            strategy_type=StrategyType.ATTACK,
        )
        library.record_failure(
            strategy_id="test_001",
            attack_path="SQL injection via id parameter",
            failure_reason="WAF blocked request",
            defense_that_blocked="ModSecurity WAF",
        )
        assert len(library.failure_records) == 1
        assert library.total_failures == 1

    def test_record_success(self):
        """Test recording a success."""
        library = StrategyLibrary(
            library_id="test",
            strategy_type=StrategyType.ATTACK,
        )
        library.record_success(
            strategy_id="test_001",
            approach="XSS via innerHTML",
            why_it_worked="No output encoding applied",
            patterns=["innerHTML assignment", "user input directly used"],
        )
        assert len(library.success_records) == 1
        assert library.total_successes == 1

    def test_get_best_strategies(self):
        """Test getting best strategies."""
        library = StrategyLibrary(
            library_id="test",
            strategy_type=StrategyType.ATTACK,
        )

        # Add strategies with different fitness
        for i, (conf, uses, successes) in enumerate([
            (0.5, 10, 5),  # fitness ~0.5
            (0.8, 10, 8),  # fitness ~0.7
            (0.3, 10, 3),  # fitness ~0.3
        ]):
            s = AttackStrategy(
                strategy_id=f"test_{i}",
                vulnerability_type="xss",
                confidence=conf,
            )
            s.usage_count = uses
            s.success_count = successes
            s.calculate_fitness()
            library.add_attack_strategy(s)

        best = library.get_best_attack_strategies(vulnerability_type="xss", top_n=2)
        assert len(best) == 2
        assert best[0].confidence >= best[1].confidence

    def test_get_lessons_from_failures(self):
        """Test getting lessons from failures."""
        library = StrategyLibrary(
            library_id="test",
            strategy_type=StrategyType.ATTACK,
        )

        for i in range(5):
            library.record_failure(
                strategy_id=f"test_{i}",
                attack_path=f"path_{i}",
                failure_reason=f"reason_{i}",
            )

        lessons = library.get_lessons_from_failures(limit=3)
        assert len(lessons) <= 3

    def test_get_applicable_bypasses(self):
        """Test getting applicable bypasses."""
        library = StrategyLibrary(
            library_id="test",
            strategy_type=StrategyType.ATTACK,
        )

        library.bypass_techniques = [
            BypassTechnique(
                name="case_bypass",
                description="Case variation",
                applicable_scenarios=["input_validation"],
                success_rate=0.7,
            ),
            BypassTechnique(
                name="encoding_bypass",
                description="URL encoding",
                applicable_scenarios=["waf_bypass"],
                success_rate=0.5,
            ),
        ]

        bypasses = library.get_applicable_bypasses("input_validation", top_n=5)
        assert len(bypasses) >= 1
        assert bypasses[0].name == "case_bypass"

    def test_prune_strategies(self):
        """Test strategy pruning when over limit."""
        library = StrategyLibrary(
            library_id="test",
            strategy_type=StrategyType.ATTACK,
            max_strategies=3,
        )

        # Add more strategies than limit
        for i in range(5):
            s = AttackStrategy(
                strategy_id=f"test_{i}",
                vulnerability_type="xss",
                confidence=0.5 + i * 0.1,
            )
            s.usage_count = 10
            s.success_count = 5 + i
            s.calculate_fitness()
            library.add_attack_strategy(s)

        assert len(library.attack_strategies) <= library.max_strategies

    def test_get_statistics(self):
        """Test getting library statistics."""
        library = StrategyLibrary(
            library_id="test",
            strategy_type=StrategyType.ATTACK,
        )
        library.record_success("test", "approach", "reason")
        library.record_failure("test", "path", "reason")

        stats = library.get_statistics()
        assert stats["library_id"] == "test"
        assert stats["total_successes"] == 1
        assert stats["total_failures"] == 1


class TestDefaultLibraries:
    """Tests for default library creation."""

    def test_create_attacker_library_defaults(self):
        """Test creating default attacker library."""
        library = create_attacker_library("test_attacker")
        assert library.strategy_type == StrategyType.ATTACK
        assert len(library.bypass_techniques) > 0
        assert len(library.attack_chains) > 0

    def test_create_defender_library_defaults(self):
        """Test creating default defender library."""
        library = create_defender_library("test_defender")
        assert library.strategy_type == StrategyType.DEFENSE
        assert len(library.defense_mechanisms) > 0
        assert len(library.predicted_attacks) > 0


# =============================================================================
# Convergence Tests
# =============================================================================

class TestConvergenceConfig:
    """Tests for ConvergenceConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = ConvergenceConfig()
        assert config.max_rounds == 5
        assert config.confidence_threshold == 0.85
        assert config.min_rounds == 1

    def test_custom_config(self):
        """Test custom configuration."""
        config = ConvergenceConfig(
            max_rounds=3,
            confidence_threshold=0.9,
            strategy_stability_rounds=1,
        )
        assert config.max_rounds == 3
        assert config.confidence_threshold == 0.9


class TestRoundSummary:
    """Tests for RoundSummary."""

    def test_create_round_summary(self):
        """Test creating a round summary."""
        summary = RoundSummary(
            round_number=1,
            verdict_type=VerdictType.CONFIRMED,
            verdict_confidence=0.85,
            attacker_strength=0.8,
            defender_strength=0.3,
        )
        assert summary.round_number == 1
        assert summary.verdict_type == VerdictType.CONFIRMED
        assert summary.strength_diff == pytest.approx(0.5)

    def test_is_decisive(self):
        """Test decisive verdict detection."""
        # Decisive: high confidence + large strength diff
        decisive = RoundSummary(
            round_number=1,
            verdict_type=VerdictType.CONFIRMED,
            verdict_confidence=0.9,
            attacker_strength=0.9,
            defender_strength=0.2,
        )
        assert decisive.is_decisive is True

        # Not decisive: low confidence
        low_conf = RoundSummary(
            round_number=1,
            verdict_type=VerdictType.CONFIRMED,
            verdict_confidence=0.5,
            attacker_strength=0.9,
            defender_strength=0.2,
        )
        assert low_conf.is_decisive is False

        # Not decisive: small strength diff
        small_diff = RoundSummary(
            round_number=1,
            verdict_type=VerdictType.CONFIRMED,
            verdict_confidence=0.9,
            attacker_strength=0.6,
            defender_strength=0.5,
        )
        assert small_diff.is_decisive is False


class TestConvergenceChecker:
    """Tests for ConvergenceChecker."""

    @pytest.fixture
    def checker(self):
        """Create a convergence checker."""
        config = ConvergenceConfig(
            max_rounds=5,
            confidence_threshold=0.85,
            min_rounds=1,
        )
        return ConvergenceChecker(config=config)

    def test_initial_state(self, checker):
        """Test initial state."""
        assert checker.state.current_round() == 0
        assert len(checker.state.round_summaries) == 0

    def test_record_round_continue(self, checker):
        """Test recording a round that should continue."""
        verdict = AdversarialVerdict(
            verdict=VerdictType.NEEDS_REVIEW,
            confidence=0.5,
            summary="Needs more debate",
            reasoning="Unclear",
            attacker_strength=0.5,
            defender_strength=0.5,
        )

        result = checker.record_round(verdict)
        assert result.should_converge is False
        assert checker.state.current_round() == 1

    def test_converge_on_high_confidence(self, checker):
        """Test convergence on high confidence."""
        verdict = AdversarialVerdict(
            verdict=VerdictType.CONFIRMED,
            confidence=0.9,  # Above threshold
            summary="Confirmed",
            reasoning="Clear evidence",
            attacker_strength=0.9,
            defender_strength=0.2,
        )

        result = checker.record_round(verdict)
        assert result.should_converge is True
        assert result.reason == ConvergenceReason.HIGH_CONFIDENCE

    def test_converge_on_max_rounds(self, checker):
        """Test convergence on max rounds."""
        checker.config.max_rounds = 2

        for i in range(3):
            verdict = AdversarialVerdict(
                verdict=VerdictType.NEEDS_REVIEW,
                confidence=0.5,
                summary=f"Round {i+1}",
                reasoning="Still unclear",
                attacker_strength=0.5,
                defender_strength=0.5,
            )
            result = checker.record_round(verdict)

            if i < 1:  # Rounds 0, 1 should continue
                assert result.should_converge is False
            else:  # Round 2 should converge
                assert result.should_converge is True
                assert result.reason == ConvergenceReason.MAX_ROUNDS_REACHED

    def test_converge_on_decisive_verdict(self, checker):
        """Test convergence on decisive verdict."""
        verdict = AdversarialVerdict(
            verdict=VerdictType.FALSE_POSITIVE,
            confidence=0.95,
            summary="False positive confirmed",
            reasoning="Has sanitizer",
            attacker_strength=0.1,
            defender_strength=0.9,
        )

        result = checker.record_round(verdict)
        assert result.should_converge is True
        assert result.reason in [ConvergenceReason.DECISIVE_VERDICT, ConvergenceReason.HIGH_CONFIDENCE]

    def test_strategy_stability_detection(self, checker):
        """Test detection of strategy stability."""
        checker.config.strategy_stability_rounds = 1  # Only need 1 round without new strategy
        checker.config.progress_window = 5  # Prevent NO_PROGRESS from triggering first
        checker.config.confidence_threshold = 0.95  # Prevent HIGH_CONFIDENCE
        checker.config.max_rounds = 10  # Allow more rounds

        attacker_strategy = AttackStrategy(
            strategy_id="same_attacker",
            vulnerability_type="xss",
        )
        defender_strategy = DefenseStrategy(
            strategy_id="same_defender",
            vulnerability_type="xss",
        )

        # Record multiple rounds with same strategies
        # Round 1: adds strategies to seen set
        # Round 2: strategies already seen, stability counter = 1
        # Round 3: should converge due to stability (both counters >= 1)
        for i in range(3):
            verdict = AdversarialVerdict(
                verdict=VerdictType.NEEDS_REVIEW,
                confidence=0.5 + i * 0.05,  # Slight improvement to avoid NO_PROGRESS
                summary=f"Round {i+1}",
                reasoning="Still debating",
                attacker_strength=0.5,
                defender_strength=0.5,
            )
            result = checker.record_round(
                verdict=verdict,
                attacker_strategy=attacker_strategy,
                defender_strategy=defender_strategy,
            )

        # Should converge due to strategy stability
        assert result.should_converge is True
        assert result.reason == ConvergenceReason.STRATEGY_STABLE

    def test_get_progress_summary(self, checker):
        """Test getting progress summary."""
        for i in range(3):
            verdict = AdversarialVerdict(
                verdict=VerdictType.NEEDS_REVIEW,
                confidence=0.5 + i * 0.1,  # Improving
                summary=f"Round {i+1}",
                reasoning="Progress",
                attacker_strength=0.5 + i * 0.1,
                defender_strength=0.5,
            )
            checker.record_round(verdict)

        summary = checker.get_progress_summary()
        assert summary["rounds_completed"] == 3
        assert len(summary["confidence_progression"]) == 3
        assert summary["confidence_improvement"] > 0

    def test_reset(self, checker):
        """Test resetting the checker."""
        verdict = AdversarialVerdict(
            verdict=VerdictType.CONFIRMED,
            confidence=0.9,
            summary="Done",
            reasoning="Complete",
            attacker_strength=0.8,
            defender_strength=0.2,
        )
        checker.record_round(verdict)
        assert checker.state.current_round() == 1

        checker.reset()
        assert checker.state.current_round() == 0


class TestConvergenceResult:
    """Tests for ConvergenceResult."""

    def test_convergence_result_creation(self):
        """Test creating a convergence result."""
        result = ConvergenceResult(
            should_converge=True,
            reason=ConvergenceReason.HIGH_CONFIDENCE,
            confidence=0.9,
            message="High confidence reached",
            rounds_completed=2,
            final_verdict_type=VerdictType.CONFIRMED,
        )
        assert result.should_converge is True
        assert result.reason == ConvergenceReason.HIGH_CONFIDENCE
        assert result.progress_made is True


# =============================================================================
# Integration Tests
# =============================================================================

class TestStrategyEvolution:
    """Tests for strategy evolution."""

    def test_attack_strategy_evolution(self):
        """Test evolving an attack strategy."""
        library = create_attacker_library("test")

        # Create parent strategy
        parent = AttackStrategy(
            strategy_id="parent_001",
            vulnerability_type="xss",
            generation=1,
            confidence=0.6,
        )
        parent.usage_count = 10
        parent.success_count = 6
        parent.calculate_fitness()
        library.add_attack_strategy(parent)

        # Create evolved strategy
        evolved = AttackStrategy(
            strategy_id="evolved_001",
            vulnerability_type="xss",
            generation=2,
            parent_ids=["parent_001"],
            confidence=0.7,
            mutations=["added_encoding_bypass"],
        )
        library.add_attack_strategy(evolved)

        assert len(library.attack_strategies) == 2
        evolved_found = next(
            (s for s in library.attack_strategies if s.strategy_id == "evolved_001"),
            None
        )
        assert evolved_found is not None
        assert evolved_found.generation == 2
        assert "parent_001" in evolved_found.parent_ids

    def test_defense_strategy_evolution(self):
        """Test evolving a defense strategy."""
        library = create_defender_library("test")

        parent = DefenseStrategy(
            strategy_id="def_parent",
            vulnerability_type="sql_injection",
            generation=1,
        )
        library.add_defense_strategy(parent)

        evolved = DefenseStrategy(
            strategy_id="def_evolved",
            vulnerability_type="sql_injection",
            generation=2,
            parent_ids=["def_parent"],
            multi_layer_defense=["input_validation", "parameterized_queries"],
        )
        library.add_defense_strategy(evolved)

        assert len(library.defense_strategies) >= 2


class TestLearningMechanism:
    """Tests for learning from debates."""

    def test_learning_from_attack_failure(self):
        """Test learning from a failed attack."""
        library = create_attacker_library("test")

        # Record a failure
        library.record_failure(
            strategy_id="attack_001",
            attack_path="Direct SQL injection in id parameter",
            failure_reason="WAF detected SQL keywords",
            defense_that_blocked="ModSecurity",
        )

        # Get lessons
        lessons = library.get_lessons_from_failures()
        assert len(lessons) > 0
        assert any("WAF" in lesson or "ModSecurity" in lesson for lesson in lessons)

    def test_learning_from_attack_success(self):
        """Test learning from a successful attack."""
        library = create_attacker_library("test")

        # Record a success
        library.record_success(
            strategy_id="attack_002",
            approach="XSS via SVG onload event",
            why_it_worked="SVG files not sanitized, onload event allowed",
            patterns=["svg_upload", "event_handler_xss"],
        )

        # Get patterns
        patterns = library.get_success_patterns()
        assert len(patterns) > 0

    def test_fitness_improvement_through_learning(self):
        """Test that fitness improves with successful usage."""
        library = StrategyLibrary(
            library_id="test",
            strategy_type=StrategyType.ATTACK,
        )

        strategy = AttackStrategy(
            strategy_id="test_strategy",
            vulnerability_type="xss",
            confidence=0.5,
        )

        # Initial fitness
        initial_fitness = strategy.calculate_fitness()

        # Simulate successful uses
        strategy.usage_count = 10
        strategy.success_count = 8
        new_fitness = strategy.calculate_fitness()

        assert new_fitness > initial_fitness


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_library(self):
        """Test operations on empty library."""
        library = StrategyLibrary(
            library_id="empty",
            strategy_type=StrategyType.ATTACK,
        )

        best = library.get_best_attack_strategies()
        assert len(best) == 0

        lessons = library.get_lessons_from_failures()
        assert len(lessons) == 0

    def test_strategy_with_all_fields(self):
        """Test strategy with all fields populated."""
        entry = EntryPoint(
            path="/api/users/{id}",
            entry_type="http",
            parameters=["id"],
            risk_level="high",
        )

        bypass = BypassTechnique(
            name="test_bypass",
            description="Test bypass",
            applicable_scenarios=["test"],
            examples=["example1"],
        )

        chain = AttackChainTemplate(
            name="test_chain",
            steps=["step1", "step2"],
        )

        strategy = AttackStrategy(
            strategy_id="full_strategy",
            vulnerability_type="sql_injection",
            entry_point=entry,
            bypass_techniques=[bypass],
            attack_chain=chain,
            confidence=0.8,
            generation=3,
            parent_ids=["parent1", "parent2"],
            mutations=["mutation1"],
        )

        assert strategy.entry_point.path == "/api/users/{id}"
        assert len(strategy.bypass_techniques) == 1
        assert strategy.attack_chain.name == "test_chain"

    def test_convergence_with_no_progress(self):
        """Test convergence when there's no progress."""
        config = ConvergenceConfig(
            max_rounds=10,
            progress_window=2,
            min_progress_threshold=0.1,
        )
        checker = ConvergenceChecker(config=config)

        # Record rounds with no progress (same confidence)
        for i in range(5):
            verdict = AdversarialVerdict(
                verdict=VerdictType.NEEDS_REVIEW,
                confidence=0.5,  # Same confidence every round
                summary=f"Round {i+1}",
                reasoning="No progress",
                attacker_strength=0.5,
                defender_strength=0.5,
            )
            result = checker.record_round(verdict)

        # Should eventually converge due to no progress
        assert result.should_converge is True
        assert result.reason == ConvergenceReason.NO_PROGRESS

    def test_max_history_pruning(self):
        """Test that history is pruned when over limit."""
        library = StrategyLibrary(
            library_id="test",
            strategy_type=StrategyType.ATTACK,
            max_history=5,
        )

        # Add more records than limit
        for i in range(10):
            library.record_failure(
                strategy_id=f"test_{i}",
                attack_path=f"path_{i}",
                failure_reason=f"reason_{i}",
            )

        assert len(library.failure_records) <= library.max_history
