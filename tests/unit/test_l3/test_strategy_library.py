"""
Tests for the Adversarial Verification Strategy Library.

Phase 18 / P6-子项4: convergence/enhanced 死机械已删除，本文件只保留
``strategy_library`` 的真实攻防知识测试（该模块被子项5 接进基础版 prompt）。
覆盖：
- 绕过技巧 / 攻击链 / 攻防策略 数据模型与统计
- 策略库增删、按场景取用、剪枝
- 默认攻防知识库（create_attacker/defender_library）
"""

import pytest

from src.layers.l3_analysis.verification.strategy_library import (
    AttackChainTemplate,
    AttackStrategy,
    BypassTechnique,
    DefenseStrategy,
    EntryPoint,
    StrategyLibrary,
    StrategyType,
    create_attacker_library,
    create_defender_library,
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
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases (strategy library only)."""

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
