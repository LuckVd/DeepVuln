"""
Unit tests for Audit Strategy Engine.

Tests the priority calculator and strategy engine components.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.layers.l3_analysis.strategy.models import (
    AuditPriority,
    AuditPriorityLevel,
    AuditTarget,
    AuditStrategy,
    EngineAllocation,
    TargetGroup,
    PriorityScore,
)
from src.layers.l3_analysis.strategy.calculator import PriorityCalculator
from src.layers.l3_analysis.strategy.engine import StrategyEngine
from src.layers.l1_intelligence.attack_surface.models import (
    AttackSurfaceReport,
    EntryPoint,
    EntryPointType,
    HTTPMethod,
)


class TestAuditPriorityLevel:
    """Tests for AuditPriorityLevel enum."""

    def test_priority_levels_exist(self):
        """Test that all expected priority levels exist."""
        assert AuditPriorityLevel.CRITICAL.value == "critical"
        assert AuditPriorityLevel.HIGH.value == "high"
        assert AuditPriorityLevel.MEDIUM.value == "medium"
        assert AuditPriorityLevel.LOW.value == "low"
        assert AuditPriorityLevel.SKIP.value == "skip"


class TestAuditPriority:
    """Tests for AuditPriority model."""

    def test_default_init(self):
        """Test default initialization."""
        priority = AuditPriority(level=AuditPriorityLevel.MEDIUM)
        assert priority.level == AuditPriorityLevel.MEDIUM
        assert priority.attack_surface_score == 0.0
        assert priority.tech_risk_score == 0.0
        assert priority.complexity_score == 0.0
        assert priority.history_risk_score == 0.0
        assert priority.final_score == 0.0

    def test_custom_scores(self):
        """Test custom score values."""
        priority = AuditPriority(
            level=AuditPriorityLevel.HIGH,
            attack_surface_score=0.8,
            tech_risk_score=0.6,
            complexity_score=0.5,
            history_risk_score=0.4,
            final_score=0.65,
        )
        assert priority.attack_surface_score == 0.8
        assert priority.final_score == 0.65

    def test_to_level_critical(self):
        """Test score to level conversion for critical."""
        priority = AuditPriority(level=AuditPriorityLevel.MEDIUM)
        assert priority.to_level(0.85) == AuditPriorityLevel.CRITICAL
        assert priority.to_level(0.8) == AuditPriorityLevel.CRITICAL

    def test_to_level_high(self):
        """Test score to level conversion for high."""
        priority = AuditPriority(level=AuditPriorityLevel.MEDIUM)
        assert priority.to_level(0.6) == AuditPriorityLevel.HIGH
        assert priority.to_level(0.79) == AuditPriorityLevel.HIGH

    def test_to_level_medium(self):
        """Test score to level conversion for medium."""
        priority = AuditPriority(level=AuditPriorityLevel.MEDIUM)
        assert priority.to_level(0.4) == AuditPriorityLevel.MEDIUM
        assert priority.to_level(0.59) == AuditPriorityLevel.MEDIUM

    def test_to_level_low(self):
        """Test score to level conversion for low."""
        priority = AuditPriority(level=AuditPriorityLevel.MEDIUM)
        assert priority.to_level(0.2) == AuditPriorityLevel.LOW
        assert priority.to_level(0.39) == AuditPriorityLevel.LOW

    def test_to_level_skip(self):
        """Test score to level conversion for skip."""
        priority = AuditPriority(level=AuditPriorityLevel.MEDIUM)
        assert priority.to_level(0.0) == AuditPriorityLevel.SKIP
        assert priority.to_level(0.19) == AuditPriorityLevel.SKIP


class TestAuditTarget:
    """Tests for AuditTarget model."""

    def test_file_target(self):
        """Test creating a file target."""
        target = AuditTarget(
            id="file-001",
            name="main.py",
            target_type="file",
            file_path="src/main.py",
        )
        assert target.target_type == "file"
        assert target.file_path == "src/main.py"
        assert target.priority is None

    def test_entry_point_target(self):
        """Test creating an entry point target."""
        target = AuditTarget(
            id="entry-001",
            name="login_handler",
            target_type="entry_point",
            file_path="src/api/auth.py",
            entry_point_type="http",
            http_method="POST",
            endpoint_path="/api/login",
            auth_required=False,
        )
        assert target.target_type == "entry_point"
        assert target.http_method == "POST"
        assert target.auth_required is False

    def test_to_display_entry_point(self):
        """Test display for entry point target."""
        target = AuditTarget(
            id="entry-001",
            name="handler",
            target_type="entry_point",
            file_path="api.py",
            http_method="POST",
            endpoint_path="/api/users",
        )
        display = target.to_display()
        assert "POST" in display
        assert "/api/users" in display

    def test_to_display_file(self):
        """Test display for file target."""
        target = AuditTarget(
            id="file-001",
            name="main.py",
            target_type="file",
            file_path="src/main.py",
            function_name="main",
        )
        display = target.to_display()
        assert "main()" in display


class TestPriorityScore:
    """Tests for PriorityScore model."""

    def test_default_values(self):
        """Test default initialization."""
        score = PriorityScore()
        assert score.attack_surface == 0.0
        assert score.tech_risk == 0.0
        assert score.complexity == 0.0
        assert score.history_risk == 0.0

    def test_default_weights(self):
        """Test default weight values."""
        score = PriorityScore()
        assert score.attack_surface_weight == 0.35
        assert score.tech_risk_weight == 0.25
        assert score.complexity_weight == 0.20
        assert score.history_risk_weight == 0.20

    def test_calculate_weighted_score(self):
        """Test weighted score calculation."""
        score = PriorityScore(
            attack_surface=0.8,
            tech_risk=0.6,
            complexity=0.4,
            history_risk=0.2,
        )
        result = score.calculate_weighted_score()
        # 0.8*0.35 + 0.6*0.25 + 0.4*0.20 + 0.2*0.20 = 0.28 + 0.15 + 0.08 + 0.04 = 0.55
        assert 0.54 < result < 0.56

    def test_score_bounds(self):
        """Test score is bounded to 0.0-1.0."""
        score = PriorityScore(
            attack_surface=1.0,
            tech_risk=1.0,
            complexity=1.0,
            history_risk=1.0,
        )
        result = score.calculate_weighted_score()
        assert result == 1.0

    def test_to_level(self):
        """Test score to level conversion."""
        score = PriorityScore()
        assert score.to_level(0.85).value == "critical"
        assert score.to_level(0.65).value == "high"
        assert score.to_level(0.45).value == "medium"
        assert score.to_level(0.25).value == "low"
        assert score.to_level(0.1).value == "skip"


class TestEngineAllocation:
    """Tests for EngineAllocation model."""

    def test_default_init(self):
        """Test default initialization."""
        alloc = EngineAllocation(engine="semgrep")
        assert alloc.engine == "semgrep"
        assert alloc.concurrent == 1
        assert alloc.timeout_seconds == 300
        assert alloc.enabled is True

    def test_custom_init(self):
        """Test custom initialization."""
        alloc = EngineAllocation(
            engine="agent",
            concurrent=3,
            timeout_seconds=600,
            focus=["sql_injection", "xss"],
            priority=1,
            required=True,
        )
        assert alloc.concurrent == 3
        assert alloc.focus == ["sql_injection", "xss"]
        assert alloc.required is True


class TestTargetGroup:
    """Tests for TargetGroup model."""

    def test_empty_group(self):
        """Test empty group initialization."""
        group = TargetGroup(priority_level=AuditPriorityLevel.HIGH)
        assert group.target_count == 0
        assert group.total_lines_of_code == 0

    def test_with_targets(self):
        """Test group with targets."""
        targets = [
            AuditTarget(
                id="file-001",
                name="main.py",
                target_type="file",
                file_path="main.py",
                lines_of_code=100,
            ),
            AuditTarget(
                id="file-002",
                name="utils.py",
                target_type="file",
                file_path="utils.py",
                lines_of_code=50,
            ),
        ]
        group = TargetGroup(
            priority_level=AuditPriorityLevel.HIGH,
            targets=targets,
        )
        assert group.target_count == 2
        assert group.total_lines_of_code == 150


class TestAuditStrategy:
    """Tests for AuditStrategy model."""

    def test_default_init(self):
        """Test default initialization."""
        strategy = AuditStrategy(
            project_name="test-project",
            source_path="/path/to/project",
        )
        assert strategy.project_name == "test-project"
        assert strategy.total_targets == 0

    def test_with_targets(self):
        """Test strategy with targets."""
        targets = [
            AuditTarget(
                id="file-001",
                name="main.py",
                target_type="file",
                file_path="main.py",
                priority=AuditPriority(level=AuditPriorityLevel.HIGH),
            ),
            AuditTarget(
                id="file-002",
                name="utils.py",
                target_type="file",
                file_path="utils.py",
                priority=AuditPriority(level=AuditPriorityLevel.MEDIUM),
            ),
        ]
        strategy = AuditStrategy(
            project_name="test",
            source_path="/test",
            targets=targets,
            total_targets=2,
        )
        assert len(strategy.get_high_targets()) == 1
        assert len(strategy.get_targets_by_level(AuditPriorityLevel.MEDIUM)) == 1

    def test_get_sorted_targets(self):
        """Test target sorting by priority."""
        targets = [
            AuditTarget(
                id="low",
                name="low.py",
                target_type="file",
                file_path="low.py",
                priority=AuditPriority(level=AuditPriorityLevel.LOW),
            ),
            AuditTarget(
                id="critical",
                name="critical.py",
                target_type="file",
                file_path="critical.py",
                priority=AuditPriority(level=AuditPriorityLevel.CRITICAL),
            ),
            AuditTarget(
                id="high",
                name="high.py",
                target_type="file",
                file_path="high.py",
                priority=AuditPriority(level=AuditPriorityLevel.HIGH),
            ),
        ]
        strategy = AuditStrategy(
            project_name="test",
            source_path="/test",
            targets=targets,
            total_targets=3,
        )
        sorted_targets = strategy.get_sorted_targets()
        assert sorted_targets[0].id == "critical"
        assert sorted_targets[1].id == "high"
        assert sorted_targets[2].id == "low"

    def test_get_summary(self):
        """Test summary generation."""
        targets = [
            AuditTarget(
                id="1",
                name="a.py",
                target_type="file",
                file_path="a.py",
                priority=AuditPriority(level=AuditPriorityLevel.HIGH),
            ),
            AuditTarget(
                id="2",
                name="b.py",
                target_type="file",
                file_path="b.py",
                priority=AuditPriority(level=AuditPriorityLevel.MEDIUM),
            ),
        ]
        strategy = AuditStrategy(
            project_name="test-project",
            source_path="/test",
            targets=targets,
            total_targets=2,
        )
        summary = strategy.get_summary()
        assert summary["project"] == "test-project"
        assert summary["total_targets"] == 2
        assert summary["by_priority"]["high"] == 1
        assert summary["by_priority"]["medium"] == 1

    def test_to_yaml_config(self):
        """Test YAML config generation."""
        strategy = AuditStrategy(
            project_name="my-project",
            source_path="/path/to/project",
            total_targets=10,
            available_engines=["semgrep", "agent"],
        )
        yaml_config = strategy.to_yaml_config()
        assert "my-project" in yaml_config
        assert "priority_groups" in yaml_config


class TestPriorityCalculator:
    """Tests for PriorityCalculator."""

    @pytest.fixture
    def calculator(self):
        """Create a calculator instance."""
        return PriorityCalculator()

    def test_default_weights(self, calculator):
        """Test default weight configuration."""
        assert calculator.weights["attack_surface"] == 0.35
        assert calculator.weights["tech_risk"] == 0.25
        assert calculator.weights["complexity"] == 0.20
        assert calculator.weights["history_risk"] == 0.20

    def test_custom_weights(self):
        """Test custom weight configuration."""
        # Weights are normalized to sum to 1.0
        # DEFAULT_WEIGHTS are: attack_surface=0.35, tech_risk=0.25, complexity=0.20, history_risk=0.20
        # When we override with attack_surface=0.5, tech_risk=0.5, the total becomes:
        # 0.5 + 0.5 + 0.20 + 0.20 = 1.4
        # Normalized: attack_surface = 0.5/1.4 ≈ 0.357
        calculator = PriorityCalculator(weights={"attack_surface": 0.5, "tech_risk": 0.5})
        # Check that weights are normalized
        total = sum(calculator.weights.values())
        assert abs(total - 1.0) < 0.001  # Weights sum to 1.0
        assert calculator.weights["attack_surface"] > 0.35  # Increased from default

    def test_calculate_file_target(self, calculator):
        """Test calculating priority for a file target."""
        target = AuditTarget(
            id="file-001",
            name="main.py",
            target_type="file",
            file_path="src/main.py",
        )
        priority = calculator.calculate(target)
        assert priority is not None
        assert priority.level in AuditPriorityLevel

    def test_calculate_http_entry_point(self, calculator):
        """Test calculating priority for HTTP entry point."""
        target = AuditTarget(
            id="entry-001",
            name="login",
            target_type="entry_point",
            file_path="api/auth.py",
            entry_point_type="http",
            http_method="POST",
            endpoint_path="/api/login",
            auth_required=False,
            params=["username", "password"],
        )
        priority = calculator.calculate(target)
        # POST + no auth + many params should result in higher score
        assert priority.attack_surface_score > 0.3

    def test_calculate_high_risk_path(self, calculator):
        """Test priority for high-risk file path."""
        target = AuditTarget(
            id="file-001",
            name="auth.py",
            target_type="file",
            file_path="src/auth/login.py",
        )
        priority = calculator.calculate(target)
        # Contains 'auth' and 'login' - high risk patterns
        assert "High-risk pattern" in str(priority.factors) or priority.attack_surface_score > 0

    def test_skip_test_files(self, calculator):
        """Test that test files are marked as skip."""
        target = AuditTarget(
            id="file-001",
            name="test_main.py",
            target_type="file",
            file_path="tests/test_main.py",
        )
        priority = calculator.calculate(target)
        assert priority.level == AuditPriorityLevel.SKIP

    def test_skip_generated_files(self, calculator):
        """Test that generated files are marked as skip."""
        target = AuditTarget(
            id="file-001",
            name="bundle.min.js",
            target_type="file",
            file_path="static/bundle.min.js",
        )
        priority = calculator.calculate(target)
        assert priority.level == AuditPriorityLevel.SKIP

    def test_calculate_batch(self, calculator):
        """Test batch priority calculation."""
        targets = [
            AuditTarget(id="1", name="a.py", target_type="file", file_path="a.py"),
            AuditTarget(id="2", name="b.py", target_type="file", file_path="b.py"),
            AuditTarget(id="3", name="c.py", target_type="file", file_path="c.py"),
        ]
        result = calculator.calculate_batch(targets)
        assert len(result) == 3
        for t in result:
            assert t.priority is not None

    def test_get_priority_distribution(self, calculator):
        """Test priority distribution calculation."""
        targets = [
            AuditTarget(
                id="1", name="a.py", target_type="file", file_path="a.py",
                priority=AuditPriority(level=AuditPriorityLevel.HIGH),
            ),
            AuditTarget(
                id="2", name="b.py", target_type="file", file_path="b.py",
                priority=AuditPriority(level=AuditPriorityLevel.HIGH),
            ),
            AuditTarget(
                id="3", name="c.py", target_type="file", file_path="c.py",
                priority=AuditPriority(level=AuditPriorityLevel.LOW),
            ),
        ]
        distribution = calculator.get_priority_distribution(targets)
        assert distribution["high"] == 2
        assert distribution["low"] == 1


class TestStrategyEngine:
    """Tests for StrategyEngine."""

    @pytest.fixture
    def engine(self):
        """Create a strategy engine instance."""
        return StrategyEngine()

    def test_default_init(self, engine):
        """Test default initialization."""
        assert engine.calculator is not None
        assert "semgrep" in engine.available_engines
        assert "codeql" in engine.available_engines
        assert "agent" in engine.available_engines

    def test_create_strategy_empty(self, engine, tmp_path):
        """Test creating strategy for empty project."""
        strategy = engine.create_strategy(
            source_path=tmp_path,
            project_name="empty-project",
        )
        assert strategy.project_name == "empty-project"
        assert strategy.total_targets == 0

    def test_create_strategy_with_files(self, engine, tmp_path):
        """Test creating strategy with source files."""
        # Create some source files
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("def helper(): pass")

        strategy = engine.create_strategy(
            source_path=tmp_path,
            project_name="test-project",
        )
        assert strategy.project_name == "test-project"
        assert strategy.total_targets >= 2

    def test_create_strategy_with_attack_surface(self, engine, tmp_path):
        """Test creating strategy with attack surface data."""
        # Create attack surface report
        report = AttackSurfaceReport(source_path=str(tmp_path))
        report.add_entry_point(EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.POST,
            path="/api/login",
            handler="login_handler",
            file="api/auth.py",
            line=10,
            auth_required=False,
            params=["username", "password"],
        ))

        strategy = engine.create_strategy(
            source_path=tmp_path,
            attack_surface=report,
        )
        assert strategy.total_targets == 1

    def test_convert_entry_points(self, engine):
        """Test converting entry points to targets."""
        entry_points = [
            EntryPoint(
                type=EntryPointType.HTTP,
                method=HTTPMethod.GET,
                path="/api/users",
                handler="get_users",
                file="api/users.py",
                line=20,
                auth_required=True,
            ),
            EntryPoint(
                type=EntryPointType.RPC,
                path="UserService.GetUser",
                handler="get_user",
                file="rpc/users.go",
                line=15,
            ),
        ]

        targets = engine._convert_entry_points(entry_points)
        assert len(targets) == 2
        assert targets[0].http_method == "GET"
        assert targets[0].auth_required is True
        assert targets[1].entry_point_type == "rpc"

    def test_get_execution_order(self, engine, tmp_path):
        """Test getting execution order."""
        # Create targets with different priorities
        targets = [
            AuditTarget(
                id="1", name="a.py", target_type="file", file_path="a.py",
                priority=AuditPriority(level=AuditPriorityLevel.HIGH, final_score=0.7),
            ),
            AuditTarget(
                id="2", name="b.py", target_type="file", file_path="b.py",
                priority=AuditPriority(level=AuditPriorityLevel.CRITICAL, final_score=0.9),
            ),
            AuditTarget(
                id="3", name="c.py", target_type="file", file_path="c.py",
                priority=AuditPriority(level=AuditPriorityLevel.LOW, final_score=0.3),
            ),
        ]

        strategy = AuditStrategy(
            project_name="test",
            source_path=str(tmp_path),
            targets=targets,
            total_targets=3,
        )

        # Group targets
        strategy.groups = engine._group_targets(targets)

        order = engine.get_execution_order(strategy)
        assert len(order) == 3
        assert order[0][0] == "critical"
        assert order[1][0] == "high"
        assert order[2][0] == "low"

    def test_optimize_for_time(self, engine, tmp_path):
        """Test time-based optimization."""
        targets = [
            AuditTarget(
                id="1", name="a.py", target_type="file", file_path="a.py",
                priority=AuditPriority(level=AuditPriorityLevel.LOW),
            ),
        ]

        strategy = AuditStrategy(
            project_name="test",
            source_path=str(tmp_path),
            targets=targets,
            total_targets=1,
        )
        strategy.groups = engine._group_targets(targets)

        # Optimize with small budget
        optimized = engine.optimize_strategy(strategy, time_budget_seconds=10)

        # Low priority group should be affected
        assert optimized is not None

    def test_custom_available_engines(self):
        """Test with custom engine availability."""
        engine = StrategyEngine(available_engines=["semgrep"])
        assert "semgrep" in engine.available_engines
        assert "agent" not in engine.available_engines


class TestEngineAllocationDefaults:
    """Tests for default engine allocations."""

    def test_critical_has_all_engines(self):
        """Test that critical level has all engines."""
        engine = StrategyEngine()
        allocations = engine.engine_allocations[AuditPriorityLevel.CRITICAL]
        engine_names = [a.engine for a in allocations]
        assert "agent" in engine_names
        assert "semgrep" in engine_names
        assert "codeql" in engine_names

    def test_high_has_agent_and_semgrep(self):
        """Test that high level has agent and semgrep."""
        engine = StrategyEngine()
        allocations = engine.engine_allocations[AuditPriorityLevel.HIGH]
        engine_names = [a.engine for a in allocations]
        assert "agent" in engine_names
        assert "semgrep" in engine_names

    def test_medium_has_semgrep_and_codeql(self):
        """Test that medium level has semgrep and codeql."""
        engine = StrategyEngine()
        allocations = engine.engine_allocations[AuditPriorityLevel.MEDIUM]
        engine_names = [a.engine for a in allocations]
        assert "semgrep" in engine_names
        assert "codeql" in engine_names

    def test_low_has_only_semgrep(self):
        """Test that low level only has semgrep."""
        engine = StrategyEngine()
        allocations = engine.engine_allocations[AuditPriorityLevel.LOW]
        engine_names = [a.engine for a in allocations]
        assert "semgrep" in engine_names
        assert "agent" not in engine_names

    def test_skip_has_no_engines(self):
        """Test that skip level has no engines."""
        engine = StrategyEngine()
        allocations = engine.engine_allocations[AuditPriorityLevel.SKIP]
        assert len(allocations) == 0
