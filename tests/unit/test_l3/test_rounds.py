"""
Unit tests for Multi-Round Audit System.

Tests round models, controller, and executors.
"""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.layers.l3_analysis.models import (
    Finding,
    FindingType,
    SeverityLevel,
    CodeLocation,
)
from src.layers.l3_analysis.rounds.models import (
    AnalysisDepth,
    AuditSession,
    ConfidenceLevel,
    CoverageStats,
    EngineStats,
    RoundResult,
    RoundStatus,
    VulnerabilityCandidate,
)
from src.layers.l3_analysis.rounds.controller import RoundController
from src.layers.l3_analysis.rounds.round_one import RoundOneExecutor
from src.layers.l3_analysis.strategy.models import (
    AuditPriority,
    AuditPriorityLevel,
    AuditStrategy,
    AuditTarget,
)


class TestRoundStatus:
    """Tests for RoundStatus enum."""

    def test_statuses_exist(self):
        """Test that all expected statuses exist."""
        assert RoundStatus.PENDING.value == "pending"
        assert RoundStatus.RUNNING.value == "running"
        assert RoundStatus.COMPLETED.value == "completed"
        assert RoundStatus.FAILED.value == "failed"
        assert RoundStatus.SKIPPED.value == "skipped"


class TestConfidenceLevel:
    """Tests for ConfidenceLevel enum."""

    def test_levels_exist(self):
        """Test that all expected levels exist."""
        assert ConfidenceLevel.HIGH.value == "high"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.LOW.value == "low"


class TestAnalysisDepth:
    """Tests for AnalysisDepth enum."""

    def test_depths_exist(self):
        """Test that all expected depths exist."""
        assert AnalysisDepth.QUICK.value == "quick"
        assert AnalysisDepth.STANDARD.value == "standard"
        assert AnalysisDepth.DEEP.value == "deep"
        assert AnalysisDepth.EXHAUSTIVE.value == "exhaustive"


class TestVulnerabilityCandidate:
    """Tests for VulnerabilityCandidate model."""

    @pytest.fixture
    def sample_finding(self):
        """Create a sample finding."""
        return Finding(
            id="finding-001",
            severity=SeverityLevel.HIGH,
            title="SQL Injection",
            description="Potential SQL injection vulnerability",
            location=CodeLocation(file="test.py", line=10),
            source="semgrep",
        )

    def test_default_init(self, sample_finding):
        """Test default initialization."""
        candidate = VulnerabilityCandidate(
            id="candidate-001",
            finding=sample_finding,
            discovered_in_round=1,
        )
        assert candidate.id == "candidate-001"
        assert candidate.confidence == ConfidenceLevel.MEDIUM
        assert candidate.discovered_in_round == 1
        assert candidate.needs_deep_analysis is False

    def test_add_evidence(self, sample_finding):
        """Test adding evidence."""
        candidate = VulnerabilityCandidate(
            id="candidate-001",
            finding=sample_finding,
            discovered_in_round=1,
        )
        candidate.add_evidence("semgrep", {"rule": "sql-injection"})
        assert len(candidate.evidence) == 1
        assert candidate.evidence[0]["source"] == "semgrep"

    def test_mark_for_deep_analysis(self, sample_finding):
        """Test marking for deep analysis."""
        candidate = VulnerabilityCandidate(
            id="candidate-001",
            finding=sample_finding,
            discovered_in_round=1,
        )
        candidate.mark_for_deep_analysis()
        assert candidate.needs_deep_analysis is True

    def test_to_summary(self, sample_finding):
        """Test summary generation."""
        candidate = VulnerabilityCandidate(
            id="candidate-001",
            finding=sample_finding,
            discovered_in_round=1,
        )
        summary = candidate.to_summary()
        assert "MEDIUM" in summary
        assert "SQL Injection" in summary
        assert "Round 1" in summary


class TestCoverageStats:
    """Tests for CoverageStats model."""

    def test_default_init(self):
        """Test default initialization."""
        stats = CoverageStats()
        assert stats.total_files == 0
        assert stats.scanned_files == 0

    def test_coverage_percent(self):
        """Test coverage percentage calculation."""
        stats = CoverageStats(total_files=100, scanned_files=75)
        assert stats.file_coverage_percent == 75.0

    def test_zero_coverage(self):
        """Test zero coverage case."""
        stats = CoverageStats(total_files=0)
        assert stats.file_coverage_percent == 0.0


class TestEngineStats:
    """Tests for EngineStats model."""

    def test_default_init(self):
        """Test default initialization."""
        stats = EngineStats(engine="semgrep")
        assert stats.engine == "semgrep"
        assert stats.enabled is True
        assert stats.executed is False

    def test_add_error(self):
        """Test adding error."""
        stats = EngineStats(engine="semgrep")
        stats.add_error("Test error")
        assert len(stats.errors) == 1
        assert "Test error" in stats.errors[0]

    def test_add_warning(self):
        """Test adding warning."""
        stats = EngineStats(engine="semgrep")
        stats.add_warning("Test warning")
        assert len(stats.warnings) == 1


class TestRoundResult:
    """Tests for RoundResult model."""

    @pytest.fixture
    def sample_candidate(self):
        """Create a sample candidate."""
        finding = Finding(
            id="finding-001",
            severity=SeverityLevel.HIGH,
            title="SQL Injection",
            description="Test",
            location=CodeLocation(file="test.py", line=10),
            source="semgrep",
        )
        return VulnerabilityCandidate(
            id="candidate-001",
            finding=finding,
            confidence=ConfidenceLevel.HIGH,
            discovered_in_round=1,
        )

    def test_default_init(self):
        """Test default initialization."""
        result = RoundResult(round_number=1)
        assert result.round_number == 1
        assert result.status == RoundStatus.PENDING
        assert result.total_candidates == 0

    def test_add_candidate(self, sample_candidate):
        """Test adding candidate."""
        result = RoundResult(round_number=1)
        result.add_candidate(sample_candidate)
        assert result.total_candidates == 1
        assert result.high_confidence_count == 1

    def test_get_candidates_by_severity(self, sample_candidate):
        """Test filtering by severity."""
        result = RoundResult(round_number=1)
        result.add_candidate(sample_candidate)

        high_sev = result.get_candidates_by_severity([SeverityLevel.HIGH])
        assert len(high_sev) == 1

        low_sev = result.get_candidates_by_severity([SeverityLevel.LOW])
        assert len(low_sev) == 0

    def test_get_candidates_needing_deep_analysis(self, sample_candidate):
        """Test getting candidates needing deep analysis."""
        sample_candidate.needs_deep_analysis = True
        result = RoundResult(round_number=1)
        result.add_candidate(sample_candidate)

        needs_deep = result.get_candidates_needing_deep_analysis()
        assert len(needs_deep) == 1

    def test_mark_completed(self):
        """Test marking round completed."""
        result = RoundResult(
            round_number=1,
            status=RoundStatus.RUNNING,
            started_at=datetime.now(UTC),
        )
        result.mark_completed()
        assert result.status == RoundStatus.COMPLETED
        assert result.completed_at is not None

    def test_mark_failed(self):
        """Test marking round failed."""
        result = RoundResult(
            round_number=1,
            status=RoundStatus.RUNNING,
            started_at=datetime.now(UTC),
        )
        result.mark_failed("Test error")
        assert result.status == RoundStatus.FAILED
        assert "Test error" in result.errors

    def test_to_summary(self, sample_candidate):
        """Test summary generation."""
        result = RoundResult(round_number=1)
        result.add_candidate(sample_candidate)
        summary = result.to_summary()
        assert "Round 1" in summary
        assert "Candidates: 1" in summary


class TestAuditSession:
    """Tests for AuditSession model."""

    def test_default_init(self):
        """Test default initialization."""
        session = AuditSession(
            id="session-001",
            project_name="test-project",
            source_path="/path/to/code",
        )
        assert session.id == "session-001"
        assert session.current_round == 0
        assert session.max_rounds == 3

    def test_add_round(self):
        """Test adding round result."""
        session = AuditSession(
            id="session-001",
            project_name="test-project",
            source_path="/path/to/code",
        )
        round_result = RoundResult(round_number=1)
        session.add_round(round_result)

        assert session.current_round == 1
        assert len(session.rounds) == 1

    def test_get_current_round(self):
        """Test getting current round."""
        session = AuditSession(
            id="session-001",
            project_name="test-project",
            source_path="/path/to/code",
        )
        assert session.get_current_round() is None

        round_result = RoundResult(round_number=1)
        session.add_round(round_result)
        assert session.get_current_round() == round_result

    def test_should_continue(self):
        """Test continuation logic."""
        session = AuditSession(
            id="session-001",
            project_name="test-project",
            source_path="/path/to/code",
            max_rounds=3,
        )
        assert session.should_continue() is False  # No rounds yet

        round_result = RoundResult(
            round_number=1,
            next_round_candidates=["candidate-001"],
        )
        session.add_round(round_result)
        assert session.should_continue() is True

    def test_get_statistics(self):
        """Test statistics generation."""
        session = AuditSession(
            id="session-001",
            project_name="test-project",
            source_path="/path/to/code",
        )
        stats = session.get_statistics()
        assert stats["session_id"] == "session-001"
        assert stats["project_name"] == "test-project"

    def test_mark_completed(self):
        """Test marking session completed."""
        session = AuditSession(
            id="session-001",
            project_name="test-project",
            source_path="/path/to/code",
            started_at=datetime.now(UTC),
        )
        session.mark_completed()
        assert session.status == RoundStatus.COMPLETED
        assert session.completed_at is not None

    def test_to_summary(self):
        """Test summary generation."""
        session = AuditSession(
            id="session-001",
            project_name="test-project",
            source_path="/path/to/code",
        )
        summary = session.to_summary()
        assert "test-project" in summary
        assert "Rounds:" in summary


class TestRoundController:
    """Tests for RoundController."""

    @pytest.fixture
    def controller(self):
        """Create a controller instance."""
        return RoundController(max_rounds=3)

    @pytest.fixture
    def sample_strategy(self, tmp_path):
        """Create a sample strategy."""
        target = AuditTarget(
            id="target-001",
            name="test.py",
            target_type="file",
            file_path="test.py",
            priority=AuditPriority(level=AuditPriorityLevel.HIGH),
        )
        return AuditStrategy(
            project_name="test-project",
            source_path=str(tmp_path),
            targets=[target],
            total_targets=1,
        )

    def test_default_init(self, controller):
        """Test default initialization."""
        assert controller.max_rounds == 3
        assert controller.current_round == 0
        assert controller.session is None

    def test_start_session(self, controller, sample_strategy, tmp_path):
        """Test starting a session."""
        session = controller.start_session(
            source_path=tmp_path,
            strategy=sample_strategy,
        )
        assert session is not None
        assert session.project_name == tmp_path.name
        assert controller.session == session

    @pytest.mark.asyncio
    async def test_execute_round(self, controller, sample_strategy, tmp_path):
        """Test executing a round."""
        controller.start_session(
            source_path=tmp_path,
            strategy=sample_strategy,
        )

        async def mock_executor(strategy, prev_round):
            return RoundResult(
                round_number=1,
                status=RoundStatus.COMPLETED,
            )

        result = await controller.execute_round(mock_executor)
        assert result.round_number == 1
        assert controller.current_round == 1

    def test_get_statistics(self, controller):
        """Test getting statistics."""
        stats = controller.get_statistics()
        assert stats["status"] == "no_session"

    def test_reset(self, controller, sample_strategy, tmp_path):
        """Test resetting controller."""
        controller.start_session(
            source_path=tmp_path,
            strategy=sample_strategy,
        )
        controller.reset()
        assert controller.session is None


class TestRoundOneExecutor:
    """Tests for RoundOneExecutor."""

    @pytest.fixture
    def executor(self, tmp_path):
        """Create an executor instance."""
        return RoundOneExecutor(source_path=tmp_path)

    @pytest.fixture
    def sample_strategy(self, tmp_path):
        """Create a sample strategy."""
        target = AuditTarget(
            id="target-001",
            name="test.py",
            target_type="entry_point",
            file_path="test.py",
            priority=AuditPriority(level=AuditPriorityLevel.HIGH),
        )
        return AuditStrategy(
            project_name="test-project",
            source_path=str(tmp_path),
            targets=[target],
            total_targets=1,
        )

    def test_default_init(self, executor):
        """Test default initialization."""
        assert executor.source_path is not None

    @pytest.mark.asyncio
    async def test_execute_without_engines(self, executor, sample_strategy):
        """Test execution without engines configured."""
        result = await executor.execute(sample_strategy)

        assert result.round_number == 1
        assert result.status == RoundStatus.COMPLETED
        # Should have completed even without engines
        assert "semgrep" in result.engine_stats
        assert "agent" in result.engine_stats

    @pytest.mark.asyncio
    async def test_execute_with_mock_semgrep(self, executor, sample_strategy):
        """Test execution with mocked Semgrep."""
        mock_semgrep = MagicMock()
        mock_scan_result = MagicMock()
        mock_scan_result.findings = []
        mock_scan_result.duration_seconds = 1.0
        mock_scan_result.metadata = {}

        mock_semgrep.scan = AsyncMock(return_value=mock_scan_result)
        executor._semgrep_engine = mock_semgrep

        result = await executor.execute(sample_strategy)

        assert result.status == RoundStatus.COMPLETED
        assert result.engine_stats["semgrep"].executed is True


class TestIntegration:
    """Integration tests for round system."""

    def test_controller_with_executor(self, tmp_path):
        """Test controller with executor integration."""
        controller = RoundController(max_rounds=2)
        strategy = AuditStrategy(
            project_name="test-project",
            source_path=str(tmp_path),
            targets=[],
            total_targets=0,
        )

        session = controller.start_session(
            source_path=tmp_path,
            strategy=strategy,
        )
        assert session is not None

    @pytest.mark.asyncio
    async def test_full_round_one_flow(self, tmp_path):
        """Test complete round one flow."""
        # Create a test file
        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): print('hello')")

        # Create strategy
        target = AuditTarget(
            id="target-001",
            name="test.py",
            target_type="file",
            file_path="test.py",
            priority=AuditPriority(level=AuditPriorityLevel.HIGH),
        )
        strategy = AuditStrategy(
            project_name="test-project",
            source_path=str(tmp_path),
            targets=[target],
            total_targets=1,
        )

        # Execute round one
        executor = RoundOneExecutor(source_path=tmp_path)
        result = await executor.execute(strategy)

        assert result.round_number == 1
        assert result.status in (RoundStatus.COMPLETED, RoundStatus.FAILED)
        assert result.coverage is not None
