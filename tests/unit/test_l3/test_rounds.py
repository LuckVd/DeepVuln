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
from src.layers.l3_analysis.rounds.round_two import RoundTwoExecutor
from src.layers.l3_analysis.rounds.dataflow import (
    DataFlowPath,
    DeepAnalysisResult,
    PathNode,
    Sanitizer,
    SanitizerType,
    SinkType,
    SourceType,
    TaintSink,
    TaintSource,
)
from src.layers.l3_analysis.rounds.correlation import (
    CorrelationResult,
    CorrelationRule,
    Evidence,
    EvidenceChain,
    EvidenceSource,
    EvidenceType,
    VerificationStatus,
)
from src.layers.l3_analysis.rounds.round_three import RoundThreeExecutor
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


class TestSourceType:
    """Tests for SourceType enum."""

    def test_types_exist(self):
        """Test that all expected source types exist."""
        assert SourceType.HTTP_PARAM.value == "http_param"
        assert SourceType.HTTP_HEADER.value == "http_header"
        assert SourceType.HTTP_BODY.value == "http_body"
        assert SourceType.USER_INPUT.value == "user_input"


class TestSinkType:
    """Tests for SinkType enum."""

    def test_types_exist(self):
        """Test that all expected sink types exist."""
        assert SinkType.SQL_QUERY.value == "sql_query"
        assert SinkType.COMMAND_EXEC.value == "command_exec"
        assert SinkType.HTTP_RESPONSE.value == "http_response"


class TestSanitizerType:
    """Tests for SanitizerType enum."""

    def test_types_exist(self):
        """Test that all expected sanitizer types exist."""
        assert SanitizerType.SQL_ESCAPE.value == "sql_escape"
        assert SanitizerType.HTML_ENCODE.value == "html_encode"
        assert SanitizerType.PREPARED_STMT.value == "prepared_stmt"


class TestTaintSource:
    """Tests for TaintSource model."""

    @pytest.fixture
    def sample_location(self):
        """Create a sample code location."""
        return CodeLocation(file="test.py", line=10, function="get_input")

    def test_default_init(self, sample_location):
        """Test default initialization."""
        source = TaintSource(
            id="source-001",
            location=sample_location,
            source_type=SourceType.HTTP_PARAM,
        )
        assert source.id == "source-001"
        assert source.source_type == SourceType.HTTP_PARAM
        assert source.user_controlled is True

    def test_to_prompt_context(self, sample_location):
        """Test prompt context generation."""
        source = TaintSource(
            id="source-001",
            location=sample_location,
            source_type=SourceType.HTTP_PARAM,
            variable_name="user_input",
            parameter_name="id",
        )
        context = source.to_prompt_context()
        assert "http_param" in context
        assert "user_input" in context
        assert "id" in context


class TestTaintSink:
    """Tests for TaintSink model."""

    @pytest.fixture
    def sample_location(self):
        """Create a sample code location."""
        return CodeLocation(file="db.py", line=50, function="execute_query")

    def test_default_init(self, sample_location):
        """Test default initialization."""
        sink = TaintSink(
            id="sink-001",
            location=sample_location,
            sink_type=SinkType.SQL_QUERY,
        )
        assert sink.id == "sink-001"
        assert sink.sink_type == SinkType.SQL_QUERY
        assert sink.dangerous_if_tainted is True

    def test_to_prompt_context(self, sample_location):
        """Test prompt context generation."""
        sink = TaintSink(
            id="sink-001",
            location=sample_location,
            sink_type=SinkType.SQL_QUERY,
            function_name="execute",
            vulnerability_class=["SQL Injection"],
        )
        context = sink.to_prompt_context()
        assert "sql_query" in context
        assert "execute" in context
        assert "SQL Injection" in context


class TestSanitizer:
    """Tests for Sanitizer model."""

    @pytest.fixture
    def sample_location(self):
        """Create a sample code location."""
        return CodeLocation(file="utils.py", line=20)

    def test_default_init(self, sample_location):
        """Test default initialization."""
        sanitizer = Sanitizer(
            id="sanitizer-001",
            location=sample_location,
            sanitizer_type=SanitizerType.PREPARED_STMT,
        )
        assert sanitizer.id == "sanitizer-001"
        assert sanitizer.sanitizer_type == SanitizerType.PREPARED_STMT
        assert sanitizer.effective is True


class TestPathNode:
    """Tests for PathNode model."""

    @pytest.fixture
    def sample_location(self):
        """Create a sample code location."""
        return CodeLocation(file="flow.py", line=30, function="process")

    def test_default_init(self, sample_location):
        """Test default initialization."""
        node = PathNode(
            location=sample_location,
            node_type="propagation",
            variable_name="data",
        )
        assert node.node_type == "propagation"
        assert node.variable_name == "data"
        assert node.is_interprocedural is False


class TestDataFlowPath:
    """Tests for DataFlowPath model."""

    @pytest.fixture
    def sample_source(self):
        """Create a sample source."""
        return TaintSource(
            id="source-001",
            location=CodeLocation(file="input.py", line=10),
            source_type=SourceType.HTTP_PARAM,
            variable_name="user_id",
        )

    @pytest.fixture
    def sample_sink(self):
        """Create a sample sink."""
        return TaintSink(
            id="sink-001",
            location=CodeLocation(file="db.py", line=50),
            sink_type=SinkType.SQL_QUERY,
            function_name="execute",
        )

    def test_default_init(self, sample_source, sample_sink):
        """Test default initialization."""
        path = DataFlowPath(
            id="path-001",
            source=sample_source,
            sink=sample_sink,
        )
        assert path.id == "path-001"
        assert path.source == sample_source
        assert path.sink == sample_sink
        assert path.is_complete is False
        assert path.path_length == 0

    def test_add_node(self, sample_source, sample_sink):
        """Test adding a node."""
        path = DataFlowPath(
            id="path-001",
            source=sample_source,
            sink=sample_sink,
        )
        node = PathNode(
            location=CodeLocation(file="flow.py", line=30),
            node_type="propagation",
        )
        path.add_node(node)
        assert path.path_length == 1
        assert node in path.path_nodes

    def test_add_interprocedural_node(self, sample_source, sample_sink):
        """Test adding an interprocedural node."""
        path = DataFlowPath(
            id="path-001",
            source=sample_source,
            sink=sample_sink,
        )
        node = PathNode(
            location=CodeLocation(file="flow.py", line=30),
            node_type="propagation",
            is_interprocedural=True,
        )
        path.add_node(node)
        assert path.is_interprocedural is True

    def test_add_sanitizer(self, sample_source, sample_sink):
        """Test adding a sanitizer."""
        path = DataFlowPath(
            id="path-001",
            source=sample_source,
            sink=sample_sink,
        )
        sanitizer = Sanitizer(
            id="san-001",
            location=CodeLocation(file="sanitize.py", line=15),
            sanitizer_type=SanitizerType.PREPARED_STMT,
            effective=True,
        )
        path.add_sanitizer(sanitizer)
        assert len(path.sanitizers) == 1
        assert path.has_effective_sanitizer is True

    def test_get_summary(self, sample_source, sample_sink):
        """Test summary generation."""
        path = DataFlowPath(
            id="path-001",
            source=sample_source,
            sink=sample_sink,
        )
        summary = path.get_summary()
        assert "http_param" in summary
        assert "sql_query" in summary

    def test_to_prompt_context(self, sample_source, sample_sink):
        """Test prompt context generation."""
        path = DataFlowPath(
            id="path-001",
            source=sample_source,
            sink=sample_sink,
            is_complete=True,
            path_confidence=0.9,
        )
        context = path.to_prompt_context()
        assert "Data Flow Path" in context
        assert "Source" in context
        assert "Sink" in context


class TestDeepAnalysisResult:
    """Tests for DeepAnalysisResult model."""

    def test_default_init(self):
        """Test default initialization."""
        result = DeepAnalysisResult(
            id="deep-001",
            candidate_id="candidate-001",
        )
        assert result.id == "deep-001"
        assert result.candidate_id == "candidate-001"
        assert result.confirmed_vulnerability is False
        assert result.false_positive is False

    def test_add_dataflow_path(self):
        """Test adding a dataflow path."""
        result = DeepAnalysisResult(
            id="deep-001",
            candidate_id="candidate-001",
        )
        source = TaintSource(
            id="source-001",
            location=CodeLocation(file="test.py", line=10),
            source_type=SourceType.HTTP_PARAM,
        )
        sink = TaintSink(
            id="sink-001",
            location=CodeLocation(file="test.py", line=20),
            sink_type=SinkType.SQL_QUERY,
        )
        path = DataFlowPath(
            id="path-001",
            source=source,
            sink=sink,
            is_complete=True,
        )
        result.add_dataflow_path(path)
        assert len(result.dataflow_paths) == 1
        assert result.complete_paths == 1

    def test_mark_confirmed(self):
        """Test marking as confirmed."""
        result = DeepAnalysisResult(
            id="deep-001",
            candidate_id="candidate-001",
        )
        result.mark_confirmed("Complete data flow path found")
        assert result.confirmed_vulnerability is True
        assert result.false_positive is False
        assert result.updated_confidence == "high"

    def test_mark_false_positive(self):
        """Test marking as false positive."""
        result = DeepAnalysisResult(
            id="deep-001",
            candidate_id="candidate-001",
        )
        result.mark_false_positive("Input is properly sanitized")
        assert result.false_positive is True
        assert result.confirmed_vulnerability is False
        assert result.updated_confidence == "low"

    def test_get_summary(self):
        """Test summary generation."""
        result = DeepAnalysisResult(
            id="deep-001",
            candidate_id="candidate-001",
        )
        summary = result.get_summary()
        assert "Needs Review" in summary

        result.mark_confirmed("Test")
        summary = result.get_summary()
        assert "Confirmed" in summary

    def test_to_prompt_context(self):
        """Test prompt context generation."""
        result = DeepAnalysisResult(
            id="deep-001",
            candidate_id="candidate-001",
            original_confidence="medium",
            updated_confidence="high",
        )
        context = result.to_prompt_context()
        assert "candidate-001" in context
        assert "medium" in context
        assert "high" in context


class TestRoundTwoExecutor:
    """Tests for RoundTwoExecutor."""

    @pytest.fixture
    def executor(self, tmp_path):
        """Create an executor instance."""
        return RoundTwoExecutor(source_path=tmp_path)

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

    @pytest.fixture
    def sample_previous_round(self):
        """Create a sample previous round result with candidates."""
        finding = Finding(
            id="finding-001",
            severity=SeverityLevel.HIGH,
            title="SQL Injection",
            description="Test SQL injection",
            location=CodeLocation(file="test.py", line=10, function="get_user"),
            source="semgrep",
            tags=["sql", "injection"],
        )
        candidate = VulnerabilityCandidate(
            id="candidate-001",
            finding=finding,
            confidence=ConfidenceLevel.MEDIUM,
            discovered_in_round=1,
        )
        round_result = RoundResult(
            round_number=1,
            status=RoundStatus.COMPLETED,
        )
        round_result.add_candidate(candidate)
        return round_result

    def test_default_init(self, executor):
        """Test default initialization."""
        assert executor.source_path is not None
        assert executor._codeql_engine is None
        assert executor._agent_executor is None

    @pytest.mark.asyncio
    async def test_execute_without_previous_round(self, executor, sample_strategy):
        """Test execution without previous round."""
        result = await executor.execute(sample_strategy, previous_round=None)
        assert result.round_number == 2
        assert result.status == RoundStatus.COMPLETED
        assert result.total_candidates == 0

    @pytest.mark.asyncio
    async def test_execute_without_candidates(self, executor, sample_strategy):
        """Test execution without candidates in previous round."""
        previous = RoundResult(round_number=1, status=RoundStatus.COMPLETED)
        result = await executor.execute(sample_strategy, previous_round=previous)
        assert result.round_number == 2
        assert result.status == RoundStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_execute_with_candidates(self, executor, sample_strategy, sample_previous_round):
        """Test execution with candidates."""
        result = await executor.execute(sample_strategy, previous_round=sample_previous_round)
        assert result.round_number == 2
        assert result.status == RoundStatus.COMPLETED
        assert "codeql" in result.engine_stats
        assert "agent" in result.engine_stats

    @pytest.mark.asyncio
    async def test_execute_with_agent_executor(self, executor, sample_strategy, sample_previous_round):
        """Test execution with agent executor."""
        async def mock_agent(context):
            return {
                "confirmed": True,
                "false_positive": False,
                "tokens_used": 100,
            }

        executor._agent_executor = mock_agent
        result = await executor.execute(sample_strategy, previous_round=sample_previous_round)
        assert result.status == RoundStatus.COMPLETED
        assert result.engine_stats["agent"].executed is True

    def test_infer_source_type(self, executor):
        """Test source type inference."""
        finding = Finding(
            id="test",
            severity=SeverityLevel.HIGH,
            title="SQL Injection",
            description="Test",
            location=CodeLocation(file="test.py", line=10),
            source="semgrep",
            tags=["sqli"],
        )
        source_type = executor._infer_source_type(finding)
        assert source_type == SourceType.HTTP_PARAM

    def test_infer_sink_type(self, executor):
        """Test sink type inference."""
        finding = Finding(
            id="test",
            severity=SeverityLevel.HIGH,
            title="SQL Injection",
            description="Test",
            location=CodeLocation(file="test.py", line=10),
            source="semgrep",
            tags=["sqli"],
        )
        sink_type = executor._infer_sink_type(finding)
        assert sink_type == SinkType.SQL_QUERY


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


class TestVerificationStatus:
    """Tests for VerificationStatus enum."""

    def test_statuses_exist(self):
        """Test that all expected statuses exist."""
        assert VerificationStatus.CONFIRMED.value == "confirmed"
        assert VerificationStatus.LIKELY.value == "likely"
        assert VerificationStatus.UNCERTAIN.value == "uncertain"
        assert VerificationStatus.FALSE_POSITIVE.value == "false_positive"
        assert VerificationStatus.NOT_EXPLOITABLE.value == "not_exploitable"


class TestEvidenceSource:
    """Tests for EvidenceSource enum."""

    def test_sources_exist(self):
        """Test that all expected sources exist."""
        assert EvidenceSource.SEMGREP.value == "semgrep"
        assert EvidenceSource.CODEQL.value == "codeql"
        assert EvidenceSource.AGENT.value == "agent"


class TestEvidence:
    """Tests for Evidence model."""

    @pytest.fixture
    def sample_location(self):
        """Create a sample code location."""
        return CodeLocation(file="test.py", line=10, function="get_input")

    def test_default_init(self, sample_location):
        """Test default initialization."""
        evidence = Evidence(
            id="ev-001",
            source=EvidenceSource.SEMGREP,
            evidence_type=EvidenceType.PATTERN_MATCH,
            location=sample_location,
        )
        assert evidence.id == "ev-001"
        assert evidence.source == EvidenceSource.SEMGREP
        assert evidence.confidence == 0.5

    def test_to_summary(self, sample_location):
        """Test summary generation."""
        evidence = Evidence(
            id="ev-001",
            source=EvidenceSource.SEMGREP,
            evidence_type=EvidenceType.PATTERN_MATCH,
            confidence=0.8,
        )
        summary = evidence.to_summary()
        assert "semgrep" in summary
        assert "80%" in summary


class TestEvidenceChain:
    """Tests for EvidenceChain model."""

    def test_default_init(self):
        """Test default initialization."""
        chain = EvidenceChain(
            id="chain-001",
            candidate_id="candidate-001",
        )
        assert chain.id == "chain-001"
        assert chain.candidate_id == "candidate-001"
        assert len(chain.evidences) == 0
        assert chain.total_confidence == 0.0

    def test_add_evidence(self):
        """Test adding evidence."""
        chain = EvidenceChain(
            id="chain-001",
            candidate_id="candidate-001",
        )
        evidence = Evidence(
            id="ev-001",
            source=EvidenceSource.SEMGREP,
            evidence_type=EvidenceType.PATTERN_MATCH,
            confidence=0.8,
        )
        chain.add_evidence(evidence)
        assert len(chain.evidences) == 1
        assert EvidenceSource.SEMGREP in chain.sources
        assert chain.total_confidence == 0.8

    def test_multiple_evidence_confidence(self):
        """Test confidence with multiple evidence."""
        chain = EvidenceChain(
            id="chain-001",
            candidate_id="candidate-001",
        )
        chain.add_evidence(Evidence(
            id="ev-001",
            source=EvidenceSource.SEMGREP,
            evidence_type=EvidenceType.PATTERN_MATCH,
            confidence=0.6,
            weight=1.0,
        ))
        chain.add_evidence(Evidence(
            id="ev-002",
            source=EvidenceSource.CODEQL,
            evidence_type=EvidenceType.DATAFLOW_PATH,
            confidence=0.8,
            weight=2.0,
        ))
        assert len(chain.evidences) == 2
        assert chain.source_count == 2
        # Weighted: (0.6 * 1 + 0.8 * 2) / 3 = 0.733
        assert abs(chain.weighted_confidence - 0.733) < 0.01

    def test_get_evidence_by_source(self):
        """Test filtering evidence by source."""
        chain = EvidenceChain(
            id="chain-001",
            candidate_id="candidate-001",
        )
        chain.add_evidence(Evidence(
            id="ev-001",
            source=EvidenceSource.SEMGREP,
            evidence_type=EvidenceType.PATTERN_MATCH,
        ))
        chain.add_evidence(Evidence(
            id="ev-002",
            source=EvidenceSource.CODEQL,
            evidence_type=EvidenceType.DATAFLOW_PATH,
        ))
        semgrep_evidence = chain.get_evidence_by_source(EvidenceSource.SEMGREP)
        assert len(semgrep_evidence) == 1

    def test_check_consistency(self):
        """Test consistency checking."""
        chain = EvidenceChain(
            id="chain-001",
            candidate_id="candidate-001",
        )
        chain.add_evidence(Evidence(
            id="ev-001",
            source=EvidenceSource.SEMGREP,
            evidence_type=EvidenceType.PATTERN_MATCH,
            confidence=0.9,
        ))
        chain.add_evidence(Evidence(
            id="ev-002",
            source=EvidenceSource.AGENT,
            evidence_type=EvidenceType.AGENT_ANALYSIS,
            confidence=0.9,
            metadata={"is_false_positive": True},
        ))
        chain.check_consistency()
        assert chain.consistent is False
        assert len(chain.conflicts) > 0

    def test_get_summary(self):
        """Test summary generation."""
        chain = EvidenceChain(
            id="chain-001",
            candidate_id="candidate-001",
            verification_status=VerificationStatus.CONFIRMED,
        )
        chain.add_evidence(Evidence(
            id="ev-001",
            source=EvidenceSource.SEMGREP,
            evidence_type=EvidenceType.PATTERN_MATCH,
            confidence=0.8,
        ))
        summary = chain.get_summary()
        assert "confirmed" in summary
        assert "semgrep" in summary


class TestCorrelationRule:
    """Tests for CorrelationRule model."""

    def test_default_init(self):
        """Test default initialization."""
        rule = CorrelationRule(
            id="rule-001",
            name="Test Rule",
        )
        assert rule.id == "rule-001"
        assert rule.name == "Test Rule"
        assert rule.min_sources == 1

    def test_matches_min_sources(self):
        """Test rule matching with minimum sources."""
        rule = CorrelationRule(
            id="rule-001",
            name="Multi-Source",
            min_sources=2,
        )
        chain = EvidenceChain(
            id="chain-001",
            candidate_id="candidate-001",
        )
        chain.add_evidence(Evidence(
            id="ev-001",
            source=EvidenceSource.SEMGREP,
            evidence_type=EvidenceType.PATTERN_MATCH,
        ))
        assert rule.matches(chain) is False

        chain.add_evidence(Evidence(
            id="ev-002",
            source=EvidenceSource.CODEQL,
            evidence_type=EvidenceType.DATAFLOW_PATH,
        ))
        assert rule.matches(chain) is True

    def test_matches_required_sources(self):
        """Test rule matching with required sources."""
        rule = CorrelationRule(
            id="rule-001",
            name="CodeQL Required",
            required_sources=[EvidenceSource.CODEQL],
        )
        chain = EvidenceChain(
            id="chain-001",
            candidate_id="candidate-001",
        )
        chain.add_evidence(Evidence(
            id="ev-001",
            source=EvidenceSource.SEMGREP,
            evidence_type=EvidenceType.PATTERN_MATCH,
        ))
        assert rule.matches(chain) is False

        chain.add_evidence(Evidence(
            id="ev-002",
            source=EvidenceSource.CODEQL,
            evidence_type=EvidenceType.DATAFLOW_PATH,
        ))
        assert rule.matches(chain) is True


class TestCorrelationResult:
    """Tests for CorrelationResult model."""

    @pytest.fixture
    def sample_chain(self):
        """Create a sample evidence chain."""
        chain = EvidenceChain(
            id="chain-001",
            candidate_id="candidate-001",
        )
        chain.add_evidence(Evidence(
            id="ev-001",
            source=EvidenceSource.SEMGREP,
            evidence_type=EvidenceType.PATTERN_MATCH,
            confidence=0.8,
        ))
        return chain

    def test_default_init(self, sample_chain):
        """Test default initialization."""
        result = CorrelationResult(
            id="corr-001",
            candidate_id="candidate-001",
            evidence_chain=sample_chain,
        )
        assert result.id == "corr-001"
        assert result.correlated is False
        assert result.verification_status == VerificationStatus.UNCERTAIN

    def test_add_matched_rule(self, sample_chain):
        """Test adding matched rule."""
        result = CorrelationResult(
            id="corr-001",
            candidate_id="candidate-001",
            evidence_chain=sample_chain,
        )
        rule = CorrelationRule(
            id="rule-001",
            name="Test Rule",
            confidence_boost=0.2,
            if_matched=VerificationStatus.LIKELY,
        )
        result.add_matched_rule(rule)
        assert "rule-001" in result.matched_rules
        assert result.final_confidence == 0.2
        assert result.verification_status == VerificationStatus.LIKELY

    def test_set_verdict(self, sample_chain):
        """Test setting verdict."""
        result = CorrelationResult(
            id="corr-001",
            candidate_id="candidate-001",
            evidence_chain=sample_chain,
        )
        result.set_verdict(
            VerificationStatus.CONFIRMED,
            "Confirmed vulnerability",
            ["Multi-source confirmation"],
        )
        assert result.verification_status == VerificationStatus.CONFIRMED
        assert result.verdict == "Confirmed vulnerability"
        assert "Multi-source confirmation" in result.verdict_reasons

    def test_mark_for_review(self, sample_chain):
        """Test marking for review."""
        result = CorrelationResult(
            id="corr-001",
            candidate_id="candidate-001",
            evidence_chain=sample_chain,
        )
        result.mark_for_review("Low confidence")
        assert result.needs_manual_review is True
        assert "Low confidence" in result.review_reasons


class TestRoundThreeExecutor:
    """Tests for RoundThreeExecutor."""

    @pytest.fixture
    def executor(self, tmp_path):
        """Create an executor instance."""
        return RoundThreeExecutor(source_path=tmp_path)

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

    @pytest.fixture
    def sample_previous_round(self):
        """Create a sample previous round result with candidates."""
        finding = Finding(
            id="finding-001",
            severity=SeverityLevel.HIGH,
            title="SQL Injection",
            description="Test SQL injection",
            location=CodeLocation(file="test.py", line=10, function="get_user"),
            source="semgrep",
            tags=["sql", "injection"],
        )
        candidate = VulnerabilityCandidate(
            id="candidate-001",
            finding=finding,
            confidence=ConfidenceLevel.MEDIUM,
            discovered_in_round=1,
        )
        candidate.add_evidence("semgrep", {"rule": "sql-injection"})
        round_result = RoundResult(
            round_number=2,
            status=RoundStatus.COMPLETED,
        )
        round_result.add_candidate(candidate)
        return round_result

    def test_default_init(self, executor):
        """Test default initialization."""
        assert executor.source_path is not None
        assert executor._agent_executor is None

    @pytest.mark.asyncio
    async def test_execute_without_previous_round(self, executor, sample_strategy):
        """Test execution without previous round."""
        result = await executor.execute(sample_strategy, previous_round=None)
        assert result.round_number == 3
        assert result.status == RoundStatus.COMPLETED
        assert result.total_candidates == 0

    @pytest.mark.asyncio
    async def test_execute_without_candidates(self, executor, sample_strategy):
        """Test execution without candidates in previous round."""
        previous = RoundResult(round_number=2, status=RoundStatus.COMPLETED)
        result = await executor.execute(sample_strategy, previous_round=previous)
        assert result.round_number == 3
        assert result.status == RoundStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_execute_with_candidates(self, executor, sample_strategy, sample_previous_round):
        """Test execution with candidates."""
        result = await executor.execute(sample_strategy, previous_round=sample_previous_round)
        assert result.round_number == 3
        assert result.status == RoundStatus.COMPLETED
        assert "correlation" in result.engine_stats
        assert "rules" in result.engine_stats

    def test_map_confidence(self, executor):
        """Test confidence mapping."""
        assert executor._map_confidence(ConfidenceLevel.HIGH) == 0.85
        assert executor._map_confidence(ConfidenceLevel.MEDIUM) == 0.6
        assert executor._map_confidence(ConfidenceLevel.LOW) == 0.3

    def test_map_source_string(self, executor):
        """Test source string mapping."""
        assert executor._map_source_string("semgrep") == EvidenceSource.SEMGREP
        assert executor._map_source_string("codeql") == EvidenceSource.CODEQL
        assert executor._map_source_string("agent") == EvidenceSource.AGENT
        assert executor._map_source_string("unknown") is None
