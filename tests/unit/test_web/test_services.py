"""Unit tests for scan executor service."""

from unittest.mock import AsyncMock, MagicMock, patch, Mock
from datetime import datetime, timezone
import pytest

from src.web.services.scan_executor import ScanExecutor, get_scan_executor
from src.web.models.scan import Scan, ScanStatus, ScanType
from src.web.models.schemas import ScanCreate


# Mock AsyncSessionLocal for all tests
@pytest.fixture(autouse=True)
def mock_async_session_local():
    """Mock AsyncSessionLocal for all tests."""
    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.commit = AsyncMock()
    mock_session.flush = AsyncMock()
    mock_session.refresh = AsyncMock()

    with patch("src.web.models.database.AsyncSessionLocal", return_value=mock_session):
        with patch("src.web.services.scan_executor.AsyncSessionLocal", return_value=mock_session):
            yield mock_session


@pytest.fixture
def mock_scan():
    """Create a mock scan instance."""
    scan = MagicMock(spec=Scan)
    scan.id = 1
    scan.project_id = 100
    scan.status = ScanStatus.PENDING
    scan.scan_type = ScanType.FULL
    scan.config = {"engines": ["semgrep", "agent"]}
    scan.progress_percent = 0
    scan.current_phase = None
    scan.current_step = None
    scan.current_engine = None
    scan.total_files = 0
    scan.indexed_files = 0
    scan.analyzed_files = 0
    scan.files_with_findings = 0
    scan.engines_completed = 0
    scan.engines_total = 5
    scan.tokens_used = 0
    scan.tokens_budget = 100000
    scan.llm_requests_count = 0
    scan.findings_count = 0
    scan.verified_count = 0
    scan.false_positive_count = 0
    scan.critical_count = 0
    scan.high_count = 0
    scan.medium_count = 0
    scan.low_count = 0
    scan.info_count = 0
    scan.quality_score = 0.0
    scan.coverage_score = 0.0
    scan.created_at = datetime.now(timezone.utc)
    scan.started_at = None
    scan.completed_at = None
    scan.estimated_completion = None
    scan.error_message = None
    scan.failed_engines = None
    scan.checkpoint_data = None
    scan.report_path = None
    scan.phases = []
    return scan


@pytest.fixture
def mock_project():
    """Create a mock project instance."""
    project = MagicMock()
    project.id = 100
    project.name = "Test Project"
    project.description = "Test Description"
    project.source_type = "local"
    project.source_path = "/path/to/source"
    project.branch = "main"
    project.commit_hash = "abc123"
    project.created_at = datetime.now(timezone.utc)
    project.updated_at = datetime.now(timezone.utc)
    project.last_scan_id = None
    project.extra_metadata = None
    return project


class TestScanExecutor:
    """Test ScanExecutor service."""

    def test_scan_executor_initialization(self):
        """Test ScanExecutor can be initialized."""
        executor = ScanExecutor()
        assert executor is not None
        assert executor.scan_repo is not None
        assert executor.phase_repo is not None
        assert executor.event_repo is not None
        assert executor.finding_repo is not None
        assert executor.project_repo is not None

    def test_get_scan_executor_singleton(self):
        """Test get_scan_executor returns singleton instance."""
        executor1 = get_scan_executor()
        executor2 = get_scan_executor()
        assert executor1 is executor2

    @pytest.mark.asyncio
    async def test_create_scan(self, mock_project, mock_scan):
        """Test creating a new scan."""
        executor = ScanExecutor()
        scan_create = ScanCreate(
            project_id=100,
            scan_type=ScanType.FULL,
            config={"engines": ["semgrep", "agent"]},
        )

        with patch.object(
            executor.project_repo, "get", new=AsyncMock(return_value=mock_project)
        ):
            with patch.object(
                executor.scan_repo, "create", new=AsyncMock(return_value=mock_scan)
            ):
                with patch.object(executor, "_create_initial_phases", new=AsyncMock()):
                    result = await executor.create_scan(100, scan_create)

        assert result is not None
        assert result.id == 1
        assert result.project_id == 100

    @pytest.mark.asyncio
    async def test_create_scan_project_not_found(self):
        """Test creating a scan with non-existent project raises ValueError."""
        executor = ScanExecutor()
        scan_create = ScanCreate(
            project_id=999,
            scan_type=ScanType.FULL,
            config={},
        )

        with patch.object(executor.project_repo, "get", new=AsyncMock(return_value=None)):
            with pytest.raises(ValueError, match="Project 999 not found"):
                await executor.create_scan(999, scan_create)

    @pytest.mark.asyncio
    async def test_get_scan_status(self, mock_scan):
        """Test getting scan status."""
        executor = ScanExecutor()
        mock_scan.status = ScanStatus.RUNNING
        mock_scan.progress_percent = 45
        mock_scan.current_phase = "L3_agent"
        mock_scan.current_step = "Processing file 10/100"
        mock_scan.findings_count = 5
        mock_scan.tokens_used = 5000
        mock_scan.started_at = datetime.now(timezone.utc)

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
        ):
            status = await executor.get_scan_status(1)

        assert status is not None
        assert status["scan_id"] == 1
        assert status["status"] == ScanStatus.RUNNING
        assert status["progress_percent"] == 45
        assert status["current_phase"] == "L3_agent"
        assert status["findings_count"] == 5
        assert status["tokens_used"] == 5000

    @pytest.mark.asyncio
    async def test_get_scan_status_not_found(self):
        """Test getting status for non-existent scan returns None."""
        executor = ScanExecutor()

        with patch.object(executor.scan_repo, "get", new=AsyncMock(return_value=None)):
            status = await executor.get_scan_status(999)

        assert status is None

    @pytest.mark.asyncio
    async def test_get_scan_progress(self, mock_scan):
        """Test getting detailed scan progress."""
        executor = ScanExecutor()
        mock_scan.status = ScanStatus.RUNNING
        mock_scan.progress_percent = 60
        mock_scan.current_phase = "L3_agent"
        mock_scan.current_step = "Analyzing src/main.py"
        mock_scan.tokens_used = 12000
        mock_scan.tokens_budget = 100000
        mock_scan.findings_count = 8
        mock_scan.verified_count = 5
        mock_scan.false_positive_count = 1
        mock_scan.critical_count = 1
        mock_scan.high_count = 2
        mock_scan.medium_count = 3
        mock_scan.low_count = 1
        mock_scan.info_count = 0
        mock_scan.phases = []

        with patch.object(
            executor.scan_repo, "get_with_phases", new=AsyncMock(return_value=mock_scan)
        ):
            progress = await executor.get_scan_progress(1)

        assert progress is not None
        assert progress.scan_id == 1
        assert progress.status == ScanStatus.RUNNING
        assert progress.progress_percent == 60
        assert progress.tokens.used == 12000
        assert progress.tokens.budget == 100000
        assert progress.findings.total == 8
        assert progress.findings.verified == 5
        assert progress.findings.by_severity["critical"] == 1

    @pytest.mark.asyncio
    async def test_cancel_scan(self, mock_scan):
        """Test cancelling a scan."""
        executor = ScanExecutor()
        mock_scan.status = ScanStatus.RUNNING

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
        ):
            with patch.object(
                executor.scan_repo, "update_status", new=AsyncMock(return_value=mock_scan)
            ):
                result = await executor.cancel_scan(1)

        assert result is True

    @pytest.mark.asyncio
    async def test_cancel_scan_not_running(self, mock_scan):
        """Test cancelling a completed scan returns False."""
        executor = ScanExecutor()
        mock_scan.status = ScanStatus.COMPLETED

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
        ):
            result = await executor.cancel_scan(1)

        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_scan_not_found(self):
        """Test cancelling non-existent scan returns False."""
        executor = ScanExecutor()

        with patch.object(executor.scan_repo, "get", new=AsyncMock(return_value=None)):
            result = await executor.cancel_scan(999)

        assert result is False

    @pytest.mark.asyncio
    async def test_retry_scan(self, mock_scan):
        """Test retrying a failed scan."""
        executor = ScanExecutor()
        mock_scan.status = ScanStatus.FAILED
        mock_scan.project_id = 100
        mock_scan.scan_type = ScanType.FULL
        mock_scan.config = {"engines": ["semgrep"]}

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
        ):
            with patch.object(
                executor, "create_scan", new=AsyncMock(return_value=mock_scan)
            ):
                with patch.object(
                    executor, "start_scan", new=AsyncMock(return_value={"task_id": "test-task-id"})
                ):
                    result = await executor.retry_scan(1)

        assert result["original_scan_id"] == 1
        assert result["new_scan_id"] == 1
        assert result["task_id"] == "test-task-id"

    @pytest.mark.asyncio
    async def test_retry_scan_not_failed(self, mock_scan):
        """Test retrying a non-failed scan raises ValueError."""
        executor = ScanExecutor()
        mock_scan.status = ScanStatus.RUNNING

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
        ):
            with pytest.raises(ValueError, match="is not in failed status"):
                await executor.retry_scan(1)

    @pytest.mark.asyncio
    async def test_extract_adversarial_status(self):
        """Test extracting adversarial status from events."""
        executor = ScanExecutor()

        # No events
        status = executor._extract_adversarial_status([])
        assert status.active is False

        # Active adversarial
        event = MagicMock()
        event.event_type = "adversarial_start"
        event.details = {"round": 2, "max_rounds": 5, "current_findings": 1}
        status = executor._extract_adversarial_status([event])
        assert status.active is True
        assert status.round == 2
        assert status.max_rounds == 5

        # Completed
        event.event_type = "adversarial_complete"
        status = executor._extract_adversarial_status([event])
        assert status.active is False

    @pytest.mark.asyncio
    async def test_extract_current_file_info(self):
        """Test extracting current file from events."""
        executor = ScanExecutor()

        # No events
        info = executor._extract_current_file_info([])
        assert info is None

        # File event
        event = MagicMock()
        event.event_type = "file_start"
        event.file_path = "src/main.py"
        event.file_index = 10
        event.file_total = 100
        info = executor._extract_current_file_info([event])
        assert info is not None
        assert info["path"] == "src/main.py"
        assert info["index"] == 10
        assert info["total"] == 100
