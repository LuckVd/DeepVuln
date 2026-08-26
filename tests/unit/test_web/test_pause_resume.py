"""Unit tests for pause/resume functionality."""

import sys
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from datetime import datetime, timezone
import pytest

from src.web.services.scan_executor import ScanExecutor
from src.web.models.scan import Scan, ScanStatus, ScanType, PhaseName
from src.web.services.checkpoint_service import CheckpointData, PhaseCheckpoint


# Mock scan_tasks module to avoid celery import
sys.modules["src.web.tasks.scan_tasks"] = Mock()


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(autouse=True)
def mock_async_session_local():
    """Mock the async session factory used by ScanExecutor.

    ScanExecutor resolves the sessionmaker via get_session_local() at call
    time (it intentionally does not import AsyncSessionLocal directly), so we
    patch that factory rather than a nonexistent module attribute. Patching a
    missing attribute made every test in this file depend on some earlier test
    polluting the module namespace — i.e. they could not run standalone.
    """
    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.commit = AsyncMock()
    mock_session.flush = AsyncMock()
    mock_session.refresh = AsyncMock()

    # get_session_local() returns an async_sessionmaker; calling it yields the
    # context manager that scan_executor opens via `async with session_maker()`.
    mock_sessionmaker = MagicMock(return_value=mock_session)
    with patch("src.web.services.scan_executor.get_session_local", return_value=mock_sessionmaker):
        yield mock_session


@pytest.fixture
def mock_scan_running():
    """Create a mock running scan."""
    scan = MagicMock(spec=Scan)
    scan.id = 1
    scan.project_id = 100
    scan.status = ScanStatus.RUNNING
    scan.scan_type = ScanType.FULL
    scan.current_phase = PhaseName.L3_AGENT
    scan.config = {"engines": ["semgrep", "agent"]}
    scan.engines_completed = 2
    scan.total_files = 100
    scan.analyzed_files = 50
    scan.findings_count = 5
    scan.tokens_used = 5000
    scan.started_at = datetime.now(timezone.utc)
    return scan


@pytest.fixture
def mock_scan_paused():
    """Create a mock paused scan with checkpoint."""
    scan = MagicMock(spec=Scan)
    scan.id = 1
    scan.project_id = 100
    scan.status = ScanStatus.PAUSED
    scan.scan_type = ScanType.FULL
    scan.config = {"engines": ["semgrep", "agent"]}
    scan.current_phase = PhaseName.L3_AGENT

    # Create checkpoint data
    checkpoint = CheckpointData(
        scan_id=1,
        current_phase=PhaseName.L3_AGENT,
        phases={
            PhaseName.L1_PREPARATION: PhaseCheckpoint(
                status="completed",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            ),
            PhaseName.L3_AGENT: PhaseCheckpoint(
                status="running",
                started_at=datetime.now(timezone.utc),
            ),
        },
        global_state={},
        resume_data={},
    )
    scan.checkpoint_data = checkpoint.model_dump()
    return scan


@pytest.fixture
def mock_checkpoint():
    """Create a mock checkpoint."""
    return CheckpointData(
        scan_id=1,
        current_phase=PhaseName.L3_AGENT,
        phases={
            PhaseName.L1_PREPARATION: PhaseCheckpoint(
                status="completed",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            ),
            PhaseName.L3_AGENT: PhaseCheckpoint(
                status="running",
                started_at=datetime.now(timezone.utc),
            ),
        },
        global_state={},
        resume_data={},
    )


# ============================================================================
# Test Pause Scan
# ============================================================================

class TestPauseScan:
    """Test pause scan functionality."""

    @pytest.mark.asyncio
    async def test_pause_scan_success(self, mock_scan_running):
        """Test successfully pausing a running scan."""
        executor = ScanExecutor()

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan_running)
        ):
            with patch.object(
                executor.checkpoint_service, "save_checkpoint", new=AsyncMock(return_value=True)
            ):
                with patch.object(
                    executor.scan_repo, "update_status", new=AsyncMock()
                ):
                    result = await executor.pause_scan(scan_id=1)

        assert result["scan_id"] == 1
        assert result["status"] == ScanStatus.PAUSED
        assert result["can_resume"] is True
        assert result["current_phase"] == PhaseName.L3_AGENT

    @pytest.mark.asyncio
    async def test_pause_scan_not_found(self):
        """Test pausing a non-existent scan."""
        executor = ScanExecutor()

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=None)
        ):
            with pytest.raises(ValueError, match="Scan 999 not found"):
                await executor.pause_scan(scan_id=999)

    @pytest.mark.asyncio
    async def test_pause_scan_not_running(self):
        """Test pausing a scan that is not running."""
        executor = ScanExecutor()
        scan = MagicMock(spec=Scan)
        scan.id = 1
        scan.status = ScanStatus.PENDING

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=scan)
        ):
            with pytest.raises(ValueError, match="is not running"):
                await executor.pause_scan(scan_id=1)

    @pytest.mark.asyncio
    async def test_pause_scan_revokes_celery_task(self, mock_scan_running):
        """Phase 18/P5-A6: pause must really revoke the Celery task, not just flip status."""
        mock_scan_running.task_id = "celery-task-pause-1"
        executor = ScanExecutor()
        mock_celery_app = MagicMock()

        with patch("src.web.services.scan_executor.get_celery_app", return_value=mock_celery_app):
            with patch.object(
                executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan_running)
            ):
                with patch.object(
                    executor.checkpoint_service, "save_checkpoint", new=AsyncMock(return_value=True)
                ):
                    with patch.object(
                        executor.scan_repo, "update_status", new=AsyncMock()
                    ):
                        result = await executor.pause_scan(scan_id=1)

        # The Celery task must actually be revoked with terminate=True
        mock_celery_app.control.revoke.assert_called_once_with(
            "celery-task-pause-1", terminate=True, signal="SIGTERM"
        )
        assert result["task_revoked"] is True

    @pytest.mark.asyncio
    async def test_pause_scan_preserves_orchestrator_resume_data(self, mock_scan_running):
        """Audit B1: pausing must not wipe the orchestrator's resume_data.

        save_checkpoint REPLACES the whole checkpoint; a hand-rolled minimal
        payload used to drop scan_results/completed_engines so resuming
        re-ran every engine and lost findings.
        """
        executor = ScanExecutor()
        # The orchestrator already saved a rich checkpoint mid-engine_execution.
        mock_scan_running.checkpoint_data = {
            "current_phase": "engine_execution",
            "global_state": {"scan_type": "full"},
            "resume_data": {
                "scan_results": {"semgrep": {"findings": ["f1"]}},
                "completed_engines": ["semgrep"],
            },
        }

        save_mock = AsyncMock(return_value=True)

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan_running)
        ):
            with patch.object(executor.checkpoint_service, "save_checkpoint", new=save_mock):
                with patch.object(
                    executor.scan_repo, "update_status", new=AsyncMock()
                ):
                    await executor.pause_scan(scan_id=1)

        assert save_mock.await_count == 1
        saved_resume = save_mock.await_args.kwargs["data"]["resume_data"]
        # Engine results recorded by the orchestrator must survive the pause.
        assert saved_resume["scan_results"] == {"semgrep": {"findings": ["f1"]}}
        assert saved_resume["completed_engines"] == ["semgrep"]
        # Live counters are refreshed on top of the preserved data.
        assert saved_resume["total_files"] == 100
        assert saved_resume["findings_count"] == 5

    @pytest.mark.asyncio
    async def test_pause_scan_without_prior_checkpoint_saves_counters(self, mock_scan_running):
        """First-time pause (no prior checkpoint) still saves live counters."""
        executor = ScanExecutor()
        mock_scan_running.checkpoint_data = None

        save_mock = AsyncMock(return_value=True)

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan_running)
        ):
            with patch.object(executor.checkpoint_service, "save_checkpoint", new=save_mock):
                with patch.object(
                    executor.scan_repo, "update_status", new=AsyncMock()
                ):
                    await executor.pause_scan(scan_id=1)

        saved_resume = save_mock.await_args.kwargs["data"]["resume_data"]
        assert saved_resume["total_files"] == 100
        assert saved_resume["analyzed_files"] == 50

    @pytest.mark.asyncio
    async def test_pause_scan_without_task_id_does_not_revoke(self, mock_scan_running):
        """When there is no task_id, pause must not attempt to revoke."""
        mock_scan_running.task_id = None
        executor = ScanExecutor()
        mock_celery_app = MagicMock()

        with patch("src.web.services.scan_executor.get_celery_app", return_value=mock_celery_app):
            with patch.object(
                executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan_running)
            ):
                with patch.object(
                    executor.checkpoint_service, "save_checkpoint", new=AsyncMock(return_value=True)
                ):
                    with patch.object(
                        executor.scan_repo, "update_status", new=AsyncMock()
                    ):
                        result = await executor.pause_scan(scan_id=1)

        mock_celery_app.control.revoke.assert_not_called()
        assert result["task_revoked"] is False


# ============================================================================
# Test Resume Scan
# ============================================================================

class TestResumeScan:
    """Test resume scan functionality."""

    @pytest.mark.asyncio
    async def test_resume_scan_success(self, mock_scan_paused, mock_checkpoint):
        """Test successfully resuming a paused scan."""
        executor = ScanExecutor()

        # Create mock for Celery task
        mock_task_instance = MagicMock()
        mock_task_instance.id = "celery-task-123"

        mock_celery_task = MagicMock()
        mock_celery_task.apply_async = MagicMock(return_value=mock_task_instance)

        with patch("src.web.tasks.scan_tasks.execute_scan_task", mock_celery_task):
            with patch.object(
                executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan_paused)
            ):
                with patch.object(
                    executor.checkpoint_service, "load_checkpoint", new=AsyncMock(return_value=mock_checkpoint)
                ):
                    with patch.object(
                        executor.checkpoint_service, "verify_checkpoint", new=AsyncMock(return_value=True)
                    ):
                        with patch.object(
                            executor.checkpoint_service, "get_resume_strategy", new=AsyncMock(
                                return_value=MagicMock(
                                    can_resume=True,
                                    resume_phase=PhaseName.L3_AGENT,
                                    skip_phases=[PhaseName.L1_PREPARATION],
                                )
                            )
                        ):
                            with patch.object(
                                executor.scan_repo, "update_status", new=AsyncMock()
                            ):
                                result = await executor.resume_scan(scan_id=1)

        assert result["scan_id"] == 1
        assert result["status"] == ScanStatus.PENDING
        assert result["resumed_from_phase"] == PhaseName.L3_AGENT
        assert result["task_id"] == "celery-task-123"

    @pytest.mark.asyncio
    async def test_resume_scan_not_found(self):
        """Test resuming a non-existent scan."""
        executor = ScanExecutor()

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=None)
        ):
            with pytest.raises(ValueError, match="Scan 999 not found"):
                await executor.resume_scan(scan_id=999)

    @pytest.mark.asyncio
    async def test_resume_scan_not_paused(self, mock_scan_running):
        """Test resuming a scan that is not paused."""
        executor = ScanExecutor()

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan_running)
        ):
            with pytest.raises(ValueError, match="is not paused"):
                await executor.resume_scan(scan_id=1)

    @pytest.mark.asyncio
    async def test_resume_scan_no_checkpoint(self, mock_scan_paused):
        """Test resuming a scan with no checkpoint."""
        executor = ScanExecutor()

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan_paused)
        ):
            with patch.object(
                executor.checkpoint_service, "load_checkpoint", new=AsyncMock(return_value=None)
            ):
                with pytest.raises(ValueError, match="No checkpoint found"):
                    await executor.resume_scan(scan_id=1)


# ============================================================================
# Test Cancel Scan (Enhanced)
# ============================================================================

class TestCancelScanEnhanced:
    """Test enhanced cancel scan functionality."""

    @pytest.mark.asyncio
    async def test_cancel_scan_running(self, mock_scan_running):
        """Test canceling a running scan."""
        executor = ScanExecutor()

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan_running)
        ):
            with patch.object(
                executor.scan_repo, "update_status", new=AsyncMock()
            ):
                result = await executor.cancel_scan(scan_id=1)

        assert result is True

    @pytest.mark.asyncio
    async def test_cancel_scan_pending(self):
        """Test canceling a pending scan."""
        executor = ScanExecutor()
        scan = MagicMock(spec=Scan)
        scan.id = 1
        scan.status = ScanStatus.PENDING

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=scan)
        ):
            with patch.object(
                executor.scan_repo, "update_status", new=AsyncMock()
            ):
                result = await executor.cancel_scan(scan_id=1)

        assert result is True

    @pytest.mark.asyncio
    async def test_cancel_scan_already_completed(self):
        """Test canceling an already completed scan."""
        executor = ScanExecutor()
        scan = MagicMock(spec=Scan)
        scan.id = 1
        scan.status = ScanStatus.COMPLETED

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=scan)
        ):
            result = await executor.cancel_scan(scan_id=1)

        assert result is False


# ============================================================================
# Test Task Signature
# ============================================================================

class TestTaskSignature:
    """Test scan task signature changes."""

    def test_execute_scan_task_accepts_resume(self):
        """Test execute_scan_task accepts resume_from parameter."""
        # Skip this test as it requires loading the real module
        pytest.skip("Requires real celery module - tested in other tests")

    @pytest.mark.asyncio
    async def test_execute_scan_async_signature(self):
        """Test _execute_scan_async accepts resume_from parameter."""
        # Skip this test as it requires loading the real module
        pytest.skip("Requires real celery module - tested in other tests")


# ============================================================================
# Test Integration
# ============================================================================

class TestPauseResumeIntegration:
    """Test integration between pause and resume."""

    @pytest.mark.asyncio
    async def test_pause_resume_cycle(self, mock_scan_running, mock_checkpoint):
        """Test full pause and resume cycle."""
        executor = ScanExecutor()

        # Step 1: Pause the scan
        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan_running)
        ):
            with patch.object(
                executor.checkpoint_service, "save_checkpoint", new=AsyncMock(return_value=True)
            ):
                with patch.object(
                    executor.scan_repo, "update_status", new=AsyncMock()
                ):
                    pause_result = await executor.pause_scan(scan_id=1)

        assert pause_result["status"] == ScanStatus.PAUSED

        # Step 2: Resume the scan
        mock_scan_paused = MagicMock(spec=Scan)
        mock_scan_paused.id = 1
        mock_scan_paused.status = ScanStatus.PAUSED
        mock_scan_paused.project_id = 100
        mock_scan_paused.scan_type = ScanType.FULL
        mock_scan_paused.config = {}

        with patch.object(
            executor.scan_repo, "get", new=AsyncMock(return_value=mock_scan_paused)
        ):
            with patch.object(
                executor.checkpoint_service, "load_checkpoint", new=AsyncMock(return_value=mock_checkpoint)
            ):
                with patch.object(
                    executor.checkpoint_service, "verify_checkpoint", new=AsyncMock(return_value=True)
                ):
                    with patch.object(
                        executor.checkpoint_service, "get_resume_strategy", new=AsyncMock(
                            return_value=MagicMock(
                                can_resume=True,
                                resume_phase=PhaseName.L3_AGENT,
                                skip_phases=[],
                            )
                        )
                    ):
                        with patch.object(
                            executor.scan_repo, "update_status", new=AsyncMock()
                        ):
                            # Create mock for Celery task
                            mock_task_instance = MagicMock()
                            mock_task_instance.id = "task-123"

                            mock_celery_task = MagicMock()
                            mock_celery_task.apply_async = MagicMock(return_value=mock_task_instance)

                            with patch("src.web.tasks.scan_tasks.execute_scan_task", mock_celery_task):
                                resume_result = await executor.resume_scan(scan_id=1)

        assert resume_result["status"] == ScanStatus.PENDING
        assert resume_result["task_id"] == "task-123"
