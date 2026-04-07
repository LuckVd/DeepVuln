"""Unit tests for scan control API endpoints.

P11-04: Tests for pause/resume/cancel API endpoints.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import sys
from datetime import datetime, timezone
import pytest

from fastapi.testclient import TestClient
from fastapi import FastAPI, Depends

from src.web.api.v1.scans import router as scan_router
from src.web.models.scan import Scan, ScanStatus, ScanType
from src.web.models.schemas import ScanCreate
from src.web.repositories.scan import ScanRepository

# Mock scan_tasks module to avoid celery import
sys.modules["src.web.tasks.scan_tasks"] = MagicMock()


# ============================================================================
# Fixtures
# ============================================================================

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
        with patch("src.web.api.deps.AsyncSessionLocal", return_value=mock_session):
            yield mock_session


@pytest.fixture
def mock_app():
    """Create a test app with the scan router."""
    from src.web.core.security import require_api_key

    app = FastAPI()
    # Include with the same prefix as the real app
    app.include_router(scan_router, prefix="/api/v1")

    # Create test client with dependency override
    client = TestClient(app)
    # Override require_api_key to allow requests without API key in tests
    app.dependency_overrides[require_api_key] = lambda: None
    return client


@pytest.fixture
def mock_scan_running():
    """Create a mock running scan."""
    scan = MagicMock(spec=Scan)
    scan.id = 1
    scan.project_id = 100
    scan.status = ScanStatus.RUNNING
    scan.scan_type = ScanType.FULL
    scan.current_phase = "L3_agent"
    scan.progress_percent = 45
    scan.checkpoint_data = None
    return scan


@pytest.fixture
def mock_scan_paused():
    """Create a mock paused scan with checkpoint."""
    scan = MagicMock(spec=Scan)
    scan.id = 1
    scan.project_id = 100
    scan.status = ScanStatus.PAUSED
    scan.scan_type = ScanType.FULL
    scan.current_phase = "L3_agent"
    scan.checkpoint_data = {
        "scan_id": 1,
        "current_phase": "L3_agent",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return scan


@pytest.fixture
def mock_scan_pending():
    """Create a mock pending scan."""
    scan = MagicMock(spec=Scan)
    scan.id = 1
    scan.project_id = 100
    scan.status = ScanStatus.PENDING
    scan.scan_type = ScanType.FULL
    scan.current_phase = None
    scan.progress_percent = 0
    scan.checkpoint_data = None
    return scan


@pytest.fixture
def mock_scan_completed():
    """Create a mock completed scan."""
    scan = MagicMock(spec=Scan)
    scan.id = 1
    scan.project_id = 100
    scan.status = ScanStatus.COMPLETED
    scan.scan_type = ScanType.FULL
    scan.current_phase = None
    scan.progress_percent = 100
    scan.checkpoint_data = None
    return scan


# ============================================================================
# Test Pause Endpoint
# ============================================================================

class TestPauseEndpoint:
    """Test pause scan endpoint."""

    def test_pause_scan_success(self, mock_app, mock_scan_running):
        """Test successfully pausing a scan."""
        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=mock_scan_running)):
            with patch("src.web.services.scan_executor.get_scan_executor") as mock_get_executor:
                executor_instance = MagicMock()
                executor_instance.pause_scan = AsyncMock(return_value={
                    "scan_id": 1,
                    "status": ScanStatus.PAUSED,
                    "checkpoint_saved": True,
                    "paused_at": datetime.now(timezone.utc),
                    "current_phase": "L3_agent",
                    "can_resume": True,
                })
                mock_get_executor.return_value = executor_instance

                response = mock_app.post("/api/v1/scans/1/pause")

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == 1
        assert data["status"] == ScanStatus.PAUSED
        assert data["can_resume"] is True

    def test_pause_scan_not_found(self, mock_app):
        """Test pausing a non-existent scan."""
        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=None)):
            response = mock_app.post("/api/v1/scans/999/pause")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_pause_scan_not_running(self, mock_app, mock_scan_pending):
        """Test pausing a scan that is not running."""
        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=mock_scan_pending)):
            response = mock_app.post("/api/v1/scans/1/pause")

        assert response.status_code == 400
        assert "not running" in response.json()["detail"].lower()


# ============================================================================
# Test Resume Endpoint
# ============================================================================

class TestResumeEndpoint:
    """Test resume scan endpoint."""

    def test_resume_scan_success(self, mock_app, mock_scan_paused):
        """Test successfully resuming a paused scan."""
        checkpoint = MagicMock()

        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=mock_scan_paused)):
            with patch("src.web.services.checkpoint_service.get_checkpoint_service") as mock_cs:
                cs_instance = MagicMock()
                cs_instance.load_checkpoint = AsyncMock(return_value=checkpoint)
                cs_instance.verify_checkpoint = AsyncMock(return_value=True)
                cs_instance.get_resume_strategy = AsyncMock(
                    return_value=MagicMock(
                        can_resume=True,
                        resume_phase="L3_agent",
                        skip_phases=["L1_preparation"],
                    )
                )
                mock_cs.return_value = cs_instance

                with patch("src.web.services.scan_executor.get_scan_executor") as mock_get_executor:
                    executor_instance = MagicMock()
                    executor_instance.resume_scan = AsyncMock(return_value={
                        "scan_id": 1,
                        "status": ScanStatus.PENDING,
                        "resumed_from_phase": "L3_agent",
                        "resumed_at": datetime.now(timezone.utc),
                        "task_id": "celery-task-123",
                        "skip_phases": ["L1_preparation"],
                    })
                    mock_get_executor.return_value = executor_instance

                    response = mock_app.post("/api/v1/scans/1/resume")

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == 1
        assert data["status"] == ScanStatus.PENDING
        assert data["task_id"] == "celery-task-123"

    def test_resume_scan_not_paused(self, mock_app, mock_scan_running):
        """Test resuming a scan that is not paused."""
        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=mock_scan_running)):
            response = mock_app.post("/api/v1/scans/1/resume")

        assert response.status_code == 400
        assert "not paused" in response.json()["detail"].lower()


# ============================================================================
# Test Cancel Endpoint
# ============================================================================

class TestCancelEndpoint:
    """Test cancel scan endpoint."""

    def test_cancel_scan_success(self, mock_app, mock_scan_running):
        """Test successfully cancelling a running scan."""
        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=mock_scan_running)):
            with patch("src.web.services.scan_executor.get_scan_executor") as mock_get_executor:
                executor_instance = MagicMock()
                executor_instance.cancel_scan = AsyncMock(return_value=True)
                mock_get_executor.return_value = executor_instance

                response = mock_app.post("/api/v1/scans/1/cancel")

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == 1
        assert data["status"] == ScanStatus.CANCELLED
        assert data["cleanup_started"] is True

    def test_cancel_scan_pending(self, mock_app, mock_scan_pending):
        """Test cancelling a pending scan."""
        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=mock_scan_pending)):
            with patch("src.web.services.scan_executor.get_scan_executor") as mock_get_executor:
                executor_instance = MagicMock()
                executor_instance.cancel_scan = AsyncMock(return_value=True)
                mock_get_executor.return_value = executor_instance

                response = mock_app.post("/api/v1/scans/1/cancel")

        assert response.status_code == 200

    def test_cancel_scan_completed(self, mock_app, mock_scan_completed):
        """Test cancelling a completed scan."""
        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=mock_scan_completed)):
            response = mock_app.post("/api/v1/scans/1/cancel")

        assert response.status_code == 400
        assert "cannot be cancelled" in response.json()["detail"].lower()


# ============================================================================
# Test Status Endpoint
# ============================================================================

class TestStatusEndpoint:
    """Test scan control status endpoint."""

    def test_get_status_running(self, mock_app, mock_scan_running):
        """Test getting status for running scan."""
        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=mock_scan_running)):
            response = mock_app.get("/api/v1/scans/1/status")

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == 1
        assert data["status"] == ScanStatus.RUNNING
        assert "pause" in data["available_actions"]
        assert "cancel" in data["available_actions"]
        assert data["can_pause"] is True
        assert data["can_cancel"] is True

    def test_get_status_paused(self, mock_app, mock_scan_paused):
        """Test getting status for paused scan."""
        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=mock_scan_paused)):
            response = mock_app.get("/api/v1/scans/1/status")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == ScanStatus.PAUSED
        assert "resume" in data["available_actions"]
        assert data["can_resume"] is True

    def test_get_status_completed(self, mock_app, mock_scan_completed):
        """Test getting status for completed scan."""
        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=mock_scan_completed)):
            response = mock_app.get("/api/v1/scans/1/status")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == ScanStatus.COMPLETED
        # Completed scan has limited actions
        assert "retry" in data["available_actions"] or len(data["available_actions"]) == 0


# ============================================================================
# Test State Transitions
# ============================================================================

class TestStateTransitions:
    """Test valid state transitions."""

    @pytest.mark.parametrize("current_status,can_pause,can_resume,can_cancel", [
        (ScanStatus.PENDING, False, False, True),
        (ScanStatus.RUNNING, True, False, True),
        (ScanStatus.PAUSED, False, True, True),
        (ScanStatus.COMPLETED, False, False, False),
        (ScanStatus.FAILED, False, False, True),
        (ScanStatus.CANCELLED, False, False, False),
    ])
    def test_action_availability_by_state(
        self,
        mock_app,
        current_status,
        can_pause,
        can_resume,
        can_cancel,
    ):
        """Test action availability based on scan state."""
        scan = MagicMock(spec=Scan)
        scan.id = 1
        scan.status = current_status
        scan.progress_percent = 50
        scan.current_phase = "L3_agent" if current_status == ScanStatus.RUNNING else None

        with patch.object(ScanRepository, "get", new=AsyncMock(return_value=scan)):
            response = mock_app.get(f"/api/v1/scans/1/status")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == current_status
        assert data["can_pause"] == can_pause
        assert data["can_resume"] == can_resume
        assert data["can_cancel"] == can_cancel
