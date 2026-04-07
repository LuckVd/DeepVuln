"""Unit tests for phase manager service."""

from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
import pytest

from src.web.services.phase_manager import (
    PhaseManager,
    get_phase_manager,
    PhaseStatus,
    PhaseTransition,
    PhaseInfo,
    PHASE_ORDER,
    VALID_TRANSITIONS,
)
from src.web.models.scan import Scan, ScanPhase, ScanStatus, ScanType, PhaseName


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
        with patch("src.web.services.phase_manager.AsyncSessionLocal", return_value=mock_session):
            yield mock_session


@pytest.fixture
def mock_scan():
    """Create a mock scan instance."""
    scan = MagicMock(spec=Scan)
    scan.id = 1
    scan.project_id = 100
    scan.status = ScanStatus.RUNNING
    scan.scan_type = ScanType.FULL
    scan.engines_completed = 2
    return scan


@pytest.fixture
def mock_phase():
    """Create a mock phase instance."""
    phase = MagicMock(spec=ScanPhase)
    phase.id = 1
    phase.scan_id = 1
    phase.phase_name = PhaseName.L3_AGENT
    phase.status = PhaseStatus.PENDING.value
    phase.progress_percent = 0
    phase.started_at = None
    phase.completed_at = None
    phase.duration_seconds = None
    phase.files_processed = 0
    phase.findings_found = 0
    phase.tokens_used = 0
    phase.error_message = None
    phase.output_path = None
    phase.output_data = None
    return phase


@pytest.fixture
def mock_phase_running():
    """Create a mock phase in running state."""
    phase = MagicMock(spec=ScanPhase)
    phase.id = 1
    phase.scan_id = 1
    phase.phase_name = PhaseName.L3_AGENT
    phase.status = PhaseStatus.RUNNING.value
    phase.progress_percent = 50
    phase.started_at = datetime.now(timezone.utc)
    phase.completed_at = None
    phase.files_processed = 10
    phase.findings_found = 2
    phase.tokens_used = 1000
    phase.error_message = None
    phase.output_path = None
    phase.output_data = None
    return phase


# ============================================================================
# Test PhaseManager Initialization
# ============================================================================

class TestPhaseManagerInit:
    """Test PhaseManager initialization."""

    def test_phase_manager_initialization(self):
        """Test PhaseManager can be initialized."""
        manager = PhaseManager()
        assert manager is not None
        assert manager.scan_repo is not None
        assert manager.phase_repo is not None

    def test_get_phase_manager_singleton(self):
        """Test get_phase_manager returns singleton instance."""
        manager1 = get_phase_manager()
        manager2 = get_phase_manager()
        assert manager1 is manager2


# ============================================================================
# Test Get Phase Status
# ============================================================================

class TestGetPhaseStatus:
    """Test getting phase status."""

    @pytest.mark.asyncio
    async def test_get_phase_status_success(self, mock_phase):
        """Test successfully getting phase status."""
        manager = PhaseManager()

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=mock_phase)
        ):
            status = await manager.get_phase_status(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
            )

        assert status is not None
        assert status.phase_name == PhaseName.L3_AGENT
        assert status.status == PhaseStatus.PENDING.value

    @pytest.mark.asyncio
    async def test_get_phase_status_not_found(self):
        """Test getting status for non-existent phase."""
        manager = PhaseManager()

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=None)
        ):
            status = await manager.get_phase_status(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
            )

        assert status is None

    @pytest.mark.asyncio
    async def test_get_phase_status_with_duration(self, mock_phase_running):
        """Test getting phase status with duration calculation."""
        manager = PhaseManager()

        # Mock a completed phase
        completed_phase = MagicMock(spec=ScanPhase)
        completed_phase.phase_name = PhaseName.L3_AGENT
        completed_phase.status = PhaseStatus.COMPLETED.value
        completed_phase.started_at = datetime.now(timezone.utc)
        completed_phase.completed_at = datetime.now(timezone.utc)
        completed_phase.progress_percent = 100
        completed_phase.files_processed = 20
        completed_phase.findings_found = 5
        completed_phase.tokens_used = 2000
        completed_phase.error_message = None

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=completed_phase)
        ):
            status = await manager.get_phase_status(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
            )

        assert status is not None
        assert status.status == PhaseStatus.COMPLETED.value
        assert status.duration_seconds is not None
        assert status.duration_seconds >= 0


# ============================================================================
# Test Start Phase
# ============================================================================

class TestStartPhase:
    """Test starting a phase."""

    @pytest.mark.asyncio
    async def test_start_phase_success(self, mock_phase):
        """Test successfully starting a phase."""
        manager = PhaseManager()

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=mock_phase)
        ):
            result = await manager.start_phase(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
            )

        assert result.success is True
        assert result.to_status == PhaseStatus.RUNNING.value
        assert "started" in result.message.lower()

    @pytest.mark.asyncio
    async def test_start_phase_not_found(self):
        """Test starting a non-existent phase."""
        manager = PhaseManager()

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=None)
        ):
            result = await manager.start_phase(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
            )

        assert result.success is False
        assert "not found" in result.message.lower()

    @pytest.mark.asyncio
    async def test_start_phase_invalid_transition(self, mock_phase):
        """Test starting a phase with invalid transition."""
        manager = PhaseManager()
        mock_phase.status = PhaseStatus.COMPLETED.value

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=mock_phase)
        ):
            result = await manager.start_phase(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
            )

        assert result.success is False
        assert "Cannot transition" in result.message or "Cannot start" in result.message


# ============================================================================
# Test Complete Phase
# ============================================================================

class TestCompletePhase:
    """Test completing a phase."""

    @pytest.mark.asyncio
    async def test_complete_phase_success(self, mock_phase_running, mock_scan):
        """Test successfully completing a phase."""
        manager = PhaseManager()
        output = {
            "files_processed": 20,
            "findings_found": 5,
            "tokens_used": 2000,
            "output_path": "/tmp/output.json",
        }

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=mock_phase_running)
        ):
            with patch.object(
                manager.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
            ):
                result = await manager.complete_phase(
                    scan_id=1,
                    phase_name=PhaseName.L3_AGENT,
                    output=output,
                )

        assert result.success is True
        assert result.to_status == PhaseStatus.COMPLETED.value

    @pytest.mark.asyncio
    async def test_complete_phase_not_running(self, mock_phase):
        """Test completing a phase that is not running."""
        manager = PhaseManager()
        mock_phase.status = PhaseStatus.PENDING.value

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=mock_phase)
        ):
            result = await manager.complete_phase(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
                output={},
            )

        assert result.success is False
        assert "not running" in result.message.lower() or "from pending" in result.message.lower()


# ============================================================================
# Test Fail Phase
# ============================================================================

class TestFailPhase:
    """Test failing a phase."""

    @pytest.mark.asyncio
    async def test_fail_phase_success(self, mock_phase_running):
        """Test successfully marking a phase as failed."""
        manager = PhaseManager()

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=mock_phase_running)
        ):
            result = await manager.fail_phase(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
                error="Database connection failed",
            )

        assert result.success is True
        assert result.to_status == PhaseStatus.FAILED.value

    @pytest.mark.asyncio
    async def test_fail_phase_from_pending(self, mock_phase):
        """Test failing a phase from pending state."""
        manager = PhaseManager()

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=mock_phase)
        ):
            result = await manager.fail_phase(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
                error="Pre-check failed",
            )

        assert result.success is True

    @pytest.mark.asyncio
    async def test_fail_phase_invalid_state(self):
        """Test failing a phase from invalid state."""
        manager = PhaseManager()
        phase = MagicMock(spec=ScanPhase)
        phase.status = PhaseStatus.COMPLETED.value

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=phase)
        ):
            result = await manager.fail_phase(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
                error="Test error",
            )

        assert result.success is False


# ============================================================================
# Test Skip Phase
# ============================================================================

class TestSkipPhase:
    """Test skipping a phase."""

    @pytest.mark.asyncio
    async def test_skip_phase_success(self, mock_phase, mock_scan):
        """Test successfully skipping a phase."""
        manager = PhaseManager()

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=mock_phase)
        ):
            with patch.object(
                manager.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
            ):
                result = await manager.skip_phase(
                    scan_id=1,
                    phase_name=PhaseName.L2_CODEQL,
                    reason="CodeQL not available",
                )

        assert result.success is True
        assert result.to_status == PhaseStatus.SKIPPED.value
        assert "CodeQL not available" in result.message

    @pytest.mark.asyncio
    async def test_skip_phase_from_failed(self, mock_phase, mock_scan):
        """Test skipping a previously failed phase."""
        manager = PhaseManager()
        mock_phase.status = PhaseStatus.FAILED.value

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=mock_phase)
        ):
            with patch.object(
                manager.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
            ):
                result = await manager.skip_phase(
                    scan_id=1,
                    phase_name=PhaseName.L2_CODEQL,
                    reason="User requested skip",
                )

        assert result.success is True


# ============================================================================
# Test Get Next Phase
# ============================================================================

class TestGetNextPhase:
    """Test getting next phase."""

    @pytest.mark.asyncio
    async def test_get_next_phase_pending(self, mock_scan):
        """Test getting next pending phase."""
        manager = PhaseManager()

        # Mock phases - L1_preparation completed, L1_attack_surface pending
        phase1 = MagicMock(spec=ScanPhase)
        phase1.phase_name = PhaseName.L1_PREPARATION
        phase1.status = PhaseStatus.COMPLETED.value

        phase2 = MagicMock(spec=ScanPhase)
        phase2.phase_name = PhaseName.L1_ATTACK_SURFACE
        phase2.status = PhaseStatus.PENDING.value

        with patch.object(
            manager.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
        ):
            with patch.object(
                manager.phase_repo, "get_by_scan", new=AsyncMock(return_value=[phase1, phase2])
            ):
                next_phase = await manager.get_next_phase(scan_id=1)

        assert next_phase == PhaseName.L1_ATTACK_SURFACE

    @pytest.mark.asyncio
    async def test_get_next_phase_all_complete(self, mock_scan):
        """Test getting next phase when all are complete."""
        manager = PhaseManager()

        # All phases completed
        phases = []
        for phase_name in PHASE_ORDER[ScanType.FULL]:
            phase = MagicMock(spec=ScanPhase)
            phase.phase_name = phase_name
            phase.status = PhaseStatus.COMPLETED.value
            phases.append(phase)

        with patch.object(
            manager.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
        ):
            with patch.object(
                manager.phase_repo, "get_by_scan", new=AsyncMock(return_value=phases)
            ):
                next_phase = await manager.get_next_phase(scan_id=1)

        assert next_phase is None

    @pytest.mark.asyncio
    async def test_get_next_phase_retry_failed(self, mock_scan):
        """Test getting next phase returns failed phase for retry."""
        manager = PhaseManager()

        phase1 = MagicMock(spec=ScanPhase)
        phase1.phase_name = PhaseName.L1_PREPARATION
        phase1.status = PhaseStatus.COMPLETED.value

        phase2 = MagicMock(spec=ScanPhase)
        phase2.phase_name = PhaseName.L1_ATTACK_SURFACE
        phase2.status = PhaseStatus.FAILED.value

        with patch.object(
            manager.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
        ):
            with patch.object(
                manager.phase_repo, "get_by_scan", new=AsyncMock(return_value=[phase1, phase2])
            ):
                next_phase = await manager.get_next_phase(scan_id=1)

        assert next_phase == PhaseName.L1_ATTACK_SURFACE  # Return failed phase for retry


# ============================================================================
# Test Can Resume From
# ============================================================================

class TestCanResumeFrom:
    """Test resume capability check."""

    @pytest.mark.asyncio
    async def test_can_resume_from_running(self, mock_phase_running):
        """Test can resume from running phase."""
        manager = PhaseManager()

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=mock_phase_running)
        ):
            result = await manager.can_resume_from(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
            )

        assert result is True

    @pytest.mark.asyncio
    async def test_can_resume_from_failed(self):
        """Test can resume from failed phase."""
        manager = PhaseManager()
        phase = MagicMock(spec=ScanPhase)
        phase.status = PhaseStatus.FAILED.value

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=phase)
        ):
            result = await manager.can_resume_from(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
            )

        assert result is True

    @pytest.mark.asyncio
    async def test_cannot_resume_from_completed(self):
        """Test cannot resume from completed phase."""
        manager = PhaseManager()
        phase = MagicMock(spec=ScanPhase)
        phase.status = PhaseStatus.COMPLETED.value

        with patch.object(
            manager.phase_repo, "get_by_name", new=AsyncMock(return_value=phase)
        ):
            result = await manager.can_resume_from(
                scan_id=1,
                phase_name=PhaseName.L3_AGENT,
            )

        assert result is False


# ============================================================================
# Test Data Models
# ============================================================================

class TestPhaseTransitionModel:
    """Test PhaseTransition model."""

    def test_phase_transition_success(self):
        """Test PhaseTransition for successful transition."""
        transition = PhaseTransition(
            success=True,
            from_status=PhaseStatus.PENDING.value,
            to_status=PhaseStatus.RUNNING.value,
            message="Phase started",
        )
        assert transition.success is True
        assert transition.error is None

    def test_phase_transition_failure(self):
        """Test PhaseTransition for failed transition."""
        transition = PhaseTransition(
            success=False,
            to_status=PhaseStatus.RUNNING.value,
            message="Transition failed",
            error="Invalid state",
        )
        assert transition.success is False
        assert transition.error == "Invalid state"


class TestPhaseInfoModel:
    """Test PhaseInfo model."""

    def test_phase_info_creation(self):
        """Test PhaseInfo creation."""
        now = datetime.now(timezone.utc)
        info = PhaseInfo(
            phase_name=PhaseName.L3_AGENT,
            status=PhaseStatus.RUNNING.value,
            progress_percent=50,
            started_at=now,
            files_processed=10,
            findings_found=2,
        )
        assert info.phase_name == PhaseName.L3_AGENT
        assert info.progress_percent == 50


class TestConstants:
    """Test module constants."""

    def test_valid_transitions(self):
        """Test VALID_TRANSITIONS is correctly defined."""
        assert PhaseStatus.PENDING in VALID_TRANSITIONS
        assert PhaseStatus.RUNNING in VALID_TRANSITIONS[PhaseStatus.PENDING]
        assert PhaseStatus.COMPLETED in VALID_TRANSITIONS[PhaseStatus.RUNNING]

    def test_phase_order(self):
        """Test PHASE_ORDER is correctly defined."""
        assert ScanType.FULL in PHASE_ORDER
        assert ScanType.INCREMENTAL in PHASE_ORDER
        assert len(PHASE_ORDER[ScanType.INCREMENTAL]) < len(PHASE_ORDER[ScanType.FULL])
