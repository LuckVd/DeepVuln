"""Unit tests for checkpoint service."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from datetime import datetime, timezone
import pytest
import tempfile
import shutil

from src.web.services.checkpoint_service import (
    CheckpointService,
    get_checkpoint_service,
    CheckpointData,
    PhaseCheckpoint,
    ResumeStrategy,
)
from src.web.models.scan import Scan, ScanStatus, ScanType, PhaseName
from src.layers.pipeline.phases import ScanPhase, SCAN_PHASE_ORDER


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

    # checkpoint_service resolves the sessionmaker via get_session_local() at
    # call time (it does not import AsyncSessionLocal directly), so patch the
    # factory function rather than a nonexistent module attribute.
    mock_sessionmaker = MagicMock(return_value=mock_session)
    with patch("src.web.services.checkpoint_service.get_session_local", return_value=mock_sessionmaker):
        yield mock_session


@pytest.fixture
def temp_checkpoint_dir():
    """Create a temporary checkpoint directory."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_scan():
    """Create a mock scan instance."""
    scan = MagicMock(spec=Scan)
    scan.id = 1
    scan.project_id = 100
    scan.status = ScanStatus.RUNNING
    scan.scan_type = ScanType.FULL
    scan.config = {"engines": ["semgrep", "agent"]}
    scan.progress_percent = 50
    scan.current_phase = PhaseName.L3_AGENT
    scan.checkpoint_data = None
    return scan


@pytest.fixture
def mock_scan_with_checkpoint():
    """Create a mock scan with checkpoint data."""
    # Create a valid checkpoint with matching hash
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

    # Use model_dump to create the checkpoint_data dict with correct structure
    scan = MagicMock(spec=Scan)
    scan.id = 1
    scan.project_id = 100
    scan.status = ScanStatus.PAUSED
    checkpoint_dict = checkpoint.model_dump()
    checkpoint_dict["created_at"] = checkpoint_dict["created_at"].isoformat()
    # Convert datetime fields in phases to ISO format
    for phase_data in checkpoint_dict["phases"].values():
        if phase_data.get("started_at"):
            phase_data["started_at"] = phase_data["started_at"].isoformat()
        if phase_data.get("completed_at"):
            phase_data["completed_at"] = phase_data["completed_at"].isoformat()
    checkpoint_dict["hash"] = checkpoint.get_hash()  # Add hash
    scan.checkpoint_data = checkpoint_dict
    return scan


@pytest.fixture
def sample_checkpoint_data():
    """Create sample checkpoint data using canonical ScanPhase values.

    The pipeline persists ScanPhase values (snake_case) into checkpoints —
    fixtures must mirror that, not the legacy PhaseName enum, or they hide the
    resume naming mismatch (Phase 18/P5-A5).
    """
    return CheckpointData(
        scan_id=1,
        current_phase=ScanPhase.ENGINE_EXECUTION.value,
        phases={
            ScanPhase.L1_PREPARATION.value: PhaseCheckpoint(
                status="completed",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                files_processed=10,
            ),
            ScanPhase.ENGINE_EXECUTION.value: PhaseCheckpoint(
                status="running",
                started_at=datetime.now(timezone.utc),
                files_processed=5,
            ),
        },
        global_state={"engines": ["semgrep", "agent"]},
        resume_data={"file_index": 5},
    )


# ============================================================================
# Test CheckpointService Initialization
# ============================================================================

class TestCheckpointServiceInit:
    """Test CheckpointService initialization."""

    def test_checkpoint_service_initialization(self):
        """Test CheckpointService can be initialized."""
        service = CheckpointService()
        assert service is not None
        assert service.scan_repo is not None
        assert service.phase_repo is not None

    def test_get_checkpoint_service_singleton(self):
        """Test get_checkpoint_service returns singleton instance."""
        service1 = get_checkpoint_service()
        service2 = get_checkpoint_service()
        assert service1 is service2


# ============================================================================
# Test Save Checkpoint
# ============================================================================

class TestSaveCheckpoint:
    """Test checkpoint saving functionality."""

    @pytest.mark.asyncio
    async def test_save_checkpoint_success(self, mock_scan):
        """Test successfully saving a checkpoint."""
        service = CheckpointService()

        mock_phases = []
        with patch.object(
            service.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
        ):
            with patch.object(
                service.phase_repo, "get_by_scan", new=AsyncMock(return_value=mock_phases)
            ):
                with patch.object(
                    service.scan_repo, "update", new=AsyncMock(return_value=mock_scan)
                ):
                    with patch.object(
                        service, "_save_checkpoint_to_file", new=AsyncMock(return_value=True)
                    ):
                        result = await service.save_checkpoint(
                            scan_id=1,
                            phase=PhaseName.L3_AGENT,
                            data={"global_state": {"test": "data"}},
                        )

        assert result is True

    @pytest.mark.asyncio
    async def test_save_checkpoint_scan_not_found(self):
        """Test saving checkpoint for non-existent scan."""
        service = CheckpointService()

        with patch.object(
            service.scan_repo, "get", new=AsyncMock(return_value=None)
        ):
            result = await service.save_checkpoint(
                scan_id=999,
                phase=PhaseName.L3_AGENT,
                data={},
            )

        assert result is False


# ============================================================================
# Test Load Checkpoint
# ============================================================================

class TestLoadCheckpoint:
    """Test checkpoint loading functionality."""

    @pytest.mark.asyncio
    async def test_load_checkpoint_success(self, mock_scan_with_checkpoint):
        """Test successfully loading a checkpoint."""
        service = CheckpointService()

        with patch.object(
            service.scan_repo, "get", new=AsyncMock(return_value=mock_scan_with_checkpoint)
        ):
            checkpoint = await service.load_checkpoint(scan_id=1)

        assert checkpoint is not None
        assert checkpoint.scan_id == 1
        assert checkpoint.current_phase == PhaseName.L3_AGENT

    @pytest.mark.asyncio
    async def test_load_checkpoint_no_data(self, mock_scan):
        """Test loading checkpoint when no checkpoint data exists."""
        service = CheckpointService()

        with patch.object(
            service.scan_repo, "get", new=AsyncMock(return_value=mock_scan)
        ):
            checkpoint = await service.load_checkpoint(scan_id=1)

        assert checkpoint is None

    @pytest.mark.asyncio
    async def test_load_checkpoint_scan_not_found(self):
        """Test loading checkpoint for non-existent scan."""
        service = CheckpointService()

        with patch.object(
            service.scan_repo, "get", new=AsyncMock(return_value=None)
        ):
            checkpoint = await service.load_checkpoint(scan_id=999)

        assert checkpoint is None


# ============================================================================
# Test Verify Checkpoint
# ============================================================================

class TestVerifyCheckpoint:
    """Test checkpoint verification functionality."""

    @pytest.mark.asyncio
    async def test_verify_checkpoint_valid(self, sample_checkpoint_data):
        """Test verifying a valid checkpoint."""
        service = CheckpointService()
        result = await service.verify_checkpoint(sample_checkpoint_data)
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_checkpoint_invalid_scan_id(self):
        """Test verifying checkpoint with invalid scan ID."""
        service = CheckpointService()
        checkpoint = CheckpointData(scan_id=0)
        result = await service.verify_checkpoint(checkpoint)
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_checkpoint_invalid_phase_status(self):
        """Test verifying checkpoint validates phase status.

        Note: Pydantic validation prevents creating invalid PhaseCheckpoint.
        This test verifies the validation layer works correctly.
        """
        service = CheckpointService()
        # Try to create a checkpoint with invalid status
        # This should fail at the Pydantic validation layer
        with pytest.raises(ValueError, match="Invalid phase status"):
            PhaseCheckpoint(status="invalid_status")

        # Test that creating with valid status works
        valid_checkpoint = PhaseCheckpoint(status="completed")
        assert valid_checkpoint.status == "completed"

    @pytest.mark.asyncio
    async def test_verify_checkpoint_completed_without_time(self):
        """Test verifying checkpoint where completed phase lacks completion time."""
        service = CheckpointService()
        checkpoint = CheckpointData(
            scan_id=1,
            phases={
                "test_phase": PhaseCheckpoint(
                    status="completed",
                    completed_at=None,  # Missing completion time
                ),
            },
        )
        result = await service.verify_checkpoint(checkpoint)
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_checkpoint_unsupported_version(self):
        """Test verifying checkpoint with unsupported version."""
        service = CheckpointService()
        checkpoint = CheckpointData(scan_id=1, version="2.0")
        result = await service.verify_checkpoint(checkpoint)
        assert result is False


# ============================================================================
# Test Clean Checkpoint
# ============================================================================

class TestCleanCheckpoint:
    """Test checkpoint cleanup functionality."""

    @pytest.mark.asyncio
    async def test_clean_checkpoint_success(self, mock_scan_with_checkpoint):
        """Test successfully cleaning a checkpoint."""
        service = CheckpointService()

        with patch.object(
            service.scan_repo, "get", new=AsyncMock(return_value=mock_scan_with_checkpoint)
        ):
            with patch.object(
                service.scan_repo, "update", new=AsyncMock(return_value=mock_scan_with_checkpoint)
            ):
                with patch.object(
                    service, "_delete_checkpoint_file", new=AsyncMock(return_value=True)
                ):
                    result = await service.clean_checkpoint(scan_id=1)

        assert result is True

    @pytest.mark.asyncio
    async def test_clean_checkpoint_scan_not_found(self):
        """Test cleaning checkpoint for non-existent scan."""
        service = CheckpointService()

        with patch.object(
            service.scan_repo, "get", new=AsyncMock(return_value=None)
        ):
            result = await service.clean_checkpoint(scan_id=999)

        assert result is False


# ============================================================================
# Test Resume Strategy
# ============================================================================

class TestResumeStrategy:
    """Resume strategy over canonical ScanPhase values (Phase 18/P5-A5)."""

    @pytest.mark.asyncio
    async def test_resume_from_running_phase(self, sample_checkpoint_data):
        """A running current phase is resumed directly; completed ones skipped."""
        service = CheckpointService()
        strategy = await service.get_resume_strategy(sample_checkpoint_data)

        assert strategy.can_resume is True
        assert ScanPhase.L1_PREPARATION.value in strategy.skip_phases
        assert strategy.resume_phase == ScanPhase.ENGINE_EXECUTION.value

    @pytest.mark.asyncio
    async def test_resume_advances_past_completed(self):
        """Core resume bug: when current_phase is completed, resume from the
        NEXT pending ScanPhase — not from the first PhaseName value, which the
        old PhaseName-based phase_order wrongly returned."""
        service = CheckpointService()
        checkpoint = CheckpointData(
            scan_id=1,
            current_phase=ScanPhase.ENGINE_EXECUTION.value,
            phases={
                ScanPhase.L1_PREPARATION.value: PhaseCheckpoint(status="completed"),
                ScanPhase.SOURCE_PREPARATION.value: PhaseCheckpoint(status="completed"),
                ScanPhase.ENGINE_SELECTION.value: PhaseCheckpoint(status="completed"),
                ScanPhase.ENGINE_EXECUTION.value: PhaseCheckpoint(status="completed"),
            },
        )
        strategy = await service.get_resume_strategy(checkpoint)

        assert strategy.can_resume is True
        assert strategy.resume_phase == ScanPhase.EXPLOITABILITY_VERIFICATION.value

    @pytest.mark.asyncio
    async def test_resume_retries_failed_phase(self):
        """A failed current phase is retried and becomes the resume phase."""
        service = CheckpointService()
        checkpoint = CheckpointData(
            scan_id=1,
            current_phase=ScanPhase.ENGINE_EXECUTION.value,
            phases={
                ScanPhase.L1_PREPARATION.value: PhaseCheckpoint(status="completed"),
                ScanPhase.ENGINE_EXECUTION.value: PhaseCheckpoint(status="failed"),
            },
        )
        strategy = await service.get_resume_strategy(checkpoint)

        assert strategy.can_resume is True
        assert ScanPhase.ENGINE_EXECUTION.value in strategy.retry_phases
        assert strategy.resume_phase == ScanPhase.ENGINE_EXECUTION.value

    @pytest.mark.asyncio
    async def test_no_current_phase(self):
        """With no current phase and no tracked phases, resume is undecided."""
        service = CheckpointService()
        checkpoint = CheckpointData(
            scan_id=1,
            current_phase=None,
            phases={},
        )
        strategy = await service.get_resume_strategy(checkpoint)

        assert strategy.can_resume is True
        assert strategy.resume_phase is None or strategy.resume_phase == ScanPhase.L1_PREPARATION.value

    @pytest.mark.asyncio
    async def test_normalizes_legacy_phasename_values(self):
        """Checkpoints written with legacy PhaseName (CamelCase) values must
        still resume correctly via the alias compat map — no DB migration."""
        service = CheckpointService()
        checkpoint = CheckpointData(
            scan_id=1,
            current_phase="L3_agent",  # legacy PhaseName value
            phases={
                "L1_preparation": PhaseCheckpoint(status="completed"),
                "L3_agent": PhaseCheckpoint(status="running"),
            },
        )
        strategy = await service.get_resume_strategy(checkpoint)

        assert strategy.can_resume is True
        # Legacy L3_agent aliases to engine_execution; running → resume there.
        assert strategy.resume_phase == ScanPhase.ENGINE_EXECUTION.value
        # skip_phases are normalized to canonical ScanPhase values too.
        assert ScanPhase.L1_PREPARATION.value in strategy.skip_phases


# ============================================================================
# Test PhaseCheckpoint Model
# ============================================================================

class TestPhaseCheckpointModel:
    """Test PhaseCheckpoint Pydantic model."""

    def test_phase_checkpoint_valid_status(self):
        """Test PhaseCheckpoint with valid status."""
        checkpoint = PhaseCheckpoint(status="completed")
        assert checkpoint.status == "completed"

    def test_phase_checkpoint_invalid_status(self):
        """Test PhaseCheckpoint with invalid status raises error."""
        with pytest.raises(ValueError, match="Invalid phase status"):
            PhaseCheckpoint(status="invalid")

    def test_phase_checkpoint_with_optional_fields(self):
        """Test PhaseCheckpoint with optional fields."""
        now = datetime.now(timezone.utc)
        checkpoint = PhaseCheckpoint(
            status="running",
            output_path="/tmp/output.json",
            output_data={"count": 10},
            error_message="No error",
            started_at=now,
            files_processed=5,
            findings_found=2,
            tokens_used=1000,
        )
        assert checkpoint.status == "running"
        assert checkpoint.output_path == "/tmp/output.json"
        assert checkpoint.files_processed == 5


# ============================================================================
# Test CheckpointData Model
# ============================================================================

class TestCheckpointDataModel:
    """Test CheckpointData Pydantic model."""

    def test_checkpoint_data_creation(self):
        """Test CheckpointData creation."""
        checkpoint = CheckpointData(
            scan_id=1,
            current_phase=PhaseName.L3_AGENT,
            phases={},
            global_state={"test": "value"},
            resume_data={"index": 5},
        )
        assert checkpoint.scan_id == 1
        assert checkpoint.current_phase == PhaseName.L3_AGENT
        assert checkpoint.global_state == {"test": "value"}

    def test_checkpoint_data_get_hash(self):
        """Test CheckpointData hash generation."""
        checkpoint = CheckpointData(scan_id=1)
        hash1 = checkpoint.get_hash()
        hash2 = checkpoint.get_hash()
        assert hash1 == hash2
        assert len(hash1) == 16

    def test_checkpoint_data_default_values(self):
        """Test CheckpointData default values."""
        checkpoint = CheckpointData(scan_id=1)
        assert checkpoint.phases == {}
        assert checkpoint.global_state == {}
        assert checkpoint.resume_data == {}
        assert checkpoint.version == "1.0"
        assert isinstance(checkpoint.created_at, datetime)


# ============================================================================
# Test File Operations
# ============================================================================

class TestFileOperations:
    """Test checkpoint file operations."""

    @pytest.mark.asyncio
    async def test_save_checkpoint_to_file(self, temp_checkpoint_dir):
        """Test saving checkpoint to file."""
        service = CheckpointService()
        service._checkpoint_dir = Path(temp_checkpoint_dir)

        checkpoint = CheckpointData(scan_id=1)
        result = await service._save_checkpoint_to_file(checkpoint)

        assert result is True

        # Verify file exists
        file_path = Path(temp_checkpoint_dir) / "scan_1_checkpoint.json"
        assert file_path.exists()

    @pytest.mark.asyncio
    async def test_delete_checkpoint_file(self, temp_checkpoint_dir):
        """Test deleting checkpoint file."""
        service = CheckpointService()
        service._checkpoint_dir = Path(temp_checkpoint_dir)

        # Create a dummy file
        file_path = Path(temp_checkpoint_dir) / "scan_1_checkpoint.json"
        file_path.write_text("test")

        result = await service._delete_checkpoint_file(1)

        assert result is True
        assert not file_path.exists()
