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
        with patch("src.web.services.checkpoint_service.AsyncSessionLocal", return_value=mock_session):
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
    """Create sample checkpoint data."""
    return CheckpointData(
        scan_id=1,
        current_phase=PhaseName.L3_AGENT,
        phases={
            PhaseName.L1_PREPARATION: PhaseCheckpoint(
                status="completed",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                files_processed=10,
            ),
            PhaseName.L3_AGENT: PhaseCheckpoint(
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
    """Test resume strategy determination."""

    @pytest.mark.asyncio
    async def test_get_resume_strategy_with_completed_phases(self, sample_checkpoint_data):
        """Test resume strategy when some phases are completed."""
        service = CheckpointService()
        strategy = await service.get_resume_strategy(sample_checkpoint_data)

        assert strategy.can_resume is True
        assert PhaseName.L1_PREPARATION in strategy.skip_phases
        assert strategy.resume_phase == PhaseName.L3_AGENT

    @pytest.mark.asyncio
    async def test_get_resume_strategy_all_completed(self):
        """Test resume strategy when all phases are completed."""
        service = CheckpointService()
        checkpoint = CheckpointData(
            scan_id=1,
            current_phase=PhaseName.REPORT_GENERATION,
            phases={
                PhaseName.L1_PREPARATION: PhaseCheckpoint(status="completed"),
                PhaseName.L3_AGENT: PhaseCheckpoint(status="completed"),
                PhaseName.REPORT_GENERATION: PhaseCheckpoint(status="completed"),
            },
        )
        strategy = await service.get_resume_strategy(checkpoint)

        assert strategy.can_resume is True
        assert len(strategy.skip_phases) == 3

    @pytest.mark.asyncio
    async def test_get_resume_strategy_with_failed_phase(self):
        """Test resume strategy when a phase failed."""
        service = CheckpointService()
        checkpoint = CheckpointData(
            scan_id=1,
            current_phase=PhaseName.L3_AGENT,
            phases={
                PhaseName.L1_PREPARATION: PhaseCheckpoint(status="completed"),
                PhaseName.L3_AGENT: PhaseCheckpoint(status="failed"),
            },
        )
        strategy = await service.get_resume_strategy(checkpoint)

        assert strategy.can_resume is True
        assert PhaseName.L3_AGENT in strategy.retry_phases
        assert strategy.resume_phase == PhaseName.L3_AGENT

    @pytest.mark.asyncio
    async def test_get_resume_strategy_no_current_phase(self):
        """Test resume strategy when no current phase is set."""
        service = CheckpointService()
        checkpoint = CheckpointData(
            scan_id=1,
            current_phase=None,
            phases={},
        )
        strategy = await service.get_resume_strategy(checkpoint)

        # When no phases exist, strategy should determine first phase
        assert strategy.can_resume is True
        # Should resume from first phase (L1_PREPARATION)
        # or it could be None if no phases are tracked
        assert strategy.resume_phase is None or strategy.resume_phase == PhaseName.L1_PREPARATION


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
