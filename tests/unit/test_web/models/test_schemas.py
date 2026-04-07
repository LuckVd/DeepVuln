"""Unit tests for Pydantic schemas."""

import pytest
from pydantic import ValidationError

from src.web.models.schemas import (
    ProjectCreate, ProjectUpdate, ProjectResponse,
    ScanCreate, ScanResponse, ScanProgressResponse, TokenInfo, FindingSummary,
    FindingCreate, FindingUpdate, FindingResponse,
    AgentConversationResponse, AdversarialStatus, AgentConversationMessage,
    ScanStatus, ScanType, SeverityLevel, FindingStatus,
)


class TestProjectSchemas:
    """Test project schemas."""

    def test_project_create_valid(self):
        """Test creating a valid project."""
        project = ProjectCreate(
            name="test-project",
            source_type="git",
            source_path="https://github.com/test/repo.git"
        )
        assert project.name == "test-project"
        assert project.source_type == "git"

    def test_project_create_invalid_source_type(self):
        """Test project creation fails with invalid source type."""
        with pytest.raises(ValidationError):
            ProjectCreate(
                name="test",
                source_type="invalid",
                source_path="/path"
            )

    def test_project_update_partial(self):
        """Test partial project update."""
        update = ProjectUpdate(name="new-name")
        assert update.name == "new-name"
        assert update.description is None


class TestScanSchemas:
    """Test scan schemas."""

    def test_scan_create_valid(self):
        """Test creating a valid scan."""
        scan = ScanCreate(
            project_id=1,
            scan_type=ScanType.FULL,
            config={"max_depth": 3}
        )
        assert scan.project_id == 1
        assert scan.scan_type == ScanType.FULL

    def test_scan_create_invalid_type(self):
        """Test scan creation fails with invalid type."""
        with pytest.raises(ValidationError):
            ScanCreate(
                project_id=1,
                scan_type="invalid"
            )


class TestTokenInfo:
    """Test TokenInfo schema."""

    def test_token_info_calculate(self):
        """Test token percentage calculation."""
        info = TokenInfo.calculate(used=25000, budget=100000)
        assert info.used == 25000
        assert info.budget == 100000
        assert info.percent == 25.0

    def test_token_info_zero_budget(self):
        """Test token info with zero budget."""
        info = TokenInfo.calculate(used=100, budget=0)
        assert info.percent == 0.0


class TestFindingSummary:
    """Test FindingSummary schema."""

    def test_finding_summary_defaults(self):
        """Test finding summary default values."""
        summary = FindingSummary()
        assert summary.total == 0
        assert summary.by_severity["critical"] == 0
        assert summary.by_severity["high"] == 0


class TestScanProgressResponse:
    """Test ScanProgressResponse schema."""

    def test_scan_progress_response(self):
        """Test scan progress response structure."""
        progress = ScanProgressResponse(
            scan_id=1,
            status="running",
            progress_percent=45,
            current_phase="L3_agent",
            current_step="Analyzing file...",
            current_engine="agent"
        )
        assert progress.scan_id == 1
        assert progress.progress_percent == 45
        assert progress.current_phase == "L3_agent"


class TestAgentConversationResponse:
    """Test AgentConversationResponse schema."""

    def test_agent_conversation_response(self):
        """Test agent conversation response structure."""
        response = AgentConversationResponse(
            scan_id=1,
            phase="L3_agent",
            current_file={"path": "src/main.py", "index": 5, "total": 100},
            conversation=[
                AgentConversationMessage(
                    turn=1,
                    role="user",
                    message="Analyze this code"
                ),
                AgentConversationMessage(
                    turn=2,
                    role="assistant",
                    message="I found a vulnerability",
                    reasoning="Data flow analysis shows...",
                    tokens=280
                )
            ],
            adversarial_status=AdversarialStatus(
                active=True,
                round=2,
                max_rounds=5
            )
        )
        assert response.scan_id == 1
        assert len(response.conversation) == 2
        assert response.conversation[0].role == "user"
        assert response.conversation[1].reasoning is not None
        assert response.adversarial_status.active is True


class TestFindingSchemas:
    """Test finding schemas."""

    def test_finding_create_valid(self):
        """Test creating a valid finding."""
        finding = FindingCreate(
            vuln_type="sql_injection",
            severity=SeverityLevel.HIGH,
            file_path="src/main.py",
            line_start=42,
            title="SQL injection vulnerability"
        )
        assert finding.vuln_type == "sql_injection"
        assert finding.severity == SeverityLevel.HIGH

    def test_finding_update_status(self):
        """Test updating finding status."""
        update = FindingUpdate(
            status=FindingStatus.CONFIRMED
        )
        assert update.status == FindingStatus.CONFIRMED


class TestEnums:
    """Test enum constants."""

    def test_scan_status_values(self):
        """Test ScanStatus enum values."""
        assert ScanStatus.PENDING == "pending"
        assert ScanStatus.RUNNING == "running"
        assert ScanStatus.COMPLETED == "completed"

    def test_scan_type_values(self):
        """Test ScanType enum values."""
        assert ScanType.FULL == "full"
        assert ScanType.INCREMENTAL == "incremental"

    def test_severity_level_values(self):
        """Test SeverityLevel enum values."""
        assert SeverityLevel.CRITICAL == "critical"
        assert SeverityLevel.HIGH == "high"
        assert SeverityLevel.MEDIUM == "medium"
