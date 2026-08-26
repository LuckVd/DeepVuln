"""Unit tests for web service models."""

import pytest

from src.web.models.database import Base
from src.web.models.scan import Scan, ScanPhase, ScanEvent, ScanStatus, ScanType, PhaseName
from src.web.models.finding import Finding
from src.web.models.checkpoint import ScanFile, ApiKey


class TestScan:
    """Test Scan model."""

    def test_scan_create(self):
        """Test creating a scan instance."""
        scan = Scan(
            status=ScanStatus.PENDING,
            scan_type=ScanType.FULL,
            config={"max_depth": 3},
            progress_percent=0
        )
        assert scan.scan_type == ScanType.FULL
        assert scan.status == ScanStatus.PENDING
        assert scan.progress_percent == 0

    def test_scan_counts_initialization(self):
        """Test scan statistics are initialized to zero."""
        scan = Scan(
            status=ScanStatus.PENDING,
            scan_type=ScanType.FULL,
            config={},
            findings_count=0,
            verified_count=0,
            critical_count=0,
            tokens_used=0
        )
        assert scan.findings_count == 0
        assert scan.verified_count == 0
        assert scan.critical_count == 0
        assert scan.tokens_used == 0


class TestScanPhase:
    """Test ScanPhase model."""

    def test_scan_phase_create(self):
        """Test creating a scan phase instance."""
        phase = ScanPhase(
            scan_id=1,
            phase_name=PhaseName.L3_AGENT,
            engine_name="agent",
            status="running"
        )
        assert phase.scan_id == 1
        assert phase.phase_name == PhaseName.L3_AGENT
        assert phase.status == "running"


class TestScanEvent:
    """Test ScanEvent model."""

    def test_scan_event_create(self):
        """Test creating a scan event instance."""
        event = ScanEvent(
            scan_id=1,
            event_type="finding_new",
            message="Found SQL injection",
            file_path="src/main.py",
            file_index=5,
            file_total=100
        )
        assert event.scan_id == 1
        assert event.event_type == "finding_new"
        assert event.file_index == 5
        assert event.file_total == 100

    def test_scan_event_agent_fields(self):
        """Test agent-specific fields."""
        event = ScanEvent(
            scan_id=1,
            event_type="adversarial_round",
            agent_turn=2,
            agent_role="critic",
            agent_message="I question this finding...",
            tokens_used=350
        )
        assert event.agent_turn == 2
        assert event.agent_role == "critic"
        assert event.tokens_used == 350


class TestFinding:
    """Test Finding model."""

    def test_finding_create(self):
        """Test creating a finding instance."""
        finding = Finding(
            scan_id=1,
            vuln_type="sql_injection",
            severity="high",
            file_path="src/main.py",
            line_start=42,
            title="SQL injection vulnerability"
        )
        assert finding.scan_id == 1
        assert finding.vuln_type == "sql_injection"
        assert finding.severity == "high"
        assert finding.line_start == 42


class TestScanFile:
    """Test ScanFile model."""

    def test_scan_file_create(self):
        """Test creating a scan file instance."""
        scan_file = ScanFile(
            scan_id=1,
            file_path="src/main.py",
            file_hash="abc123",
            findings_count=2
        )
        assert scan_file.scan_id == 1
        assert scan_file.file_path == "src/main.py"
        assert scan_file.findings_count == 2


class TestApiKey:
    """Test ApiKey model."""

    def test_api_key_create(self):
        """Test creating an API key instance."""
        api_key = ApiKey(
            key_hash="hashed_key_here",
            name="Test Key",
            is_active=True
        )
        assert api_key.key_hash == "hashed_key_here"
        assert api_key.name == "Test Key"
        assert api_key.is_active is True
