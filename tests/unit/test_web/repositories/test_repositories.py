"""Unit tests for repository classes."""

import pytest

from src.web.repositories.scan import ScanRepository
from src.web.repositories.finding import FindingRepository
from src.web.repositories.event import ScanPhaseRepository, ScanEventRepository


class TestScanRepository:
    """Test ScanRepository."""

    def test_scan_repository_initialization(self):
        """Test that ScanRepository can be initialized."""
        repo = ScanRepository()
        assert hasattr(repo, "get_with_phases")
        assert hasattr(repo, "get_with_events")
        assert hasattr(repo, "list_by_status")
        assert hasattr(repo, "get_running_scans")
        assert hasattr(repo, "update_progress")
        assert hasattr(repo, "update_status")


class TestFindingRepository:
    """Test FindingRepository."""

    def test_finding_repository_initialization(self):
        """Test that FindingRepository can be initialized."""
        repo = FindingRepository()
        assert hasattr(repo, "get_by_scan")
        assert hasattr(repo, "get_by_file")
        assert hasattr(repo, "count_by_severity")
        assert hasattr(repo, "get_summary")


class TestScanEventRepository:
    """Test ScanEvent and ScanPhase repositories."""

    def test_scan_phase_repository_initialization(self):
        """Test that ScanPhaseRepository can be initialized."""
        repo = ScanPhaseRepository()
        assert hasattr(repo, "get_by_scan")
        assert hasattr(repo, "get_by_name")
        assert hasattr(repo, "get_current_phase")
        assert hasattr(repo, "update_status")

    def test_scan_event_repository_initialization(self):
        """Test that ScanEventRepository can be initialized."""
        repo = ScanEventRepository()
        assert hasattr(repo, "get_by_scan")
        assert hasattr(repo, "get_recent_by_scan")
        assert hasattr(repo, "get_agent_conversation")
        assert hasattr(repo, "create_event")
