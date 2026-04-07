"""Unit tests for WebSocket connection manager.

P11-06: Tests for WebSocket connection management and event broadcasting.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from datetime import datetime, timezone

from src.web.api.websocket import (
    WebSocketEvent,
    ConnectionManager,
    ScanEventBroadcaster,
    get_connection_manager,
    get_event_broadcaster,
)


# ============================================================================
# Test WebSocketEvent
# ============================================================================

class TestWebSocketEvent:
    """Test WebSocketEvent model."""

    def test_event_creation(self):
        """Test creating a WebSocket event."""
        event = WebSocketEvent(
            event_type="test",
            data={"key": "value"},
            scan_id=1,
        )
        assert event.event_type == "test"
        assert event.data == {"key": "value"}
        assert event.scan_id == 1
        assert isinstance(event.timestamp, datetime)

    def test_event_to_dict(self):
        """Test converting event to dictionary."""
        event = WebSocketEvent(
            event_type="phase_start",
            data={"phase": "L1_preparation"},
            scan_id=1,
        )
        data = event.to_dict()
        assert data["type"] == "phase_start"
        assert data["scan_id"] == 1
        assert data["data"]["phase"] == "L1_preparation"
        assert "timestamp" in data

    def test_event_to_json(self):
        """Test converting event to JSON string."""
        event = WebSocketEvent(
            event_type="progress",
            data={"percent": 50},
            scan_id=1,
        )
        json_str = event.to_json()
        parsed = json.loads(json_str)
        assert parsed["type"] == "progress"
        assert parsed["data"]["percent"] == 50


# ============================================================================
# Test ConnectionManager
# ============================================================================

class TestConnectionManager:
    """Test connection manager."""

    @pytest.fixture
    def manager(self):
        """Create a connection manager for testing."""
        return ConnectionManager()

    @pytest.mark.asyncio
    async def test_connect(self, manager):
        """Test connecting a WebSocket."""
        websocket = MagicMock()
        websocket.accept = AsyncMock()
        websocket.send_text = AsyncMock()
        manager.scan_connections = {}
        manager.websocket_scan_map = {}

        await manager.connect(websocket, scan_id=1)

        assert 1 in manager.scan_connections
        assert websocket in manager.scan_connections[1]
        assert manager.websocket_scan_map[websocket] == 1
        websocket.send_text.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect(self, manager):
        """Test disconnecting a WebSocket."""
        websocket = MagicMock(spec=MagicMock)
        websocket.send_text = AsyncMock()
        manager.scan_connections = {1: {websocket}}
        manager.websocket_scan_map = {websocket: 1}
        manager.ping_tasks = {}

        await manager.disconnect(websocket)

        assert 1 not in manager.scan_connections
        assert websocket not in manager.websocket_scan_map

    @pytest.mark.asyncio
    async def test_send_personal(self, manager):
        """Test sending personal message."""
        websocket = MagicMock(spec=MagicMock)
        websocket.send_text = AsyncMock()

        event = WebSocketEvent(
            event_type="test",
            data={"message": "hello"},
            scan_id=1,
        )

        await manager.send_personal(event, websocket)

        websocket.send_text.assert_called_once()
        sent_data = json.loads(websocket.send_text.call_args[0][0])
        assert sent_data["type"] == "test"

    @pytest.mark.asyncio
    async def test_broadcast_to_scan(self, manager):
        """Test broadcasting to specific scan."""
        websocket1 = MagicMock(spec=MagicMock)
        websocket1.send_text = AsyncMock()
        websocket2 = MagicMock(spec=MagicMock)
        websocket2.send_text = AsyncMock()

        manager.scan_connections = {1: {websocket1, websocket2}}

        event = WebSocketEvent(
            event_type="progress",
            data={"percent": 50},
            scan_id=1,
        )

        await manager.broadcast_to_scan(event, scan_id=1)

        assert websocket1.send_text.call_count == 1
        assert websocket2.send_text.call_count == 1

    @pytest.mark.asyncio
    async def test_broadcast_to_all(self, manager):
        """Test broadcasting to all connections."""
        websocket1 = MagicMock(spec=MagicMock)
        websocket1.send_text = AsyncMock()
        websocket2 = MagicMock(spec=MagicMock)
        websocket2.send_text = AsyncMock()

        manager.scan_connections = {
            1: {websocket1},
            2: {websocket2},
        }

        event = WebSocketEvent(
            event_type="announcement",
            data={"message": "hello all"},
        )

        await manager.broadcast_to_all(event)

        assert websocket1.send_text.call_count == 1
        assert websocket2.send_text.call_count == 1

    def test_get_connection_count_specific_scan(self, manager):
        """Test getting connection count for specific scan."""
        websocket1 = MagicMock()
        websocket2 = MagicMock()
        manager.scan_connections = {
            1: {websocket1, websocket2},
            2: {MagicMock()},
        }

        count = manager.get_connection_count(scan_id=1)
        assert count == 2

    def test_get_connection_count_all(self, manager):
        """Test getting total connection count."""
        websocket1 = MagicMock()
        websocket2 = MagicMock()
        websocket3 = MagicMock()
        manager.scan_connections = {
            1: {websocket1, websocket2},
            2: {websocket3},
        }

        count = manager.get_connection_count()
        assert count == 3

    def test_get_active_scans(self, manager):
        """Test getting list of active scans."""
        manager.scan_connections = {1: set(), 2: set(), 3: set()}

        active = manager.get_active_scans()
        assert set(active) == {1, 2, 3}


# ============================================================================
# Test ScanEventBroadcaster
# ============================================================================

class TestScanEventBroadcaster:
    """Test scan event broadcaster."""

    @pytest.fixture
    def broadcaster(self):
        """Create a broadcaster for testing."""
        manager = ConnectionManager()
        return ScanEventBroadcaster(manager)

    @pytest.mark.asyncio
    async def test_broadcast_phase_start(self, broadcaster):
        """Test broadcasting phase start."""
        websocket = MagicMock(spec=MagicMock)
        websocket.send_text = AsyncMock()
        broadcaster.manager.scan_connections = {1: {websocket}}

        await broadcaster.broadcast_phase_start(
            scan_id=1,
            phase_name="L1_preparation",
            phase_data={"files_count": 100},
        )

        websocket.send_text.assert_called_once()
        sent_data = json.loads(websocket.send_text.call_args[0][0])
        assert sent_data["type"] == "phase_start"
        assert sent_data["data"]["phase"] == "L1_preparation"
        assert sent_data["data"]["files_count"] == 100

    @pytest.mark.asyncio
    async def test_broadcast_phase_complete(self, broadcaster):
        """Test broadcasting phase complete."""
        websocket = MagicMock(spec=MagicMock)
        websocket.send_text = AsyncMock()
        broadcaster.manager.scan_connections = {1: {websocket}}

        await broadcaster.broadcast_phase_complete(
            scan_id=1,
            phase_name="L1_preparation",
            duration_seconds=45.5,
            findings=3,
            tokens_used=1000,
        )

        websocket.send_text.assert_called_once()
        sent_data = json.loads(websocket.send_text.call_args[0][0])
        assert sent_data["type"] == "phase_complete"
        assert sent_data["data"]["duration_seconds"] == 45.5
        assert sent_data["data"]["findings"] == 3
        assert sent_data["data"]["tokens_used"] == 1000

    @pytest.mark.asyncio
    async def test_broadcast_finding(self, broadcaster):
        """Test broadcasting new finding."""
        websocket = MagicMock(spec=MagicMock)
        websocket.send_text = AsyncMock()
        broadcaster.manager.scan_connections = {1: {websocket}}

        finding_data = {
            "vuln_type": "sql_injection",
            "severity": "high",
            "file_path": "test.py",
            "line": 42,
        }

        await broadcaster.broadcast_finding(scan_id=1, finding_data=finding_data)

        websocket.send_text.assert_called_once()
        sent_data = json.loads(websocket.send_text.call_args[0][0])
        assert sent_data["type"] == "finding_new"
        assert sent_data["data"]["vuln_type"] == "sql_injection"
        assert sent_data["data"]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_broadcast_scan_progress(self, broadcaster):
        """Test broadcasting scan progress."""
        websocket = MagicMock(spec=MagicMock)
        websocket.send_text = AsyncMock()
        broadcaster.manager.scan_connections = {1: {websocket}}

        await broadcaster.broadcast_scan_progress(
            scan_id=1,
            progress_percent=75,
            current_file="test.py",
            message="Analyzing file",
        )

        websocket.send_text.assert_called_once()
        sent_data = json.loads(websocket.send_text.call_args[0][0])
        assert sent_data["type"] == "progress"
        assert sent_data["data"]["progress_percent"] == 75
        assert sent_data["data"]["current_file"] == "test.py"
        assert sent_data["data"]["message"] == "Analyzing file"

    @pytest.mark.asyncio
    async def test_broadcast_scan_complete(self, broadcaster):
        """Test broadcasting scan complete."""
        websocket = MagicMock(spec=MagicMock)
        websocket.send_text = AsyncMock()
        broadcaster.manager.scan_connections = {1: {websocket}}

        await broadcaster.broadcast_scan_complete(
            scan_id=1,
            findings_count=15,
            duration_seconds=300.0,
            tokens_used=50000,
        )

        websocket.send_text.assert_called_once()
        sent_data = json.loads(websocket.send_text.call_args[0][0])
        assert sent_data["type"] == "scan_complete"
        assert sent_data["data"]["findings_count"] == 15
        assert sent_data["data"]["duration_seconds"] == 300.0

    @pytest.mark.asyncio
    async def test_broadcast_scan_failed(self, broadcaster):
        """Test broadcasting scan failed."""
        websocket = MagicMock(spec=MagicMock)
        websocket.send_text = AsyncMock()
        broadcaster.manager.scan_connections = {1: {websocket}}

        await broadcaster.broadcast_scan_failed(
            scan_id=1,
            error_message="Out of memory",
        )

        websocket.send_text.assert_called_once()
        sent_data = json.loads(websocket.send_text.call_args[0][0])
        assert sent_data["type"] == "scan_failed"
        assert "Out of memory" in sent_data["data"]["error"]

    @pytest.mark.asyncio
    async def test_broadcast_scan_paused(self, broadcaster):
        """Test broadcasting scan paused."""
        websocket = MagicMock(spec=MagicMock)
        websocket.send_text = AsyncMock()
        broadcaster.manager.scan_connections = {1: {websocket}}

        await broadcaster.broadcast_scan_paused(
            scan_id=1,
            checkpoint_saved=True,
        )

        websocket.send_text.assert_called_once()
        sent_data = json.loads(websocket.send_text.call_args[0][0])
        assert sent_data["type"] == "scan_paused"
        assert sent_data["data"]["checkpoint_saved"] is True


# ============================================================================
# Test Factory Functions
# ============================================================================

class TestFactoryFunctions:
    """Test factory functions."""

    def test_get_connection_manager_singleton(self):
        """Test that get_connection_manager returns singleton."""
        manager1 = get_connection_manager()
        manager2 = get_connection_manager()
        assert manager1 is manager2

    def test_get_event_broadcaster_singleton(self):
        """Test that get_event_broadcaster returns singleton."""
        broadcaster1 = get_event_broadcaster()
        broadcaster2 = get_event_broadcaster()
        assert broadcaster1 is not broadcaster2
        assert broadcaster1.manager is broadcaster2.manager
