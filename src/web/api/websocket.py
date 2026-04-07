"""WebSocket connection manager for real-time scan progress.

P11-06: This module provides WebSocket support for broadcasting scan events
to connected clients in real-time.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Set, Any, Optional

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


# ============================================================================
# WebSocket Events
# ============================================================================

class WebSocketEvent:
    """Structured WebSocket event."""

    def __init__(
        self,
        event_type: str,
        data: Dict[str, Any],
        scan_id: Optional[int] = None,
        timestamp: Optional[datetime] = None,
    ):
        self.event_type = event_type
        self.data = data
        self.scan_id = scan_id
        self.timestamp = timestamp or datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for JSON serialization."""
        return {
            "type": self.event_type,
            "scan_id": self.scan_id,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_json(self) -> str:
        """Convert event to JSON string."""
        return json.dumps(self.to_dict())


# ============================================================================
# Connection Manager
# ============================================================================

class ConnectionManager:
    """Manages WebSocket connections and broadcasts messages."""

    def __init__(self):
        """Initialize the connection manager."""
        # scan_id -> set of WebSocket connections
        self.scan_connections: Dict[int, Set[WebSocket]] = {}
        # WebSocket -> scan_id mapping for cleanup
        self.websocket_scan_map: Dict[WebSocket, int] = {}
        # Active ping tasks
        self.ping_tasks: Dict[WebSocket, asyncio.Task] = {}

    async def connect(self, websocket: WebSocket, scan_id: int) -> None:
        """Connect a WebSocket to a scan.

        Args:
            websocket: WebSocket connection
            scan_id: ID of the scan to subscribe to
        """
        await websocket.accept()

        # Add to scan connections
        if scan_id not in self.scan_connections:
            self.scan_connections[scan_id] = set()
        self.scan_connections[scan_id].add(websocket)

        # Track mapping
        self.websocket_scan_map[websocket] = scan_id

        # Send welcome message
        await self.send_personal(
            WebSocketEvent(
                event_type="connected",
                data={"scan_id": scan_id},
                scan_id=scan_id,
            ),
            websocket,
        )

        # Start heartbeat
        self.ping_tasks[websocket] = asyncio.create_task(
            self._heartbeat(websocket)
        )

        logger.info(f"WebSocket connected for scan {scan_id}")

    async def disconnect(self, websocket: WebSocket) -> None:
        """Disconnect a WebSocket.

        Args:
            websocket: WebSocket connection to disconnect
        """
        # Cancel heartbeat if running
        if websocket in self.ping_tasks:
            self.ping_tasks[websocket].cancel()
            del self.ping_tasks[websocket]

        # Remove from scan connections
        if websocket in self.websocket_scan_map:
            scan_id = self.websocket_scan_map[websocket]
            if scan_id in self.scan_connections:
                self.scan_connections[scan_id].discard(websocket)
                # Clean up empty sets
                if not self.scan_connections[scan_id]:
                    del self.scan_connections[scan_id]
            del self.websocket_scan_map[websocket]

        logger.info("WebSocket disconnected")

    async def send_personal(
        self,
        event: WebSocketEvent,
        websocket: WebSocket,
    ) -> None:
        """Send an event to a specific WebSocket connection.

        Args:
            event: Event to send
            websocket: WebSocket connection to send to
        """
        try:
            await websocket.send_text(event.to_json())
        except Exception as e:
            logger.warning(f"Failed to send personal message: {e}")
            await self.disconnect(websocket)

    async def broadcast_to_scan(
        self,
        event: WebSocketEvent,
        scan_id: int,
    ) -> None:
        """Broadcast an event to all connections watching a scan.

        Args:
            event: Event to broadcast
            scan_id: ID of the scan to broadcast to
        """
        if scan_id not in self.scan_connections:
            return

        # Create a copy of connections to avoid modification during iteration
        connections = list(self.scan_connections[scan_id])

        for websocket in connections:
            try:
                await websocket.send_text(event.to_json())
            except Exception as e:
                logger.warning(
                    f"Failed to broadcast to scan {scan_id}: {e}"
                )
                await self.disconnect(websocket)

    async def broadcast_to_all(self, event: WebSocketEvent) -> None:
        """Broadcast an event to all connected WebSockets.

        Args:
            event: Event to broadcast
        """
        # Gather all unique connections
        all_connections: Set[WebSocket] = set()
        for connections in self.scan_connections.values():
            all_connections.update(connections)

        for websocket in list(all_connections):
            try:
                await websocket.send_text(event.to_json())
            except Exception as e:
                logger.warning(f"Failed to broadcast to all: {e}")
                await self.disconnect(websocket)

    async def _heartbeat(self, websocket: WebSocket, interval: int = 30) -> None:
        """Send periodic ping to keep connection alive.

        Args:
            websocket: WebSocket connection
            interval: Ping interval in seconds
        """
        try:
            while True:
                await asyncio.sleep(interval)
                ping_event = WebSocketEvent(
                    event_type="ping",
                    data={},
                )
                await self.send_personal(ping_event, websocket)
        except asyncio.CancelledError:
            # Task was cancelled, exit gracefully
            pass
        except Exception as e:
            logger.warning(f"Heartbeat error: {e}")
            await self.disconnect(websocket)

    def get_connection_count(self, scan_id: Optional[int] = None) -> int:
        """Get the number of active connections.

        Args:
            scan_id: Optional scan ID to filter by

        Returns:
            Number of active connections
        """
        if scan_id is not None:
            return len(self.scan_connections.get(scan_id, set()))
        return sum(len(conns) for conns in self.scan_connections.values())

    def get_active_scans(self) -> List[int]:
        """Get list of scan IDs with active connections.

        Returns:
            List of scan IDs
        """
        return list(self.scan_connections.keys())


# ============================================================================
# Scan Event Broadcasting
# ============================================================================

class ScanEventBroadcaster:
    """Broadcasts scan events to WebSocket clients."""

    def __init__(self, manager: ConnectionManager):
        """Initialize the broadcaster.

        Args:
            manager: Connection manager instance
        """
        self.manager = manager

    async def broadcast_phase_start(
        self,
        scan_id: int,
        phase_name: str,
        phase_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Broadcast phase start event.

        Args:
            scan_id: ID of the scan
            phase_name: Name of the phase starting
            phase_data: Optional additional phase data
        """
        event = WebSocketEvent(
            event_type="phase_start",
            data={
                "phase": phase_name,
                **(phase_data or {}),
            },
            scan_id=scan_id,
        )
        await self.manager.broadcast_to_scan(event, scan_id)

    async def broadcast_phase_complete(
        self,
        scan_id: int,
        phase_name: str,
        duration_seconds: float,
        findings: int = 0,
        tokens_used: int = 0,
    ) -> None:
        """Broadcast phase complete event.

        Args:
            scan_id: ID of the scan
            phase_name: Name of the completed phase
            duration_seconds: Phase duration
            findings: Number of findings found
            tokens_used: Number of tokens used
        """
        event = WebSocketEvent(
            event_type="phase_complete",
            data={
                "phase": phase_name,
                "duration_seconds": duration_seconds,
                "findings": findings,
                "tokens_used": tokens_used,
            },
            scan_id=scan_id,
        )
        await self.manager.broadcast_to_scan(event, scan_id)

    async def broadcast_finding(
        self,
        scan_id: int,
        finding_data: Dict[str, Any],
    ) -> None:
        """Broadcast new finding event.

        Args:
            scan_id: ID of the scan
            finding_data: Finding details
        """
        event = WebSocketEvent(
            event_type="finding_new",
            data=finding_data,
            scan_id=scan_id,
        )
        await self.manager.broadcast_to_scan(event, scan_id)

    async def broadcast_scan_progress(
        self,
        scan_id: int,
        progress_percent: int,
        current_file: Optional[str] = None,
        message: Optional[str] = None,
    ) -> None:
        """Broadcast scan progress update.

        Args:
            scan_id: ID of the scan
            progress_percent: Progress percentage (0-100)
            current_file: Optional current file being processed
            message: Optional status message
        """
        event = WebSocketEvent(
            event_type="progress",
            data={
                "progress_percent": progress_percent,
                "current_file": current_file,
                "message": message,
            },
            scan_id=scan_id,
        )
        await self.manager.broadcast_to_scan(event, scan_id)

    async def broadcast_scan_complete(
        self,
        scan_id: int,
        findings_count: int,
        duration_seconds: float,
        tokens_used: int,
    ) -> None:
        """Broadcast scan complete event.

        Args:
            scan_id: ID of the scan
            findings_count: Total findings found
            duration_seconds: Total scan duration
            tokens_used: Total tokens used
        """
        event = WebSocketEvent(
            event_type="scan_complete",
            data={
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
                "tokens_used": tokens_used,
            },
            scan_id=scan_id,
        )
        await self.manager.broadcast_to_scan(event, scan_id)

    async def broadcast_scan_failed(
        self,
        scan_id: int,
        error_message: str,
    ) -> None:
        """Broadcast scan failed event.

        Args:
            scan_id: ID of the scan
            error_message: Error message
        """
        event = WebSocketEvent(
            event_type="scan_failed",
            data={
                "error": error_message,
            },
            scan_id=scan_id,
        )
        await self.manager.broadcast_to_scan(event, scan_id)

    async def broadcast_scan_paused(
        self,
        scan_id: int,
        checkpoint_saved: bool,
    ) -> None:
        """Broadcast scan paused event.

        Args:
            scan_id: ID of the scan
            checkpoint_saved: Whether checkpoint was saved
        """
        event = WebSocketEvent(
            event_type="scan_paused",
            data={
                "checkpoint_saved": checkpoint_saved,
            },
            scan_id=scan_id,
        )
        await self.manager.broadcast_to_scan(event, scan_id)


# ============================================================================
# Global Manager Instance
# ============================================================================

_manager: Optional[ConnectionManager] = None


def get_connection_manager() -> ConnectionManager:
    """Get or create the global connection manager.

    Returns:
        ConnectionManager instance
    """
    global _manager
    if _manager is None:
        _manager = ConnectionManager()
    return _manager


def get_event_broadcaster() -> ScanEventBroadcaster:
    """Get or create the event broadcaster.

    Returns:
        ScanEventBroadcaster instance
    """
    manager = get_connection_manager()
    return ScanEventBroadcaster(manager)
