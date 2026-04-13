"""WebSocket connection manager for real-time scan progress.

P11-06: This module provides WebSocket support for broadcasting scan events
to connected clients in real-time.

Redis Pub/Sub bridge: Celery workers broadcast events via Redis pub/sub.
The FastAPI process subscribes and relays to connected WebSocket clients.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Set, Any, Optional

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

# Redis pub/sub channel pattern for scan events
REDIS_SCAN_CHANNEL_PREFIX = "deepvuln:scan_events:"


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
    """Manages WebSocket connections and broadcasts messages.

    Supports Redis pub/sub bridge for cross-process communication:
    - Celery workers publish events to Redis channels
    - This manager subscribes and relays to local WebSocket clients
    """

    def __init__(self):
        """Initialize the connection manager."""
        # scan_id -> set of WebSocket connections
        self.scan_connections: Dict[int, Set[WebSocket]] = {}
        # WebSocket -> scan_id mapping for cleanup
        self.websocket_scan_map: Dict[WebSocket, int] = {}
        # Active ping tasks
        self.ping_tasks: Dict[WebSocket, asyncio.Task] = {}
        # Redis pub/sub state
        self._redis_publisher = None
        self._redis_subscriber = None
        self._subscriber_task: Optional[asyncio.Task] = None

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

        Also publishes to Redis so other processes (e.g. Celery workers)
        can relay events to their local WebSocket clients.

        Args:
            event: Event to broadcast
            scan_id: ID of the scan to broadcast to
        """
        # Always publish to Redis for cross-process delivery
        await self._publish_to_redis(scan_id, event)

        # Deliver to local WebSocket connections
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

    # ========================================================================
    # Redis Pub/Sub Bridge
    # ========================================================================

    async def _get_redis_publisher(self):
        """Get or create Redis client for publishing."""
        if self._redis_publisher is None:
            try:
                import redis.asyncio as aioredis
                from src.web.core.celery_app import get_celery_settings
                settings = get_celery_settings()
                self._redis_publisher = aioredis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                )
                logger.info("Redis publisher connected")
            except Exception as e:
                logger.warning(f"Failed to create Redis publisher: {e}")
        return self._redis_publisher

    async def _publish_to_redis(self, scan_id: int, event: WebSocketEvent) -> None:
        """Publish an event to Redis channel for cross-process delivery.

        Args:
            scan_id: ID of the scan
            event: Event to publish
        """
        try:
            redis = await self._get_redis_publisher()
            if redis is None:
                return
            channel = f"{REDIS_SCAN_CHANNEL_PREFIX}{scan_id}"
            await redis.publish(channel, event.to_json())
        except Exception as e:
            logger.debug(f"Redis publish failed (non-critical): {e}")

    async def start_redis_subscriber(self) -> None:
        """Start Redis subscriber to relay events from Celery workers.

        This should be called during FastAPI startup.
        """
        if self._subscriber_task is not None:
            return
        self._subscriber_task = asyncio.create_task(self._redis_subscribe_loop())
        logger.info("Redis subscriber started")

    async def stop_redis_subscriber(self) -> None:
        """Stop Redis subscriber. Called during FastAPI shutdown."""
        if self._subscriber_task:
            self._subscriber_task.cancel()
            try:
                await self._subscriber_task
            except asyncio.CancelledError:
                pass
            self._subscriber_task = None
        if self._redis_subscriber:
            await self._redis_subscriber.close()
            self._redis_subscriber = None
        if self._redis_publisher:
            await self._redis_publisher.close()
            self._redis_publisher = None
        logger.info("Redis subscriber stopped")

    async def _redis_subscribe_loop(self) -> None:
        """Background task that subscribes to scan event channels via Redis.

        Includes automatic reconnection with exponential backoff.
        """
        import redis.asyncio as aioredis
        from src.web.core.celery_app import get_celery_settings

        retry_count = 0
        max_retries = 100
        base_delay = 2

        while self._running:
            try:
                settings = get_celery_settings()
                self._redis_subscriber = aioredis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                )
                pubsub = self._redis_subscriber.pubsub()
                await pubsub.psubscribe(f"{REDIS_SCAN_CHANNEL_PREFIX}*")
                logger.info(f"Redis subscribed to {REDIS_SCAN_CHANNEL_PREFIX}*")
                retry_count = 0  # Reset on successful connection

                async for message in pubsub.listen():
                    if message["type"] != "pmessage":
                        continue
                    try:
                        channel = message["channel"]
                        scan_id_str = channel.replace(REDIS_SCAN_CHANNEL_PREFIX, "")
                        scan_id = int(scan_id_str)

                        event_data = json.loads(message["data"])

                        if scan_id not in self.scan_connections:
                            continue

                        connections = list(self.scan_connections[scan_id])
                        for websocket in connections:
                            try:
                                await websocket.send_text(message["data"])
                            except Exception as e:
                                logger.warning(f"Failed to relay to scan {scan_id}: {e}")
                                await self.disconnect(websocket)

                    except Exception as e:
                        logger.warning(f"Error processing Redis message: {e}")

                # If pubsub.listen() returns normally (unsubscribed), try to reconnect
                if pubsub:
                    await pubsub.close()

            except asyncio.CancelledError:
                logger.info("Redis subscriber loop cancelled")
                return
            except Exception as e:
                retry_count += 1
                if retry_count >= max_retries:
                    logger.error(f"Redis subscriber max retries ({max_retries}) exceeded")
                    return
                delay = min(base_delay * (2 ** (retry_count - 1)), 60)
                logger.error(f"Redis subscriber error (retry {retry_count}/{max_retries} in {delay}s): {e}")
                await asyncio.sleep(delay)

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
        result: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Broadcast phase complete event.

        Args:
            scan_id: ID of the scan
            phase_name: Name of the completed phase
            duration_seconds: Phase duration
            findings: Number of findings found
            tokens_used: Number of tokens used
            result: Optional phase result data for detailed terminal output
        """
        data: Dict[str, Any] = {
            "phase": phase_name,
            "duration_seconds": duration_seconds,
            "findings": findings,
            "tokens_used": tokens_used,
        }
        if result:
            # Forward selected result fields for terminal display
            for key in (
                "total_files", "languages", "frameworks", "attack_surface",
                "engines", "verified_findings", "unique_findings",
                "duplicates_removed", "confirmed", "rejected",
                "total_findings", "total_tokens", "estimated_cost",
                "per_engine_details", "severity_breakdown", "per_phase_tokens",
                "file_counts", "primary_language",
            ):
                if key in result:
                    data[key] = result[key]
        event = WebSocketEvent(
            event_type="phase_complete",
            data=data,
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
        severity_breakdown: Optional[Dict[str, int]] = None,
        per_phase_tokens: Optional[Dict[str, int]] = None,
    ) -> None:
        """Broadcast scan complete event.

        Args:
            scan_id: ID of the scan
            findings_count: Total findings found
            duration_seconds: Total scan duration
            tokens_used: Total tokens used
            severity_breakdown: Optional severity distribution stats
            per_phase_tokens: Optional per-phase token usage breakdown
        """
        data: Dict[str, Any] = {
            "findings_count": findings_count,
            "duration_seconds": duration_seconds,
            "tokens_used": tokens_used,
        }
        if severity_breakdown:
            data["severity_breakdown"] = severity_breakdown
        if per_phase_tokens:
            data["per_phase_tokens"] = per_phase_tokens
        event = WebSocketEvent(
            event_type="scan_complete",
            data=data,
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

    async def broadcast_event(
        self,
        scan_id: int,
        event_type: str,
        data: Dict[str, Any],
    ) -> None:
        """Broadcast a custom event to WebSocket clients.

        This is a generic method used for ad-hoc event types such as
        adversarial verification rounds, agent conversation turns, etc.

        Args:
            scan_id: ID of the scan
            event_type: Custom event type string (e.g. "adversarial_round")
            data: Event payload
        """
        event = WebSocketEvent(
            event_type=event_type,
            data=data,
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
