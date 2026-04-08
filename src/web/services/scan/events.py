"""Scan event system.

This module provides an in-memory event system for real-time scan updates.
Events are emitted during scan execution and can be handled by database writers,
WebSocket broadcasters, etc.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional
import asyncio
import logging


logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Event type enumeration."""
    # Scan lifecycle
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    SCAN_FAILED = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"

    # Phase lifecycle
    PHASE_START = "phase_start"
    PHASE_COMPLETE = "phase_complete"
    PHASE_FAILED = "phase_failed"

    # Engine events
    ENGINE_START = "engine_start"
    ENGINE_COMPLETE = "engine_complete"
    ENGINE_FAILED = "engine_failed"

    # File processing
    FILE_START = "file_start"
    FILE_COMPLETE = "file_complete"

    # Findings
    FINDING_NEW = "finding_new"
    FINDING_VERIFIED = "finding_verified"

    # Progress
    PROGRESS_UPDATE = "progress_update"

    # Error
    ERROR = "error"


@dataclass
class ScanEvent:
    """Scan event data.

    Attributes:
        type: Event type
        scan_id: Scan ID
        timestamp: Event timestamp
        data: Event-specific data
    """
    type: EventType
    scan_id: int
    timestamp: datetime = field(default_factory=datetime.utcnow)
    data: dict[str, Any] = field(default_factory=dict)


class ScanEventEmitter:
    """Event emitter for scan events.

    This class manages event emission and handler registration.
    Handlers can be registered to receive events of specific types.

    Example:
        emitter = ScanEventEmitter(scan_id=28)

        # Register handler
        @emitter.on(EventType.PHASE_COMPLETE)
        async def handle_phase_complete(event: ScanEvent):
            print(f"Phase {event.data['phase']} complete")

        # Emit events
        await emitter.emit(EventType.PHASE_START, {"phase": "L1_preparation"})
    """

    def __init__(self, scan_id: int):
        """Initialize event emitter.

        Args:
            scan_id: Scan ID for this emitter
        """
        self.scan_id = scan_id
        self._handlers: dict[EventType, list[Callable]] = {}
        self._global_handlers: list[Callable] = []
        self._lock = asyncio.Lock()

    def on(
        self,
        event_type: Optional[EventType] = None,
    ) -> Callable:
        """Register an event handler.

        Args:
            event_type: Event type to handle, or None for all events

        Returns:
            Decorator function

        Example:
            @emitter.on(EventType.PHASE_COMPLETE)
            async def handler(event: ScanEvent):
                ...
        """
        def decorator(func: Callable) -> Callable:
            if event_type:
                if event_type not in self._handlers:
                    self._handlers[event_type] = []
                self._handlers[event_type].append(func)
            else:
                self._global_handlers.append(func)
            return func
        return decorator

    async def emit(
        self,
        event_type: EventType,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Emit an event.

        Args:
            event_type: Type of event to emit
            data: Event-specific data
        """
        event = ScanEvent(
            type=event_type,
            scan_id=self.scan_id,
            data=data or {},
        )

        # Get handlers for this event type
        async with self._lock:
            handlers = self._handlers.get(event_type, []).copy()
            global_handlers = self._global_handlers.copy()

        # Execute all handlers
        all_handlers = handlers + global_handlers
        if all_handlers:
            await asyncio.gather(
                *[self._execute_handler(handler, event) for handler in all_handlers],
                return_exceptions=True,
            )

    async def _execute_handler(
        self,
        handler: Callable,
        event: ScanEvent,
    ) -> None:
        """Execute a single event handler.

        Args:
            handler: Handler function
            event: Event data
        """
        try:
            if asyncio.iscoroutinefunction(handler):
                await handler(event)
            else:
                handler(event)
        except Exception as e:
            logger.warning(
                f"Event handler failed for {event.type}: {e}",
                exc_info=True,
            )

    # Convenience methods for common events

    async def emit_scan_start(
        self,
        source_path: str,
        scan_type: str,
        config: dict[str, Any],
    ) -> None:
        """Emit scan start event.

        Args:
            source_path: Path to source code
            scan_type: Type of scan
            config: Scan configuration
        """
        await self.emit(
            EventType.SCAN_START,
            {
                "source_path": source_path,
                "scan_type": scan_type,
                "config": config,
            },
        )

    async def emit_scan_complete(
        self,
        duration_seconds: float,
        findings_total: int,
        tokens_used: int,
    ) -> None:
        """Emit scan complete event.

        Args:
            duration_seconds: Scan duration
            findings_total: Total findings found
            tokens_used: Total tokens used
        """
        await self.emit(
            EventType.SCAN_COMPLETE,
            {
                "duration_seconds": duration_seconds,
                "findings_total": findings_total,
                "tokens_used": tokens_used,
            },
        )

    async def emit_phase_start(
        self,
        phase: str,
        description: str = "",
    ) -> None:
        """Emit phase start event.

        Args:
            phase: Phase name
            description: Phase description
        """
        await self.emit(
            EventType.PHASE_START,
            {
                "phase": phase,
                "description": description,
            },
        )

    async def emit_phase_complete(
        self,
        phase: str,
        duration_seconds: float = 0,
        findings: int = 0,
        tokens_used: int = 0,
    ) -> None:
        """Emit phase complete event.

        Args:
            phase: Phase name
            duration_seconds: Phase duration
            findings: Findings found in this phase
            tokens_used: Tokens used in this phase
        """
        await self.emit(
            EventType.PHASE_COMPLETE,
            {
                "phase": phase,
                "duration_seconds": duration_seconds,
                "findings": findings,
                "tokens_used": tokens_used,
            },
        )

    async def emit_engine_start(
        self,
        engine: str,
    ) -> None:
        """Emit engine start event.

        Args:
            engine: Engine name
        """
        await self.emit(
            EventType.ENGINE_START,
            {"engine": engine},
        )

    async def emit_engine_complete(
        self,
        engine: str,
        findings: int = 0,
        tokens_used: int = 0,
    ) -> None:
        """Emit engine complete event.

        Args:
            engine: Engine name
            findings: Findings found
            tokens_used: Tokens used
        """
        await self.emit(
            EventType.ENGINE_COMPLETE,
            {
                "engine": engine,
                "findings": findings,
                "tokens_used": tokens_used,
            },
        )

    async def emit_finding_new(
        self,
        file_path: str,
        line: int,
        severity: str,
        vuln_type: str,
        title: str,
        engine: str,
        confidence: float = 0.0,
        code_snippet: str = "",
    ) -> None:
        """Emit new finding event.

        Args:
            file_path: Path to file with finding
            line: Line number
            severity: Severity level
            vuln_type: Vulnerability type
            title: Finding title
            engine: Engine that found it
            confidence: Confidence score
            code_snippet: Code snippet
        """
        await self.emit(
            EventType.FINDING_NEW,
            {
                "file_path": file_path,
                "line": line,
                "severity": severity,
                "vuln_type": vuln_type,
                "title": title,
                "engine": engine,
                "confidence": confidence,
                "code_snippet": code_snippet,
            },
        )

    async def emit_progress(
        self,
        progress_percent: int,
        current_phase: str = "",
        current_step: str = "",
    ) -> None:
        """Emit progress update event.

        Args:
            progress_percent: Progress percentage (0-100)
            current_phase: Current phase name
            current_step: Current step description
        """
        await self.emit(
            EventType.PROGRESS_UPDATE,
            {
                "progress_percent": progress_percent,
                "current_phase": current_phase,
                "current_step": current_step,
            },
        )
