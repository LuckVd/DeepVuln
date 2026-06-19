"""Progress sink protocol for pipeline phase events."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ProgressSink(Protocol):
    """Receives phase lifecycle events.

    The Web adapter wraps ProgressBroadcaster (Redis pub/sub → WebSocket);
    the CLI adapter renders to a rich console. The pipeline depends only on
    this protocol.
    """

    async def on_phase_start(self, phase: str, **data: Any) -> None: ...

    async def on_phase_progress(
        self, phase: str, current: int, total: int, **extra: Any
    ) -> None: ...

    async def on_phase_complete(self, phase: str, **data: Any) -> None: ...

    async def on_phase_skipped(self, phase: str) -> None: ...

    async def on_phase_failed(self, phase: str, error: str) -> None: ...

    async def on_scan_complete(self, **summary: Any) -> None: ...

    async def on_scan_failed(self, error: str) -> None: ...
