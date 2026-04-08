"""Modular scan service.

This package provides a coroutine-based, modular scanning architecture
that eliminates the need for CLI subprocess calls.

Architecture:
    - Orchestrator: Manages scan lifecycle and phase coordination
    - Phases: Independent scan phases (preparation, engines, verification)
    - Engines: Adapters for existing scanning engines
    - Events: In-memory event system for real-time updates
    - Context: Shared scan state and configuration

Example:
    from src.web.services.scan import ScanOrchestrator

    orchestrator = ScanOrchestrator(
        scan_id=28,
        project_id=7,
        source_path="/path/to/code",
        config={"scan_type": "base", "engines": ["semgrep", "codeql"]}
    )

    result = await orchestrator.run()
"""

from src.web.services.scan.orchestrator import ScanOrchestrator
from src.web.services.scan.context import ScanContext, ScanConfig
from src.web.services.scan.events import ScanEventEmitter

__all__ = [
    "ScanOrchestrator",
    "ScanContext",
    "ScanConfig",
    "ScanEventEmitter",
]
