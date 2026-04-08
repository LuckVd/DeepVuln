"""Scan context and configuration.

This module provides shared state management for scan execution.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import asyncio


class ScanType(str, Enum):
    """Scan type enumeration."""
    FULL = "full"
    BASE = "base"
    INCREMENTAL = "incremental"


class ScanStatus(str, Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanConfig:
    """Scan configuration.

    Attributes:
        scan_type: Type of scan to perform
        engines: List of engines to use (e.g., ["semgrep", "codeql", "agent"])
        llm_verify: Enable LLM verification
        adversarial: Enable adversarial verification
        model: LLM model to use
        include_low_severity: Include low severity findings
        agent_max_files: Max files for agent engine
        incremental_refs: Git refs for incremental scan (base_ref, head_ref)
        exclude_patterns: File patterns to exclude
    """
    scan_type: ScanType = ScanType.BASE
    engines: list[str] = field(default_factory=lambda: ["semgrep", "codeql", "agent"])
    llm_verify: bool = False
    adversarial: bool = False
    model: Optional[str] = None
    include_low_severity: bool = False
    agent_max_files: int = 50
    incremental_refs: Optional[tuple[str, str]] = None
    exclude_patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_type": self.scan_type.value,
            "engines": self.engines,
            "llm_verify": self.llm_verify,
            "adversarial": self.adversarial,
            "model": self.model,
            "include_low_severity": self.include_low_severity,
            "agent_max_files": self.agent_max_files,
            "incremental_refs": self.incremental_refs,
            "exclude_patterns": self.exclude_patterns,
            "skip_low_severity": not self.include_low_severity,
        }


@dataclass
class ScanStatistics:
    """Scan statistics.

    Attributes:
        total_files: Total files to scan
        indexed_files: Files indexed
        analyzed_files: Files analyzed
        findings_count: Total findings
        critical_count: Critical severity findings
        high_count: High severity findings
        medium_count: Medium severity findings
        low_count: Low severity findings
        info_count: Info severity findings
        verified_count: Verified findings
        tokens_used: Total tokens used
    """
    total_files: int = 0
    indexed_files: int = 0
    analyzed_files: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    verified_count: int = 0
    tokens_used: int = 0

    def add_finding(self, severity: str) -> None:
        """Add a finding and update statistics.

        Args:
            severity: Finding severity level
        """
        self.findings_count += 1
        severity_map = {
            "critical": "critical_count",
            "high": "high_count",
            "medium": "medium_count",
            "low": "low_count",
            "info": "info_count",
        }
        if severity in severity_map:
            setattr(self, severity_map[severity], getattr(self, severity_map[severity]) + 1)


class ScanContext:
    """Shared scan context.

    This class provides thread-safe state management for scan execution.
    All state changes are atomic and can be observed by event handlers.

    Attributes:
        scan_id: Scan ID
        project_id: Project ID
        source_path: Path to source code
        config: Scan configuration
        status: Current scan status
        progress: Progress percentage (0-100)
        current_phase: Current phase name
        statistics: Scan statistics
        findings: List of discovered findings
        errors: List of errors encountered
        started_at: Scan start time
        completed_at: Scan completion time
        _cancel_event: Event for cancellation signaling
        _lock: Async lock for thread safety
    """

    def __init__(
        self,
        scan_id: int,
        project_id: int,
        source_path: Path,
        config: ScanConfig,
    ):
        """Initialize scan context.

        Args:
            scan_id: Scan ID
            project_id: Project ID
            source_path: Path to source code
            config: Scan configuration
        """
        self.scan_id = scan_id
        self.project_id = project_id
        self.source_path = source_path
        self.config = config

        self.status = ScanStatus.PENDING
        self.progress = 0
        self.current_phase = ""
        self.statistics = ScanStatistics()
        self.findings: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self.data: dict[str, Any] = {}  # Shared data between phases

        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None

        self._cancel_event = asyncio.Event()
        self._lock = asyncio.Lock()
        self._state_changed_callbacks: list[callable] = []

    def add_state_changed_callback(self, callback: callable) -> None:
        """Add a callback to be called when state changes.

        Args:
            callback: Async callback function
        """
        self._state_changed_callbacks.append(callback)

    async def _notify_state_change(self) -> None:
        """Notify all registered callbacks of state change."""
        for callback in self._state_changed_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(self)
                else:
                    callback(self)
            except Exception as e:
                # Don't let callback errors break the scan
                import logging
                logging.getLogger(__name__).warning(
                    f"State change callback failed: {e}"
                )

    async def set_status(self, status: ScanStatus) -> None:
        """Set scan status.

        Args:
            status: New status
        """
        async with self._lock:
            self.status = status
            if status == ScanStatus.RUNNING and self.started_at is None:
                self.started_at = datetime.utcnow()
            elif status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                self.completed_at = datetime.utcnow()
            await self._notify_state_change()

    async def set_progress(self, progress: int, phase: str = "") -> None:
        """Set scan progress.

        Args:
            progress: Progress percentage (0-100)
            phase: Current phase name
        """
        async with self._lock:
            self.progress = max(0, min(100, progress))
            if phase:
                self.current_phase = phase
            await self._notify_state_change()

    async def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a finding.

        Args:
            finding: Finding data
        """
        async with self._lock:
            self.findings.append(finding)
            severity = finding.get("severity", "info")
            self.statistics.add_finding(severity)
            await self._notify_state_change()

    async def add_error(self, error: str) -> None:
        """Add an error.

        Args:
            error: Error message
        """
        async with self._lock:
            self.errors.append(error)
            await self._notify_state_change()

    async def cancel(self) -> None:
        """Request scan cancellation."""
        self._cancel_event.set()
        await self.set_status(ScanStatus.CANCELLED)

    def is_cancelled(self) -> bool:
        """Check if scan was cancelled.

        Returns:
            True if cancellation was requested
        """
        return self._cancel_event.is_set()

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary.

        Returns:
            Dictionary representation of context
        """
        return {
            "scan_id": self.scan_id,
            "project_id": self.project_id,
            "status": self.status.value,
            "progress": self.progress,
            "current_phase": self.current_phase,
            "statistics": {
                "total_files": self.statistics.total_files,
                "indexed_files": self.statistics.indexed_files,
                "analyzed_files": self.statistics.analyzed_files,
                "findings_count": self.statistics.findings_count,
                "critical_count": self.statistics.critical_count,
                "high_count": self.statistics.high_count,
                "medium_count": self.statistics.medium_count,
                "low_count": self.statistics.low_count,
                "info_count": self.statistics.info_count,
                "verified_count": self.statistics.verified_count,
                "tokens_used": self.statistics.tokens_used,
            },
            "errors": self.errors,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
