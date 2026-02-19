"""
Base Engine - Abstract base class for analysis engines.

All analysis engines (Semgrep, CodeQL, Agent) must inherit from this class
and implement the required methods.
"""

import asyncio
import shutil
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.layers.l3_analysis.models import Finding, ScanResult, SeverityLevel


class BaseEngine(ABC):
    """
    Abstract base class for static analysis engines.

    Provides common functionality and defines the interface that all
    analysis engines must implement.
    """

    # Engine metadata (override in subclasses)
    name: str = "base"
    description: str = "Base analysis engine"
    supported_languages: list[str] = []

    def __init__(
        self,
        timeout: int = 300,
        max_memory_mb: int = 4096,
    ):
        """
        Initialize the engine.

        Args:
            timeout: Maximum scan duration in seconds.
            max_memory_mb: Maximum memory usage in MB.
        """
        self.timeout = timeout
        self.max_memory_mb = max_memory_mb
        self._last_scan_result: ScanResult | None = None

    @abstractmethod
    async def scan(
        self,
        source_path: Path,
        **options,
    ) -> ScanResult:
        """
        Execute a scan on the given source path.

        Args:
            source_path: Path to the source code to scan.
            **options: Engine-specific options.

        Returns:
            ScanResult containing all findings.
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the engine is available and ready to use.

        Returns:
            True if the engine can be used, False otherwise.
        """
        pass

    def get_supported_languages(self) -> list[str]:
        """
        Get the list of supported programming languages.

        Returns:
            List of language names.
        """
        return self.supported_languages

    def supports_language(self, language: str) -> bool:
        """
        Check if a language is supported.

        Args:
            language: Language name to check.

        Returns:
            True if the language is supported.
        """
        return language.lower() in [l.lower() for l in self.supported_languages]

    def validate_source_path(self, source_path: Path) -> None:
        """
        Validate that the source path exists and is accessible.

        Args:
            source_path: Path to validate.

        Raises:
            ValueError: If the path is invalid.
        """
        if not source_path.exists():
            raise ValueError(f"Source path does not exist: {source_path}")
        if not source_path.is_dir():
            raise ValueError(f"Source path is not a directory: {source_path}")

    def create_scan_result(
        self,
        source_path: Path,
        rules_used: list[str] | None = None,
    ) -> ScanResult:
        """
        Create a new ScanResult with initial values.

        Args:
            source_path: Path being scanned.
            rules_used: List of rules used in the scan.

        Returns:
            A new ScanResult instance.
        """
        return ScanResult(
            source_path=str(source_path),
            engine=self.name,
            rules_used=rules_used or [],
            started_at=datetime.now(UTC),
        )

    def finalize_scan_result(
        self,
        result: ScanResult,
        success: bool = True,
        error_message: str | None = None,
        raw_output: dict[str, Any] | None = None,
    ) -> ScanResult:
        """
        Finalize a scan result with timing and status.

        Args:
            result: The ScanResult to finalize.
            success: Whether the scan succeeded.
            error_message: Error message if failed.
            raw_output: Raw engine output.

        Returns:
            The finalized ScanResult.
        """
        result.completed_at = datetime.now(UTC)
        result.duration_seconds = (
            result.completed_at - result.started_at
        ).total_seconds()
        result.success = success
        result.error_message = error_message
        result.raw_output = raw_output
        self._last_scan_result = result
        return result

    async def run_command(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        """
        Run a shell command asynchronously.

        Args:
            cmd: Command and arguments.
            cwd: Working directory.
            env: Environment variables.

        Returns:
            Tuple of (return_code, stdout, stderr).
        """
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout,
            )
            return (
                process.returncode or 0,
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
            )
        except asyncio.TimeoutError:
            process.kill()
            raise TimeoutError(
                f"Command timed out after {self.timeout} seconds"
            )

    @staticmethod
    def check_binary_available(binary_name: str) -> bool:
        """
        Check if a binary is available in PATH.

        Args:
            binary_name: Name of the binary to check.

        Returns:
            True if the binary is available.
        """
        return shutil.which(binary_name) is not None

    def get_last_scan_result(self) -> ScanResult | None:
        """
        Get the result of the last scan.

        Returns:
            The last ScanResult, or None if no scan has been run.
        """
        return self._last_scan_result


class EngineRegistry:
    """
    Registry for managing analysis engines.
    """

    def __init__(self):
        self._engines: dict[str, BaseEngine] = {}

    def register(self, engine: BaseEngine) -> None:
        """Register an engine."""
        self._engines[engine.name] = engine

    def get(self, name: str) -> BaseEngine | None:
        """Get an engine by name."""
        return self._engines.get(name)

    def get_available_engines(self) -> list[BaseEngine]:
        """Get all available engines."""
        return [e for e in self._engines.values() if e.is_available()]

    def get_engines_for_language(self, language: str) -> list[BaseEngine]:
        """Get engines that support a specific language."""
        return [
            e
            for e in self.get_available_engines()
            if e.supports_language(language)
        ]

    def list_engines(self) -> list[str]:
        """List all registered engine names."""
        return list(self._engines.keys())


# Global registry instance
engine_registry = EngineRegistry()
