"""Build executor for running build commands.

This module provides functionality to execute build commands
before CodeQL database creation.
"""

import asyncio
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.build.detector import BuildConfig, BuildSystem

logger = get_logger(__name__)


@dataclass
class BuildResult:
    """Result of a build execution.

    Attributes:
        success: Whether the build succeeded.
        return_code: Exit code of the build command.
        stdout: Standard output from the build.
        stderr: Standard error from the build.
        duration_seconds: Time taken for the build.
        command: The command that was executed.
        error_message: Error message if build failed.
    """

    success: bool
    return_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    command: str | None = None
    error_message: str | None = None
    skipped: bool = False
    skip_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            "success": self.success,
            "return_code": self.return_code,
            "duration_seconds": self.duration_seconds,
            "command": self.command,
            "error_message": self.error_message,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
        }


class BuildExecutor:
    """Executes build commands for a project.

    This class handles:
    - Installing dependencies
    - Running build commands
    - Capturing build output for diagnostics
    - Handling build failures gracefully
    """

    def __init__(
        self,
        timeout: int = 600,  # 10 minutes default
        max_retries: int = 1,
    ):
        """Initialize the build executor.

        Args:
            timeout: Maximum time for each command in seconds.
            max_retries: Number of times to retry failed builds.
        """
        self.timeout = timeout
        self.max_retries = max_retries

    async def execute(
        self,
        config: BuildConfig,
        source_path: Path,
        skip_build: bool = False,
        skip_dependencies: bool = False,
    ) -> BuildResult:
        """Execute the build process.

        Args:
            config: Build configuration from detector.
            source_path: Path to the source code.
            skip_build: Whether to skip the build step.
            skip_dependencies: Whether to skip dependency installation.

        Returns:
            BuildResult with execution details.
        """
        # Check if build should be skipped
        if skip_build:
            return BuildResult(
                success=True,
                skipped=True,
                skip_reason="Build skipped by user request (--no-build)",
            )

        if not config.requires_build:
            return BuildResult(
                success=True,
                skipped=True,
                skip_reason=f"Language '{config.language}' does not require compilation",
            )

        if not config.build_command:
            return BuildResult(
                success=True,
                skipped=True,
                skip_reason="No build command detected",
            )

        logger.info(
            f"Executing build for {config.language} project. "
            f"Build system: {config.build_system.value}"
        )

        # Prepare environment
        env = os.environ.copy()
        if config.env_vars:
            env.update(config.env_vars)

        # Install dependencies first
        if config.dependency_command and not skip_dependencies:
            dep_result = await self._run_command(
                command=config.dependency_command,
                cwd=source_path,
                env=env,
                description="Installing dependencies",
            )
            if not dep_result.success:
                logger.warning(
                    f"Dependency installation failed: {dep_result.error_message}. "
                    f"Continuing with build anyway..."
                )

        # Execute build
        build_result = await self._run_command(
            command=config.build_command,
            cwd=source_path,
            env=env,
            description="Building project",
        )

        if build_result.success:
            logger.info(
                f"Build completed successfully in {build_result.duration_seconds:.1f}s"
            )
        else:
            logger.warning(
                f"Build failed with code {build_result.return_code}. "
                f"Error: {build_result.stderr[:500] if build_result.stderr else 'Unknown error'}"
            )

        return build_result

    async def _run_command(
        self,
        command: str,
        cwd: Path,
        env: dict[str, str],
        description: str = "Executing command",
    ) -> BuildResult:
        """Run a shell command.

        Args:
            command: Command to execute.
            cwd: Working directory.
            env: Environment variables.
            description: Description for logging.

        Returns:
            BuildResult with execution details.
        """
        logger.info(f"{description}: {command}")

        import time
        start_time = time.time()

        try:
            process = await asyncio.create_subprocess_shell(
                command,
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
            except asyncio.TimeoutError:
                process.kill()
                return BuildResult(
                    success=False,
                    return_code=-1,
                    stderr=f"Command timed out after {self.timeout} seconds",
                    command=command,
                    error_message="Timeout",
                )

            duration = time.time() - start_time
            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            return BuildResult(
                success=process.returncode == 0,
                return_code=process.returncode or 0,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_seconds=duration,
                command=command,
                error_message=None if process.returncode == 0 else stderr_str[:1000],
            )

        except Exception as e:
            duration = time.time() - start_time
            return BuildResult(
                success=False,
                return_code=-1,
                stderr=str(e),
                duration_seconds=duration,
                command=command,
                error_message=str(e),
            )

    async def try_multiple_builds(
        self,
        configs: list[BuildConfig],
        source_path: Path,
    ) -> BuildResult:
        """Try multiple build configurations until one succeeds.

        Args:
            configs: List of build configurations to try.
            source_path: Path to the source code.

        Returns:
            BuildResult from the first successful build, or last failure.
        """
        last_result = BuildResult(
            success=False,
            error_message="No build configurations to try",
        )

        for i, config in enumerate(configs):
            logger.info(f"Trying build configuration {i + 1}/{len(configs)}: {config.build_system.value}")
            result = await self.execute(config, source_path)

            if result.success:
                return result

            last_result = result

        return last_result


async def execute_build(
    source_path: Path,
    language: str | None = None,
    skip_build: bool = False,
    timeout: int = 600,
) -> BuildResult:
    """Convenience function to detect and execute build.

    Args:
        source_path: Path to the source code.
        language: Programming language (auto-detected if not specified).
        skip_build: Whether to skip the build step.
        timeout: Maximum time for build commands.

    Returns:
        BuildResult with execution details.
    """
    from src.layers.l3_analysis.build.detector import detect_build_system

    config = detect_build_system(source_path, language)
    executor = BuildExecutor(timeout=timeout)

    return await executor.execute(config, source_path, skip_build=skip_build)
