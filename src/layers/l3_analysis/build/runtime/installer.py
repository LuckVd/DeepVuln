"""Runtime Installer - Downloads and installs runtime versions.

This module provides installers for different runtime types, handling
the download, extraction, and setup of runtime environments.
"""

import asyncio
import os
import shutil
import tarfile
import tempfile
import time
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

from .models import RuntimeInstallResult, RuntimeType, RuntimeVersionInfo
from .registry import RuntimeRegistry

logger = get_logger(__name__)


class RuntimeInstaller(ABC):
    """Base class for runtime installers."""

    def __init__(
        self,
        runtime_root: Path,
        registry: RuntimeRegistry | None = None,
        timeout: int = 600,  # 10 minutes default
    ):
        """Initialize the installer.

        Args:
            runtime_root: Root directory for runtime installations.
            registry: Runtime registry for version info.
            timeout: Download/install timeout in seconds.
        """
        self.runtime_root = runtime_root
        self.registry = registry or RuntimeRegistry()
        self.timeout = timeout

    async def install(self, runtime_type: RuntimeType, version: str) -> RuntimeInstallResult:
        """Install a runtime version.

        Args:
            runtime_type: Type of runtime to install.
            version: Version to install.

        Returns:
            RuntimeInstallResult with installation details.
        """
        start_time = time.time()

        # Get version info from registry
        version_info = self.registry.get_info(runtime_type, version)
        if not version_info:
            return RuntimeInstallResult(
                success=False,
                runtime_type=runtime_type,
                version=version,
                error=f"Version {version} not found in registry for {runtime_type.value}",
            )

        # Check if already installed
        install_path = self._get_install_path(runtime_type, version)
        if self._is_installed(runtime_type, version, install_path):
            logger.info(f"{runtime_type.value} {version} already installed at {install_path}")
            return RuntimeInstallResult(
                success=True,
                runtime_type=runtime_type,
                version=version,
                install_path=install_path,
                duration_seconds=time.time() - start_time,
            )

        # Create install directory
        install_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            # Download
            logger.info(f"Downloading {runtime_type.value} {version} from {version_info.download_url}")
            downloaded_file = await self._download(version_info.download_url, runtime_type, version)

            # Extract/Install
            logger.info(f"Installing {runtime_type.value} {version} to {install_path}")
            await self._extract_and_setup(downloaded_file, version_info, install_path, runtime_type)

            # Cleanup
            if downloaded_file.exists():
                downloaded_file.unlink()

            duration = time.time() - start_time
            logger.info(f"Successfully installed {runtime_type.value} {version} in {duration:.1f}s")

            return RuntimeInstallResult(
                success=True,
                runtime_type=runtime_type,
                version=version,
                install_path=install_path,
                duration_seconds=duration,
            )

        except Exception as e:
            logger.error(f"Failed to install {runtime_type.value} {version}: {e}")
            return RuntimeInstallResult(
                success=False,
                runtime_type=runtime_type,
                version=version,
                error=str(e),
                duration_seconds=time.time() - start_time,
            )

    def _get_install_path(self, runtime_type: RuntimeType, version: str) -> Path:
        """Get the installation path for a runtime version."""
        return self.runtime_root / runtime_type.value / version

    def _is_installed(self, runtime_type: RuntimeType, version: str, install_path: Path) -> bool:
        """Check if a runtime version is already installed."""
        if not install_path.exists():
            return False

        # Check for executable
        version_info = self.registry.get_info(runtime_type, version)
        if not version_info:
            return False

        executable = self._get_executable_path(runtime_type, install_path, version_info)
        return executable.exists() and os.access(executable, os.X_OK)

    @abstractmethod
    def _get_executable_path(
        self, runtime_type: RuntimeType, install_path: Path, version_info: RuntimeVersionInfo
    ) -> Path:
        """Get the path to the main executable."""
        pass

    async def _download(self, url: str, runtime_type: RuntimeType, version: str) -> Path:
        """Download a runtime package.

        Args:
            url: Download URL.
            runtime_type: Runtime type.
            version: Version string.

        Returns:
            Path to downloaded file.
        """
        # Create temp directory for download
        temp_dir = Path(tempfile.mkdtemp(prefix=f"deepvuln_{runtime_type.value}_{version}_"))

        # Determine filename from URL
        filename = url.split("/")[-1]
        if "?" in filename:
            filename = filename.split("?")[0]

        output_path = temp_dir / filename

        # Use curl for download with progress
        cmd = [
            "curl",
            "-fsSL",
            "--connect-timeout", "120",
            "--max-time", str(self.timeout),
            "-o", str(output_path),
            url,
        ]

        logger.debug(f"Running download command: {' '.join(cmd)}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout + 30,
            )

            if process.returncode != 0:
                raise RuntimeError(f"Download failed: {stderr.decode() if stderr else 'Unknown error'}")

            return output_path

        except asyncio.TimeoutError:
            process.kill()
            raise RuntimeError(f"Download timed out after {self.timeout} seconds")

    async def _extract_and_setup(
        self,
        downloaded_file: Path,
        version_info: RuntimeVersionInfo,
        install_path: Path,
        runtime_type: RuntimeType,
    ) -> None:
        """Extract downloaded file and set up the runtime.

        Args:
            downloaded_file: Path to downloaded archive.
            version_info: Version info from registry.
            install_path: Target installation path.
            runtime_type: Runtime type.
        """
        # Remove existing installation if any
        if install_path.exists():
            shutil.rmtree(install_path)

        # Create parent directory
        install_path.parent.mkdir(parents=True, exist_ok=True)

        # Determine archive type and extract
        if downloaded_file.suffix == ".gz" or downloaded_file.name.endswith(".tar.gz"):
            await self._extract_tar_gz(downloaded_file, install_path, version_info)
        elif downloaded_file.suffix == ".xz" or downloaded_file.name.endswith(".tar.xz"):
            await self._extract_tar_xz(downloaded_file, install_path, version_info)
        elif downloaded_file.suffix == ".zip":
            await self._extract_zip(downloaded_file, install_path, version_info)
        elif downloaded_file.suffix == ".sh":
            await self._run_installer_script(downloaded_file, install_path, version_info)
        else:
            raise RuntimeError(f"Unknown archive format: {downloaded_file.suffix}")

    async def _extract_tar_gz(
        self, archive: Path, install_path: Path, version_info: RuntimeVersionInfo
    ) -> None:
        """Extract a .tar.gz archive."""
        # Extract to temp location first
        temp_extract = Path(tempfile.mkdtemp(prefix="deepvuln_extract_"))

        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(temp_extract)

        # Find extracted directory and move to install_path
        extracted_dir = self._find_extracted_dir(temp_extract, version_info.extract_dir)
        shutil.move(str(extracted_dir), str(install_path))

        # Cleanup
        shutil.rmtree(temp_extract, ignore_errors=True)

    async def _extract_tar_xz(
        self, archive: Path, install_path: Path, version_info: RuntimeVersionInfo
    ) -> None:
        """Extract a .tar.xz archive."""
        temp_extract = Path(tempfile.mkdtemp(prefix="deepvuln_extract_"))

        with tarfile.open(archive, "r:xz") as tf:
            tf.extractall(temp_extract)

        extracted_dir = self._find_extracted_dir(temp_extract, version_info.extract_dir)
        shutil.move(str(extracted_dir), str(install_path))

        shutil.rmtree(temp_extract, ignore_errors=True)

    async def _extract_zip(
        self, archive: Path, install_path: Path, version_info: RuntimeVersionInfo
    ) -> None:
        """Extract a .zip archive."""
        temp_extract = Path(tempfile.mkdtemp(prefix="deepvuln_extract_"))

        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(temp_extract)

        extracted_dir = self._find_extracted_dir(temp_extract, version_info.extract_dir)
        shutil.move(str(extracted_dir), str(install_path))

        shutil.rmtree(temp_extract, ignore_errors=True)

    async def _run_installer_script(
        self, script: Path, install_path: Path, version_info: RuntimeVersionInfo
    ) -> None:
        """Run an installer script (e.g., miniconda)."""
        install_path.mkdir(parents=True, exist_ok=True)

        # Make script executable
        os.chmod(script, 0o755)

        # Run the installer
        cmd = [
            "bash",
            str(script),
            "-b",  # Batch mode
            "-p", str(install_path),
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=self.timeout,
        )

        if process.returncode != 0:
            raise RuntimeError(f"Installer script failed: {stderr.decode() if stderr else 'Unknown error'}")

    def _find_extracted_dir(self, temp_extract: Path, expected_name: str | None) -> Path:
        """Find the extracted directory."""
        if expected_name:
            expected_path = temp_extract / expected_name
            if expected_path.exists():
                return expected_path

        # Fall back to first directory in temp_extract
        for item in temp_extract.iterdir():
            if item.is_dir():
                return item

        # If no directory, return temp_extract itself
        return temp_extract


class JavaInstaller(RuntimeInstaller):
    """Java runtime installer using Eclipse Temurin."""

    def _get_executable_path(
        self, runtime_type: RuntimeType, install_path: Path, version_info: RuntimeVersionInfo
    ) -> Path:
        """Get the path to java executable."""
        return install_path / "bin" / "java"


class PythonInstaller(RuntimeInstaller):
    """Python runtime installer using Miniconda."""

    def _get_executable_path(
        self, runtime_type: RuntimeType, install_path: Path, version_info: RuntimeVersionInfo
    ) -> Path:
        """Get the path to python executable."""
        return install_path / "bin" / "python"


class NodeInstaller(RuntimeInstaller):
    """Node.js runtime installer."""

    def _get_executable_path(
        self, runtime_type: RuntimeType, install_path: Path, version_info: RuntimeVersionInfo
    ) -> Path:
        """Get the path to node executable."""
        return install_path / "bin" / "node"


class GoInstaller(RuntimeInstaller):
    """Go runtime installer."""

    def _get_executable_path(
        self, runtime_type: RuntimeType, install_path: Path, version_info: RuntimeVersionInfo
    ) -> Path:
        """Get the path to go executable."""
        return install_path / "bin" / "go"


# Installer factory
INSTALLER_CLASSES: dict[RuntimeType, type[RuntimeInstaller]] = {
    RuntimeType.JAVA: JavaInstaller,
    RuntimeType.PYTHON: PythonInstaller,
    RuntimeType.NODE: NodeInstaller,
    RuntimeType.GO: GoInstaller,
}


def get_installer(
    runtime_type: RuntimeType,
    runtime_root: Path,
    registry: RuntimeRegistry | None = None,
    timeout: int = 600,
) -> RuntimeInstaller:
    """Get an installer for a runtime type.

    Args:
        runtime_type: Type of runtime.
        runtime_root: Root directory for installations.
        registry: Runtime registry.
        timeout: Installation timeout.

    Returns:
        RuntimeInstaller instance.
    """
    installer_class = INSTALLER_CLASSES.get(runtime_type)
    if not installer_class:
        raise ValueError(f"No installer available for {runtime_type.value}")

    return installer_class(runtime_root=runtime_root, registry=registry, timeout=timeout)
