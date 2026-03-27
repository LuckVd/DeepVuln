"""Runtime Version Manager - Unified manager for runtime version management.

This module provides the main interface for managing runtime versions,
coordinating installation, switching, and verification.
"""

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.build.version_detector import VersionRequirement

from .installer import RuntimeInstaller, get_installer
from .models import RuntimeInstallResult, RuntimeType, RuntimeSwitchResult
from .registry import RuntimeRegistry
from .switcher import RuntimeSwitcher

logger = get_logger(__name__)


@dataclass
class RuntimeEnsureResult:
    """Result of ensuring runtime versions."""

    success: bool
    installed: dict[RuntimeType, RuntimeInstallResult] = field(default_factory=dict)
    switched: dict[RuntimeType, RuntimeSwitchResult] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def installed_versions(self) -> dict[RuntimeType, str]:
        """Get map of successfully installed versions."""
        return {
            rt: result.version
            for rt, result in self.installed.items()
            if result.success
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "installed": {rt.value: r.to_dict() for rt, r in self.installed.items()},
            "switched": {rt.value: r.to_dict() for rt, r in self.switched.items()},
            "errors": self.errors,
        }


class RuntimeVersionManager:
    """Unified manager for runtime version management.

    This class coordinates:
    1. Checking if required versions are installed
    2. Installing missing versions
    3. Switching to the correct versions

    Usage:
        manager = RuntimeVersionManager()
        result = await manager.ensure({
            RuntimeType.JAVA: "8",
            RuntimeType.PYTHON: "3.9",
        })
    """

    # Default runtime installation root
    DEFAULT_RUNTIME_ROOT = Path("/opt/runtimes")

    def __init__(
        self,
        runtime_root: Path | None = None,
        registry: RuntimeRegistry | None = None,
        install_timeout: int = 600,
        auto_install: bool = True,
    ):
        """Initialize the runtime version manager.

        Args:
            runtime_root: Root directory for runtime installations.
            registry: Runtime registry for version info.
            install_timeout: Timeout for installation in seconds.
            auto_install: Whether to automatically install missing versions.
        """
        self.runtime_root = runtime_root or self.DEFAULT_RUNTIME_ROOT
        self.registry = registry or RuntimeRegistry()
        self.install_timeout = install_timeout
        self.auto_install = auto_install

        self.switcher = RuntimeSwitcher(registry)
        self._installers: dict[RuntimeType, RuntimeInstaller] = {}

    def _get_installer(self, runtime_type: RuntimeType) -> RuntimeInstaller:
        """Get or create an installer for a runtime type."""
        if runtime_type not in self._installers:
            self._installers[runtime_type] = get_installer(
                runtime_type=runtime_type,
                runtime_root=self.runtime_root,
                registry=self.registry,
                timeout=self.install_timeout,
            )
        return self._installers[runtime_type]

    async def ensure(
        self,
        requirements: dict[RuntimeType, str],
    ) -> RuntimeEnsureResult:
        """Ensure all required runtime versions are installed and switched.

        Args:
            requirements: Map of runtime type to required version.

        Returns:
            RuntimeEnsureResult with details.
        """
        result = RuntimeEnsureResult(success=True)

        for runtime_type, version in requirements.items():
            if not version:
                continue

            # Validate version is available
            if not self.registry.is_version_available(runtime_type, version):
                msg = f"Version {version} not available for {runtime_type.value}"
                logger.warning(msg)
                result.errors.append(msg)
                result.success = False
                continue

            try:
                # Install if needed
                install_result = await self._ensure_installed(runtime_type, version)
                result.installed[runtime_type] = install_result

                if not install_result.success:
                    result.success = False
                    result.errors.append(f"Failed to install {runtime_type.value} {version}: {install_result.error}")
                    continue

                # Switch to this version
                switch_result = self._switch(runtime_type, version, install_result.install_path)
                result.switched[runtime_type] = switch_result

                if not switch_result.success:
                    result.success = False
                    result.errors.append(f"Failed to switch {runtime_type.value} {version}: {switch_result.error}")

            except Exception as e:
                logger.error(f"Error ensuring {runtime_type.value} {version}: {e}")
                result.success = False
                result.errors.append(f"Error: {str(e)}")

        return result

    async def _ensure_installed(
        self,
        runtime_type: RuntimeType,
        version: str,
    ) -> RuntimeInstallResult:
        """Ensure a runtime version is installed.

        Args:
            runtime_type: Type of runtime.
            version: Version string.

        Returns:
            RuntimeInstallResult.
        """
        installer = self._get_installer(runtime_type)
        install_path = installer._get_install_path(runtime_type, version)

        # Check if already installed
        version_info = self.registry.get_info(runtime_type, version)
        if installer._is_installed(runtime_type, version, install_path):
            logger.info(f"{runtime_type.value} {version} already installed")
            return RuntimeInstallResult(
                success=True,
                runtime_type=runtime_type,
                version=version,
                install_path=install_path,
            )

        # Install if auto_install is enabled
        if self.auto_install:
            logger.info(f"Installing {runtime_type.value} {version}...")
            return await installer.install(runtime_type, version)
        else:
            return RuntimeInstallResult(
                success=False,
                runtime_type=runtime_type,
                version=version,
                error=f"{runtime_type.value} {version} not installed and auto_install is disabled",
            )

    def _switch(
        self,
        runtime_type: RuntimeType,
        version: str,
        install_path: Path | None,
    ) -> RuntimeSwitchResult:
        """Switch to a runtime version.

        Args:
            runtime_type: Type of runtime.
            version: Version string.
            install_path: Installation path.

        Returns:
            RuntimeSwitchResult.
        """
        if not install_path:
            return RuntimeSwitchResult(
                success=False,
                runtime_type=runtime_type,
                version=version,
                error="No install path provided",
            )

        return self.switcher.switch(runtime_type, version, install_path)

    def is_version_installed(self, runtime_type: RuntimeType, version: str) -> bool:
        """Check if a version is already installed.

        Args:
            runtime_type: Type of runtime.
            version: Version string.

        Returns:
            True if installed.
        """
        installer = self._get_installer(runtime_type)
        install_path = installer._get_install_path(runtime_type, version)
        return installer._is_installed(runtime_type, version, install_path)

    def get_installed_versions(self) -> dict[RuntimeType, list[str]]:
        """Get all installed versions for each runtime type.

        Returns:
            Map of runtime type to list of installed versions.
        """
        installed = {}
        for runtime_type in RuntimeType:
            installed[runtime_type] = []
            runtime_dir = self.runtime_root / runtime_type.value
            if runtime_dir.exists():
                for version_dir in runtime_dir.iterdir():
                    if version_dir.is_dir():
                        # Verify it's a valid installation
                        if self.is_version_installed(runtime_type, version_dir.name):
                            installed[runtime_type].append(version_dir.name)
        return installed

    def get_current_version(self, runtime_type: RuntimeType) -> str | None:
        """Get the currently active version for a runtime type.

        Args:
            runtime_type: Type of runtime.

        Returns:
            Current version or None.
        """
        return self.switcher.get_current_version(runtime_type)

    @staticmethod
    def from_version_requirement(
        version_req: VersionRequirement,
    ) -> dict[RuntimeType, str]:
        """Convert VersionRequirement to runtime requirements dict.

        Args:
            version_req: VersionRequirement from VersionDetector.

        Returns:
            Dict mapping RuntimeType to version string.
        """
        requirements = {}

        if version_req.java_version:
            requirements[RuntimeType.JAVA] = version_req.java_version

        if version_req.go_version:
            requirements[RuntimeType.GO] = version_req.go_version

        if version_req.node_version:
            requirements[RuntimeType.NODE] = version_req.node_version

        # Python version is typically the runtime Python, not project Python
        # But we can include it if needed

        return requirements

    def to_dict(self) -> dict[str, Any]:
        """Convert state to dictionary."""
        return {
            "runtime_root": str(self.runtime_root),
            "auto_install": self.auto_install,
            "install_timeout": self.install_timeout,
            "installed_versions": {
                rt.value: versions
                for rt, versions in self.get_installed_versions().items()
            },
            "current_versions": {
                rt.value: version
                for rt in RuntimeType
                if (version := self.get_current_version(rt)) is not None
            },
        }
