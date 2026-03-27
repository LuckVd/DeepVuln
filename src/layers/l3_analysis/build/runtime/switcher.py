"""Runtime Switcher - Switches environment variables to use specific runtime version.

This module handles the switching of environment variables (JAVA_HOME, PATH, etc.)
to use a specific installed runtime version.
"""

import os
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

from .models import RuntimeSwitchResult, RuntimeType, RuntimeVersionInfo
from .registry import RuntimeRegistry

logger = get_logger(__name__)


class RuntimeSwitcher:
    """Switches between runtime versions by modifying environment variables."""

    def __init__(self, registry: RuntimeRegistry | None = None):
        """Initialize the switcher.

        Args:
            registry: Runtime registry for version info.
        """
        self.registry = registry or RuntimeRegistry()
        self._switched_runtime: dict[RuntimeType, str] = {}

    def switch(
        self,
        runtime_type: RuntimeType,
        version: str,
        install_path: Path,
    ) -> RuntimeSwitchResult:
        """Switch to a specific runtime version.

        Args:
            runtime_type: Type of runtime.
            version: Version string.
            install_path: Path where the runtime is installed.

        Returns:
            RuntimeSwitchResult with details.
        """
        version_info = self.registry.get_info(runtime_type, version)

        # Capture old environment
        old_env = self._capture_env(runtime_type)

        try:
            # Perform the switch based on runtime type
            if runtime_type == RuntimeType.JAVA:
                self._switch_java(install_path, version_info)
            elif runtime_type == RuntimeType.PYTHON:
                self._switch_python(install_path, version_info)
            elif runtime_type == RuntimeType.NODE:
                self._switch_node(install_path, version_info)
            elif runtime_type == RuntimeType.GO:
                self._switch_go(install_path, version_info)
            else:
                raise ValueError(f"Unknown runtime type: {runtime_type}")

            # Track switched runtime
            self._switched_runtime[runtime_type] = version

            # Capture new environment
            new_env = self._capture_env(runtime_type)

            logger.info(f"Switched {runtime_type.value} to version {version}")

            return RuntimeSwitchResult(
                success=True,
                runtime_type=runtime_type,
                version=version,
                old_env=old_env,
                new_env=new_env,
            )

        except Exception as e:
            logger.error(f"Failed to switch {runtime_type.value} to {version}: {e}")
            return RuntimeSwitchResult(
                success=False,
                runtime_type=runtime_type,
                version=version,
                old_env=old_env,
                error=str(e),
            )

    def _capture_env(self, runtime_type: RuntimeType) -> dict[str, str]:
        """Capture current environment variables for a runtime type."""
        env_keys = self._get_env_keys(runtime_type)
        return {key: os.environ.get(key, "") for key in env_keys}

    def _get_env_keys(self, runtime_type: RuntimeType) -> list[str]:
        """Get environment variable keys for a runtime type."""
        if runtime_type == RuntimeType.JAVA:
            return ["JAVA_HOME", "PATH"]
        elif runtime_type == RuntimeType.PYTHON:
            return ["PATH"]
        elif runtime_type == RuntimeType.NODE:
            return ["PATH", "NODE_PATH"]
        elif runtime_type == RuntimeType.GO:
            return ["GOPATH", "GOROOT", "PATH"]
        return ["PATH"]

    def _switch_java(self, install_path: Path, version_info: RuntimeVersionInfo | None) -> None:
        """Switch Java runtime."""
        java_home = install_path
        bin_path = install_path / "bin"

        # Verify java executable exists
        java_exec = bin_path / "java"
        if not java_exec.exists():
            raise RuntimeError(f"Java executable not found at {java_exec}")

        # Set JAVA_HOME
        os.environ["JAVA_HOME"] = str(java_home)
        logger.debug(f"Set JAVA_HOME={java_home}")

        # Update PATH
        self._update_path(bin_path, priority="front")

    def _switch_python(self, install_path: Path, version_info: RuntimeVersionInfo | None) -> None:
        """Switch Python runtime."""
        bin_path = install_path / "bin"

        # Verify python executable exists
        python_exec = bin_path / "python"
        if not python_exec.exists():
            # Try python3
            python_exec = bin_path / "python3"
            if not python_exec.exists():
                raise RuntimeError(f"Python executable not found at {bin_path}")

        # Update PATH
        self._update_path(bin_path, priority="front")

        # Create symlink for python if only python3 exists
        python_link = bin_path / "python"
        python3_exec = bin_path / "python3"
        if not python_link.exists() and python3_exec.exists():
            try:
                python_link.symlink_to(python3_exec.name)
            except OSError:
                pass  # Ignore symlink errors

    def _switch_node(self, install_path: Path, version_info: RuntimeVersionInfo | None) -> None:
        """Switch Node.js runtime."""
        bin_path = install_path / "bin"

        # Verify node executable exists
        node_exec = bin_path / "node"
        if not node_exec.exists():
            raise RuntimeError(f"Node executable not found at {node_exec}")

        # Update PATH
        self._update_path(bin_path, priority="front")

        # Set NODE_PATH for modules
        node_modules = install_path / "lib" / "node_modules"
        if node_modules.exists():
            os.environ["NODE_PATH"] = str(node_modules)

    def _switch_go(self, install_path: Path, version_info: RuntimeVersionInfo | None) -> None:
        """Switch Go runtime."""
        bin_path = install_path / "bin"

        # Verify go executable exists
        go_exec = bin_path / "go"
        if not go_exec.exists():
            raise RuntimeError(f"Go executable not found at {go_exec}")

        # Set GOROOT
        os.environ["GOROOT"] = str(install_path)
        logger.debug(f"Set GOROOT={install_path}")

        # Update PATH
        self._update_path(bin_path, priority="front")

    def _update_path(self, new_path: Path, priority: str = "front") -> None:
        """Update PATH environment variable.

        Args:
            new_path: Path to add to PATH.
            priority: "front" to prepend, "back" to append.
        """
        current_path = os.environ.get("PATH", "")
        new_path_str = str(new_path)

        # Remove existing instance of this path if present
        path_parts = [p for p in current_path.split(":") if p != new_path_str]

        if priority == "front":
            path_parts.insert(0, new_path_str)
        else:
            path_parts.append(new_path_str)

        os.environ["PATH"] = ":".join(path_parts)
        logger.debug(f"Updated PATH to include {new_path}")

    def get_current_version(self, runtime_type: RuntimeType) -> str | None:
        """Get the currently switched version for a runtime type.

        Args:
            runtime_type: Type of runtime.

        Returns:
            Current version string or None if not switched.
        """
        return self._switched_runtime.get(runtime_type)

    def get_executable(self, runtime_type: RuntimeType) -> str | None:
        """Get the path to the current executable for a runtime type.

        Args:
            runtime_type: Type of runtime.

        Returns:
            Path to executable or None.
        """
        if runtime_type == RuntimeType.JAVA:
            java_home = os.environ.get("JAVA_HOME")
            if java_home:
                return str(Path(java_home) / "bin" / "java")
            return shutil_which("java")

        elif runtime_type == RuntimeType.PYTHON:
            return shutil_which("python") or shutil_which("python3")

        elif runtime_type == RuntimeType.NODE:
            return shutil_which("node")

        elif runtime_type == RuntimeType.GO:
            return shutil_which("go")

        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert state to dictionary."""
        return {
            "switched_runtime": {
                rt.value: version for rt, version in self._switched_runtime.items()
            }
        }


def shutil_which(cmd: str) -> str | None:
    """Cross-platform which utility."""
    import shutil
    return shutil.which(cmd)
