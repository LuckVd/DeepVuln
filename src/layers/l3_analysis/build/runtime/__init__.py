"""Runtime Version Management Module.

This module provides multi-version runtime management for DeepVuln,
enabling automatic detection, installation, and switching of language
runtimes (Java, Python, Node.js, Go) based on project requirements.

Components:
- RuntimeRegistry: Registry of available runtime versions and download URLs
- RuntimeInstaller: Downloads and installs runtime versions
- RuntimeSwitcher: Switches environment variables to use specific runtime version
- RuntimeVersionManager: Unified manager coordinating all operations
"""

from .models import (
    RuntimeType,
    RuntimeInfo,
    RuntimeRequirement,
    RuntimeInstallResult,
)
from .registry import (
    RuntimeRegistry,
    RUNTIME_REGISTRY,
    get_runtime_download_url,
)
from .installer import (
    RuntimeInstaller,
    JavaInstaller,
    PythonInstaller,
    NodeInstaller,
    GoInstaller,
)
from .switcher import RuntimeSwitcher
from .manager import RuntimeVersionManager

__all__ = [
    # Models
    "RuntimeType",
    "RuntimeInfo",
    "RuntimeRequirement",
    "RuntimeInstallResult",
    # Registry
    "RuntimeRegistry",
    "RUNTIME_REGISTRY",
    "get_runtime_download_url",
    # Installer
    "RuntimeInstaller",
    "JavaInstaller",
    "PythonInstaller",
    "NodeInstaller",
    "GoInstaller",
    # Switcher
    "RuntimeSwitcher",
    # Manager
    "RuntimeVersionManager",
]
