"""Data models for runtime version management."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class RuntimeType(str, Enum):
    """Supported runtime types."""

    JAVA = "java"
    PYTHON = "python"
    NODE = "node"
    GO = "go"


@dataclass
class RuntimeInfo:
    """Information about an installed runtime."""

    runtime_type: RuntimeType
    version: str
    install_path: Path
    executable: Path
    installed_at: str | None = None
    source: str = "download"  # "download", "preinstalled", "managed"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "runtime_type": self.runtime_type.value,
            "version": self.version,
            "install_path": str(self.install_path),
            "executable": str(self.executable),
            "installed_at": self.installed_at,
            "source": self.source,
        }

    @property
    def bin_path(self) -> Path:
        """Get the bin directory for this runtime."""
        return self.executable.parent


@dataclass
class RuntimeRequirement:
    """Version requirement for a runtime."""

    runtime_type: RuntimeType
    required_version: str
    detected_source: str = ""  # e.g., "pom.xml:maven.compiler.source"
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "runtime_type": self.runtime_type.value,
            "required_version": self.required_version,
            "detected_source": self.detected_source,
            "confidence": self.confidence,
        }


@dataclass
class RuntimeInstallResult:
    """Result of a runtime installation attempt."""

    success: bool
    runtime_type: RuntimeType
    version: str
    install_path: Path | None = None
    error: str | None = None
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "runtime_type": self.runtime_type.value,
            "version": self.version,
            "install_path": str(self.install_path) if self.install_path else None,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class RuntimeVersionInfo:
    """Information about an available runtime version in the registry."""

    version: str
    package_name: str
    download_url: str
    checksum_url: str | None = None
    checksum_type: str = "sha256"
    extract_dir: str | None = None  # Directory name after extraction
    bin_subpath: str = "bin"  # Subpath to bin directory

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "version": self.version,
            "package_name": self.package_name,
            "download_url": self.download_url,
            "checksum_url": self.checksum_url,
            "checksum_type": self.checksum_type,
            "extract_dir": self.extract_dir,
            "bin_subpath": self.bin_subpath,
        }


@dataclass
class RuntimeSwitchResult:
    """Result of switching to a runtime version."""

    success: bool
    runtime_type: RuntimeType
    version: str
    old_env: dict[str, str] = field(default_factory=dict)
    new_env: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "runtime_type": self.runtime_type.value,
            "version": self.version,
            "old_env": self.old_env,
            "new_env": self.new_env,
            "error": self.error,
        }
