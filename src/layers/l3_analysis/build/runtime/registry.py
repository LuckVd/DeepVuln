"""Runtime Registry - Available runtime versions and download URLs.

This module provides a registry of available runtime versions with their
download URLs, checksums, and installation metadata.
"""

from dataclasses import dataclass
from typing import Any

from .models import RuntimeType, RuntimeVersionInfo

# =============================================================================
# Java (Eclipse Temurin / Adoptium)
# =============================================================================

# Temurin download URLs (Linux x64)
# Format: https://github.com/adoptium/temurin{version}-binaries/releases/download/jdk-{version}...
TEMURIN_BASE_URL = "https://github.com/adoptium/temurin{major}-binaries/releases/download"

JAVA_VERSIONS: dict[str, RuntimeVersionInfo] = {
    "8": RuntimeVersionInfo(
        version="8",
        package_name="temurin-8-jdk",
        download_url="https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u422-b05/OpenJDK8U-jdk_x64_linux_hotspot_8u422b05.tar.gz",
        checksum_url=None,
        extract_dir="jdk8u422-b05",
        bin_subpath="bin",
    ),
    "11": RuntimeVersionInfo(
        version="11",
        package_name="temurin-11-jdk",
        download_url="https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.24%2B8/OpenJDK11U-jdk_x64_linux_hotspot_11.0.24_8.tar.gz",
        checksum_url=None,
        extract_dir="jdk-11.0.24+8",
        bin_subpath="bin",
    ),
    "17": RuntimeVersionInfo(
        version="17",
        package_name="temurin-17-jdk",
        download_url="https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.12%2B7/OpenJDK17U-jdk_x64_linux_hotspot_17.0.12_7.tar.gz",
        checksum_url=None,
        extract_dir="jdk-17.0.12+7",
        bin_subpath="bin",
    ),
    "21": RuntimeVersionInfo(
        version="21",
        package_name="temurin-21-jdk",
        download_url="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.4%2B7/OpenJDK21U-jdk_x64_linux_hotspot_21.0.4_7.tar.gz",
        checksum_url=None,
        extract_dir="jdk-21.0.4+7",
        bin_subpath="bin",
    ),
}

# =============================================================================
# Python (python.org official builds)
# =============================================================================

PYTHON_BASE_URL = "https://www.python.org/ftp/python"

PYTHON_VERSIONS: dict[str, RuntimeVersionInfo] = {
    "3.8": RuntimeVersionInfo(
        version="3.8",
        package_name="python-3.8",
        download_url="https://www.python.org/ftp/python/3.8.20/Python-3.8.20.tgz",
        checksum_url=None,
        extract_dir="Python-3.8.20",
        bin_subpath="",  # Python needs to be built, special handling
    ),
    "3.9": RuntimeVersionInfo(
        version="3.9",
        package_name="python-3.9",
        download_url="https://www.python.org/ftp/python/3.9.21/Python-3.9.21.tgz",
        checksum_url=None,
        extract_dir="Python-3.9.21",
        bin_subpath="",
    ),
    "3.10": RuntimeVersionInfo(
        version="3.10",
        package_name="python-3.10",
        download_url="https://www.python.org/ftp/python/3.10.16/Python-3.10.16.tgz",
        checksum_url=None,
        extract_dir="Python-3.10.16",
        bin_subpath="",
    ),
    "3.11": RuntimeVersionInfo(
        version="3.11",
        package_name="python-3.11",
        download_url="https://www.python.org/ftp/python/3.11.11/Python-3.11.11.tgz",
        checksum_url=None,
        extract_dir="Python-3.11.11",
        bin_subpath="",
    ),
    "3.12": RuntimeVersionInfo(
        version="3.12",
        package_name="python-3.12",
        download_url="https://www.python.org/ftp/python/3.12.8/Python-3.12.8.tgz",
        checksum_url=None,
        extract_dir="Python-3.12.8",
        bin_subpath="",
    ),
}

# For Python, we'll use pre-built binaries from PyPy or deadsnakes PPA alternative
# Using conda/miniconda as a simpler alternative for Python version management
PYTHON_MINICONDA_URLS: dict[str, RuntimeVersionInfo] = {
    "3.8": RuntimeVersionInfo(
        version="3.8",
        package_name="miniconda-py38",
        download_url="https://repo.anaconda.com/miniconda/Miniconda3-py38_24.7.1-0-Linux-x86_64.sh",
        checksum_url=None,
        extract_dir=None,  # Shell script, special handling
        bin_subpath="bin",
    ),
    "3.9": RuntimeVersionInfo(
        version="3.9",
        package_name="miniconda-py39",
        download_url="https://repo.anaconda.com/miniconda/Miniconda3-py39_24.7.1-0-Linux-x86_64.sh",
        checksum_url=None,
        extract_dir=None,
        bin_subpath="bin",
    ),
    "3.10": RuntimeVersionInfo(
        version="3.10",
        package_name="miniconda-py310",
        download_url="https://repo.anaconda.com/miniconda/Miniconda3-py310_24.7.1-0-Linux-x86_64.sh",
        checksum_url=None,
        extract_dir=None,
        bin_subpath="bin",
    ),
    "3.11": RuntimeVersionInfo(
        version="3.11",
        package_name="miniconda-py311",
        download_url="https://repo.anaconda.com/miniconda/Miniconda3-py311_24.7.1-0-Linux-x86_64.sh",
        checksum_url=None,
        extract_dir=None,
        bin_subpath="bin",
    ),
    "3.12": RuntimeVersionInfo(
        version="3.12",
        package_name="miniconda-py312",
        download_url="https://repo.anaconda.com/miniconda/Miniconda3-py312_24.7.1-0-Linux-x86_64.sh",
        checksum_url=None,
        extract_dir=None,
        bin_subpath="bin",
    ),
}

# =============================================================================
# Node.js (nodejs.org official builds)
# =============================================================================

NODE_BASE_URL = "https://nodejs.org/dist"

NODE_VERSIONS: dict[str, RuntimeVersionInfo] = {
    "16": RuntimeVersionInfo(
        version="16",
        package_name="node-16",
        download_url="https://nodejs.org/dist/v16.20.2/node-v16.20.2-linux-x64.tar.xz",
        checksum_url=None,
        extract_dir="node-v16.20.2-linux-x64",
        bin_subpath="bin",
    ),
    "18": RuntimeVersionInfo(
        version="18",
        package_name="node-18",
        download_url="https://nodejs.org/dist/v18.20.5/node-v18.20.5-linux-x64.tar.xz",
        checksum_url=None,
        extract_dir="node-v18.20.5-linux-x64",
        bin_subpath="bin",
    ),
    "20": RuntimeVersionInfo(
        version="20",
        package_name="node-20",
        download_url="https://nodejs.org/dist/v20.18.0/node-v20.18.0-linux-x64.tar.xz",
        checksum_url=None,
        extract_dir="node-v20.18.0-linux-x64",
        bin_subpath="bin",
    ),
}

# =============================================================================
# Go (go.dev official builds)
# =============================================================================

GO_BASE_URL = "https://go.dev/dl"

GO_VERSIONS: dict[str, RuntimeVersionInfo] = {
    "1.20": RuntimeVersionInfo(
        version="1.20",
        package_name="go-1.20",
        download_url="https://go.dev/dl/go1.20.14.linux-amd64.tar.gz",
        checksum_url=None,
        extract_dir="go",
        bin_subpath="bin",
    ),
    "1.21": RuntimeVersionInfo(
        version="1.21",
        package_name="go-1.21",
        download_url="https://go.dev/dl/go1.21.13.linux-amd64.tar.gz",
        checksum_url=None,
        extract_dir="go",
        bin_subpath="bin",
    ),
    "1.22": RuntimeVersionInfo(
        version="1.22",
        package_name="go-1.22",
        download_url="https://go.dev/dl/go1.22.8.linux-amd64.tar.gz",
        checksum_url=None,
        extract_dir="go",
        bin_subpath="bin",
    ),
}

# =============================================================================
# Combined Registry
# =============================================================================

RUNTIME_REGISTRY: dict[RuntimeType, dict[str, RuntimeVersionInfo]] = {
    RuntimeType.JAVA: JAVA_VERSIONS,
    RuntimeType.PYTHON: PYTHON_MINICONDA_URLS,  # Using miniconda for easier install
    RuntimeType.NODE: NODE_VERSIONS,
    RuntimeType.GO: GO_VERSIONS,
}


class RuntimeRegistry:
    """Registry for available runtime versions."""

    def __init__(self, registry: dict[RuntimeType, dict[str, RuntimeVersionInfo]] | None = None):
        """Initialize the registry.

        Args:
            registry: Optional custom registry. Uses default if not provided.
        """
        self._registry = registry or RUNTIME_REGISTRY

    def get_versions(self, runtime_type: RuntimeType) -> list[str]:
        """Get list of available versions for a runtime.

        Args:
            runtime_type: Type of runtime.

        Returns:
            List of available version strings.
        """
        versions = self._registry.get(runtime_type, {})
        return list(versions.keys())

    def get_info(self, runtime_type: RuntimeType, version: str) -> RuntimeVersionInfo | None:
        """Get version info for a specific runtime version.

        Args:
            runtime_type: Type of runtime.
            version: Version string.

        Returns:
            RuntimeVersionInfo or None if not found.
        """
        versions = self._registry.get(runtime_type, {})
        return versions.get(version)

    def is_version_available(self, runtime_type: RuntimeType, version: str) -> bool:
        """Check if a version is available in the registry.

        Args:
            runtime_type: Type of runtime.
            version: Version string.

        Returns:
            True if version is available.
        """
        return version in self._registry.get(runtime_type, {})

    def to_dict(self) -> dict[str, Any]:
        """Convert registry to dictionary."""
        return {
            rt.value: {v: info.to_dict() for v, info in versions.items()}
            for rt, versions in self._registry.items()
        }


def get_runtime_download_url(runtime_type: RuntimeType, version: str) -> str | None:
    """Convenience function to get download URL for a runtime version.

    Args:
        runtime_type: Type of runtime.
        version: Version string.

    Returns:
        Download URL or None if not found.
    """
    registry = RuntimeRegistry()
    info = registry.get_info(runtime_type, version)
    return info.download_url if info else None
