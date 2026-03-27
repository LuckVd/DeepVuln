"""Tests for Runtime Models."""

import pytest
from pathlib import Path

from src.layers.l3_analysis.build.runtime.models import (
    RuntimeType,
    RuntimeInfo,
    RuntimeRequirement,
    RuntimeInstallResult,
    RuntimeVersionInfo,
    RuntimeSwitchResult,
)


class TestRuntimeType:
    """Tests for RuntimeType enum."""

    def test_runtime_type_values(self):
        """Test runtime type enum values."""
        assert RuntimeType.JAVA.value == "java"
        assert RuntimeType.PYTHON.value == "python"
        assert RuntimeType.NODE.value == "node"
        assert RuntimeType.GO.value == "go"

    def test_runtime_type_string_conversion(self):
        """Test string conversion of runtime type."""
        assert RuntimeType.JAVA.value == "java"
        assert RuntimeType("python") == RuntimeType.PYTHON


class TestRuntimeInfo:
    """Tests for RuntimeInfo dataclass."""

    def test_runtime_info_creation(self):
        """Test creating a RuntimeInfo instance."""
        info = RuntimeInfo(
            runtime_type=RuntimeType.JAVA,
            version="8",
            install_path=Path("/opt/runtimes/java/8"),
            executable=Path("/opt/runtimes/java/8/bin/java"),
        )
        assert info.runtime_type == RuntimeType.JAVA
        assert info.version == "8"
        assert info.install_path == Path("/opt/runtimes/java/8")
        assert info.executable == Path("/opt/runtimes/java/8/bin/java")

    def test_runtime_info_to_dict(self):
        """Test converting RuntimeInfo to dictionary."""
        info = RuntimeInfo(
            runtime_type=RuntimeType.PYTHON,
            version="3.10",
            install_path=Path("/opt/runtimes/python/3.10"),
            executable=Path("/opt/runtimes/python/3.10/bin/python"),
            source="download",
        )
        d = info.to_dict()
        assert d["runtime_type"] == "python"
        assert d["version"] == "3.10"
        assert d["install_path"] == "/opt/runtimes/python/3.10"
        assert d["executable"] == "/opt/runtimes/python/3.10/bin/python"
        assert d["source"] == "download"

    def test_runtime_info_bin_path(self):
        """Test getting bin path from RuntimeInfo."""
        info = RuntimeInfo(
            runtime_type=RuntimeType.NODE,
            version="18",
            install_path=Path("/opt/runtimes/node/18"),
            executable=Path("/opt/runtimes/node/18/bin/node"),
        )
        assert info.bin_path == Path("/opt/runtimes/node/18/bin")


class TestRuntimeRequirement:
    """Tests for RuntimeRequirement dataclass."""

    def test_runtime_requirement_creation(self):
        """Test creating a RuntimeRequirement instance."""
        req = RuntimeRequirement(
            runtime_type=RuntimeType.JAVA,
            required_version="8",
            detected_source="pom.xml:maven.compiler.source",
        )
        assert req.runtime_type == RuntimeType.JAVA
        assert req.required_version == "8"
        assert req.detected_source == "pom.xml:maven.compiler.source"

    def test_runtime_requirement_to_dict(self):
        """Test converting RuntimeRequirement to dictionary."""
        req = RuntimeRequirement(
            runtime_type=RuntimeType.GO,
            required_version="1.21",
            detected_source="go.mod",
            confidence=0.95,
        )
        d = req.to_dict()
        assert d["runtime_type"] == "go"
        assert d["required_version"] == "1.21"
        assert d["detected_source"] == "go.mod"
        assert d["confidence"] == 0.95


class TestRuntimeInstallResult:
    """Tests for RuntimeInstallResult dataclass."""

    def test_install_result_success(self):
        """Test successful install result."""
        result = RuntimeInstallResult(
            success=True,
            runtime_type=RuntimeType.JAVA,
            version="8",
            install_path=Path("/opt/runtimes/java/8"),
            duration_seconds=45.5,
        )
        assert result.success is True
        assert result.error is None
        assert result.duration_seconds == 45.5

    def test_install_result_failure(self):
        """Test failed install result."""
        result = RuntimeInstallResult(
            success=False,
            runtime_type=RuntimeType.PYTHON,
            version="3.9",
            error="Download failed",
        )
        assert result.success is False
        assert result.error == "Download failed"

    def test_install_result_to_dict(self):
        """Test converting install result to dictionary."""
        result = RuntimeInstallResult(
            success=True,
            runtime_type=RuntimeType.NODE,
            version="18",
            install_path=Path("/opt/runtimes/node/18"),
            duration_seconds=30.0,
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["runtime_type"] == "node"
        assert d["version"] == "18"
        assert d["install_path"] == "/opt/runtimes/node/18"


class TestRuntimeVersionInfo:
    """Tests for RuntimeVersionInfo dataclass."""

    def test_version_info_creation(self):
        """Test creating a RuntimeVersionInfo instance."""
        info = RuntimeVersionInfo(
            version="8",
            package_name="temurin-8-jdk",
            download_url="https://example.com/jdk8.tar.gz",
            extract_dir="jdk8u422-b05",
            bin_subpath="bin",
        )
        assert info.version == "8"
        assert info.package_name == "temurin-8-jdk"
        assert info.download_url == "https://example.com/jdk8.tar.gz"

    def test_version_info_to_dict(self):
        """Test converting version info to dictionary."""
        info = RuntimeVersionInfo(
            version="3.10",
            package_name="python-3.10",
            download_url="https://example.com/python.tgz",
            checksum_type="sha256",
        )
        d = info.to_dict()
        assert d["version"] == "3.10"
        assert d["package_name"] == "python-3.10"
        assert d["checksum_type"] == "sha256"


class TestRuntimeSwitchResult:
    """Tests for RuntimeSwitchResult dataclass."""

    def test_switch_result_success(self):
        """Test successful switch result."""
        result = RuntimeSwitchResult(
            success=True,
            runtime_type=RuntimeType.JAVA,
            version="8",
            old_env={"JAVA_HOME": "/opt/jdk21"},
            new_env={"JAVA_HOME": "/opt/runtimes/java/8"},
        )
        assert result.success is True
        assert result.error is None
        assert result.old_env["JAVA_HOME"] == "/opt/jdk21"
        assert result.new_env["JAVA_HOME"] == "/opt/runtimes/java/8"

    def test_switch_result_failure(self):
        """Test failed switch result."""
        result = RuntimeSwitchResult(
            success=False,
            runtime_type=RuntimeType.GO,
            version="1.21",
            error="GOPATH not set",
        )
        assert result.success is False
        assert result.error == "GOPATH not set"
