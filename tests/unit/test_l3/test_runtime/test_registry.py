"""Tests for Runtime Registry."""

import pytest

from src.layers.l3_analysis.build.runtime.registry import (
    RuntimeRegistry,
    RUNTIME_REGISTRY,
    get_runtime_download_url,
)
from src.layers.l3_analysis.build.runtime.models import RuntimeType


class TestRuntimeRegistry:
    """Tests for RuntimeRegistry class."""

    def test_registry_has_all_runtime_types(self):
        """Test that registry contains all runtime types."""
        registry = RuntimeRegistry()
        assert RuntimeType.JAVA in registry._registry
        assert RuntimeType.PYTHON in registry._registry
        assert RuntimeType.NODE in registry._registry
        assert RuntimeType.GO in registry._registry

    def test_get_java_versions(self):
        """Test getting available Java versions."""
        registry = RuntimeRegistry()
        versions = registry.get_versions(RuntimeType.JAVA)
        assert "8" in versions
        assert "11" in versions
        assert "17" in versions
        assert "21" in versions

    def test_get_python_versions(self):
        """Test getting available Python versions."""
        registry = RuntimeRegistry()
        versions = registry.get_versions(RuntimeType.PYTHON)
        assert "3.8" in versions
        assert "3.9" in versions
        assert "3.10" in versions
        assert "3.11" in versions
        assert "3.12" in versions

    def test_get_node_versions(self):
        """Test getting available Node.js versions."""
        registry = RuntimeRegistry()
        versions = registry.get_versions(RuntimeType.NODE)
        assert "16" in versions
        assert "18" in versions
        assert "20" in versions

    def test_get_go_versions(self):
        """Test getting available Go versions."""
        registry = RuntimeRegistry()
        versions = registry.get_versions(RuntimeType.GO)
        assert "1.20" in versions
        assert "1.21" in versions
        assert "1.22" in versions

    def test_get_info_java_8(self):
        """Test getting Java 8 version info."""
        registry = RuntimeRegistry()
        info = registry.get_info(RuntimeType.JAVA, "8")
        assert info is not None
        assert info.version == "8"
        assert "temurin" in info.download_url.lower()
        assert info.download_url.endswith(".tar.gz")

    def test_get_info_nonexistent_version(self):
        """Test getting info for non-existent version."""
        registry = RuntimeRegistry()
        info = registry.get_info(RuntimeType.JAVA, "999")
        assert info is None

    def test_is_version_available_true(self):
        """Test version availability check for existing version."""
        registry = RuntimeRegistry()
        assert registry.is_version_available(RuntimeType.JAVA, "8") is True
        assert registry.is_version_available(RuntimeType.PYTHON, "3.10") is True

    def test_is_version_available_false(self):
        """Test version availability check for non-existing version."""
        registry = RuntimeRegistry()
        assert registry.is_version_available(RuntimeType.JAVA, "999") is False
        assert registry.is_version_available(RuntimeType.PYTHON, "2.7") is False

    def test_to_dict(self):
        """Test converting registry to dictionary."""
        registry = RuntimeRegistry()
        d = registry.to_dict()
        assert "java" in d
        assert "python" in d
        assert "node" in d
        assert "go" in d
        assert "8" in d["java"]
        assert "3.10" in d["python"]


class TestGetRuntimeDownloadUrl:
    """Tests for get_runtime_download_url convenience function."""

    def test_get_java_url(self):
        """Test getting Java download URL."""
        url = get_runtime_download_url(RuntimeType.JAVA, "8")
        assert url is not None
        assert "temurin" in url.lower()
        assert ".tar.gz" in url

    def test_get_python_url(self):
        """Test getting Python download URL."""
        url = get_runtime_download_url(RuntimeType.PYTHON, "3.10")
        assert url is not None
        assert "miniconda" in url.lower()

    def test_get_node_url(self):
        """Test getting Node.js download URL."""
        url = get_runtime_download_url(RuntimeType.NODE, "18")
        assert url is not None
        assert "nodejs.org" in url

    def test_get_go_url(self):
        """Test getting Go download URL."""
        url = get_runtime_download_url(RuntimeType.GO, "1.21")
        assert url is not None
        assert "go.dev" in url

    def test_get_nonexistent_url(self):
        """Test getting URL for non-existent version."""
        url = get_runtime_download_url(RuntimeType.JAVA, "999")
        assert url is None
