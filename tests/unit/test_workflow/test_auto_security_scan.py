"""Tests for auto security scan workflow."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.layers.l1_intelligence.workflow.auto_security_scan import (
    AutoSecurityScanner,
    ScanConfig,
    ScanResult,
)


class TestScanConfig:
    """Tests for ScanConfig model."""

    def test_default_config(self):
        """Test default configuration."""
        config = ScanConfig()
        assert config.scan_dependencies is True
        assert config.scan_frameworks is True
        assert config.lookup_cves is True
        assert config.include_low_severity is False
        assert config.concurrent_lookups == 5

    def test_custom_config(self):
        """Test custom configuration."""
        config = ScanConfig(
            scan_dependencies=False,
            max_cves_per_dependency=20,
            include_low_severity=True,
            timeout_seconds=600,
        )
        assert config.scan_dependencies is False
        assert config.max_cves_per_dependency == 20
        assert config.include_low_severity is True
        assert config.timeout_seconds == 600


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_empty_result(self):
        """Test empty scan result."""
        result = ScanResult(success=False)
        assert result.success is False
        assert result.report is None
        assert len(result.errors) == 0
        assert len(result.warnings) == 0

    def test_result_to_dict(self):
        """Test converting result to dict."""
        result = ScanResult(
            success=True,
            source_path="/test/path",
            scan_duration_seconds=1.5,
            errors=[],
            warnings=["test warning"],
        )
        data = result.to_dict()

        assert data["success"] is True
        assert data["source_path"] == "/test/path"
        assert data["scan_duration_seconds"] == 1.5
        assert data["warnings"] == ["test warning"]


class TestAutoSecurityScanner:
    """Tests for AutoSecurityScanner."""

    @pytest.fixture
    def mock_intel_service(self):
        """Create mock intel service."""
        service = MagicMock()
        service.search_cves = AsyncMock(return_value=[])
        return service

    @pytest.fixture
    def scanner(self, mock_intel_service):
        """Create scanner instance."""
        return AutoSecurityScanner(intel_service=mock_intel_service)

    def test_create_scanner(self, scanner):
        """Test creating scanner."""
        assert scanner.intel_service is not None
        assert scanner.config is not None
        assert scanner.security_analyzer is not None
        assert scanner.tech_detector is not None

    def test_create_scanner_with_config(self, mock_intel_service):
        """Test creating scanner with custom config."""
        config = ScanConfig(include_low_severity=True)
        scanner = AutoSecurityScanner(
            intel_service=mock_intel_service,
            config=config,
        )
        assert scanner.config.include_low_severity is True

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path(self, scanner):
        """Test scanning non-existent path."""
        result = await scanner.scan(Path("/nonexistent/path"))
        assert result.success is False
        assert len(result.errors) > 0
        assert "does not exist" in result.errors[0]

    @pytest.mark.asyncio
    async def test_scan_file_not_directory(self, scanner):
        """Test scanning a file instead of directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            file_path = path / "test.txt"
            file_path.write_text("test")

            result = await scanner.scan(file_path)
            assert result.success is False
            assert len(result.errors) > 0
            assert "not a directory" in result.errors[0]

    @pytest.mark.asyncio
    async def test_scan_empty_directory(self, scanner):
        """Test scanning empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            result = await scanner.scan(path)

            assert result.success is True
            assert result.report is not None
            assert result.report.dependencies_scanned == 0

    @pytest.mark.asyncio
    async def test_scan_python_project(self, mock_intel_service):
        """Test scanning Python project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "requirements.txt").write_text("requests==2.28.0\ndjango>=4.0.0")
            (path / "main.py").write_text("print('hello')")

            scanner = AutoSecurityScanner(intel_service=mock_intel_service)
            result = await scanner.scan(path)

            assert result.success is True
            assert result.report is not None
            assert result.report.dependencies_scanned >= 2
            # Should detect Python language
            assert result.report.tech_stack is not None

    @pytest.mark.asyncio
    async def test_scan_javascript_project(self, mock_intel_service):
        """Test scanning JavaScript project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            import json

            package_json = {
                "dependencies": {
                    "express": "^4.18.0",
                    "lodash": "^4.17.21",
                },
            }
            (path / "package.json").write_text(json.dumps(package_json))

            scanner = AutoSecurityScanner(intel_service=mock_intel_service)
            result = await scanner.scan(path)

            assert result.success is True
            assert result.report is not None
            assert result.report.dependencies_scanned >= 2

    def test_get_tech_stack_summary(self, scanner):
        """Test getting tech stack summary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "requirements.txt").write_text("django>=4.0.0")
            (path / "manage.py").write_text("# Django project")

            summary = scanner.get_tech_stack_summary(path)

            assert "python" in summary["languages"]
            assert len(summary["frameworks"]) > 0
            fw_names = [fw["name"] for fw in summary["frameworks"]]
            assert "django" in fw_names

    @pytest.mark.asyncio
    async def test_quick_scan(self, mock_intel_service):
        """Test quick scan functionality."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "requirements.txt").write_text("requests==2.28.0")

            scanner = AutoSecurityScanner(intel_service=mock_intel_service)
            result = await scanner.quick_scan(path)

            assert result["success"] is True
            assert "dependencies" in result
            assert "duration" in result

    @pytest.mark.asyncio
    async def test_quick_scan_nonexistent(self, scanner):
        """Test quick scan on non-existent path."""
        result = await scanner.quick_scan(Path("/nonexistent/path"))
        assert result["success"] is False
        assert "errors" in result

    @pytest.mark.asyncio
    async def test_scan_with_warnings(self, mock_intel_service):
        """Test scan that produces warnings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            # Create an invalid requirements.txt
            (path / "requirements.txt").write_text("invalid package spec !!!")

            scanner = AutoSecurityScanner(intel_service=mock_intel_service)
            result = await scanner.scan(path)

            # Scan should still succeed
            assert result.success is True
            # But may have warnings/errors
            assert result.report is not None
