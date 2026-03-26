"""
Unit tests for Builder integration in CodeQL engine (P7-05e).

Tests that the CodeQLEngine uses Builder system for intelligent build analysis.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.layers.l3_analysis.build.builders.base import (
    BuildResult,
    BuilderOutput,
    FailureCategory,
)
from src.layers.l3_analysis.readiness_gate import BuildReadinessInfo


class TestExecuteBuildWithBuilder:
    """Tests for _execute_build using Builder system."""

    @pytest.fixture
    def codeql_engine(self):
        """Create a CodeQLEngine instance."""
        from src.layers.l3_analysis.engines.codeql import CodeQLEngine
        engine = CodeQLEngine()
        engine.build_timeout = 300
        return engine

    @pytest.mark.asyncio
    async def test_execute_build_with_readiness_info_skip(
        self, codeql_engine, tmp_path: Path
    ) -> None:
        """Test _execute_build respects skip_reason from readiness_info."""
        # Create readiness_info with skip_reason
        readiness_info = BuildReadinessInfo(
            target_name="test-target",
            language="python",
            buildable=True,
            skip_reason="No Python files found",
        )

        result = await codeql_engine._execute_build(
            source_path=tmp_path,
            language="python",
            readiness_info=readiness_info,
        )

        assert result["success"] is True
        assert result["skipped"] is True
        assert "No Python files found" in result["reason"]

    @pytest.mark.asyncio
    async def test_execute_build_with_readiness_info_warnings(
        self, codeql_engine, tmp_path: Path
    ) -> None:
        """Test _execute_build passes warnings from readiness_info."""
        readiness_info = BuildReadinessInfo(
            target_name="test-target",
            language="python",
            buildable=True,
            warnings=["Cython extension detected"],
        )

        result = await codeql_engine._execute_build(
            source_path=tmp_path,
            language="python",
            readiness_info=readiness_info,
        )

        assert result["success"] is True
        assert "Cython extension detected" in result.get("warnings", [])

    @pytest.mark.asyncio
    async def test_execute_build_without_readiness_info_uses_builder(
        self, codeql_engine, tmp_path: Path
    ) -> None:
        """Test _execute_build uses Builder when no readiness_info provided."""
        # Create a Python file
        (tmp_path / "main.py").write_text("print('hello')\n")

        result = await codeql_engine._execute_build(
            source_path=tmp_path,
            language="python",
            readiness_info=None,
        )

        # Python should not require build
        assert result["success"] is True
        assert result["skipped"] is True

    @pytest.mark.asyncio
    async def test_execute_build_java_no_command(
        self, codeql_engine, tmp_path: Path
    ) -> None:
        """Test _execute_build handles Java without build command."""
        result = await codeql_engine._execute_build(
            source_path=tmp_path,
            language="java",
            readiness_info=None,
        )

        # Java requires build but no command available
        assert result["success"] is True
        assert result["skipped"] is True
        # Builder now returns proper skip reason
        assert "No build system" in result["reason"] or "No build command" in result["reason"]

    @pytest.mark.asyncio
    async def test_execute_build_interpreted_language(
        self, codeql_engine, tmp_path: Path
    ) -> None:
        """Test _execute_build for interpreted languages."""
        for lang in ["python", "javascript", "typescript", "ruby"]:
            result = await codeql_engine._execute_build(
                source_path=tmp_path,
                language=lang,
                readiness_info=None,
            )

            assert result["success"] is True
            assert result["skipped"] is True
            # Builder returns specific skip reason for no files found
            assert "No" in result["reason"] or "no build" in result["reason"].lower()


class TestScanAcceptsReadinessResult:
    """Tests for scan() accepting readiness_result parameter."""

    @pytest.fixture
    def codeql_engine(self):
        """Create a CodeQLEngine instance."""
        from src.layers.l3_analysis.engines.codeql import CodeQLEngine
        engine = CodeQLEngine()
        engine.build_timeout = 300
        return engine

    @pytest.mark.asyncio
    async def test_scan_accepts_readiness_result_parameter(
        self, codeql_engine, tmp_path: Path
    ) -> None:
        """Test scan() method accepts readiness_result parameter."""
        # Create a simple Python file
        (tmp_path / "main.py").write_text("print('hello')\n")

        # Mock the readiness_result
        readiness_result = MagicMock()
        readiness_result.build_targets = []
        readiness_result.build_warnings = {}

        # This should not raise an error
        # Note: The actual scan will fail because CodeQL is not available,
        # but we're testing that the parameter is accepted
        result = await codeql_engine.scan(
            source_path=tmp_path,
            language="python",
            readiness_result=readiness_result,
        )

        # Result should be a ScanResult
        assert result is not None

    @pytest.mark.asyncio
    async def test_scan_without_readiness_result_still_works(
        self, codeql_engine, tmp_path: Path
    ) -> None:
        """Test scan() works without readiness_result (backward compatibility)."""
        (tmp_path / "main.py").write_text("print('hello')\n")

        result = await codeql_engine.scan(
            source_path=tmp_path,
            language="python",
        )

        # Should still work
        assert result is not None


class TestScanMultiLanguageAcceptsReadinessResult:
    """Tests for scan_multi_language accepting readiness_result parameter."""

    @pytest.fixture
    def codeql_engine(self):
        """Create a CodeQLEngine instance."""
        from src.layers.l3_analysis.engines.codeql import CodeQLEngine
        engine = CodeQLEngine()
        engine.build_timeout = 300
        return engine

    @pytest.mark.asyncio
    async def test_scan_multi_language_accepts_readiness_result(
        self, codeql_engine, tmp_path: Path
    ) -> None:
        """Test scan_multi_language accepts readiness_result parameter."""
        (tmp_path / "main.py").write_text("print('hello')\n")
        (tmp_path / "app.js").write_text("console.log('hello');\n")

        readiness_result = MagicMock()
        readiness_result.build_targets = []
        readiness_result.build_warnings = {}

        result = await codeql_engine.scan_multi_language(
            source_path=tmp_path,
            languages=["python", "javascript"],
            readiness_result=readiness_result,
        )

        assert result is not None


class TestBuildWarningsInMetadata:
    """Tests for build_warnings in scan result metadata."""

    def test_build_warnings_structure(self) -> None:
        """Test BuildReadinessInfo data structure."""
        info = BuildReadinessInfo(
            target_name="test-target",
            language="python",
            buildable=True,
            warnings=["Warning 1", "Warning 2"],
            skip_reason=None,
            build_command=None,
            detected_files=["main.py"],
        )

        assert info.target_name == "test-target"
        assert info.language == "python"
        assert info.buildable is True
        assert len(info.warnings) == 2
        assert info.skip_reason is None

    def test_build_readiness_info_skip_reason(self) -> None:
        """Test BuildReadinessInfo with skip_reason."""
        info = BuildReadinessInfo(
            target_name="test-target",
            language="python",
            buildable=False,
            warnings=[],
            skip_reason="No Python files found",
        )

        assert info.buildable is False
        assert info.skip_reason == "No Python files found"


class TestBuilderOutputUsage:
    """Tests for BuilderOutput usage in integration."""

    def test_builder_output_no_build(self) -> None:
        """Test BuilderOutput for no-build scenario."""
        output = BuilderOutput(
            result=BuildResult.SUCCESS,
            language="python",
            build_command=None,
            dependency_command=None,
            warnings=["Cython detected"],
            detected_files=["main.py", "setup.py"],
        )

        assert output.result == BuildResult.SUCCESS
        assert output.build_command is None
        assert "Cython detected" in output.warnings

    def test_builder_output_skipped(self) -> None:
        """Test BuilderOutput for skipped scenario."""
        output = BuilderOutput(
            result=BuildResult.SKIPPED,
            language="python",
            skip_reason="No Python files found",
            failure_category=FailureCategory.CONFIG_ERROR,
        )

        assert output.result == BuildResult.SKIPPED
        assert output.skip_reason == "No Python files found"
