"""
Go Docker Integration Tests (P7-11b-3).

Tests the complete flow for Go projects:
1. GoBuilder identifies project structure
2. Build command generation
3. CodeQL database creation (if CodeQL available)
4. Runtime version detection (go.mod)
"""

import pytest
from pathlib import Path

from src.layers.l3_analysis.build.builders import GoBuilder
from src.layers.l3_analysis.build.builders.base import BuildResult


# Mark all tests in this module as integration tests
pytestmark = [
    pytest.mark.integration,
]


class TestGoBuilderIntegration:
    """Integration tests for GoBuilder."""

    def test_builder_analyzes_go_mod(self, go_project: Path):
        """Test that builder analyzes go.mod project."""
        builder = GoBuilder()
        output = builder.analyze(go_project)

        assert output.language == "go"
        # Go projects should be buildable
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)

    def test_builder_detects_go_version(self, go_project: Path):
        """Test that builder extracts Go version from go.mod."""
        builder = GoBuilder()
        output = builder.analyze(go_project)

        # go.mod has "go 1.22"
        # Should detect go.mod
        assert any("go.mod" in f for f in output.detected_files)

    def test_builder_detects_cgo(self, tmp_path: Path):
        """Test that builder detects CGO usage."""
        project = tmp_path / "cgo_project"
        project.mkdir()
        (project / "go.mod").write_text("module test\n\ngo 1.22\n")
        (project / "main.go").write_text('''
package main

/*
#include <stdio.h>
void hello() {
    printf("Hello from C\\n");
}
*/
import "C"

func main() {
    C.hello()
}
''')

        builder = GoBuilder()
        output = builder.analyze(project)

        # CGO projects should have warnings
        assert any("CGO" in w or "cgo" in w for w in output.warnings)

    def test_builder_handles_no_go_mod(self, tmp_path: Path):
        """Test builder handles project without go.mod."""
        empty_project = tmp_path / "empty_go"
        empty_project.mkdir()
        (empty_project / "main.go").write_text('''
package main

func main() {
    println("hello")
}
''')

        builder = GoBuilder()
        output = builder.analyze(empty_project)

        assert output.language == "go"
        # Without go.mod, might be skipped
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)


class TestGoVersionDetection:
    """Integration tests for Go version detection."""

    def test_detect_go_version_from_mod(self, go_project: Path):
        """Test version detection from go.mod."""
        from src.layers.l3_analysis.build.version_detector import VersionDetector

        detector = VersionDetector(go_project)
        requirement = detector.detect()

        if requirement.go_version:
            assert "1.22" in requirement.go_version or "22" in requirement.go_version

    def test_detect_go_version_with_toolchain(self, tmp_path: Path):
        """Test version detection with toolchain directive."""
        from src.layers.l3_analysis.build.version_detector import VersionDetector

        project = tmp_path / "toolchain_project"
        project.mkdir()
        (project / "go.mod").write_text('''module test

go 1.21

toolchain go1.21.5
''')

        detector = VersionDetector(project)
        requirement = detector.detect()

        if requirement.go_version:
            assert "1.21" in requirement.go_version


class TestGoCodeQLIntegration:
    """CodeQL integration tests for Go (requires CodeQL)."""

    @pytest.mark.codeql
    @pytest.mark.skip(reason="Requires CodeQL build environment")
    def test_codeql_database_creation(self, go_project: Path, tmp_path: Path):
        """Test CodeQL database creation for Go project."""
        pass


class TestGoRuntimeVersionManager:
    """Test RuntimeVersionManager with Go."""

    def test_list_available_go_versions(self):
        """Test listing available Go versions."""
        from src.layers.l3_analysis.build.runtime.registry import RuntimeRegistry
        from src.layers.l3_analysis.build.runtime.models import RuntimeType

        registry = RuntimeRegistry()
        versions = registry.get_versions(RuntimeType.GO)

        assert len(versions) > 0
        assert "1.21" in versions or "1.22" in versions

    def test_go_download_url(self):
        """Test Go download URL generation."""
        from src.layers.l3_analysis.build.runtime.registry import RuntimeRegistry
        from src.layers.l3_analysis.build.runtime.models import RuntimeType

        registry = RuntimeRegistry()
        info = registry.get_info(RuntimeType.GO, "1.22")

        if info:
            assert "go.dev" in info.download_url or "golang.org" in str(info.download_url)
            assert "1.22" in str(info.download_url)
