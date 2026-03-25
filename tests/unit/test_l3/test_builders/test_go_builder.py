"""
Unit tests for Go builder.
"""

from pathlib import Path

import pytest

from src.layers.l3_analysis.build.builders.base import (
    BuildResult,
    FailureCategory,
    FailureDiagnosis,
)
from src.layers.l3_analysis.build.builders.go import GoBuilder


class TestGoBuilderAnalyze:
    """Tests for GoBuilder.analyze method."""

    @pytest.fixture
    def builder(self) -> GoBuilder:
        """Create a GoBuilder instance."""
        return GoBuilder()

    def test_simple_go_module(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test analyzing a simple Go module."""
        # Create go.mod
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            "module example.com/myapp\n\n"
            "go 1.21\n\n"
            "require github.com/gin-gonic/gin v1.9.0\n"
        )

        # Create a simple Go file
        main_go = tmp_path / "main.go"
        main_go.write_text('package main\n\nfunc main() {}\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.language == "go"
        assert output.build_command == "go build ./..."
        assert output.dependency_command == "go mod download"
        assert "go.mod" in output.detected_files

    def test_go_without_mod(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test analyzing Go project without go.mod."""
        # Create only Go files
        main_go = tmp_path / "main.go"
        main_go.write_text('package main\n\nfunc main() {}\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SKIPPED
        assert output.skip_reason is not None
        assert "no go.mod" in output.skip_reason.lower()

    def test_cgo_detection(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test detecting CGO in Go source."""
        # Create go.mod
        go_mod = tmp_path / "go.mod"
        go_mod.write_text("module example.com/cgo-app\n\ngo 1.21\n")

        # Create file with CGO import
        cgo_go = tmp_path / "cgo.go"
        cgo_go.write_text(
            'package main\n\n'
            '/*\n'
            '#include <stdlib.h>\n'
            '*/\n'
            'import "C"\n\n'
            'func main() {}\n'
        )

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Should have CGO warning
        assert any("CGO" in w for w in output.warnings)

    def test_vendor_mode(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test vendor directory detection."""
        # Create go.mod
        go_mod = tmp_path / "go.mod"
        go_mod.write_text("module example.com/vendored\n\ngo 1.21\n")

        # Create vendor directory
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert "-mod=vendor" in output.build_command

    def test_go_work(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test go.work workspace detection."""
        # Create go.work
        go_work = tmp_path / "go.work"
        go_work.write_text(
            "go 1.21\n\n"
            "use (\n"
            "    ./module1\n"
            "    ./module2\n"
            ")\n"
        )

        # Create modules
        for name in ["module1", "module2"]:
            mod_path = tmp_path / name
            mod_path.mkdir()
            (mod_path / "go.mod").write_text(f"module example.com/{name}\n\ngo 1.21\n")

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.build_command == "go build ./..."
        assert "go.work" in output.detected_files

    def test_build_tags_detection(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test detection of build tags in Go files."""
        # Create go.mod
        go_mod = tmp_path / "go.mod"
        go_mod.write_text("module example.com/tags\n\ngo 1.21\n")

        # Create file with build tags
        tagged_go = tmp_path / "tagged_linux.go"
        tagged_go.write_text(
            '//go:build linux\n\n'
            'package main\n\n'
            'func main() {}\n'
        )

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Build tags detected should be in output
        assert output.build_command is not None


class TestGoBuilderDiagnoseFailure:
    """Tests for GoBuilder.diagnose_failure method."""

    @pytest.fixture
    def builder(self) -> GoBuilder:
        """Create a GoBuilder instance."""
        return GoBuilder()

    def test_dependency_missing(self, builder: GoBuilder) -> None:
        """Test diagnosing missing dependency."""
        stderr = (
            "main.go:5:2: cannot find package \"github.com/unknown/package\" "
            "in any of:\n"
            "\t/usr/local/go/src/github.com/unknown/package"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.DEPENDENCY_MISSING
        assert "github.com/unknown/package" in diagnosis.message

    def test_private_module_inaccessible(self, builder: GoBuilder) -> None:
        """Test diagnosing private module access failure."""
        stderr = (
            "go: github.com/private/repo@v1.0.0: reading "
            "github.com/private/repo/go.mod at revision v1.0.0: "
            "unknown revision v1.0.0\n"
            "go: module github.com/private/repo: git ls-remote -q origin"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.PRIVATE_MODULE
        assert "private" in diagnosis.message.lower()

    def test_cgo_error(self, builder: GoBuilder) -> None:
        """Test diagnosing CGO compilation failure."""
        stderr = (
            "# example.com/cgo-app\n"
            "cgo.go:5:10: fatal error: 'stdlib.h' file not found\n"
            "#include <stdlib.h>\n"
            "         ^~~~~~~~~\n"
            "1 error generated."
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.CGO_REQUIRED

    def test_compilation_error(self, builder: GoBuilder) -> None:
        """Test diagnosing Go compilation error."""
        stderr = (
            "./main.go:10:5: undefined: someFunction\n"
            "./main.go:15:2: syntax error: unexpected semicolon"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.COMPILATION_ERROR

    def test_go_version_mismatch(self, builder: GoBuilder) -> None:
        """Test diagnosing Go version mismatch."""
        stderr = (
            "go: go.mod file indicates go 1.22, but maximum supported version is 1.21"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.VERSION_MISMATCH

    def test_unknown_error(self, builder: GoBuilder) -> None:
        """Test diagnosing unknown error."""
        stderr = "some random error message"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.UNKNOWN

    def test_success_return_code(self, builder: GoBuilder) -> None:
        """Test that return code 0 is handled."""
        diagnosis = builder.diagnose_failure("built successfully", "", 0)

        assert diagnosis.category == FailureCategory.UNKNOWN
        assert diagnosis.message == ""


class TestGoBuilderUtilities:
    """Tests for GoBuilder utility methods."""

    @pytest.fixture
    def builder(self) -> GoBuilder:
        """Create a GoBuilder instance."""
        return GoBuilder()

    def test_has_cgo_true(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test CGO detection when present."""
        cgo_file = tmp_path / "cgo.go"
        cgo_file.write_text(
            'package main\n\n'
            '/*\n#include <stdio.h>\n*/\n'
            'import "C"\n'
        )

        assert builder._has_cgo(tmp_path) is True

    def test_has_cgo_false(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test CGO detection when absent."""
        go_file = tmp_path / "plain.go"
        go_file.write_text('package main\n\nfunc main() {}\n')

        assert builder._has_cgo(tmp_path) is False

    def test_has_vendor_true(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test vendor directory detection."""
        (tmp_path / "vendor").mkdir()
        assert builder._has_vendor(tmp_path) is True

    def test_has_vendor_false(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test vendor directory absence."""
        assert builder._has_vendor(tmp_path) is False

    def test_parse_go_mod(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test parsing go.mod file."""
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            "module example.com/myapp\n\n"
            "go 1.22\n\n"
            "require (\n"
            "    github.com/gin-gonic/gin v1.9.0\n"
            "    golang.org/x/tools v0.15.0\n"
            ")\n"
        )

        info = builder._parse_go_mod(go_mod)

        assert info["module"] == "example.com/myapp"
        assert info["go_version"] == "1.22"

    def test_get_build_tags(self, builder: GoBuilder, tmp_path: Path) -> None:
        """Test extracting build tags from files."""
        # Create files with build tags
        (tmp_path / "main.go").write_text("package main\n")
        (tmp_path / "linux.go").write_text(
            "//go:build linux\n\npackage main\n"
        )
        (tmp_path / "windows.go").write_text(
            "//go:build windows\n\npackage main\n"
        )

        tags = builder._get_build_tags(tmp_path)

        assert "linux" in tags
        assert "windows" in tags


class TestGoBuilderRegistration:
    """Tests for GoBuilder registration."""

    def test_go_builder_registered(self) -> None:
        """Test that GoBuilder is registered."""
        from src.layers.l3_analysis.build.builders.base import BuilderRegistry

        # Clear and re-register
        BuilderRegistry._builders.clear()
        from src.layers.l3_analysis.build.builders.go import GoBuilder
        BuilderRegistry.register(GoBuilder)

        builder = BuilderRegistry.get("go")
        assert builder is not None
        assert builder.LANGUAGE_NAME == "go"
