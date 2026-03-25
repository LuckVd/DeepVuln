"""
Unit tests for builder base classes and protocol.
"""

from pathlib import Path

import pytest

from src.layers.l3_analysis.build.builders.base import (
    BuildResult,
    BuilderOutput,
    BuilderRegistry,
    FailureCategory,
    FailureDiagnosis,
    LanguageBuilder,
)


class TestBuildResult:
    """Tests for BuildResult enum."""

    def test_build_result_values(self) -> None:
        """Test that BuildResult has expected values."""
        assert BuildResult.SUCCESS.value == "success"
        assert BuildResult.FAILED.value == "failed"
        assert BuildResult.SKIPPED.value == "skipped"
        assert BuildResult.PARTIAL.value == "partial"

    def test_build_result_from_string(self) -> None:
        """Test creating BuildResult from string."""
        assert BuildResult("success") == BuildResult.SUCCESS
        assert BuildResult("skipped") == BuildResult.SKIPPED


class TestFailureCategory:
    """Tests for FailureCategory enum."""

    def test_failure_categories_exist(self) -> None:
        """Test that key failure categories exist."""
        assert FailureCategory.DEPENDENCY_MISSING.value == "dependency_missing"
        assert FailureCategory.COMPILATION_ERROR.value == "compilation_error"
        assert FailureCategory.VERSION_MISMATCH.value == "version_mismatch"
        assert FailureCategory.CGO_REQUIRED.value == "cgo_required"
        assert FailureCategory.WRAPPER_PERMISSION.value == "wrapper_permission"


class TestBuilderOutput:
    """Tests for BuilderOutput dataclass."""

    def test_minimal_output(self) -> None:
        """Test creating minimal BuilderOutput."""
        output = BuilderOutput(
            result=BuildResult.SUCCESS,
            language="go",
        )
        assert output.result == BuildResult.SUCCESS
        assert output.language == "go"
        assert output.build_command is None
        assert output.dependency_command is None
        assert output.env_vars == {}

    def test_full_output(self) -> None:
        """Test creating full BuilderOutput with all fields."""
        output = BuilderOutput(
            result=BuildResult.SUCCESS,
            language="java",
            build_command="mvn compile",
            dependency_command="mvn dependency:resolve",
            env_vars={"MAVEN_OPTS": "-Xmx2g"},
            cwd=Path("/project"),
            timeout=600,
            build_system="maven",
            module_name="my-app",
        )
        assert output.build_command == "mvn compile"
        assert output.dependency_command == "mvn dependency:resolve"
        assert output.env_vars == {"MAVEN_OPTS": "-Xmx2g"}
        assert output.cwd == Path("/project")
        assert output.timeout == 600

    def test_skip_output(self) -> None:
        """Test creating skip output."""
        output = BuilderOutput(
            result=BuildResult.SKIPPED,
            language="go",
            skip_reason="CGO project requires C compiler",
            failure_category=FailureCategory.CGO_REQUIRED,
        )
        assert output.is_skipped is True
        assert output.is_buildable is False

    def test_buildable_output(self) -> None:
        """Test is_buildable property."""
        success_with_command = BuilderOutput(
            result=BuildResult.SUCCESS,
            language="go",
            build_command="go build ./...",
        )
        assert success_with_command.is_buildable is True

        success_no_command = BuilderOutput(
            result=BuildResult.SUCCESS,
            language="python",
        )
        assert success_no_command.is_buildable is False

    def test_to_dict(self) -> None:
        """Test serialization to dictionary."""
        output = BuilderOutput(
            result=BuildResult.SUCCESS,
            language="go",
            build_command="go build ./...",
            warnings=["No go.sum found"],
        )
        d = output.to_dict()
        assert d["result"] == "success"
        assert d["language"] == "go"
        assert d["build_command"] == "go build ./..."
        assert d["warnings"] == ["No go.sum found"]


class TestFailureDiagnosis:
    """Tests for FailureDiagnosis dataclass."""

    def test_minimal_diagnosis(self) -> None:
        """Test creating minimal diagnosis."""
        diagnosis = FailureDiagnosis(
            category=FailureCategory.COMPILATION_ERROR,
            message="Build failed",
        )
        assert diagnosis.category == FailureCategory.COMPILATION_ERROR
        assert diagnosis.message == "Build failed"
        assert diagnosis.suggestion is None
        assert diagnosis.is_recoverable is False

    def test_full_diagnosis(self) -> None:
        """Test creating full diagnosis."""
        diagnosis = FailureDiagnosis(
            category=FailureCategory.VERSION_MISMATCH,
            message="Java 17 required but Java 11 detected",
            suggestion="Install Java 17 or update pom.xml",
            is_recoverable=False,
        )
        assert diagnosis.suggestion == "Install Java 17 or update pom.xml"
        assert diagnosis.is_recoverable is False

    def test_to_dict(self) -> None:
        """Test serialization."""
        diagnosis = FailureDiagnosis(
            category=FailureCategory.DEPENDENCY_MISSING,
            message="golang.org/x/tools not found",
            suggestion="Run go mod download",
        )
        d = diagnosis.to_dict()
        assert d["category"] == "dependency_missing"
        assert d["message"] == "golang.org/x/tools not found"


class ConcreteBuilder(LanguageBuilder):
    """Concrete builder for testing abstract class."""

    LANGUAGE_NAME = "test_lang"
    SUPPORTED_BUILD_SYSTEMS = ["test_build"]

    def analyze(self, project_path: Path) -> BuilderOutput:
        return BuilderOutput(
            result=BuildResult.SUCCESS,
            language=self.LANGUAGE_NAME,
            build_command="test build",
        )

    def diagnose_failure(
        self, stdout: str, stderr: str, return_code: int
    ) -> FailureDiagnosis:
        return FailureDiagnosis(
            category=FailureCategory.UNKNOWN,
            message="Test failure",
        )


class TestLanguageBuilder:
    """Tests for LanguageBuilder abstract class."""

    def test_concrete_implementation(self) -> None:
        """Test that concrete implementation works."""
        builder = ConcreteBuilder()
        assert builder.LANGUAGE_NAME == "test_lang"
        assert builder.is_available() is True
        assert builder.get_version() is None
        assert builder.get_language_name() == "test_lang"

    def test_analyze_returns_output(self, tmp_path: Path) -> None:
        """Test that analyze returns BuilderOutput."""
        builder = ConcreteBuilder()
        output = builder.analyze(tmp_path)
        assert isinstance(output, BuilderOutput)
        assert output.language == "test_lang"

    def test_diagnose_failure_returns_diagnosis(self) -> None:
        """Test that diagnose_failure returns FailureDiagnosis."""
        builder = ConcreteBuilder()
        diagnosis = builder.diagnose_failure("", "error", 1)
        assert isinstance(diagnosis, FailureDiagnosis)


class TestBuilderRegistry:
    """Tests for BuilderRegistry."""

    def setup_method(self) -> None:
        """Clear registry before each test."""
        BuilderRegistry._builders.clear()

    def test_register_builder(self) -> None:
        """Test registering a builder."""

        @BuilderRegistry.register
        class RegisteredBuilder(LanguageBuilder):
            LANGUAGE_NAME = "registered"

            def analyze(self, project_path: Path) -> BuilderOutput:
                return BuilderOutput(result=BuildResult.SUCCESS, language="registered")

            def diagnose_failure(
                self, stdout: str, stderr: str, return_code: int
            ) -> FailureDiagnosis:
                return FailureDiagnosis(
                    category=FailureCategory.UNKNOWN, message=""
                )

        assert "registered" in BuilderRegistry.list_languages()

    def test_get_builder(self) -> None:
        """Test getting a registered builder."""
        BuilderRegistry._builders["test_lang"] = ConcreteBuilder

        builder = BuilderRegistry.get("test_lang")
        assert builder is not None
        assert builder.LANGUAGE_NAME == "test_lang"

    def test_get_builder_case_insensitive(self) -> None:
        """Test that builder lookup is case-insensitive."""
        BuilderRegistry._builders["test_lang"] = ConcreteBuilder

        assert BuilderRegistry.get("TEST_LANG") is not None
        assert BuilderRegistry.get("Test_Lang") is not None

    def test_get_unknown_builder(self) -> None:
        """Test getting unregistered builder returns None."""
        assert BuilderRegistry.get("unknown_language") is None

    def test_list_languages(self) -> None:
        """Test listing registered languages."""
        BuilderRegistry._builders["go"] = ConcreteBuilder
        BuilderRegistry._builders["java"] = ConcreteBuilder

        languages = BuilderRegistry.list_languages()
        assert "go" in languages
        assert "java" in languages
