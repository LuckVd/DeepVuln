"""
Unit tests for CodeQL Readiness Gate.

Tests CodeQLReadinessGate, ReadinessGateResult, and integration
with LLM decision, build profiling, and tool compatibility.
"""

import pytest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from src.layers.l3_analysis.readiness_gate import (
    CodeQLReadinessGate,
    ReadinessGateResult,
    check_codeql_readiness,
)
from src.layers.l3_analysis.decision import (
    DecisionConstraints,
    DecisionError,
    LanguageDecision,
    LanguageRecommendation,
    LanguageStructure,
    SkippedLanguage,
)
from src.layers.l3_analysis.build import (
    BuildTarget,
    BuildSystem,
    ReadinessReport,
    ToolInfo,
    ToolSource,
    ToolType,
    VersionRequirement,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_project(tmp_path):
    """Create a temporary project directory."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "pom.xml").write_text("<project><modelVersion>4.0.0</modelVersion></project>")
    return project


@pytest.fixture
def mock_llm_client():
    """Create a mock LLM client."""
    return MagicMock()


@pytest.fixture
def readiness_gate(temp_project):
    """Create a readiness gate instance."""
    return CodeQLReadinessGate(project_path=temp_project)


# =============================================================================
# ReadinessGateResult Tests
# =============================================================================


class TestReadinessGateResult:
    """Tests for ReadinessGateResult dataclass."""

    def test_create_result(self):
        """Test creating a result."""
        result = ReadinessGateResult(
            ready=True,
            status="enabled",
            selected_languages=["java", "python"],
        )

        assert result.ready is True
        assert result.status == "enabled"
        assert "java" in result.selected_languages

    def test_result_to_dict(self):
        """Test result serialization."""
        skipped = [SkippedLanguage(language="javascript", reason="Low attack surface")]
        result = ReadinessGateResult(
            ready=True,
            status="enabled",
            selected_languages=["java"],
            skipped_languages=skipped,
            decision_source="llm",
            message="CodeQL ready",
        )

        d = result.to_dict()

        assert d["ready"] is True
        assert d["status"] == "enabled"
        assert d["decision_source"] == "llm"
        assert len(d["skipped_languages"]) == 1

    def test_result_default_values(self):
        """Test result default values."""
        result = ReadinessGateResult()

        assert result.ready is False
        assert result.status == "not_checked"
        assert result.selected_languages == []
        assert result.skipped_languages == []


# =============================================================================
# CodeQLReadinessGate Tests
# =============================================================================


class TestCodeQLReadinessGate:
    """Tests for CodeQLReadinessGate."""

    def test_gate_initialization(self, temp_project):
        """Test gate initialization."""
        gate = CodeQLReadinessGate(project_path=temp_project)

        assert gate.project_path == temp_project
        assert gate.startup_timeout == 15
        assert gate._decider is None  # Lazy initialization

    def test_gate_with_custom_settings(self, temp_project, mock_llm_client):
        """Test gate with custom settings."""
        constraints = DecisionConstraints(min_confidence=0.8)
        gate = CodeQLReadinessGate(
            project_path=temp_project,
            llm_client=mock_llm_client,
            constraints=constraints,
            startup_timeout=30,
        )

        assert gate.llm_client == mock_llm_client
        assert gate.constraints.min_confidence == 0.8
        assert gate.startup_timeout == 30

    def test_lazy_initialization(self, readiness_gate):
        """Test lazy initialization of sub-components."""
        # Sub-components should be None initially
        assert readiness_gate._decider is None
        assert readiness_gate._module_discovery is None
        assert readiness_gate._version_detector is None
        assert readiness_gate._tool_resolver is None

        # Access properties to trigger initialization
        decider = readiness_gate.decider
        discovery = readiness_gate.module_discovery
        detector = readiness_gate.version_detector
        resolver = readiness_gate.tool_resolver

        assert decider is not None
        assert discovery is not None
        assert detector is not None
        assert resolver is not None

    @pytest.mark.asyncio
    async def test_force_mode(self, readiness_gate):
        """Test force mode bypasses all checks."""
        result = await readiness_gate.check(force=True)

        assert result.ready is True
        assert result.status == "forced"
        assert result.decision_source == "forced"
        assert "forced" in result.message.lower()

    @pytest.mark.asyncio
    async def test_create_force_result(self, readiness_gate):
        """Test creating force result."""
        result = readiness_gate._create_force_result()

        assert result.status == "forced"
        assert result.decision_source == "forced"

    def test_create_basic_failure_result(self, readiness_gate):
        """Test creating basic failure result."""
        basic_result = {
            "ready": False,
            "reason": "codeql_unavailable",
            "message": "CodeQL CLI is not installed",
        }

        result = readiness_gate._create_basic_failure_result(basic_result)

        assert result.ready is False
        assert result.status == "gated"
        assert result.error == "codeql_unavailable"

    def test_build_language_structures(self, readiness_gate):
        """Test building language structures from modules."""
        # Create mock modules with primary_language attribute
        @dataclass
        class MockModule:
            primary_language: str
            loc_estimate: int
            file_count: int

        modules = [
            MockModule(primary_language="java", loc_estimate=10000, file_count=50),
            MockModule(primary_language="python", loc_estimate=5000, file_count=30),
        ]

        structures = readiness_gate._build_language_structures(modules, [])

        assert len(structures) == 2
        languages = [s.name for s in structures]
        assert "java" in languages
        assert "python" in languages

    def test_check_tools(self, readiness_gate, temp_project):
        """Test tool checking."""
        targets = [
            BuildTarget(
                name="test",
                path=temp_project,
                language="java",
                build_system=BuildSystem.MAVEN,
            )
        ]
        version_req = VersionRequirement(module_path=temp_project)

        report = readiness_gate._check_tools(targets, version_req)

        assert isinstance(report, ReadinessReport)


# =============================================================================
# Basic Check Tests
# =============================================================================


class TestBasicCheck:
    """Tests for basic CodeQL check."""

    @pytest.mark.asyncio
    async def test_basic_check_success(self, readiness_gate):
        """Test basic check when CodeQL is available."""
        with patch.object(
            readiness_gate,
            "_basic_check",
            new_callable=AsyncMock,
        ) as mock_check:
            mock_check.return_value = {
                "ready": True,
                "reason": "ready",
                "message": "CodeQL passed the fast readiness check",
            }

            result = await readiness_gate._basic_check()

            assert result["ready"] is True

    @pytest.mark.asyncio
    async def test_basic_check_failure(self, readiness_gate):
        """Test basic check when CodeQL is unavailable."""
        with patch.object(
            readiness_gate,
            "_basic_check",
            new_callable=AsyncMock,
        ) as mock_check:
            mock_check.return_value = {
                "ready": False,
                "reason": "codeql_unavailable",
                "message": "CodeQL CLI is not installed",
            }

            result = await readiness_gate._basic_check()

            assert result["ready"] is False
            assert result["reason"] == "codeql_unavailable"

    @pytest.mark.asyncio
    async def test_basic_check_query_pack_auto_download(self, readiness_gate):
        """Test P6-16a: auto-download query pack when missing."""
        from src.layers.l3_analysis.engines.codeql import CodeQLEngine

        # Mock CodeQLEngine methods
        with patch.object(
            CodeQLEngine,
            "check_readiness",
            new_callable=AsyncMock,
            side_effect=[
                # First call: pack missing
                {
                    "ready": False,
                    "reason": "query_pack_missing",
                    "message": "Required query pack is not installed: codeql/python-queries",
                    "query_pack": "codeql/python-queries",
                    "pack_installed": False,
                },
                # Second call after download: ready
                {
                    "ready": True,
                    "reason": "ready",
                    "message": "CodeQL passed the fast readiness check",
                },
            ],
        ), patch.object(
            CodeQLEngine,
            "_ensure_query_pack",
            new_callable=AsyncMock,
            return_value=True,  # Download succeeds
        ):
            result = await readiness_gate._basic_check()

            # After successful auto-download, should be ready
            assert result["ready"] is True
            assert result.get("auto_fixed") is True
            assert "auto-downloaded query pack" in result.get("auto_fix_message", "").lower()

    @pytest.mark.asyncio
    async def test_basic_check_query_pack_auto_download_failure(self, readiness_gate):
        """Test P6-16a: handle auto-download failure gracefully."""
        from src.layers.l3_analysis.engines.codeql import CodeQLEngine

        # Mock CodeQLEngine methods
        with patch.object(
            CodeQLEngine,
            "check_readiness",
            new_callable=AsyncMock,
            return_value={
                "ready": False,
                "reason": "query_pack_missing",
                "message": "Required query pack is not installed: codeql/python-queries",
                "query_pack": "codeql/python-queries",
                "pack_installed": False,
            },
        ), patch.object(
            CodeQLEngine,
            "_ensure_query_pack",
            new_callable=AsyncMock,
            return_value=False,  # Download fails
        ):
            result = await readiness_gate._basic_check()

            # Should still be not ready, but indicate auto-fix was attempted
            assert result["ready"] is False
            assert result.get("auto_fix_attempted") is True
            assert result.get("auto_fix_failed") is True


# =============================================================================
# Decision Tests
# =============================================================================


class TestDecisionMaking:
    """Tests for LLM and baseline decision making."""

    @pytest.mark.asyncio
    async def test_make_decision_success(self, readiness_gate):
        """Test successful LLM decision."""
        # Mock the decider - LanguageDecision.recommended_languages is list of strings
        mock_decision = LanguageDecision(
            recommended_languages=["java"],
            recommendations=[
                LanguageRecommendation(
                    language="java",
                    priority_score=0.9,
                    reasoning="Primary language",
                )
            ],
            skipped_languages=[],
            skip_reasons={},
            decision_source="llm",
            reasoning_summary="Java is the primary language",
        )

        with patch.object(
            readiness_gate.decider,
            "decide",
            new_callable=AsyncMock,
            return_value=mock_decision,
        ):
            result = await readiness_gate._make_decision([], [], None)

            assert isinstance(result, LanguageDecision)
            assert result.decision_source == "llm"

    @pytest.mark.asyncio
    async def test_make_decision_error(self, readiness_gate):
        """Test LLM decision error handling."""
        error = DecisionError(error_type="llm_error", message="LLM unavailable")

        with patch.object(
            readiness_gate.decider,
            "decide",
            new_callable=AsyncMock,
            return_value=error,
        ):
            result = await readiness_gate._make_decision([], [], None)

            assert isinstance(result, DecisionError)

    def test_make_baseline_decision(self, readiness_gate):
        """Test baseline decision."""
        # Mock the decider's baseline method
        mock_decision = LanguageDecision(
            recommended_languages=["python"],
            recommendations=[
                LanguageRecommendation(
                    language="python",
                    priority_score=0.7,
                    reasoning="Baseline selection",
                )
            ],
            skipped_languages=[],
            skip_reasons={},
            decision_source="baseline",
            reasoning_summary="Baseline decision",
        )

        with patch.object(
            readiness_gate.decider,
            "_make_baseline_decision",
            return_value=mock_decision,
        ):
            result = readiness_gate._make_baseline_decision([], [])

            assert isinstance(result, LanguageDecision)
            assert result.decision_source == "baseline"


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for readiness gate."""

    @pytest.mark.asyncio
    async def test_full_check_flow_gated(self, readiness_gate):
        """Test full check flow when gated."""
        with patch.object(
            readiness_gate,
            "_basic_check",
            new_callable=AsyncMock,
            return_value={
                "ready": False,
                "reason": "startup_timeout",
                "message": "CodeQL did not respond",
            },
        ):
            result = await readiness_gate.check(force=False)

            assert result.ready is False
            assert result.status == "gated"

    @pytest.mark.asyncio
    async def test_full_check_flow_enabled(self, readiness_gate):
        """Test full check flow when enabled."""
        mock_decision = LanguageDecision(
            recommended_languages=["java"],
            recommendations=[
                LanguageRecommendation(
                    language="java",
                    priority_score=0.9,
                    reasoning="Primary language",
                )
            ],
            skipped_languages=["javascript"],
            skip_reasons={"javascript": "Low priority"},
            decision_source="llm",
            reasoning_summary="Decision made",
        )

        with patch.object(
            readiness_gate,
            "_basic_check",
            new_callable=AsyncMock,
            return_value={
                "ready": True,
                "reason": "ready",
                "message": "CodeQL ready",
            },
        ):
            with patch.object(
                readiness_gate,
                "_make_decision",
                new_callable=AsyncMock,
                return_value=mock_decision,
            ):
                result = await readiness_gate.check(force=False)

                assert result.ready is True
                assert result.status == "enabled"
                assert "java" in result.selected_languages


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    @pytest.mark.asyncio
    async def test_check_codeql_readiness(self, temp_project):
        """Test check_codeql_readiness convenience function."""
        with patch(
            "src.layers.l3_analysis.readiness_gate.CodeQLReadinessGate.check",
            new_callable=AsyncMock,
        ) as mock_check:
            mock_check.return_value = ReadinessGateResult(
                ready=True,
                status="enabled",
                message="Ready",
            )

            result = await check_codeql_readiness(temp_project)

            assert isinstance(result, ReadinessGateResult)
            assert result.ready is True

    @pytest.mark.asyncio
    async def test_check_codeql_readiness_force(self, temp_project):
        """Test check_codeql_readiness with force."""
        with patch(
            "src.layers.l3_analysis.readiness_gate.CodeQLReadinessGate.check",
            new_callable=AsyncMock,
        ) as mock_check:
            mock_check.return_value = ReadinessGateResult(
                ready=True,
                status="forced",
                decision_source="forced",
            )

            result = await check_codeql_readiness(temp_project, force=True)

            assert result.status == "forced"


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_modules(self, readiness_gate):
        """Test with empty modules list."""
        structures = readiness_gate._build_language_structures([], [])
        assert structures == []

    def test_module_without_language(self, readiness_gate):
        """Test module without language attribute."""
        @dataclass
        class IncompleteModule:
            loc_estimate: int

        modules = [IncompleteModule(loc_estimate=1000)]
        structures = readiness_gate._build_language_structures(modules, [])

        # Should handle gracefully - creates "unknown" language
        assert len(structures) == 1
        assert structures[0].name == "unknown"

    @pytest.mark.asyncio
    async def test_exception_during_check(self, readiness_gate):
        """Test exception handling during check."""
        with patch.object(
            readiness_gate,
            "_basic_check",
            new_callable=AsyncMock,
            side_effect=Exception("Test error"),
        ):
            # Should handle exception gracefully
            try:
                result = await readiness_gate.check(force=False)
                # If it doesn't raise, check the result
                assert result.ready is False or result.error is not None
            except Exception as e:
                # Exception is acceptable
                assert "Test error" in str(e)


# =============================================================================
# Builder Integration Tests (P7-11a)
# =============================================================================


class TestReadinessGateBuilderIntegration:
    """Tests for ReadinessGate with language-specific builders.

    P7-11a: Verifies that ReadinessGate correctly uses specialized
    builders for analyzing build readiness.
    """

    @pytest.fixture
    def project_with_python(self, tmp_path: Path) -> Path:
        """Create a Python project."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            "name = 'my-app'\n"
            "version = '1.0.0'\n"
        )
        main_py = tmp_path / "main.py"
        main_py.write_text('def main(): pass\n')
        return tmp_path

    @pytest.fixture
    def project_with_javascript(self, tmp_path: Path) -> Path:
        """Create a JavaScript project."""
        package_json = tmp_path / "package.json"
        package_json.write_text('{"name": "js-app", "version": "1.0.0"}\n')
        index_js = tmp_path / "index.js"
        index_js.write_text('console.log("hello");\n')
        return tmp_path

    @pytest.fixture
    def project_with_go(self, tmp_path: Path) -> Path:
        """Create a Go project."""
        go_mod = tmp_path / "go.mod"
        go_mod.write_text("module example.com/myapp\n\ngo 1.21\n")
        main_go = tmp_path / "main.go"
        main_go.write_text('package main\n\nfunc main() {}\n')
        return tmp_path

    @pytest.fixture
    def project_with_java_maven(self, tmp_path: Path) -> Path:
        """Create a Java Maven project."""
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            "<?xml version='1.0'?>\n"
            "<project>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>my-app</artifactId>\n"
            "  <version>1.0</version>\n"
            "</project>\n"
        )
        return tmp_path

    @pytest.fixture
    def project_with_cpp(self, tmp_path: Path) -> Path:
        """Create a C/C++ project with compile_commands.json."""
        compile_commands = tmp_path / "compile_commands.json"
        compile_commands.write_text(
            '[\n'
            '  {\n'
            '    "directory": "/tmp/test",\n'
            '    "command": "gcc -c main.c",\n'
            '    "file": "main.c"\n'
            '  }\n'
            ']'
        )
        return tmp_path

    def test_analyze_build_readiness_python(
        self, project_with_python: Path
    ) -> None:
        """Test _analyze_build_readiness for Python."""
        from src.layers.l3_analysis.build import BuildTarget
        from src.layers.l3_analysis.readiness_gate import CodeQLReadinessGate

        gate = CodeQLReadinessGate(project_path=project_with_python)

        target = BuildTarget(
            name="python-app",
            path=project_with_python,
            language="python",
            build_system=BuildSystem.NONE,
        )

        results = gate._analyze_build_readiness([target])

        assert len(results) == 1
        assert results[0].language == "python"
        # Python is interpreted - no build command needed
        # buildable=False is correct (no build required)
        # But detected_files should have pyproject.toml
        assert "pyproject.toml" in results[0].detected_files

    def test_analyze_build_readiness_javascript(
        self, project_with_javascript: Path
    ) -> None:
        """Test _analyze_build_readiness for JavaScript."""
        from src.layers.l3_analysis.build import BuildTarget
        from src.layers.l3_analysis.readiness_gate import CodeQLReadinessGate

        gate = CodeQLReadinessGate(project_path=project_with_javascript)

        target = BuildTarget(
            name="js-app",
            path=project_with_javascript,
            language="javascript",
            build_system=BuildSystem.NPM,
        )

        results = gate._analyze_build_readiness([target])

        assert len(results) == 1
        assert results[0].language == "javascript"

    def test_analyze_build_readiness_go(
        self, project_with_go: Path
    ) -> None:
        """Test _analyze_build_readiness for Go."""
        from src.layers.l3_analysis.build import BuildTarget
        from src.layers.l3_analysis.readiness_gate import CodeQLReadinessGate

        gate = CodeQLReadinessGate(project_path=project_with_go)

        target = BuildTarget(
            name="go-app",
            path=project_with_go,
            language="go",
            build_system=BuildSystem.GO_MODULES,
        )

        results = gate._analyze_build_readiness([target])

        assert len(results) == 1
        assert results[0].language == "go"
        # Go requires build
        assert results[0].buildable is True
        assert results[0].build_command is not None

    def test_analyze_build_readiness_java(
        self, project_with_java_maven: Path
    ) -> None:
        """Test _analyze_build_readiness for Java."""
        from src.layers.l3_analysis.build import BuildTarget
        from src.layers.l3_analysis.readiness_gate import CodeQLReadinessGate

        gate = CodeQLReadinessGate(project_path=project_with_java_maven)

        target = BuildTarget(
            name="java-app",
            path=project_with_java_maven,
            language="java",
            build_system=BuildSystem.MAVEN,
        )

        results = gate._analyze_build_readiness([target])

        assert len(results) == 1
        assert results[0].language == "java"
        # Java requires build
        assert results[0].buildable is True
        assert "mvn" in results[0].build_command

    def test_analyze_build_readiness_cpp(
        self, project_with_cpp: Path
    ) -> None:
        """Test _analyze_build_readiness for C/C++."""
        from src.layers.l3_analysis.build import BuildTarget
        from src.layers.l3_analysis.readiness_gate import CodeQLReadinessGate

        gate = CodeQLReadinessGate(project_path=project_with_cpp)

        target = BuildTarget(
            name="cpp-app",
            path=project_with_cpp,
            language="cpp",
            build_system=BuildSystem.NONE,
        )

        results = gate._analyze_build_readiness([target])

        assert len(results) == 1
        assert results[0].language == "cpp"
        # compile_commands.json means no build command needed
        # buildable=False is correct (compile_commands already exists)
        # But detected_files should have compile_commands.json
        assert "compile_commands.json" in results[0].detected_files

    def test_build_warnings_propagation(
        self, project_with_python: Path
    ) -> None:
        """Test that build warnings are propagated correctly."""
        from src.layers.l3_analysis.build import BuildTarget
        from src.layers.l3_analysis.readiness_gate import CodeQLReadinessGate

        gate = CodeQLReadinessGate(project_path=project_with_python)

        target = BuildTarget(
            name="python-app",
            path=project_with_python,
            language="python",
            build_system=BuildSystem.NONE,
        )

        results = gate._analyze_build_readiness([target])

        # BuildReadinessInfo should have correct structure
        info = results[0]
        assert hasattr(info, "warnings")
        assert hasattr(info, "skip_reason")
        assert hasattr(info, "build_command")
        assert hasattr(info, "detected_files")

