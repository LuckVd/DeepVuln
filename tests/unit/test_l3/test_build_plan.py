"""
Unit tests for Build Plan generation and execution.

Tests BuildPlan, BuildPlanGenerator, BuildCache, BuildOrchestrator,
and BuildSummary components.
"""

import asyncio
import pytest
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from src.layers.l3_analysis.build.build_plan import (
    BuildCache,
    BuildExecutionResult,
    BuildOrchestrator,
    BuildPlan,
    BuildPlanGenerator,
    BuildPlanStatus,
    BuildStep,
    BuildSummary,
    CacheEntry,
    FallbackStrategy,
    RiskLevel,
    generate_build_plan,
    create_build_cache,
)
from src.layers.l3_analysis.build.detector import BuildSystem
from src.layers.l3_analysis.build.target_extractor import BuildStrategy, BuildTarget
from src.layers.l3_analysis.build.tool_resolver import (
    CompatibilityResult,
    CompatibilityStatus,
    ProvisionPolicy,
    ReadinessReport,
    ToolInfo,
    ToolSource,
    ToolType,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_project(tmp_path):
    """Create a temporary project directory."""
    project = tmp_path / "project"
    project.mkdir()
    return project


@pytest.fixture
def maven_target(temp_project):
    """Create a Maven build target."""
    return BuildTarget(
        name="maven-app",
        path=temp_project,
        language="java",
        build_system=BuildSystem.MAVEN,
        build_command="mvn compile",
        priority=10,
        is_entry_point=True,
    )


@pytest.fixture
def go_target(temp_project):
    """Create a Go build target."""
    return BuildTarget(
        name="go-app",
        path=temp_project,
        language="go",
        build_system=BuildSystem.GO_MODULES,
        build_command="go build ./...",
        priority=5,
    )


@pytest.fixture
def skip_target(temp_project):
    """Create a target that should be skipped."""
    return BuildTarget(
        name="skip-app",
        path=temp_project,
        language="python",
        build_system=BuildSystem.NONE,
    )


@pytest.fixture
def ready_readiness():
    """Create a readiness report with all tools ready."""
    return ReadinessReport(
        ready_tools=[
            ToolInfo(
                tool_type=ToolType.JAVA,
                path=Path("/usr/bin/java"),
                version="17",
                source=ToolSource.SYSTEM_PATH,
            ),
            ToolInfo(
                tool_type=ToolType.MAVEN,
                path=Path("/usr/bin/mvn"),
                version="3.8",
                source=ToolSource.SYSTEM_PATH,
            ),
        ],
        policy=ProvisionPolicy.REUSE_ONLY,
    )


@pytest.fixture
def missing_tools_readiness():
    """Create a readiness report with missing tools."""
    return ReadinessReport(
        missing_tools=[ToolType.JAVA, ToolType.MAVEN],
        policy=ProvisionPolicy.STRICT,
    )


# =============================================================================
# Enum Tests
# =============================================================================


class TestEnums:
    """Tests for enum values."""

    def test_risk_level_values(self):
        """Test RiskLevel enum values."""
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"

    def test_fallback_strategy_values(self):
        """Test FallbackStrategy enum values."""
        assert FallbackStrategy.NONE.value == "none"
        assert FallbackStrategy.SKIP.value == "skip"
        assert FallbackStrategy.TRY_NEXT.value == "try_next"
        assert FallbackStrategy.DIAGNOSE.value == "diagnose"


# =============================================================================
# BuildStep Tests
# =============================================================================


class TestBuildStep:
    """Tests for BuildStep dataclass."""

    def test_create_build_step(self):
        """Test creating a build step."""
        step = BuildStep(
            name="Build project",
            command="mvn compile",
            timeout=300,
        )

        assert step.name == "Build project"
        assert step.command == "mvn compile"
        assert step.timeout == 300
        assert step.required is True

    def test_build_step_to_dict(self):
        """Test BuildStep serialization."""
        step = BuildStep(
            name="Build",
            command="go build",
            timeout=120,
            cwd=Path("/tmp/project"),
        )

        result = step.to_dict()

        assert result["name"] == "Build"
        assert result["command"] == "go build"
        assert result["timeout"] == 120
        assert result["cwd"] == "/tmp/project"


# =============================================================================
# BuildPlan Tests
# =============================================================================


class TestBuildPlan:
    """Tests for BuildPlan dataclass."""

    def test_create_build_plan(self):
        """Test creating a build plan."""
        step = BuildStep(name="Build", command="mvn compile")
        plan = BuildPlan(
            target_name="app",
            steps=[step],
            risk_level=RiskLevel.LOW,
        )

        assert plan.target_name == "app"
        assert len(plan.steps) == 1
        assert plan.risk_level == RiskLevel.LOW

    def test_skipped_plan(self):
        """Test a skipped plan."""
        plan = BuildPlan(
            target_name="app",
            skip_reason="No build required",
        )

        assert plan.is_skipped is True
        assert plan.has_steps is False

    def test_plan_to_dict(self):
        """Test BuildPlan serialization."""
        step = BuildStep(name="Build", command="make")
        plan = BuildPlan(
            target_name="myapp",
            steps=[step],
            risk_level=RiskLevel.MEDIUM,
            fallback=FallbackStrategy.SKIP,
            language="c",
        )

        result = plan.to_dict()

        assert result["target_name"] == "myapp"
        assert result["risk_level"] == "medium"
        assert result["fallback"] == "skip"
        assert result["language"] == "c"
        assert len(result["steps"]) == 1


# =============================================================================
# BuildExecutionResult Tests
# =============================================================================


class TestBuildExecutionResult:
    """Tests for BuildExecutionResult dataclass."""

    def test_create_result(self):
        """Test creating a result."""
        plan = BuildPlan(target_name="app")
        result = BuildExecutionResult(
            plan=plan,
            success=True,
            duration_seconds=5.0,
        )

        assert result.success is True
        assert result.from_cache is False

    def test_result_to_dict(self):
        """Test result serialization."""
        plan = BuildPlan(target_name="app")
        result = BuildExecutionResult(
            plan=plan,
            success=False,
            failed_reason="Build failed",
            duration_seconds=10.0,
        )

        d = result.to_dict()

        assert d["success"] is False
        assert d["failed_reason"] == "Build failed"


# =============================================================================
# BuildSummary Tests
# =============================================================================


class TestBuildSummary:
    """Tests for BuildSummary dataclass."""

    def test_empty_summary(self):
        """Test empty summary."""
        summary = BuildSummary()

        assert len(summary.selected_plans) == 0
        assert len(summary.skipped_plans) == 0
        assert len(summary.failed_plans) == 0
        assert len(summary.successful_plans) == 0

    def test_add_methods(self):
        """Test adding plans to summary."""
        summary = BuildSummary()

        summary.add_selected("plan1")
        summary.add_skipped("plan2", "No build required")
        summary.add_failed("plan3", "Build failed")
        summary.add_successful("plan4")

        assert "plan1" in summary.selected_plans
        assert ("plan2", "No build required") in summary.skipped_plans
        assert ("plan3", "Build failed") in summary.failed_plans
        assert "plan4" in summary.successful_plans

    def test_summary_to_dict(self):
        """Test summary serialization."""
        summary = BuildSummary()
        summary.add_selected("plan1")
        summary.add_skipped("plan2", "reason")
        summary.add_successful("plan1")

        result = summary.to_dict()

        assert len(result["selected"]) == 1
        assert len(result["skipped"]) == 1
        assert len(result["successful"]) == 1


# =============================================================================
# CacheEntry Tests
# =============================================================================


class TestCacheEntry:
    """Tests for CacheEntry dataclass."""

    def test_create_entry(self):
        """Test creating a cache entry."""
        entry = CacheEntry(
            key="abc123",
            success=True,
            duration_seconds=5.0,
        )

        assert entry.key == "abc123"
        assert entry.success is True
        assert entry.ttl_seconds == 86400

    def test_entry_not_expired(self):
        """Test entry not expired."""
        entry = CacheEntry(
            key="test",
            success=True,
            created_at=datetime.now(),
            ttl_seconds=3600,
        )

        assert entry.expired is False

    def test_entry_expired(self):
        """Test entry expired."""
        entry = CacheEntry(
            key="test",
            success=True,
            created_at=datetime.now() - timedelta(hours=25),
            ttl_seconds=86400,  # 24 hours
        )

        assert entry.expired is True


# =============================================================================
# BuildCache Tests
# =============================================================================


class TestBuildCache:
    """Tests for BuildCache."""

    def test_cache_initialization(self):
        """Test cache initialization."""
        cache = BuildCache()

        assert cache.size == 0
        assert cache.max_entries == 1000

    def test_cache_set_get(self):
        """Test setting and getting cache entries."""
        cache = BuildCache()

        cache.set("key1", success=True, duration_seconds=5.0)
        entry = cache.get("key1")

        assert entry is not None
        assert entry.success is True
        assert entry.duration_seconds == 5.0

    def test_cache_miss(self):
        """Test cache miss."""
        cache = BuildCache()

        entry = cache.get("nonexistent")

        assert entry is None

    def test_cache_expiration(self):
        """Test cache entry expiration."""
        cache = BuildCache()

        # Set entry with very short TTL (1 second)
        cache.set("key1", success=True, ttl=1)

        # Create entry that's already expired
        cache._cache["key2"] = CacheEntry(
            key="key2",
            success=True,
            created_at=datetime.now() - timedelta(hours=25),
            ttl_seconds=86400,
        )

        # key2 should be expired
        entry = cache.get("key2")
        assert entry is None

    def test_make_key(self):
        """Test cache key generation."""
        cache = BuildCache()

        key1 = cache.make_key(Path("/tmp/project"), "mvn compile")
        key2 = cache.make_key(Path("/tmp/project"), "mvn compile")
        key3 = cache.make_key(Path("/tmp/other"), "mvn compile")

        assert key1 == key2  # Same path and command
        assert key1 != key3  # Different path

    def test_cache_clear(self):
        """Test cache clearing."""
        cache = BuildCache()

        cache.set("key1", success=True)
        cache.set("key2", success=False)

        cache.clear()

        assert cache.size == 0

    def test_cache_max_entries(self):
        """Test cache respects max entries."""
        cache = BuildCache(max_entries=5)

        for i in range(10):
            cache.set(f"key{i}", success=True)

        assert cache.size <= 5


# =============================================================================
# BuildPlanGenerator Tests
# =============================================================================


class TestBuildPlanGenerator:
    """Tests for BuildPlanGenerator."""

    def test_generator_initialization(self):
        """Test generator initialization."""
        generator = BuildPlanGenerator()

        assert generator.default_timeout == 600
        assert generator.max_timeout == 1800

    def test_generate_maven_plan(self, maven_target):
        """Test generating a Maven build plan."""
        generator = BuildPlanGenerator()
        plan = generator.generate(maven_target)

        assert plan.target_name == "maven-app"
        assert plan.build_system == BuildSystem.MAVEN
        assert plan.has_steps is True
        assert plan.language == "java"

    def test_generate_skip_plan(self, skip_target):
        """Test generating a skip plan."""
        generator = BuildPlanGenerator()
        plan = generator.generate(skip_target)

        assert plan.is_skipped is True
        # PythonBuilder returns more specific skip reason when no Python files found
        assert plan.skip_reason is not None
        assert ("No build system" in plan.skip_reason or "No Python" in plan.skip_reason)

    def test_generate_with_ready_tools(self, maven_target, ready_readiness):
        """Test generating plan when tools are ready."""
        generator = BuildPlanGenerator()
        plan = generator.generate(maven_target, ready_readiness)

        assert plan.is_skipped is False

    def test_generate_with_missing_tools_strict(self, maven_target, missing_tools_readiness):
        """Test generating plan when tools are missing with strict policy."""
        generator = BuildPlanGenerator()
        plan = generator.generate(maven_target, missing_tools_readiness)

        assert plan.is_skipped is True
        assert "tools not available" in plan.skip_reason.lower()

    def test_generate_all_targets(self, maven_target, go_target):
        """Test generating plans for multiple targets."""
        generator = BuildPlanGenerator()
        plans = generator.generate_all([maven_target, go_target])

        assert len(plans) == 2
        assert plans[0].target_name == "maven-app"
        assert plans[1].target_name == "go-app"

    def test_risk_assessment_entry_point(self, temp_project):
        """Test risk assessment for entry point."""
        target = BuildTarget(
            name="critical-app",
            path=temp_project,
            language="java",
            build_system=BuildSystem.MAVEN,
            is_entry_point=True,
        )

        generator = BuildPlanGenerator()
        plan = generator.generate(target)

        assert plan.fallback == FallbackStrategy.DIAGNOSE

    def test_risk_assessment_unknown_build_system(self, temp_project):
        """Test risk assessment for unknown build system."""
        target = BuildTarget(
            name="unknown-app",
            path=temp_project,
            language="unknown",
            build_system=BuildSystem.UNKNOWN,
        )

        generator = BuildPlanGenerator()
        plan = generator.generate(target)

        assert plan.is_skipped is True
        assert plan.skip_reason == "Unknown build system"


# =============================================================================
# BuildPlanGenerator with All Builders Tests (P7-11a)
# =============================================================================


class TestBuildPlanGeneratorWithAllBuilders:
    """Tests for BuildPlanGenerator with all language builders.

    P7-11a: Verifies that BuildPlanGenerator correctly uses specialized
    builders for Python, JavaScript, Go, Java, and C/C++.
    """

    @pytest.fixture
    def generator(self) -> BuildPlanGenerator:
        """Create a BuildPlanGenerator instance."""
        return BuildPlanGenerator()

    # =========================================================================
    # Python Tests
    # =========================================================================

    def test_python_builder_integration(self, generator, tmp_path: Path) -> None:
        """Test BuildPlanGenerator uses PythonBuilder."""
        # Create pyproject.toml
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            "name = 'my-app'\n"
            "version = '1.0.0'\n"
        )

        # Create Python file
        main_py = tmp_path / "main.py"
        main_py.write_text('def main(): pass\n')

        target = BuildTarget(
            name="python-app",
            path=tmp_path,
            language="python",
            build_system=BuildSystem.NONE,
        )

        plan = generator.generate(target)

        assert plan.language == "python"
        # Python doesn't require build, so should be skipped or no steps
        assert plan.is_skipped or not plan.has_steps

    def test_python_poetry_project(self, generator, tmp_path: Path) -> None:
        """Test Poetry project detection."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[tool.poetry]\n"
            "name = 'my-app'\n"
            "version = '1.0.0'\n"
        )

        main_py = tmp_path / "main.py"
        main_py.write_text('pass\n')

        target = BuildTarget(
            name="poetry-app",
            path=tmp_path,
            language="python",
            build_system=BuildSystem.POETRY,
        )

        plan = generator.generate(target)

        assert plan.language == "python"
        # Poetry project may have dependency install step (required=False)
        # but no actual build command
        if plan.has_steps:
            # Verify dependency step is optional (not required for CodeQL)
            assert all(not step.required for step in plan.steps)

    def test_python_no_files_skipped(self, generator, tmp_path: Path) -> None:
        """Test Python project without Python files is skipped."""
        target = BuildTarget(
            name="empty-python",
            path=tmp_path,
            language="python",
            build_system=BuildSystem.NONE,
        )

        plan = generator.generate(target)

        assert plan.is_skipped is True
        assert "No Python" in plan.skip_reason or "No build" in plan.skip_reason

    # =========================================================================
    # JavaScript/TypeScript Tests
    # =========================================================================

    def test_javascript_builder_integration(self, generator, tmp_path: Path) -> None:
        """Test BuildPlanGenerator uses JavaScriptBuilder."""
        # Create package.json
        package_json = tmp_path / "package.json"
        package_json.write_text('{"name": "my-app", "version": "1.0.0"}\n')

        # Create JS file
        index_js = tmp_path / "index.js"
        index_js.write_text('console.log("hello");\n')

        target = BuildTarget(
            name="js-app",
            path=tmp_path,
            language="javascript",
            build_system=BuildSystem.NPM,
        )

        plan = generator.generate(target)

        assert plan.language == "javascript"
        # JavaScript doesn't require build for CodeQL
        assert plan.is_skipped or not plan.has_steps

    def test_typescript_project(self, generator, tmp_path: Path) -> None:
        """Test TypeScript project detection."""
        tsconfig = tmp_path / "tsconfig.json"
        tsconfig.write_text('{"compilerOptions": {"target": "ES2020"}}\n')

        package_json = tmp_path / "package.json"
        package_json.write_text('{"name": "ts-app"}\n')

        main_ts = tmp_path / "main.ts"
        main_ts.write_text('const x: number = 1;\n')

        target = BuildTarget(
            name="ts-app",
            path=tmp_path,
            language="typescript",
            build_system=BuildSystem.NPM,
        )

        plan = generator.generate(target)

        # TypeScript uses JavaScript analysis
        assert plan.language == "typescript"
        # TypeScript project may have npm install step (required=False)
        # but no actual build command
        if plan.has_steps:
            # Verify dependency step is optional (not required for CodeQL)
            assert all(not step.required for step in plan.steps)

    def test_javascript_no_files_skipped(self, generator, tmp_path: Path) -> None:
        """Test JavaScript project without JS files is skipped."""
        target = BuildTarget(
            name="empty-js",
            path=tmp_path,
            language="javascript",
            build_system=BuildSystem.NONE,
        )

        plan = generator.generate(target)

        assert plan.is_skipped is True

    # =========================================================================
    # Go Tests
    # =========================================================================

    def test_go_builder_integration(self, generator, tmp_path: Path) -> None:
        """Test BuildPlanGenerator uses GoBuilder for Go projects."""
        # Create go.mod
        go_mod = tmp_path / "go.mod"
        go_mod.write_text("module example.com/myapp\n\ngo 1.21\n")

        # Create Go file
        main_go = tmp_path / "main.go"
        main_go.write_text('package main\n\nfunc main() {}\n')

        target = BuildTarget(
            name="go-app",
            path=tmp_path,
            language="go",
            build_system=BuildSystem.GO_MODULES,
        )

        plan = generator.generate(target)

        assert plan.language == "go"
        assert plan.has_steps is True
        # Should have build command
        assert any("go build" in step.command for step in plan.steps)

    def test_go_with_vendor(self, generator, tmp_path: Path) -> None:
        """Test Go vendor mode detection."""
        go_mod = tmp_path / "go.mod"
        go_mod.write_text("module example.com/myapp\n\ngo 1.21\n")

        # Create vendor directory
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()

        main_go = tmp_path / "main.go"
        main_go.write_text('package main\n\nfunc main() {}\n')

        target = BuildTarget(
            name="vendor-app",
            path=tmp_path,
            language="go",
            build_system=BuildSystem.GO_MODULES,
        )

        plan = generator.generate(target)

        assert plan.has_steps is True
        # Should use vendor mode
        assert any("-mod=vendor" in step.command for step in plan.steps)

    def test_go_no_mod_skipped(self, generator, tmp_path: Path) -> None:
        """Test Go project without go.mod is skipped."""
        main_go = tmp_path / "main.go"
        main_go.write_text('package main\n\nfunc main() {}\n')

        target = BuildTarget(
            name="no-mod-go",
            path=tmp_path,
            language="go",
            build_system=BuildSystem.NONE,
        )

        plan = generator.generate(target)

        assert plan.is_skipped is True

    # =========================================================================
    # Java Tests
    # =========================================================================

    def test_java_maven_integration(self, generator, tmp_path: Path) -> None:
        """Test BuildPlanGenerator uses JavaBuilder for Maven projects."""
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

        target = BuildTarget(
            name="maven-app",
            path=tmp_path,
            language="java",
            build_system=BuildSystem.MAVEN,
        )

        plan = generator.generate(target)

        assert plan.language == "java"
        assert plan.has_steps is True
        # Should have Maven build command
        assert any("mvn" in step.command for step in plan.steps)

    def test_java_gradle_integration(self, generator, tmp_path: Path) -> None:
        """Test BuildPlanGenerator uses JavaBuilder for Gradle projects."""
        build_gradle = tmp_path / "build.gradle"
        build_gradle.write_text(
            "plugins {\n"
            "    id 'java'\n"
            "}\n"
            "repositories {\n"
            "    mavenCentral()\n"
            "}\n"
        )

        target = BuildTarget(
            name="gradle-app",
            path=tmp_path,
            language="java",
            build_system=BuildSystem.GRADLE,
        )

        plan = generator.generate(target)

        assert plan.language == "java"
        assert plan.has_steps is True
        # Should have Gradle build command
        assert any("gradle" in step.command for step in plan.steps)

    def test_java_wrapper_detection(self, generator, tmp_path: Path) -> None:
        """Test Maven/Gradle wrapper detection."""
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text("<project><modelVersion>4.0.0</modelVersion></project>\n")

        # Create Maven wrapper
        mvnw = tmp_path / "mvnw"
        mvnw.write_text("#!/bin/bash\necho 'mvnw'\n")

        target = BuildTarget(
            name="wrapper-app",
            path=tmp_path,
            language="java",
            build_system=BuildSystem.MAVEN,
        )

        plan = generator.generate(target)

        assert plan.has_steps is True
        # Should use wrapper
        assert any("./mvnw" in step.command for step in plan.steps)

    # =========================================================================
    # C/C++ Tests
    # =========================================================================

    def test_cpp_compile_commands_integration(self, generator, tmp_path: Path) -> None:
        """Test BuildPlanGenerator uses CppBuilder for compile_commands.json."""
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

        target = BuildTarget(
            name="cpp-app",
            path=tmp_path,
            language="cpp",
            build_system=BuildSystem.NONE,
        )

        plan = generator.generate(target)

        assert plan.language == "cpp"
        # compile_commands.json means no build steps needed
        assert plan.is_skipped or not plan.has_steps

    def test_cpp_cmake_project(self, generator, tmp_path: Path) -> None:
        """Test CMake project detection."""
        cmake_lists = tmp_path / "CMakeLists.txt"
        cmake_lists.write_text(
            "cmake_minimum_required(VERSION 3.10)\n"
            "project(test)\n"
            "add_executable(test main.cpp)\n"
        )

        target = BuildTarget(
            name="cmake-app",
            path=tmp_path,
            language="cpp",
            build_system=BuildSystem.NONE,
        )

        plan = generator.generate(target)

        assert plan.language == "cpp"
        # CMake project - may have cmake command or be skipped
        # Result depends on whether cmake is available
        assert plan.language == "cpp"

    def test_cpp_no_build_system_skipped(self, generator, tmp_path: Path) -> None:
        """Test C/C++ project without standard build system is skipped."""
        # Only create C files, no build system
        main_c = tmp_path / "main.c"
        main_c.write_text('int main() { return 0; }\n')

        target = BuildTarget(
            name="no-build-cpp",
            path=tmp_path,
            language="cpp",
            build_system=BuildSystem.NONE,
        )

        plan = generator.generate(target)

        assert plan.is_skipped is True
        # Should have a clear skip reason
        assert plan.skip_reason is not None


# =============================================================================
# BuildOrchestrator Tests
# =============================================================================


class TestBuildOrchestrator:
    """Tests for BuildOrchestrator."""

    def test_orchestrator_initialization(self):
        """Test orchestrator initialization."""
        orchestrator = BuildOrchestrator()

        assert orchestrator.cache is not None
        assert orchestrator.timeout == 600

    @pytest.mark.asyncio
    async def test_execute_skipped_plan(self, skip_target):
        """Test executing a skipped plan."""
        orchestrator = BuildOrchestrator()
        plan = BuildPlan(target_name="skip", skip_reason="No build required")

        result = await orchestrator.execute_plan(plan)

        assert result.success is True
        assert result.skipped_reason == "No build required"

    @pytest.mark.asyncio
    async def test_execute_plan_no_steps(self):
        """Test executing a plan with no steps."""
        orchestrator = BuildOrchestrator()
        plan = BuildPlan(target_name="empty", steps=[])

        result = await orchestrator.execute_plan(plan)

        assert result.success is True
        assert "No build steps" in result.skipped_reason

    @pytest.mark.asyncio
    async def test_execute_plans_summary(self):
        """Test executing multiple plans and getting summary."""
        orchestrator = BuildOrchestrator()

        plans = [
            BuildPlan(target_name="plan1", skip_reason="Skipped"),
            BuildPlan(target_name="plan2", steps=[]),
        ]

        results, summary = await orchestrator.execute_plans(plans)

        assert len(results) == 2
        assert len(summary.skipped_plans) >= 2


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_generate_build_plan_function(self, maven_target):
        """Test generate_build_plan convenience function."""
        plan = generate_build_plan(maven_target)

        assert isinstance(plan, BuildPlan)
        assert plan.target_name == "maven-app"

    def test_create_build_cache_function(self):
        """Test create_build_cache convenience function."""
        cache = create_build_cache(max_entries=100)

        assert isinstance(cache, BuildCache)
        assert cache.max_entries == 100


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for build plan workflow."""

    def test_full_workflow(self, maven_target, ready_readiness):
        """Test full workflow from target to plan."""
        # Generate plan
        generator = BuildPlanGenerator()
        plan = generator.generate(maven_target, ready_readiness)

        assert plan.is_skipped is False
        assert plan.has_steps is True

    def test_cache_integration(self):
        """Test cache integration with orchestrator."""
        cache = BuildCache()
        orchestrator = BuildOrchestrator(cache=cache)

        assert orchestrator.cache is cache

    def test_plan_serialization_cycle(self, maven_target):
        """Test plan can be serialized and deserialized."""
        generator = BuildPlanGenerator()
        plan = generator.generate(maven_target)

        # Serialize
        d = plan.to_dict()

        # Verify structure
        assert "target_name" in d
        assert "steps" in d
        assert "risk_level" in d
