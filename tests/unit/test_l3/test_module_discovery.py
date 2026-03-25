"""
Unit tests for Module Discovery.

Tests monorepo detection, module boundary identification, and
language/build signal extraction.
"""

import pytest
from pathlib import Path
import tempfile
import os

from src.layers.l3_analysis.build.module_discovery import (
    ModuleDiscovery,
    MonorepoInfo,
    MonorepoType,
    discover_modules,
)
from src.layers.l3_analysis.decision.models import ModuleSummary


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_repo(tmp_path):
    """Create a temporary repository for testing."""
    return tmp_path


@pytest.fixture
def single_project(temp_repo):
    """Create a single project structure."""
    # Create Python project
    (temp_repo / "main.py").write_text("print('hello')")
    (temp_repo / "requirements.txt").write_text("requests>=2.0")
    src_dir = temp_repo / "src"
    src_dir.mkdir()
    (src_dir / "app.py").write_text("# app code")
    return temp_repo


@pytest.fixture
def go_workspace_repo(temp_repo):
    """Create a Go workspace structure."""
    # Create go.work
    go_work_content = """
go 1.21

use (
    ./api
    ./cli
    ./pkg/utils
)
"""
    (temp_repo / "go.work").write_text(go_work_content)

    # Create modules
    for mod in ["api", "cli"]:
        mod_dir = temp_repo / mod
        mod_dir.mkdir()
        (mod_dir / "main.go").write_text("package main\nfunc main() {}")
        (mod_dir / "go.mod").write_text(f"module example.com/{mod}\n\ngo 1.21")

    utils_dir = temp_repo / "pkg" / "utils"
    utils_dir.mkdir(parents=True)
    (utils_dir / "utils.go").write_text("package utils")
    (utils_dir / "go.mod").write_text("module example.com/pkg/utils\n\ngo 1.21")

    return temp_repo


@pytest.fixture
def maven_multi_module_repo(temp_repo):
    """Create a Maven multi-module structure."""
    # Create parent pom.xml
    parent_pom = """<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>
    <modules>
        <module>api</module>
        <module>service</module>
        <module>common</module>
    </modules>
</project>
"""
    (temp_repo / "pom.xml").write_text(parent_pom)

    # Create submodules
    for mod in ["api", "service", "common"]:
        mod_dir = temp_repo / mod
        mod_dir.mkdir()
        (mod_dir / "pom.xml").write_text(f"""<?xml version="1.0"?>
<project>
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent</artifactId>
        <version>1.0.0</version>
    </parent>
    <artifactId>{mod}</artifactId>
</project>
""")
        java_dir = mod_dir / "src" / "main" / "java"
        java_dir.mkdir(parents=True)
        (java_dir / f"{mod.capitalize()}.java").write_text(
            f"package com.example.{mod}; public class {mod.capitalize()} {{}}"
        )

    return temp_repo


@pytest.fixture
def gradle_multi_project_repo(temp_repo):
    """Create a Gradle multi-project structure."""
    # Create settings.gradle
    settings_content = """
rootProject.name = 'multi-project'
include 'core'
include 'web'
include 'cli'
"""
    (temp_repo / "settings.gradle").write_text(settings_content)

    # Create subprojects
    for proj in ["core", "web", "cli"]:
        proj_dir = temp_repo / proj
        proj_dir.mkdir()
        (proj_dir / "build.gradle").write_text(f"plugins {{ id 'java' }}")

    return temp_repo


@pytest.fixture
def pnpm_workspaces_repo(temp_repo):
    """Create a pnpm workspaces structure."""
    # Create pnpm-workspace.yaml
    workspace_yaml = """
packages:
  - 'packages/*'
"""
    (temp_repo / "pnpm-workspace.yaml").write_text(workspace_yaml)

    # Create packages directory with sub-packages
    packages_dir = temp_repo / "packages"
    packages_dir.mkdir()

    for pkg in ["core", "utils", "ui"]:
        pkg_dir = packages_dir / pkg
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text(f'{{"name": "@myorg/{pkg}", "version": "1.0.0"}}')
        (pkg_dir / "index.js").write_text("module.exports = {};")

    return temp_repo


@pytest.fixture
def directory_convention_repo(temp_repo):
    """Create a directory convention monorepo."""
    # Create packages directory
    packages_dir = temp_repo / "packages"
    packages_dir.mkdir()

    for pkg in ["auth", "payment", "notification"]:
        pkg_dir = packages_dir / pkg
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text(f'{{"name": "{pkg}"}}')
        (pkg_dir / "index.js").write_text("module.exports = {};")

    # Create services directory
    services_dir = temp_repo / "services"
    services_dir.mkdir()

    for svc in ["api", "worker"]:
        svc_dir = services_dir / svc
        svc_dir.mkdir()
        (svc_dir / "main.py").write_text("# service")

    return temp_repo


# =============================================================================
# Monorepo Detection Tests
# =============================================================================


class TestMonorepoDetection:
    """Tests for monorepo detection."""

    def test_single_project_not_monorepo(self, single_project):
        """Test that single project is not detected as monorepo."""
        discovery = ModuleDiscovery(single_project)
        info = discovery.get_monorepo_info()

        assert info.is_monorepo is False
        assert info.monorepo_type == MonorepoType.NONE

    def test_detect_go_workspace(self, go_workspace_repo):
        """Test detection of Go workspace."""
        discovery = ModuleDiscovery(go_workspace_repo)
        info = discovery.get_monorepo_info()

        assert info.is_monorepo is True
        assert info.monorepo_type == MonorepoType.GO_WORKSPACE
        assert info.config_file == "go.work"
        assert len(info.module_paths) == 3

    def test_detect_maven_multi_module(self, maven_multi_module_repo):
        """Test detection of Maven multi-module."""
        discovery = ModuleDiscovery(maven_multi_module_repo)
        info = discovery.get_monorepo_info()

        assert info.is_monorepo is True
        assert info.monorepo_type == MonorepoType.MAVEN_MULTI_MODULE
        assert info.config_file == "pom.xml"
        assert len(info.module_paths) == 3

    def test_detect_gradle_multi_project(self, gradle_multi_project_repo):
        """Test detection of Gradle multi-project."""
        discovery = ModuleDiscovery(gradle_multi_project_repo)
        info = discovery.get_monorepo_info()

        assert info.is_monorepo is True
        assert info.monorepo_type == MonorepoType.GRADLE_MULTI_PROJECT
        assert len(info.module_paths) == 3

    def test_detect_pnpm_workspaces(self, pnpm_workspaces_repo):
        """Test detection of pnpm workspaces."""
        discovery = ModuleDiscovery(pnpm_workspaces_repo)
        info = discovery.get_monorepo_info()

        assert info.is_monorepo is True
        assert info.monorepo_type == MonorepoType.PNPM_WORKSPACES
        assert info.config_file == "pnpm-workspace.yaml"
        assert len(info.module_paths) == 3

    def test_detect_directory_convention(self, directory_convention_repo):
        """Test detection by directory convention."""
        discovery = ModuleDiscovery(directory_convention_repo)
        info = discovery.get_monorepo_info()

        assert info.is_monorepo is True
        assert info.monorepo_type == MonorepoType.DIRECTORY_CONVENTION


# =============================================================================
# Module Discovery Tests
# =============================================================================


class TestModuleDiscovery:
    """Tests for module discovery."""

    def test_single_project_returns_one_module(self, single_project):
        """Test that single project returns one module."""
        discovery = ModuleDiscovery(single_project)
        modules = discovery.discover()

        assert len(modules) == 1
        assert modules[0].name == single_project.name
        assert modules[0].primary_language == "python"

    def test_go_workspace_modules(self, go_workspace_repo):
        """Test module discovery for Go workspace."""
        discovery = ModuleDiscovery(go_workspace_repo)
        modules = discovery.discover()

        assert len(modules) == 3
        module_names = [m.name for m in modules]
        assert "api" in module_names
        assert "cli" in module_names

        # Check primary language
        for module in modules:
            assert module.primary_language == "go"
            assert "go.mod" in module.build_signals

    def test_maven_multi_module_modules(self, maven_multi_module_repo):
        """Test module discovery for Maven multi-module."""
        discovery = ModuleDiscovery(maven_multi_module_repo)
        modules = discovery.discover()

        assert len(modules) == 3
        module_names = [m.name for m in modules]
        assert "api" in module_names
        assert "service" in module_names
        assert "common" in module_names

        # Check primary language
        for module in modules:
            assert module.primary_language == "java"

    def test_module_languages_detection(self, temp_repo):
        """Test language detection in modules."""
        # Create a mixed-language project
        src_dir = temp_repo / "src"
        src_dir.mkdir()

        # Python files
        (src_dir / "main.py").write_text("print('hello')")
        (src_dir / "utils.py").write_text("# utils")

        # JavaScript files
        js_dir = src_dir / "js"
        js_dir.mkdir()
        (js_dir / "app.js").write_text("// app")
        (js_dir / "helper.js").write_text("// helper")

        discovery = ModuleDiscovery(temp_repo)
        modules = discovery.discover()

        assert len(modules) == 1
        assert "python" in modules[0].languages
        assert "javascript" in modules[0].languages

    def test_module_build_signals(self, single_project):
        """Test build signal detection."""
        discovery = ModuleDiscovery(single_project)
        modules = discovery.discover()

        assert len(modules) == 1
        assert "requirements.txt" in modules[0].build_signals

    def test_module_loc_estimation(self, temp_repo):
        """Test LOC estimation."""
        # Create some Python files
        (temp_repo / "main.py").write_text("print('hello')\nprint('world')\n")
        (temp_repo / "utils.py").write_text("# line 1\n# line 2\n# line 3\n")

        discovery = ModuleDiscovery(temp_repo)
        modules = discovery.discover()

        assert len(modules) == 1
        assert modules[0].loc_estimate > 0

    def test_module_path_relative(self, go_workspace_repo):
        """Test that module paths are relative to repo root."""
        discovery = ModuleDiscovery(go_workspace_repo)
        modules = discovery.discover()

        for module in modules:
            # Paths should not start with /
            assert not module.path.startswith("/")


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestDiscoverModules:
    """Tests for the discover_modules convenience function."""

    def test_discover_modules_returns_list(self, single_project):
        """Test that discover_modules returns a list."""
        modules = discover_modules(single_project)

        assert isinstance(modules, list)
        assert len(modules) > 0

    def test_discover_modules_module_summary(self, single_project):
        """Test that returned items are ModuleSummary."""
        modules = discover_modules(single_project)

        for module in modules:
            assert isinstance(module, ModuleSummary)


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_directory(self, temp_repo):
        """Test handling of empty directory."""
        discovery = ModuleDiscovery(temp_repo)
        modules = discovery.discover()

        # Should return single module with unknown language
        assert len(modules) == 1
        assert modules[0].primary_language == "unknown"

    def test_nested_monorepo_detection_priority(self, temp_repo):
        """Test that explicit config takes priority over directory convention."""
        # Create both go.work and packages directory
        # Need at least 2 modules for monorepo detection
        (temp_repo / "go.work").write_text("use (./api\n./cli)")
        api_dir = temp_repo / "api"
        api_dir.mkdir()
        (api_dir / "main.go").write_text("package main")
        (api_dir / "go.mod").write_text("module api")

        cli_dir = temp_repo / "cli"
        cli_dir.mkdir()
        (cli_dir / "main.go").write_text("package main")
        (cli_dir / "go.mod").write_text("module cli")

        packages_dir = temp_repo / "packages"
        packages_dir.mkdir()
        (packages_dir / "pkg1").mkdir()
        (packages_dir / "pkg1" / "package.json").write_text("{}")

        discovery = ModuleDiscovery(temp_repo)
        info = discovery.get_monorepo_info()

        # Should detect Go workspace, not directory convention
        assert info.monorepo_type == MonorepoType.GO_WORKSPACE

    def test_single_module_maven(self, temp_repo):
        """Test Maven with only one module is not monorepo."""
        pom_content = """<?xml version="1.0"?>
<project>
    <packaging>pom</packaging>
    <modules>
        <module>only-one</module>
    </modules>
</project>
"""
        (temp_repo / "pom.xml").write_text(pom_content)
        (temp_repo / "only-one").mkdir()
        (temp_repo / "only-one" / "pom.xml").write_text("<project/>")

        discovery = ModuleDiscovery(temp_repo)
        info = discovery.get_monorepo_info()

        # Single module should not be detected as monorepo (need >1 modules)
        assert info.is_monorepo is False

    def test_missing_go_work_modules(self, temp_repo):
        """Test handling when go.work references non-existent modules."""
        (temp_repo / "go.work").write_text("use (./nonexistent)")

        discovery = ModuleDiscovery(temp_repo)
        modules = discovery.discover()

        # Should fall back to single module
        assert len(modules) == 1


# =============================================================================
# MonorepoInfo Tests
# =============================================================================


class TestMonorepoInfo:
    """Tests for MonorepoInfo dataclass."""

    def test_to_dict(self):
        """Test MonorepoInfo serialization."""
        info = MonorepoInfo(
            is_monorepo=True,
            monorepo_type=MonorepoType.GO_WORKSPACE,
            root_path=Path("/tmp/repo"),
            module_paths=[Path("/tmp/repo/api"), Path("/tmp/repo/cli")],
            config_file="go.work",
        )

        result = info.to_dict()

        assert result["is_monorepo"] is True
        assert result["monorepo_type"] == "go_workspace"
        assert result["config_file"] == "go.work"
        assert len(result["module_paths"]) == 2
