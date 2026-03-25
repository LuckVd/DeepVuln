"""
Unit tests for Build Target Extractor.

Tests build target extraction, entry point detection, and
build recommendation generation.
"""

import json
import pytest
from pathlib import Path
import tempfile

from src.layers.l3_analysis.build.target_extractor import (
    BuildRecommendation,
    BuildStrategy,
    BuildTarget,
    BuildTargetExtractor,
    EntryPoint,
    EntryPointType,
    extract_build_targets,
)
from src.layers.l3_analysis.build.detector import BuildSystem
from src.layers.l3_analysis.decision.models import ModuleSummary


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_repo(tmp_path):
    """Create a temporary repository for testing."""
    return tmp_path


@pytest.fixture
def java_maven_module(temp_repo):
    """Create a Java Maven module structure."""
    module_dir = temp_repo / "api"
    module_dir.mkdir()

    # Create pom.xml
    pom_content = """<?xml version="1.0"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>api</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.12</version>
        </dependency>
    </dependencies>
</project>
"""
    (module_dir / "pom.xml").write_text(pom_content)

    # Create Java source
    src_dir = module_dir / "src" / "main" / "java" / "com" / "example"
    src_dir.mkdir(parents=True)
    (src_dir / "ApiApplication.java").write_text("""
package com.example;

public class ApiApplication {
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
""")
    return temp_repo


@pytest.fixture
def java_gradle_module(temp_repo):
    """Create a Java Gradle module structure."""
    module_dir = temp_repo / "service"
    module_dir.mkdir()

    # Create settings.gradle
    (module_dir / "settings.gradle").write_text("""
rootProject.name = 'service'
include 'core'
include 'web'
""")

    # Create build.gradle
    (module_dir / "build.gradle").write_text("plugins { id 'java' }")

    # Create subprojects
    for proj in ["core", "web"]:
        proj_dir = module_dir / proj
        proj_dir.mkdir()
        (proj_dir / "build.gradle").write_text("plugins { id 'java' }")
        src_dir = proj_dir / "src" / "main" / "java"
        src_dir.mkdir(parents=True)

    return temp_repo


@pytest.fixture
def go_module(temp_repo):
    """Create a Go module structure."""
    module_dir = temp_repo / "myapp"
    module_dir.mkdir()

    # Create go.mod
    (module_dir / "go.mod").write_text("module example.com/myapp\n\ngo 1.21")

    # Create main.go
    (module_dir / "main.go").write_text("""
package main

import "fmt"

func main() {
    fmt.Println("Hello")
}
""")

    # Create a library package
    lib_dir = module_dir / "lib"
    lib_dir.mkdir()
    (lib_dir / "lib.go").write_text("package lib\n\nfunc Hello() string { return \"hello\" }")

    return temp_repo


@pytest.fixture
def nodejs_module(temp_repo):
    """Create a Node.js module structure."""
    module_dir = temp_repo / "webapp"
    module_dir.mkdir()

    # Create package.json
    package_json = {
        "name": "webapp",
        "version": "1.0.0",
        "main": "index.js",
        "scripts": {
            "build": "webpack --mode production",
            "test": "jest",
        },
        "bin": {
            "cli": "./bin/cli.js",
        },
    }
    (module_dir / "package.json").write_text(json.dumps(package_json))

    # Create index.js
    (module_dir / "index.js").write_text("module.exports = { hello: () => 'hello' };")

    # Create bin directory
    bin_dir = module_dir / "bin"
    bin_dir.mkdir()
    (bin_dir / "cli.js").write_text("#!/usr/bin/env node\nconsole.log('CLI');")

    return temp_repo


@pytest.fixture
def python_module(temp_repo):
    """Create a Python module structure."""
    module_dir = temp_repo / "mypackage"
    module_dir.mkdir()

    # Create __init__.py
    (module_dir / "__init__.py").write_text("")

    # Create main.py with entry point
    (module_dir / "main.py").write_text("""
def main():
    print("Hello")

if __name__ == "__main__":
    main()
""")

    # Create requirements.txt
    (temp_repo / "requirements.txt").write_text("requests>=2.0")

    return temp_repo


# =============================================================================
# BuildTarget Tests
# =============================================================================


class TestBuildTarget:
    """Tests for BuildTarget dataclass."""

    def test_to_dict(self):
        """Test BuildTarget serialization."""
        target = BuildTarget(
            name="test",
            path=Path("/tmp/test"),
            language="java",
            build_system=BuildSystem.MAVEN,
            build_command="mvn compile",
            priority=1,
        )

        result = target.to_dict()

        assert result["name"] == "test"
        assert result["language"] == "java"
        assert result["build_system"] == "maven"
        assert result["priority"] == 1


class TestEntryPoint:
    """Tests for EntryPoint dataclass."""

    def test_to_dict(self):
        """Test EntryPoint serialization."""
        entry = EntryPoint(
            name="Main",
            path=Path("/tmp/Main.java"),
            language="java",
            entry_type=EntryPointType.MAIN,
            is_primary=True,
        )

        result = entry.to_dict()

        assert result["name"] == "Main"
        assert result["entry_type"] == "main"
        assert result["is_primary"] is True


class TestBuildRecommendation:
    """Tests for BuildRecommendation dataclass."""

    def test_get_primary_target(self):
        """Test getting primary target."""
        rec = BuildRecommendation(
            module_name="test",
            module_path=Path("/tmp/test"),
            targets=[
                BuildTarget(name="low", path=Path("/tmp"), language="java", build_system=BuildSystem.MAVEN, priority=10),
                BuildTarget(name="high", path=Path("/tmp"), language="java", build_system=BuildSystem.MAVEN, priority=1),
            ],
        )

        primary = rec.get_primary_target()

        assert primary is not None
        assert primary.name == "high"

    def test_get_primary_target_empty(self):
        """Test getting primary target when no targets."""
        rec = BuildRecommendation(
            module_name="test",
            module_path=Path("/tmp/test"),
        )

        assert rec.get_primary_target() is None


# =============================================================================
# Java Target Extraction Tests
# =============================================================================


class TestJavaTargetExtraction:
    """Tests for Java build target extraction."""

    def test_maven_single_module(self, java_maven_module):
        """Test Maven single module extraction."""
        module = ModuleSummary(
            name="api",
            path="api",
            primary_language="java",
            languages=["java"],
            build_signals=["pom.xml"],
        )

        extractor = BuildTargetExtractor(java_maven_module)
        rec = extractor.extract(module)

        assert rec.primary_language == "java"
        assert len(rec.targets) >= 1
        assert rec.build_strategy == BuildStrategy.FULL

    def test_maven_entry_points(self, java_maven_module):
        """Test Maven entry point detection."""
        module = ModuleSummary(
            name="api",
            path="api",
            primary_language="java",
            languages=["java"],
            build_signals=["pom.xml"],
        )

        extractor = BuildTargetExtractor(java_maven_module)
        rec = extractor.extract(module)

        # Should detect main class
        assert len(rec.entry_points) >= 1
        assert any(ep.entry_type == EntryPointType.MAIN for ep in rec.entry_points)

    def test_gradle_subprojects(self, java_gradle_module):
        """Test Gradle subproject extraction."""
        module = ModuleSummary(
            name="service",
            path="service",
            primary_language="java",
            languages=["java"],
            build_signals=["build.gradle", "settings.gradle"],
        )

        extractor = BuildTargetExtractor(java_gradle_module)
        rec = extractor.extract(module)

        # Should detect subprojects
        assert len(rec.targets) >= 1


# =============================================================================
# Go Target Extraction Tests
# =============================================================================


class TestGoTargetExtraction:
    """Tests for Go build target extraction."""

    def test_go_main_package(self, go_module):
        """Test Go main package extraction."""
        module = ModuleSummary(
            name="myapp",
            path="myapp",
            primary_language="go",
            languages=["go"],
            build_signals=["go.mod"],
        )

        extractor = BuildTargetExtractor(go_module)
        rec = extractor.extract(module)

        assert rec.primary_language == "go"
        assert len(rec.targets) >= 1
        # Main package should be entry point
        assert any(t.is_entry_point for t in rec.targets)

    def test_go_entry_points(self, go_module):
        """Test Go entry point detection."""
        module = ModuleSummary(
            name="myapp",
            path="myapp",
            primary_language="go",
            languages=["go"],
            build_signals=["go.mod"],
        )

        extractor = BuildTargetExtractor(go_module)
        rec = extractor.extract(module)

        assert len(rec.entry_points) >= 1
        assert any(ep.entry_type == EntryPointType.MAIN for ep in rec.entry_points)


# =============================================================================
# Node.js Target Extraction Tests
# =============================================================================


class TestNodejsTargetExtraction:
    """Tests for Node.js build target extraction."""

    def test_nodejs_package(self, nodejs_module):
        """Test Node.js package extraction."""
        module = ModuleSummary(
            name="webapp",
            path="webapp",
            primary_language="javascript",
            languages=["javascript"],
            build_signals=["package.json"],
        )

        extractor = BuildTargetExtractor(nodejs_module)
        rec = extractor.extract(module)

        assert rec.primary_language == "javascript"
        assert len(rec.targets) >= 1
        assert rec.build_strategy == BuildStrategy.NONE  # JS doesn't require compilation

    def test_nodejs_build_script(self, nodejs_module):
        """Test Node.js build script detection."""
        module = ModuleSummary(
            name="webapp",
            path="webapp",
            primary_language="javascript",
            languages=["javascript"],
            build_signals=["package.json"],
        )

        extractor = BuildTargetExtractor(nodejs_module)
        rec = extractor.extract(module)

        # Should have build command
        assert rec.targets[0].build_command is not None

    def test_nodejs_entry_points(self, nodejs_module):
        """Test Node.js entry point detection."""
        module = ModuleSummary(
            name="webapp",
            path="webapp",
            primary_language="javascript",
            languages=["javascript"],
            build_signals=["package.json"],
        )

        extractor = BuildTargetExtractor(nodejs_module)
        rec = extractor.extract(module)

        # Should detect main and bin
        assert len(rec.entry_points) >= 2
        entry_types = [ep.entry_type for ep in rec.entry_points]
        assert EntryPointType.MAIN in entry_types
        assert EntryPointType.CLI in entry_types


# =============================================================================
# Python Target Extraction Tests
# =============================================================================


class TestPythonTargetExtraction:
    """Tests for Python build target extraction."""

    def test_python_package(self, python_module):
        """Test Python package extraction."""
        module = ModuleSummary(
            name="mypackage",
            path="mypackage",
            primary_language="python",
            languages=["python"],
            build_signals=["requirements.txt"],
        )

        extractor = BuildTargetExtractor(python_module)
        rec = extractor.extract(module)

        assert rec.primary_language == "python"
        assert len(rec.targets) >= 1
        assert rec.build_strategy == BuildStrategy.NONE

    def test_python_entry_points(self, python_module):
        """Test Python entry point detection."""
        module = ModuleSummary(
            name="mypackage",
            path="mypackage",
            primary_language="python",
            languages=["python"],
            build_signals=["requirements.txt"],
        )

        extractor = BuildTargetExtractor(python_module)
        rec = extractor.extract(module)

        assert len(rec.entry_points) >= 1
        assert any(ep.entry_type == EntryPointType.MAIN for ep in rec.entry_points)


# =============================================================================
# Build Strategy Tests
# =============================================================================


class TestBuildStrategy:
    """Tests for build strategy determination."""

    def test_compiled_language_requires_build(self, temp_repo):
        """Test that compiled languages require build."""
        module = ModuleSummary(
            name="test",
            path=".",
            primary_language="java",
            languages=["java"],
            build_signals=[],
        )

        # Create pom.xml for Java
        (temp_repo / "pom.xml").write_text("<project/>")

        extractor = BuildTargetExtractor(temp_repo)
        rec = extractor.extract(module)

        assert rec.build_strategy == BuildStrategy.FULL

    def test_interpreted_language_no_build(self, temp_repo):
        """Test that interpreted languages don't require build."""
        module = ModuleSummary(
            name="test",
            path=".",
            primary_language="python",
            languages=["python"],
            build_signals=[],
        )

        extractor = BuildTargetExtractor(temp_repo)
        rec = extractor.extract(module)

        assert rec.build_strategy == BuildStrategy.NONE


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestExtractBuildTargets:
    """Tests for the extract_build_targets convenience function."""

    def test_extract_multiple_modules(self, temp_repo):
        """Test extracting targets from multiple modules."""
        # Create two simple modules
        py_module_dir = temp_repo / "py_pkg"
        py_module_dir.mkdir()
        (py_module_dir / "main.py").write_text("print('hello')")

        go_module_dir = temp_repo / "go_pkg"
        go_module_dir.mkdir()
        (go_module_dir / "main.go").write_text("package main\nfunc main() {}")
        (go_module_dir / "go.mod").write_text("module test")

        modules = [
            ModuleSummary(name="py_pkg", path="py_pkg", primary_language="python", languages=["python"]),
            ModuleSummary(name="go_pkg", path="go_pkg", primary_language="go", languages=["go"]),
        ]

        recommendations = extract_build_targets(temp_repo, modules)

        assert len(recommendations) == 2
        assert recommendations[0].primary_language == "python"
        assert recommendations[1].primary_language == "go"
