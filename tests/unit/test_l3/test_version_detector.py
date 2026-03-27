"""
Unit tests for Version Detector.

Tests runtime version detection from configuration files
for Java, Go, and Node.js.
"""

import json
import pytest
from pathlib import Path
import tempfile

from src.layers.l3_analysis.build.version_detector import (
    RuntimeType,
    VersionDetector,
    VersionInfo,
    VersionRequirement,
    detect_versions,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_repo(tmp_path):
    """Create a temporary repository for testing."""
    return tmp_path


@pytest.fixture
def maven_project(temp_repo):
    """Create a Maven project with pom.xml."""
    pom_content = """<?xml version="1.0"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test</artifactId>
    <version>1.0.0</version>
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
    </properties>
</project>
"""
    (temp_repo / "pom.xml").write_text(pom_content)
    return temp_repo


@pytest.fixture
def maven_project_with_release(temp_repo):
    """Create a Maven project with release property."""
    pom_content = """<?xml version="1.0"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <properties>
        <maven.compiler.release>17</maven.compiler.release>
    </properties>
</project>
"""
    (temp_repo / "pom.xml").write_text(pom_content)
    return temp_repo


@pytest.fixture
def gradle_project(temp_repo):
    """Create a Gradle project with build.gradle."""
    (temp_repo / "build.gradle").write_text("""
plugins {
    id 'java'
}

sourceCompatibility = '11'
targetCompatibility = '11'
""")
    return temp_repo


@pytest.fixture
def gradle_project_with_toolchain(temp_repo):
    """Create a Gradle project with toolchain."""
    (temp_repo / "build.gradle").write_text("""
plugins {
    id 'java'
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}
""")
    return temp_repo


@pytest.fixture
def gradle_kts_project(temp_repo):
    """Create a Gradle Kotlin DSL project."""
    (temp_repo / "build.gradle.kts").write_text("""
plugins {
    java
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}
""")
    return temp_repo


@pytest.fixture
def go_module(temp_repo):
    """Create a Go module."""
    (temp_repo / "go.mod").write_text("""
module example.com/test

go 1.21

require (
    github.com/stretchr/testify v1.8.0
)
""")
    return temp_repo


@pytest.fixture
def nvmrc_project(temp_repo):
    """Create a project with .nvmrc."""
    (temp_repo / ".nvmrc").write_text("18.17.0\n")
    return temp_repo


@pytest.fixture
def package_json_with_engines(temp_repo):
    """Create a project with package.json engines."""
    package_json = {
        "name": "test",
        "version": "1.0.0",
        "engines": {
            "node": ">=18.0.0",
            "npm": ">=9.0.0",
        },
    }
    (temp_repo / "package.json").write_text(json.dumps(package_json))
    return temp_repo


# =============================================================================
# VersionInfo Tests
# =============================================================================


class TestVersionInfo:
    """Tests for VersionInfo dataclass."""

    def test_to_dict(self):
        """Test VersionInfo serialization."""
        info = VersionInfo(
            runtime=RuntimeType.JAVA,
            version="17",
            source="pom.xml",
            confidence=1.0,
        )

        result = info.to_dict()

        assert result["runtime"] == "java"
        assert result["version"] == "17"
        assert result["source"] == "pom.xml"


class TestVersionRequirement:
    """Tests for VersionRequirement dataclass."""

    def test_java_version_property(self):
        """Test java_version property."""
        req = VersionRequirement(
            module_path=Path("/tmp"),
            versions={
                RuntimeType.JAVA: VersionInfo(runtime=RuntimeType.JAVA, version="17"),
            },
        )

        assert req.java_version == "17"

    def test_java_version_none(self):
        """Test java_version when not set."""
        req = VersionRequirement(module_path=Path("/tmp"))
        assert req.java_version is None

    def test_to_dict(self):
        """Test VersionRequirement serialization."""
        req = VersionRequirement(
            module_path=Path("/tmp/test"),
            versions={
                RuntimeType.JAVA: VersionInfo(runtime=RuntimeType.JAVA, version="17"),
            },
        )

        result = req.to_dict()

        assert "java" in result["versions"]


# =============================================================================
# Java Version Detection Tests
# =============================================================================


class TestJavaVersionDetection:
    """Tests for Java version detection."""

    def test_maven_source_target(self, maven_project):
        """Test detection from maven.compiler.source/target."""
        detector = VersionDetector(maven_project)
        result = detector.detect()

        assert result.java_version == "11"
        assert RuntimeType.JAVA in result.versions
        assert "pom.xml" in result.versions[RuntimeType.JAVA].source

    def test_maven_release(self, maven_project_with_release):
        """Test detection from maven.compiler.release."""
        detector = VersionDetector(maven_project_with_release)
        result = detector.detect()

        assert result.java_version == "17"
        assert "release" in result.versions[RuntimeType.JAVA].source

    def test_gradle_source_compatibility(self, gradle_project):
        """Test detection from Gradle sourceCompatibility."""
        detector = VersionDetector(gradle_project)
        result = detector.detect()

        assert result.java_version == "11"
        assert "build.gradle" in result.versions[RuntimeType.JAVA].source

    def test_gradle_toolchain(self, gradle_project_with_toolchain):
        """Test detection from Gradle toolchain."""
        detector = VersionDetector(gradle_project_with_toolchain)
        result = detector.detect()

        assert result.java_version == "17"
        assert "toolchain" in result.versions[RuntimeType.JAVA].source

    def test_gradle_kts_toolchain(self, gradle_kts_project):
        """Test detection from Gradle Kotlin DSL toolchain."""
        detector = VersionDetector(gradle_kts_project)
        result = detector.detect()

        assert result.java_version == "21"
        assert "build.gradle.kts" in result.versions[RuntimeType.JAVA].source

    def test_no_java_config(self, temp_repo):
        """Test when no Java config exists."""
        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.java_version is None

    def test_java_1_8_normalization(self, temp_repo):
        """Test that Java 1.8 is normalized to 8."""
        pom_content = """<?xml version="1.0"?>
<project>
    <properties>
        <maven.compiler.source>1.8</maven.compiler.source>
    </properties>
</project>
"""
        (temp_repo / "pom.xml").write_text(pom_content)

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.java_version == "8"


# =============================================================================
# Go Version Detection Tests
# =============================================================================


class TestGoVersionDetection:
    """Tests for Go version detection."""

    def test_go_mod_version(self, go_module):
        """Test detection from go.mod."""
        detector = VersionDetector(go_module)
        result = detector.detect()

        assert result.go_version == "1.21"
        assert result.versions[RuntimeType.GO].source == "go.mod"

    def test_go_mod_no_version(self, temp_repo):
        """Test when go.mod has no version."""
        (temp_repo / "go.mod").write_text("module example.com/test\n")

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.go_version is None

    def test_no_go_mod(self, temp_repo):
        """Test when no go.mod exists."""
        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.go_version is None


# =============================================================================
# Node Version Detection Tests
# =============================================================================


class TestNodeVersionDetection:
    """Tests for Node version detection."""

    def test_nvmrc_version(self, nvmrc_project):
        """Test detection from .nvmrc."""
        detector = VersionDetector(nvmrc_project)
        result = detector.detect()

        assert result.node_version == "18.17.0"
        assert result.versions[RuntimeType.NODE].source == ".nvmrc"

    def test_nvmrc_with_v_prefix(self, temp_repo):
        """Test .nvmrc with v prefix."""
        (temp_repo / ".nvmrc").write_text("v20.10.0\n")

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.node_version == "20.10.0"

    def test_nvmrc_lts(self, temp_repo):
        """Test .nvmrc with lts/* (should return None)."""
        (temp_repo / ".nvmrc").write_text("lts/*\n")

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        # lts/* is not a specific version
        assert result.node_version is None

    def test_package_json_engines(self, package_json_with_engines):
        """Test detection from package.json engines."""
        detector = VersionDetector(package_json_with_engines)
        result = detector.detect()

        assert result.node_version == "18.0.0"
        assert "engines.node" in result.versions[RuntimeType.NODE].source

    def test_package_json_engines_caret(self, temp_repo):
        """Test package.json engines with caret."""
        package_json = {"engines": {"node": "^18.0.0"}}
        (temp_repo / "package.json").write_text(json.dumps(package_json))

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.node_version == "18.0.0"

    def test_package_json_engines_x(self, temp_repo):
        """Test package.json engines with .x."""
        package_json = {"engines": {"node": "18.x"}}
        (temp_repo / "package.json").write_text(json.dumps(package_json))

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.node_version == "18"

    def test_no_node_config(self, temp_repo):
        """Test when no Node config exists."""
        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.node_version is None


# =============================================================================
# Multi-Runtime Detection Tests
# =============================================================================


class TestMultiRuntimeDetection:
    """Tests for detecting multiple runtimes."""

    def test_detect_multiple_runtimes(self, temp_repo):
        """Test detecting Java, Go, and Node versions."""
        # Create pom.xml
        (temp_repo / "pom.xml").write_text("""
<project>
    <properties>
        <maven.compiler.source>17</maven.compiler.source>
    </properties>
</project>
""")

        # Create go.mod
        (temp_repo / "go.mod").write_text("module test\n\ngo 1.21\n")

        # Create .nvmrc
        (temp_repo / ".nvmrc").write_text("18\n")

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.java_version == "17"
        assert result.go_version == "1.21"
        assert result.node_version == "18"

    def test_nvmrc_priority_over_engines(self, temp_repo):
        """Test that .nvmrc takes priority over package.json engines."""
        (temp_repo / ".nvmrc").write_text("20.0.0\n")

        package_json = {"engines": {"node": ">=18.0.0"}}
        (temp_repo / "package.json").write_text(json.dumps(package_json))

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        # .nvmrc should win
        assert result.node_version == "20.0.0"
        assert result.versions[RuntimeType.NODE].source == ".nvmrc"


# =============================================================================
# Edge Case Tests (P7-10c)
# =============================================================================


class TestVersionDetectionEdgeCases:
    """Tests for version detection edge cases (P7-10c)."""

    def test_nvmrc_lts_hydrogen(self, temp_repo):
        """Test .nvmrc with lts/hydrogen format."""
        (temp_repo / ".nvmrc").write_text("lts/hydrogen\n")

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        # lts/* formats should return None
        assert result.node_version is None

    def test_nvmrc_lts_latest(self, temp_repo):
        """Test .nvmrc with lts/* format."""
        (temp_repo / ".nvmrc").write_text("lts/*\n")

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.node_version is None

    def test_nvmrc_node(self, temp_repo):
        """Test .nvmrc with 'node' (latest)."""
        (temp_repo / ".nvmrc").write_text("node\n")

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.node_version is None

    def test_package_json_engines_tilde(self, temp_repo):
        """Test package.json engines with ~18.0.0."""
        package_json = {"engines": {"node": "~18.0.0"}}
        (temp_repo / "package.json").write_text(json.dumps(package_json))

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.node_version == "18.0.0"

    def test_package_json_engines_caret(self, temp_repo):
        """Test package.json engines with ^18.0.0."""
        package_json = {"engines": {"node": "^18.0.0"}}
        (temp_repo / "package.json").write_text(json.dumps(package_json))

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.node_version == "18.0.0"

    def test_package_json_engines_double_x(self, temp_repo):
        """Test package.json engines with 18.x.x."""
        package_json = {"engines": {"node": "18.x.x"}}
        (temp_repo / "package.json").write_text(json.dumps(package_json))

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.node_version == "18"

    def test_package_json_engines_or_operator(self, temp_repo):
        """Test package.json engines with || operator."""
        package_json = {"engines": {"node": "16.x || 18.x || 20.x"}}
        (temp_repo / "package.json").write_text(json.dumps(package_json))

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        # Should take first version
        assert result.node_version == "16"

    def test_package_json_engines_with_spaces(self, temp_repo):
        """Test package.json engines with spaces around operator."""
        package_json = {"engines": {"node": " >= 18.0.0 "}}
        (temp_repo / "package.json").write_text(json.dumps(package_json))

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.node_version == "18.0.0"

    def test_java_version_with_preview(self, temp_repo):
        """Test Java version with preview features."""
        pom_content = """<?xml version="1.0"?>
<project>
    <properties>
        <maven.compiler.release>21</maven.compiler.release>
        <maven.compiler.enablePreview>true</maven.compiler.enablePreview>
    </properties>
</project>
"""
        (temp_repo / "pom.xml").write_text(pom_content)

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.java_version == "21"

    def test_go_version_with_prerelease(self, temp_repo):
        """Test go.mod with prerelease version."""
        (temp_repo / "go.mod").write_text("module test\n\ngo 1.22rc1\n")

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        assert result.go_version == "1.22"

    def test_gradle_with_property_interpolation(self, temp_repo):
        """Test Gradle with property interpolation."""
        (temp_repo / "build.gradle").write_text("""
def javaTarget = 17
java {
    sourceCompatibility = javaTarget
    targetCompatibility = javaTarget
}
""")

        detector = VersionDetector(temp_repo)
        result = detector.detect()

        # Property interpolation not supported, should return None
        assert result.java_version is None


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestDetectVersions:
    """Tests for the detect_versions convenience function."""

    def test_detect_versions_returns_requirement(self, maven_project):
        """Test that detect_versions returns VersionRequirement."""
        result = detect_versions(maven_project)

        assert isinstance(result, VersionRequirement)
        assert result.java_version == "11"

    def test_detect_versions_with_module_path(self, temp_repo):
        """Test detect_versions with explicit module path."""
        # Create submodule
        submodule = temp_repo / "submodule"
        submodule.mkdir()
        (submodule / "go.mod").write_text("module test\n\ngo 1.20\n")

        result = detect_versions(temp_repo, submodule)

        assert result.go_version == "1.20"
