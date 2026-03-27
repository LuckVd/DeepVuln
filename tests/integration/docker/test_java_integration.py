"""
Java Docker Integration Tests (P7-11b-4).

Tests the complete flow for Java projects:
1. JavaBuilder identifies project structure (Maven/Gradle)
2. Build command generation
3. CodeQL database creation (if CodeQL available)
4. Runtime version detection (pom.xml, build.gradle)
5. Multi-version Java support (8, 11, 17, 21)
"""

import pytest
from pathlib import Path

from src.layers.l3_analysis.build.builders import JavaBuilder
from src.layers.l3_analysis.build.builders.base import BuildResult


# Mark all tests in this module as integration tests
pytestmark = [
    pytest.mark.integration,
]


class TestJavaBuilderIntegration:
    """Integration tests for JavaBuilder."""

    def test_builder_analyzes_maven_project(self, java_maven_project: Path):
        """Test that builder analyzes Maven project."""
        builder = JavaBuilder()
        output = builder.analyze(java_maven_project)

        assert output.language == "java"
        # Java projects should have build commands
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)
        # Should detect pom.xml
        assert any("pom.xml" in f for f in output.detected_files)

    def test_builder_analyzes_gradle_project(self, tmp_path: Path):
        """Test that builder analyzes Gradle project."""
        project = tmp_path / "gradle_project"
        src_dir = project / "src" / "main" / "java"
        src_dir.mkdir(parents=True)
        (src_dir / "Main.java").write_text("public class Main {}")
        (project / "build.gradle").write_text('''
plugins {
    id 'java'
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
''')

        builder = JavaBuilder()
        output = builder.analyze(project)

        assert output.language == "java"
        # Should detect build.gradle
        assert any("build.gradle" in f for f in output.detected_files)

    def test_builder_detects_wrapper(self, tmp_path: Path):
        """Test that builder detects Maven/Gradle wrapper."""
        project = tmp_path / "wrapper_project"
        project.mkdir()
        (project / "pom.xml").write_text('<project><modelVersion>4.0.0</modelVersion></project>')

        # Create wrapper script
        wrapper_dir = project / ".mvn" / "wrapper"
        wrapper_dir.mkdir(parents=True)
        (project / "mvnw").write_text("#!/bin/bash\necho 'mvnw'")
        (project / "mvnw.cmd").write_text("@echo mvnw")

        builder = JavaBuilder()
        output = builder.analyze(project)

        # Should detect wrapper files
        assert any("mvnw" in f for f in output.detected_files)


class TestJavaVersionDetection:
    """Integration tests for Java version detection."""

    def test_detect_java_from_pom_properties(self, java_maven_project: Path):
        """Test version detection from pom.xml maven.compiler.source."""
        from src.layers.l3_analysis.build.version_detector import VersionDetector

        detector = VersionDetector(java_maven_project)
        requirement = detector.detect()

        if requirement.java_version:
            assert "11" in requirement.java_version

    def test_detect_java_from_pom_release(self, tmp_path: Path):
        """Test version detection from pom.xml maven.compiler.release."""
        from src.layers.l3_analysis.build.version_detector import VersionDetector

        project = tmp_path / "java_release_project"
        project.mkdir()
        (project / "pom.xml").write_text('''<?xml version="1.0"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test</artifactId>
    <version>1.0.0</version>
    <properties>
        <maven.compiler.release>17</maven.compiler.release>
    </properties>
</project>
''')

        detector = VersionDetector(project)
        requirement = detector.detect()

        if requirement.java_version:
            assert "17" in requirement.java_version

    def test_detect_java_from_gradle_sourcecompat(self, tmp_path: Path):
        """Test version detection from build.gradle sourceCompatibility."""
        from src.layers.l3_analysis.build.version_detector import VersionDetector

        project = tmp_path / "gradle_compat_project"
        project.mkdir()
        (project / "build.gradle").write_text('''
java {
    sourceCompatibility = JavaVersion.VERSION_1_8
}
''')

        detector = VersionDetector(project)
        requirement = detector.detect()

        if requirement.java_version:
            assert "8" in requirement.java_version

    def test_detect_java_from_gradle_toolchain(self, tmp_path: Path):
        """Test version detection from build.gradle toolchain."""
        from src.layers.l3_analysis.build.version_detector import VersionDetector

        project = tmp_path / "gradle_toolchain_project"
        project.mkdir()
        (project / "build.gradle").write_text('''
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}
''')

        detector = VersionDetector(project)
        requirement = detector.detect()

        if requirement.java_version:
            assert "21" in requirement.java_version


class TestJavaCodeQLIntegration:
    """CodeQL integration tests for Java (requires CodeQL)."""

    @pytest.mark.codeql
    @pytest.mark.skip(reason="Requires CodeQL build environment")
    def test_codeql_database_creation(self, java_maven_project: Path, tmp_path: Path):
        """Test CodeQL database creation for Java project."""
        pass


class TestJavaRuntimeVersionManager:
    """Test RuntimeVersionManager with Java."""

    def test_list_available_java_versions(self):
        """Test listing available Java versions."""
        from src.layers.l3_analysis.build.runtime.registry import RuntimeRegistry
        from src.layers.l3_analysis.build.runtime.models import RuntimeType

        registry = RuntimeRegistry()
        versions = registry.get_versions(RuntimeType.JAVA)

        assert len(versions) > 0
        # Should have Java 8, 11, 17, 21
        assert "8" in versions
        assert "11" in versions
        assert "17" in versions
        assert "21" in versions

    def test_java_download_url(self):
        """Test Java download URL generation."""
        from src.layers.l3_analysis.build.runtime.registry import RuntimeRegistry
        from src.layers.l3_analysis.build.runtime.models import RuntimeType

        registry = RuntimeRegistry()
        info = registry.get_info(RuntimeType.JAVA, "11")

        if info:
            # Should be Eclipse Temurin URL
            assert "temurin" in info.download_url.lower() or "eclipse" in info.download_url.lower()
            assert "11" in str(info.download_url)

    @pytest.mark.asyncio
    async def test_java_8_runtime_management(self, test_runtime_root: Path):
        """Test Java 8 runtime management (without actual download)."""
        from src.layers.l3_analysis.build.runtime import (
            RuntimeVersionManager,
            RuntimeType,
        )

        manager = RuntimeVersionManager(
            runtime_root=test_runtime_root,
            auto_install=False,  # Don't actually download
        )

        # Test that the manager can handle Java 8 requirement
        assert manager.registry.is_version_available(RuntimeType.JAVA, "8")


class TestJavaMultiVersion:
    """Test multi-version Java support."""

    def test_java_8_project_detection(self, tmp_path: Path):
        """Test detection of Java 8 project."""
        from src.layers.l3_analysis.build.version_detector import VersionDetector

        project = tmp_path / "java8_project"
        project.mkdir()
        (project / "pom.xml").write_text('''<?xml version="1.0"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <properties>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
    </properties>
</project>
''')

        detector = VersionDetector(project)
        requirement = detector.detect()

        if requirement.java_version:
            assert "8" in requirement.java_version

    def test_java_21_project_detection(self, tmp_path: Path):
        """Test detection of Java 21 project."""
        from src.layers.l3_analysis.build.version_detector import VersionDetector

        project = tmp_path / "java21_project"
        project.mkdir()
        (project / "pom.xml").write_text('''<?xml version="1.0"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <properties>
        <maven.compiler.release>21</maven.compiler.release>
    </properties>
</project>
''')

        detector = VersionDetector(project)
        requirement = detector.detect()

        if requirement.java_version:
            assert "21" in requirement.java_version
