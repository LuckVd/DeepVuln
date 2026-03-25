"""
Unit tests for Java builder.
"""

from pathlib import Path

import pytest

from src.layers.l3_analysis.build.builders.base import (
    BuildResult,
    FailureCategory,
    FailureDiagnosis,
)
from src.layers.l3_analysis.build.builders.java import JavaBuilder


class TestJavaBuilderAnalyze:
    """Tests for JavaBuilder.analyze method."""

    @pytest.fixture
    def builder(self) -> JavaBuilder:
        """Create a JavaBuilder instance."""
        return JavaBuilder()

    def test_maven_wrapper_project(self, builder: JavaBuilder, tmp_path: Path) -> None:
        """Test analyzing a Maven project with wrapper."""
        # Create pom.xml
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            '<?xml version="1.0"?>\n'
            '<project>\n'
            '  <modelVersion>4.0.0</modelVersion>\n'
            '  <groupId>com.example</groupId>\n'
            '  <artifactId>my-app</artifactId>\n'
            '  <version>1.0.0</version>\n'
            '  <properties>\n'
            '    <maven.compiler.source>17</maven.compiler.source>\n'
            '    <maven.compiler.target>17</maven.compiler.target>\n'
            '  </properties>\n'
            '</project>\n'
        )

        # Create mvnw
        mvnw = tmp_path / "mvnw"
        mvnw.write_text("#!/bin/bash\n")

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.language == "java"
        assert "./mvnw" in output.build_command
        assert output.build_system == "maven"
        assert "pom.xml" in output.detected_files
        assert "mvnw" in output.detected_files

    def test_maven_project_no_wrapper(
        self, builder: JavaBuilder, tmp_path: Path
    ) -> None:
        """Test analyzing a Maven project without wrapper."""
        # Create pom.xml
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            '<?xml version="1.0"?>\n'
            '<project>\n'
            '  <modelVersion>4.0.0</modelVersion>\n'
            '  <groupId>com.example</groupId>\n'
            '  <artifactId>my-app</artifactId>\n'
            '  <version>1.0.0</version>\n'
            '</project>\n'
        )

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.build_command == "mvn compile -DskipTests -q"
        assert output.build_system == "maven"

    def test_gradle_wrapper_project(self, builder: JavaBuilder, tmp_path: Path) -> None:
        """Test analyzing a Gradle project with wrapper."""
        # Create build.gradle
        build_gradle = tmp_path / "build.gradle"
        build_gradle.write_text(
            "plugins {\n"
            "    id 'java'\n"
            "}\n"
            "java {\n"
            "    toolchain {\n"
            "        languageVersion = JavaLanguageVersion.of(17)\n"
            "    }\n"
            "}\n"
        )

        # Create gradlew
        gradlew = tmp_path / "gradlew"
        gradlew.write_text("#!/bin/bash\n")

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert "./gradlew" in output.build_command
        assert output.build_system == "gradle"
        assert "build.gradle" in output.detected_files
        assert "gradlew" in output.detected_files

    def test_gradle_kotlin_dsl(self, builder: JavaBuilder, tmp_path: Path) -> None:
        """Test analyzing a Gradle project with Kotlin DSL."""
        # Create build.gradle.kts
        build_gradle_kts = tmp_path / "build.gradle.kts"
        build_gradle_kts.write_text(
            'plugins {\n'
            '    java\n'
            '}\n'
            'java {\n'
            '    toolchain {\n'
            '        languageVersion.set(JavaLanguageVersion.of(17))\n'
            '    }\n'
            '}\n'
        )

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.build_system == "gradle"

    def test_maven_multi_module(self, builder: JavaBuilder, tmp_path: Path) -> None:
        """Test analyzing a multi-module Maven project."""
        # Create parent pom.xml
        parent_pom = tmp_path / "pom.xml"
        parent_pom.write_text(
            '<?xml version="1.0"?>\n'
            '<project>\n'
            '  <modelVersion>4.0.0</modelVersion>\n'
            '  <groupId>com.example</groupId>\n'
            '  <artifactId>parent</artifactId>\n'
            '  <version>1.0.0</version>\n'
            '  <packaging>pom</packaging>\n'
            '  <modules>\n'
            '    <module>module-a</module>\n'
            '    <module>module-b</module>\n'
            '  </modules>\n'
            '</project>\n'
        )

        # Create submodules
        for mod in ["module-a", "module-b"]:
            mod_path = tmp_path / mod
            mod_path.mkdir()
            (mod_path / "pom.xml").write_text(
                f'<?xml version="1.0"?>\n'
                f'<project>\n'
                f'  <parent>\n'
                f'    <groupId>com.example</groupId>\n'
                f'    <artifactId>parent</artifactId>\n'
                f'    <version>1.0.0</version>\n'
                f'  </parent>\n'
                f'  <artifactId>{mod}</artifactId>\n'
                f'</project>\n'
            )

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Should build all modules
        assert output.build_command is not None

    def test_no_build_system(self, builder: JavaBuilder, tmp_path: Path) -> None:
        """Test analyzing a Java project without build system."""
        # Create only Java files
        java_file = tmp_path / "Main.java"
        java_file.write_text("public class Main { public static void main() {} }")

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SKIPPED
        assert "no build system" in output.skip_reason.lower()

    def test_jdk_version_extraction_maven(
        self, builder: JavaBuilder, tmp_path: Path
    ) -> None:
        """Test extracting JDK version from pom.xml."""
        pom_xml = tmp_path / "pom.xml"
        pom_xml.write_text(
            '<?xml version="1.0"?>\n'
            '<project>\n'
            '  <modelVersion>4.0.0</modelVersion>\n'
            '  <artifactId>test</artifactId>\n'
            '  <properties>\n'
            '    <maven.compiler.release>21</maven.compiler.release>\n'
            '  </properties>\n'
            '</project>\n'
        )

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS


class TestJavaBuilderDiagnoseFailure:
    """Tests for JavaBuilder.diagnose_failure method."""

    @pytest.fixture
    def builder(self) -> JavaBuilder:
        """Create a JavaBuilder instance."""
        return JavaBuilder()

    def test_dependency_resolution_failed(self, builder: JavaBuilder) -> None:
        """Test diagnosing Maven dependency resolution failure."""
        stderr = (
            "[ERROR] Failed to execute goal on project my-app: "
            "Could not resolve dependencies for project com.example:my-app:jar:1.0: "
            "Failed to collect dependencies at com.example:lib:jar:1.0: "
            "Failed to read artifact descriptor for com.example:lib:jar:1.0: "
            "Could not find artifact com.example:lib:jar:1.0 in central"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.DEPENDENCY_RESOLUTION

    def test_compilation_error(self, builder: JavaBuilder) -> None:
        """Test diagnosing Java compilation error."""
        stderr = (
            "[ERROR] /src/main/java/com/example/Main.java:[10,5] "
            "error: cannot find symbol\n"
            "[ERROR]   symbol:   variable unknownVar\n"
            "[ERROR]   location: class Main"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.COMPILATION_ERROR

    def test_jdk_version_mismatch_maven(self, builder: JavaBuilder) -> None:
        """Test diagnosing JDK version mismatch."""
        stderr = (
            "[ERROR] Source option 17 is no longer supported. Use 21 or later.\n"
            "[ERROR] invalid target release: 17"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.VERSION_MISMATCH

    def test_jdk_version_mismatch_gradle(self, builder: JavaBuilder) -> None:
        """Test diagnosing JDK version mismatch in Gradle."""
        stderr = (
            "Execution failed for task ':compileJava'.\n"
            "error: release version 17 not supported"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.VERSION_MISMATCH

    def test_wrapper_permission(self, builder: JavaBuilder) -> None:
        """Test diagnosing wrapper permission issue."""
        stderr = "Cannot run program \"./mvnw\": error=13, Permission denied"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.WRAPPER_PERMISSION

    def test_multi_module_cycle(self, builder: JavaBuilder) -> None:
        """Test diagnosing multi-module cycle."""
        stderr = (
            "[ERROR] The projects in the reactor contain a cyclic reference: "
            "module-a -> module-b -> module-a"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.MULTI_MODULE_CYCLE

    def test_gradle_daemon_error(self, builder: JavaBuilder) -> None:
        """Test diagnosing Gradle daemon error."""
        stderr = (
            "Gradle could not start your build.\n"
            "Could not create service of type DaemonService"
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        # Should be categorized as build error
        assert diagnosis.category in [
            FailureCategory.BUILD_ERROR,
            FailureCategory.TOOL_MISSING,
        ]

    def test_unknown_error(self, builder: JavaBuilder) -> None:
        """Test diagnosing unknown error."""
        stderr = "Some random error message"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.UNKNOWN


class TestJavaBuilderUtilities:
    """Tests for JavaBuilder utility methods."""

    @pytest.fixture
    def builder(self) -> JavaBuilder:
        """Create a JavaBuilder instance."""
        return JavaBuilder()

    def test_has_maven_wrapper_true(self, builder: JavaBuilder, tmp_path: Path) -> None:
        """Test detecting Maven wrapper."""
        (tmp_path / "mvnw").write_text("#!/bin/bash\n")
        assert builder._has_maven_wrapper(tmp_path) is True

    def test_has_maven_wrapper_false(
        self, builder: JavaBuilder, tmp_path: Path
    ) -> None:
        """Test Maven wrapper absence."""
        assert builder._has_maven_wrapper(tmp_path) is False

    def test_has_gradle_wrapper_true(
        self, builder: JavaBuilder, tmp_path: Path
    ) -> None:
        """Test detecting Gradle wrapper."""
        (tmp_path / "gradlew").write_text("#!/bin/bash\n")
        assert builder._has_gradle_wrapper(tmp_path) is True

    def test_parse_pom_jdk_version_source_target(
        self, builder: JavaBuilder, tmp_path: Path
    ) -> None:
        """Test parsing JDK version from maven.compiler.source/target."""
        pom = tmp_path / "pom.xml"
        pom.write_text(
            '<project>\n'
            '  <properties>\n'
            '    <maven.compiler.source>17</maven.compiler.source>\n'
            '    <maven.compiler.target>17</maven.compiler.target>\n'
            '  </properties>\n'
            '</project>\n'
        )

        version = builder._parse_pom_jdk_version(pom)
        assert version == "17"

    def test_parse_pom_jdk_version_release(
        self, builder: JavaBuilder, tmp_path: Path
    ) -> None:
        """Test parsing JDK version from maven.compiler.release."""
        pom = tmp_path / "pom.xml"
        pom.write_text(
            '<project>\n'
            '  <properties>\n'
            '    <maven.compiler.release>21</maven.compiler.release>\n'
            '  </properties>\n'
            '</project>\n'
        )

        version = builder._parse_pom_jdk_version(pom)
        assert version == "21"

    def test_parse_gradle_jdk_version_toolchain(
        self, builder: JavaBuilder, tmp_path: Path
    ) -> None:
        """Test parsing JDK version from Gradle toolchain."""
        build_gradle = tmp_path / "build.gradle"
        build_gradle.write_text(
            "java {\n"
            "    toolchain {\n"
            "        languageVersion = JavaLanguageVersion.of(17)\n"
            "    }\n"
            "}\n"
        )

        version = builder._parse_gradle_jdk_version(build_gradle)
        assert version == "17"

    def test_parse_gradle_jdk_version_compatibility(
        self, builder: JavaBuilder, tmp_path: Path
    ) -> None:
        """Test parsing JDK version from sourceCompatibility."""
        build_gradle = tmp_path / "build.gradle"
        build_gradle.write_text(
            "sourceCompatibility = '17'\n"
            "targetCompatibility = '17'\n"
        )

        version = builder._parse_gradle_jdk_version(build_gradle)
        assert version == "17"

    def test_detect_maven_modules(self, builder: JavaBuilder, tmp_path: Path) -> None:
        """Test detecting Maven submodules."""
        pom = tmp_path / "pom.xml"
        pom.write_text(
            '<project>\n'
            '  <packaging>pom</packaging>\n'
            '  <modules>\n'
            '    <module>core</module>\n'
            '    <module>web</module>\n'
            '  </modules>\n'
            '</project>\n'
        )

        modules = builder._detect_maven_modules(pom)
        assert "core" in modules
        assert "web" in modules

    def test_detect_gradle_subprojects(
        self, builder: JavaBuilder, tmp_path: Path
    ) -> None:
        """Test detecting Gradle subprojects."""
        settings = tmp_path / "settings.gradle"
        settings.write_text(
            "rootProject.name = 'my-app'\n"
            "include 'core'\n"
            "include 'web'\n"
        )

        projects = builder._detect_gradle_subprojects(settings)
        assert "core" in projects
        assert "web" in projects


class TestJavaBuilderRegistration:
    """Tests for JavaBuilder registration."""

    def test_java_builder_registered(self) -> None:
        """Test that JavaBuilder is registered."""
        from src.layers.l3_analysis.build.builders.base import BuilderRegistry

        # Clear and re-register
        BuilderRegistry._builders.clear()
        from src.layers.l3_analysis.build.builders.java import JavaBuilder
        BuilderRegistry.register(JavaBuilder)

        builder = BuilderRegistry.get("java")
        assert builder is not None
        assert builder.LANGUAGE_NAME == "java"
