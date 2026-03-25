"""
Java language builder for CodeQL database creation.

Provides intelligent build strategies for Java projects including:
- Maven and Gradle detection
- Wrapper detection and preference
- Multi-module project support
- JDK version compatibility checking
- Build failure diagnosis
"""

import re
import shutil
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

from .base import (
    BuildResult,
    BuilderOutput,
    BuilderRegistry,
    FailureCategory,
    FailureDiagnosis,
    LanguageBuilder,
)

logger = get_logger(__name__)


@BuilderRegistry.register
class JavaBuilder(LanguageBuilder):
    """Builder for Java projects.

    Analyzes Java projects and generates appropriate build strategies
    for CodeQL database creation.
    """

    LANGUAGE_NAME = "java"
    SUPPORTED_BUILD_SYSTEMS = ["maven", "gradle", "gradlew"]

    # Default timeout for Java builds (10 minutes)
    DEFAULT_TIMEOUT = 600

    # Maximum timeout for large projects
    MAX_TIMEOUT = 1800

    def __init__(self) -> None:
        """Initialize the Java builder."""
        self._java_version: str | None = None

    def analyze(self, project_path: Path) -> BuilderOutput:
        """Analyze a Java project and generate build strategy.

        Args:
            project_path: Path to the Java project root.

        Returns:
            BuilderOutput with build commands and configuration.
        """
        project_path = Path(project_path)
        detected_files: list[str] = []

        # Check for build systems in priority order

        # 1. Check for Maven wrapper
        if self._has_maven_wrapper(project_path):
            detected_files.append("mvnw")
            return self._analyze_maven(project_path, detected_files, use_wrapper=True)

        # 2. Check for Gradle wrapper
        if self._has_gradle_wrapper(project_path):
            detected_files.append("gradlew")
            return self._analyze_gradle(project_path, detected_files, use_wrapper=True)

        # 3. Check for pom.xml (Maven without wrapper)
        pom_xml = project_path / "pom.xml"
        if pom_xml.exists():
            detected_files.append("pom.xml")
            return self._analyze_maven(project_path, detected_files, use_wrapper=False)

        # 4. Check for build.gradle (Gradle without wrapper)
        build_gradle = project_path / "build.gradle"
        build_gradle_kts = project_path / "build.gradle.kts"
        if build_gradle.exists():
            detected_files.append("build.gradle")
            return self._analyze_gradle(project_path, detected_files, use_wrapper=False)
        if build_gradle_kts.exists():
            detected_files.append("build.gradle.kts")
            return self._analyze_gradle(project_path, detected_files, use_wrapper=False)

        # No build system found
        return BuilderOutput(
            result=BuildResult.SKIPPED,
            language="java",
            skip_reason="No build system found (need pom.xml, build.gradle, or wrapper)",
            failure_category=FailureCategory.CONFIG_ERROR,
            detected_files=detected_files,
        )

    def diagnose_failure(
        self, stdout: str, stderr: str, return_code: int
    ) -> FailureDiagnosis:
        """Diagnose a Java build failure from command output.

        Args:
            stdout: Standard output from the build command.
            stderr: Standard error from the build command.
            return_code: Exit code from the build command.

        Returns:
            FailureDiagnosis with category and suggestions.
        """
        if return_code == 0:
            return FailureDiagnosis(
                category=FailureCategory.UNKNOWN,
                message="",
            )

        combined = f"{stdout}\n{stderr}".lower()

        # Dependency resolution failure
        if any(
            pattern in combined
            for pattern in [
                "could not resolve dependencies",
                "failed to collect dependencies",
                "could not find artifact",
                "dependency resolution failed",
                "cannot resolve external dependencies",
            ]
        ):
            return FailureDiagnosis(
                category=FailureCategory.DEPENDENCY_RESOLUTION,
                message="Failed to resolve project dependencies",
                suggestion="Check dependency declarations and repository access",
                is_recoverable=True,
            )

        # JDK version mismatch
        if any(
            pattern in combined
            for pattern in [
                "source option",
                "target release",
                "release version",
                "is no longer supported",
                "invalid target release",
                "unsupported class version",
                "java.lang.unsupportedclassversionerror",
            ]
        ):
            version_match = re.search(r"(?:java\s*)?(\d+)", combined)
            version = version_match.group(1) if version_match else "unknown"
            return FailureDiagnosis(
                category=FailureCategory.VERSION_MISMATCH,
                message=f"JDK version mismatch - project requires Java {version}",
                suggestion="Install compatible JDK version or adjust compiler settings",
                is_recoverable=False,
            )

        # Compilation error
        if any(
            pattern in combined
            for pattern in [
                "error:",
                "cannot find symbol",
                "incompatible types",
                "method cannot be applied",
                "package does not exist",
            ]
        ):
            # Extract first error for context
            error_lines = [
                line
                for line in (stderr or stdout).split("\n")
                if "error" in line.lower()
            ]
            error_msg = error_lines[0][:100] if error_lines else "Compilation error"
            return FailureDiagnosis(
                category=FailureCategory.COMPILATION_ERROR,
                message=f"Java compilation error: {error_msg}",
                suggestion="Fix compilation errors in source code",
                is_recoverable=False,
            )

        # Wrapper permission denied
        if "permission denied" in combined and (
            "mvnw" in combined or "gradlew" in combined
        ):
            wrapper = "mvnw" if "mvnw" in combined else "gradlew"
            return FailureDiagnosis(
                category=FailureCategory.WRAPPER_PERMISSION,
                message=f"{wrapper} wrapper script is not executable",
                suggestion=f"Run 'chmod +x {wrapper}' to make it executable",
                is_recoverable=True,
            )

        # Multi-module cycle
        if "cyclic reference" in combined or "circular dependency" in combined:
            return FailureDiagnosis(
                category=FailureCategory.MULTI_MODULE_CYCLE,
                message="Circular dependency detected between modules",
                suggestion="Refactor modules to eliminate circular dependencies",
                is_recoverable=False,
            )

        # Gradle daemon failure
        if "gradle" in combined and (
            "daemon" in combined or "could not create service" in combined
        ):
            return FailureDiagnosis(
                category=FailureCategory.BUILD_ERROR,
                message="Gradle daemon failed to start",
                suggestion="Try running with --no-daemon flag or clean Gradle cache",
                is_recoverable=True,
            )

        # Tool missing
        if "command not found" in combined or "not recognized" in combined:
            tool_match = re.search(r"'([^']+)'", combined)
            tool = tool_match.group(1) if tool_match else "unknown"
            return FailureDiagnosis(
                category=FailureCategory.TOOL_MISSING,
                message=f"Required tool not found: {tool}",
                suggestion=f"Install {tool} or use wrapper",
                is_recoverable=False,
            )

        return FailureDiagnosis(
            category=FailureCategory.UNKNOWN,
            message=f"Unknown Java build failure (exit code {return_code})",
            suggestion="Review build output for details",
        )

    def is_available(self) -> bool:
        """Check if Java is installed."""
        return shutil.which("java") is not None

    def get_version(self) -> str | None:
        """Get the installed Java version."""
        if self._java_version is not None:
            return self._java_version

        try:
            import subprocess

            result = subprocess.run(
                ["java", "-version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Java version goes to stderr
            output = result.stderr or result.stdout
            # Parse "java version "1.8.0_312"" or "openjdk version "17.0.1""
            match = re.search(r'version "?(\d+)', output)
            if match:
                version = match.group(1)
                # Handle old-style versions like 1.8
                if version == "1":
                    match2 = re.search(r'version "1\.(\d+)', output)
                    self._java_version = match2.group(1) if match2 else version
                else:
                    self._java_version = version
                return self._java_version
        except Exception:
            pass

        return None

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _analyze_maven(
        self,
        project_path: Path,
        detected_files: list[str],
        use_wrapper: bool,
    ) -> BuilderOutput:
        """Analyze a Maven project.

        Args:
            project_path: Path to project root.
            detected_files: List of detected files.
            use_wrapper: Whether to use mvnw wrapper.

        Returns:
            BuilderOutput with Maven build strategy.
        """
        pom_xml = project_path / "pom.xml"
        detected_files.append("pom.xml")

        # Parse POM for info
        artifact_id = self._parse_pom_artifact_id(pom_xml)
        jdk_version = self._parse_pom_jdk_version(pom_xml)
        modules = self._detect_maven_modules(pom_xml)

        warnings: list[str] = []
        if modules:
            warnings.append(f"Multi-module project with {len(modules)} modules")

        # Build command
        if use_wrapper:
            build_cmd = "./mvnw compile -DskipTests -q"
            dep_cmd = "./mvnw dependency:resolve -q"
        else:
            build_cmd = "mvn compile -DskipTests -q"
            dep_cmd = "mvn dependency:resolve -q"

        # Environment variables
        env_vars = {"MAVEN_OPTS": "-Xmx2g"}

        return BuilderOutput(
            result=BuildResult.SUCCESS,
            language="java",
            build_command=build_cmd,
            dependency_command=dep_cmd,
            env_vars=env_vars,
            cwd=project_path,
            timeout=self.DEFAULT_TIMEOUT,
            warnings=warnings,
            detected_files=detected_files,
            build_system="maven",
            module_name=artifact_id or project_path.name,
        )

    def _analyze_gradle(
        self,
        project_path: Path,
        detected_files: list[str],
        use_wrapper: bool,
    ) -> BuilderOutput:
        """Analyze a Gradle project.

        Args:
            project_path: Path to project root.
            detected_files: List of detected files.
            use_wrapper: Whether to use gradlew wrapper.

        Returns:
            BuilderOutput with Gradle build strategy.
        """
        # Detect build file
        build_gradle = project_path / "build.gradle"
        build_gradle_kts = project_path / "build.gradle.kts"

        if build_gradle.exists():
            detected_files.append("build.gradle")
            jdk_version = self._parse_gradle_jdk_version(build_gradle)
        elif build_gradle_kts.exists():
            detected_files.append("build.gradle.kts")
            jdk_version = self._parse_gradle_jdk_version(build_gradle_kts)
        else:
            jdk_version = None

        # Check for subprojects
        settings_gradle = project_path / "settings.gradle"
        settings_gradle_kts = project_path / "settings.gradle.kts"
        subprojects: list[str] = []

        if settings_gradle.exists():
            detected_files.append("settings.gradle")
            subprojects = self._detect_gradle_subprojects(settings_gradle)
        elif settings_gradle_kts.exists():
            detected_files.append("settings.gradle.kts")
            subprojects = self._detect_gradle_subprojects(settings_gradle_kts)

        warnings: list[str] = []
        if subprojects:
            warnings.append(f"Multi-project build with {len(subprojects)} subprojects")

        # Build command
        if use_wrapper:
            build_cmd = "./gradlew classes --no-daemon --quiet"
            dep_cmd = "./gradlew dependencies --no-daemon --quiet"
        else:
            build_cmd = "gradle classes --no-daemon --quiet"
            dep_cmd = "gradle dependencies --no-daemon --quiet"

        # Environment variables
        env_vars = {"GRADLE_OPTS": "-Xmx2g -Dorg.gradle.daemon=false"}

        return BuilderOutput(
            result=BuildResult.SUCCESS,
            language="java",
            build_command=build_cmd,
            dependency_command=dep_cmd,
            env_vars=env_vars,
            cwd=project_path,
            timeout=self.DEFAULT_TIMEOUT,
            warnings=warnings,
            detected_files=detected_files,
            build_system="gradle",
            module_name=project_path.name,
        )

    def _has_maven_wrapper(self, project_path: Path) -> bool:
        """Check if Maven wrapper exists.

        Args:
            project_path: Path to project root.

        Returns:
            True if mvnw exists.
        """
        mvnw = project_path / "mvnw"
        return mvnw.exists() and mvnw.is_file()

    def _has_gradle_wrapper(self, project_path: Path) -> bool:
        """Check if Gradle wrapper exists.

        Args:
            project_path: Path to project root.

        Returns:
            True if gradlew exists.
        """
        gradlew = project_path / "gradlew"
        return gradlew.exists() and gradlew.is_file()

    def _parse_pom_artifact_id(self, pom_path: Path) -> str | None:
        """Extract artifact ID from pom.xml.

        Args:
            pom_path: Path to pom.xml.

        Returns:
            Artifact ID or None.
        """
        try:
            content = pom_path.read_text()
            match = re.search(r"<artifactId>([^<]+)</artifactId>", content)
            return match.group(1) if match else None
        except Exception:
            return None

    def _parse_pom_jdk_version(self, pom_path: Path) -> str | None:
        """Extract JDK version from pom.xml.

        Checks in order:
        1. maven.compiler.release
        2. maven.compiler.source
        3. java.version

        Args:
            pom_path: Path to pom.xml.

        Returns:
            JDK version or None.
        """
        try:
            content = pom_path.read_text()

            # Check for maven.compiler.release (Java 9+)
            match = re.search(r"<maven\.compiler\.release>(\d+)</", content)
            if match:
                return match.group(1)

            # Check for maven.compiler.source
            match = re.search(r"<maven\.compiler\.source>(\d+)</", content)
            if match:
                return match.group(1)

            # Check for java.version property
            match = re.search(r"<java\.version>(\d+)</", content)
            if match:
                return match.group(1)

            # Check for source/target properties
            match = re.search(r"<source>(\d+)</source>", content)
            if match:
                return match.group(1)

        except Exception:
            pass

        return None

    def _parse_gradle_jdk_version(self, build_file: Path) -> str | None:
        """Extract JDK version from Gradle build file.

        Checks for:
        1. Java toolchain languageVersion
        2. sourceCompatibility

        Args:
            build_file: Path to build.gradle or build.gradle.kts.

        Returns:
            JDK version or None.
        """
        try:
            content = build_file.read_text()

            # Check for Java toolchain (JavaLanguageVersion.of(X))
            match = re.search(r"JavaLanguageVersion\.of\((\d+)\)", content)
            if match:
                return match.group(1)

            # Check for languageVersion.set(JavaLanguageVersion.of(X))
            match = re.search(r"languageVersion.*?(\d+)", content)
            if match:
                return match.group(1)

            # Check for sourceCompatibility
            match = re.search(r"sourceCompatibility\s*=\s*['\"]?(\d+)", content)
            if match:
                return match.group(1)

            # Check for targetCompatibility
            match = re.search(r"targetCompatibility\s*=\s*['\"]?(\d+)", content)
            if match:
                return match.group(1)

            # Check for Java toolchain in Kotlin DSL
            match = re.search(r"languageVersion\.set\(JavaLanguageVersion\.of\((\d+)\)\)", content)
            if match:
                return match.group(1)

        except Exception:
            pass

        return None

    def _detect_maven_modules(self, pom_path: Path) -> list[str]:
        """Detect submodules in a Maven parent POM.

        Args:
            pom_path: Path to pom.xml.

        Returns:
            List of module names.
        """
        modules: list[str] = []
        try:
            content = pom_path.read_text()

            # Check if this is a parent POM
            if "<packaging>pom</packaging>" not in content:
                return modules

            # Find modules section
            modules_match = re.search(
                r"<modules>(.*?)</modules>", content, re.DOTALL
            )
            if modules_match:
                for match in re.finditer(
                    r"<module>([^<]+)</module>", modules_match.group(1)
                ):
                    modules.append(match.group(1).strip())

        except Exception:
            pass

        return modules

    def _detect_gradle_subprojects(self, settings_file: Path) -> list[str]:
        """Detect subprojects in a Gradle settings file.

        Args:
            settings_file: Path to settings.gradle or settings.gradle.kts.

        Returns:
            List of project names.
        """
        projects: list[str] = []
        try:
            content = settings_file.read_text()

            # Match include 'project' or include "project" or include(':project')
            for match in re.finditer(r"include\s*['\"]([^'\"]+)['\"]", content):
                project = match.group(1).strip().replace(":", "")
                if project:
                    projects.append(project)

            # Kotlin DSL: include(":project")
            for match in re.finditer(r'include\("([^"]+)"\)', content):
                project = match.group(1).strip().replace(":", "")
                if project:
                    projects.append(project)

        except Exception:
            pass

        return projects
