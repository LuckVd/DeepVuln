"""Build system detection for various programming languages.

This module detects the build system used by a project and provides
appropriate build commands for CodeQL database creation.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class BuildSystem(Enum):
    """Supported build systems."""

    # Go build systems
    GO_MODULES = "go_modules"
    GO_WORK = "go_work"
    MAKEFILE = "makefile"
    GO_MAKEFILE = "go_makefile"

    # Java build systems
    MAVEN = "maven"
    GRADLE = "gradle"
    GRADLEW = "gradlew"

    # Node.js build systems
    NPM = "npm"
    YARN = "yarn"
    PNPM = "pnpm"

    # Python build systems
    PIP = "pip"
    POETRY = "poetry"
    SETUP_PY = "setup_py"

    # Other
    NONE = "none"
    UNKNOWN = "unknown"


@dataclass
class BuildConfig:
    """Configuration for building a project.

    Attributes:
        build_system: The detected build system.
        language: The programming language.
        build_command: Command to build the project.
        dependency_command: Command to install dependencies.
        build_dir: Directory to run build commands from.
        env_vars: Environment variables to set.
        requires_build: Whether the language requires compilation.
    """

    build_system: BuildSystem
    language: str
    build_command: str | None = None
    dependency_command: str | None = None
    build_dir: Path | None = None
    env_vars: dict[str, str] = field(default_factory=dict)
    requires_build: bool = False
    detected_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            "build_system": self.build_system.value,
            "language": self.language,
            "build_command": self.build_command,
            "dependency_command": self.dependency_command,
            "build_dir": str(self.build_dir) if self.build_dir else None,
            "env_vars": self.env_vars,
            "requires_build": self.requires_build,
            "detected_files": self.detected_files,
        }


class BuildSystemDetector:
    """Detects build system for a project.

    Supports:
    - Go: go.mod, go.work, Makefile
    - Java: Maven (pom.xml), Gradle (build.gradle, build.gradle.kts)
    - Node.js: package.json (npm, yarn, pnpm)
    - Python: requirements.txt, pyproject.toml, setup.py
    """

    # Languages that require compilation for CodeQL
    COMPILED_LANGUAGES = {"go", "java", "cpp", "csharp", "swift", "kotlin"}

    # Languages that don't require compilation
    INTERPRETED_LANGUAGES = {"python", "javascript", "typescript", "ruby", "php"}

    def __init__(self):
        """Initialize the build system detector."""
        pass

    def detect(self, source_path: Path, language: str | None = None) -> BuildConfig:
        """Detect the build system for a project.

        Args:
            source_path: Path to the source code.
            language: Programming language (auto-detected if not specified).

        Returns:
            BuildConfig with detected build system and commands.
        """
        # Auto-detect language if not specified
        if not language:
            language = self._detect_language(source_path)

        # Detect based on language
        if language == "go":
            return self._detect_go_build(source_path)
        elif language in ("java", "kotlin"):
            return self._detect_java_build(source_path)
        elif language in ("javascript", "typescript"):
            return self._detect_nodejs_build(source_path)
        elif language == "python":
            return self._detect_python_build(source_path)
        elif language in ("cpp", "c"):
            return self._detect_cpp_build(source_path)
        else:
            return BuildConfig(
                build_system=BuildSystem.UNKNOWN,
                language=language,
                requires_build=language in self.COMPILED_LANGUAGES,
            )

    def _detect_language(self, source_path: Path) -> str:
        """Detect the primary language of a project."""
        extensions = {
            ".go": "go",
            ".java": "java",
            ".kt": "kotlin",
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".cpp": "cpp",
            ".c": "c",
            ".rb": "ruby",
            ".php": "php",
        }

        counts: dict[str, int] = {}
        for ext, lang in extensions.items():
            files = list(source_path.rglob(f"*{ext}"))
            if files:
                counts[lang] = counts.get(lang, 0) + len(files)

        if not counts:
            return "unknown"

        return max(counts, key=counts.get)

    def _detect_go_build(self, source_path: Path) -> BuildConfig:
        """Detect Go build system."""
        detected_files = []

        # Check for go.work (multi-module workspace)
        go_work = source_path / "go.work"
        if go_work.exists():
            detected_files.append("go.work")

        # Check for go.mod
        go_mod = source_path / "go.mod"
        if go_mod.exists():
            detected_files.append("go.mod")

        # Check for Makefile
        makefile = source_path / "Makefile"
        has_makefile = makefile.exists()
        if has_makefile:
            detected_files.append("Makefile")

        # Determine build system and commands
        if has_makefile:
            # Check if Makefile has build target
            build_command = self._get_makefile_build_command(makefile)
            if build_command:
                return BuildConfig(
                    build_system=BuildSystem.GO_MAKEFILE,
                    language="go",
                    build_command=build_command,
                    dependency_command="go mod download" if go_mod.exists() else None,
                    requires_build=True,
                    detected_files=detected_files,
                )

        if go_work.exists():
            return BuildConfig(
                build_system=BuildSystem.GO_WORK,
                language="go",
                build_command="go build ./...",
                dependency_command="go mod download",
                requires_build=True,
                detected_files=detected_files,
            )

        if go_mod.exists():
            # Parse go.mod to get module name and Go version
            go_version = self._parse_go_version(go_mod)

            return BuildConfig(
                build_system=BuildSystem.GO_MODULES,
                language="go",
                build_command="go build ./...",
                dependency_command="go mod download",
                env_vars={"GOPROXY": "https://proxy.golang.org,direct"},
                requires_build=True,
                detected_files=detected_files,
            )

        # No build system detected, try basic go build
        return BuildConfig(
            build_system=BuildSystem.NONE,
            language="go",
            build_command="go build ./...",
            requires_build=True,
            detected_files=detected_files,
        )

    def _detect_java_build(self, source_path: Path) -> BuildConfig:
        """Detect Java/Kotlin build system."""
        detected_files = []

        # Check for Gradle wrapper
        gradlew = source_path / "gradlew"
        if gradlew.exists():
            detected_files.append("gradlew")
            return BuildConfig(
                build_system=BuildSystem.GRADLEW,
                language="java",
                build_command="./gradlew build -x test",
                dependency_command="./gradlew dependencies",
                requires_build=True,
                detected_files=detected_files,
            )

        # Check for Gradle
        gradle_build = source_path / "build.gradle"
        gradle_build_kts = source_path / "build.gradle.kts"
        if gradle_build.exists() or gradle_build_kts.exists():
            detected_files.append("build.gradle" if gradle_build.exists() else "build.gradle.kts")
            return BuildConfig(
                build_system=BuildSystem.GRADLE,
                language="java",
                build_command="gradle build -x test",
                dependency_command="gradle dependencies",
                requires_build=True,
                detected_files=detected_files,
            )

        # Check for Maven
        pom_xml = source_path / "pom.xml"
        if pom_xml.exists():
            detected_files.append("pom.xml")
            return BuildConfig(
                build_system=BuildSystem.MAVEN,
                language="java",
                build_command="mvn compile -DskipTests",
                dependency_command="mvn dependency:resolve",
                env_vars={"MAVEN_OPTS": "-Xmx2g"},
                requires_build=True,
                detected_files=detected_files,
            )

        return BuildConfig(
            build_system=BuildSystem.NONE,
            language="java",
            build_command="javac $(find . -name '*.java')",
            requires_build=True,
            detected_files=detected_files,
        )

    def _detect_nodejs_build(self, source_path: Path) -> BuildConfig:
        """Detect Node.js build system."""
        detected_files = []

        package_json = source_path / "package.json"
        if not package_json.exists():
            return BuildConfig(
                build_system=BuildSystem.NONE,
                language="javascript",
                requires_build=False,
                detected_files=detected_files,
            )

        detected_files.append("package.json")

        # Check for lock files to determine package manager
        yarn_lock = source_path / "yarn.lock"
        pnpm_lock = source_path / "pnpm-lock.yaml"
        package_lock = source_path / "package-lock.json"

        # Check if package.json has build script
        has_build_script = self._has_build_script(package_json)

        if yarn_lock.exists():
            detected_files.append("yarn.lock")
            return BuildConfig(
                build_system=BuildSystem.YARN,
                language="javascript",
                build_command="yarn build" if has_build_script else None,
                dependency_command="yarn install",
                requires_build=False,
                detected_files=detected_files,
            )

        if pnpm_lock.exists():
            detected_files.append("pnpm-lock.yaml")
            return BuildConfig(
                build_system=BuildSystem.PNPM,
                language="javascript",
                build_command="pnpm build" if has_build_script else None,
                dependency_command="pnpm install",
                requires_build=False,
                detected_files=detected_files,
            )

        # Default to npm
        if package_lock.exists():
            detected_files.append("package-lock.json")

        return BuildConfig(
            build_system=BuildSystem.NPM,
            language="javascript",
            build_command="npm run build" if has_build_script else None,
            dependency_command="npm install",
            requires_build=False,
            detected_files=detected_files,
        )

    def _detect_python_build(self, source_path: Path) -> BuildConfig:
        """Detect Python build system."""
        detected_files = []

        # Python doesn't require compilation for CodeQL
        # But we may need to install dependencies

        pyproject = source_path / "pyproject.toml"
        requirements = source_path / "requirements.txt"
        setup_py = source_path / "setup.py"

        if pyproject.exists():
            detected_files.append("pyproject.toml")
            # Check if it's a Poetry project
            if self._is_poetry_project(pyproject):
                return BuildConfig(
                    build_system=BuildSystem.POETRY,
                    language="python",
                    dependency_command="poetry install",
                    requires_build=False,
                    detected_files=detected_files,
                )

        if requirements.exists():
            detected_files.append("requirements.txt")

        if setup_py.exists():
            detected_files.append("setup.py")

        return BuildConfig(
            build_system=BuildSystem.PIP if requirements.exists() else BuildSystem.NONE,
            language="python",
            dependency_command="pip install -r requirements.txt" if requirements.exists() else None,
            requires_build=False,
            detected_files=detected_files,
        )

    def _detect_cpp_build(self, source_path: Path) -> BuildConfig:
        """Detect C/C++ build system."""
        detected_files = []

        # Check for Makefile
        makefile = source_path / "Makefile"
        if makefile.exists():
            detected_files.append("Makefile")
            build_command = self._get_makefile_build_command(makefile)
            return BuildConfig(
                build_system=BuildSystem.MAKEFILE,
                language="cpp",
                build_command=build_command or "make",
                requires_build=True,
                detected_files=detected_files,
            )

        # Check for CMake
        cmake_lists = source_path / "CMakeLists.txt"
        if cmake_lists.exists():
            detected_files.append("CMakeLists.txt")
            return BuildConfig(
                build_system=BuildSystem.MAKEFILE,  # Use MAKEFILE as generic
                language="cpp",
                build_command="cmake -B build && cmake --build build",
                requires_build=True,
                detected_files=detected_files,
            )

        return BuildConfig(
            build_system=BuildSystem.NONE,
            language="cpp",
            requires_build=True,
            detected_files=detected_files,
        )

    def _get_makefile_build_command(self, makefile: Path) -> str | None:
        """Extract build command from Makefile."""
        try:
            content = makefile.read_text()
            # Check for common build targets
            targets = ["build", "all", "compile", "bin"]
            for target in targets:
                if re.search(rf"^{target}:", content, re.MULTILINE):
                    return f"make {target}"
            return "make"
        except Exception:
            return "make"

    def _parse_go_version(self, go_mod: Path) -> str | None:
        """Parse Go version from go.mod."""
        try:
            content = go_mod.read_text()
            match = re.search(r"^go\s+(\d+\.\d+)", content, re.MULTILINE)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None

    def _has_build_script(self, package_json: Path) -> bool:
        """Check if package.json has a build script."""
        try:
            import json
            content = json.loads(package_json.read_text())
            scripts = content.get("scripts", {})
            return "build" in scripts
        except Exception:
            return False

    def _is_poetry_project(self, pyproject: Path) -> bool:
        """Check if pyproject.toml is a Poetry project."""
        try:
            content = pyproject.read_text()
            return "[tool.poetry]" in content
        except Exception:
            return False


import re


def detect_build_system(source_path: Path, language: str | None = None) -> BuildConfig:
    """Convenience function to detect build system.

    Args:
        source_path: Path to the source code.
        language: Programming language (auto-detected if not specified).

    Returns:
        BuildConfig with detected build system and commands.
    """
    detector = BuildSystemDetector()
    return detector.detect(source_path, language)
