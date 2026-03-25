"""
Build Target Extractor for CodeQL scanning optimization.

Extracts buildable units, identifies entry points, and generates
build recommendations for CodeQL database creation.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.build.detector import BuildConfig, BuildSystem, BuildSystemDetector
from src.layers.l3_analysis.decision.models import ModuleSummary

logger = get_logger(__name__)


class BuildStrategy(str, Enum):
    """Build strategy for CodeQL."""

    FULL = "full"              # Full build required
    INCREMENTAL = "incremental"  # Incremental build possible
    NONE = "none"              # No build required (interpreted languages)
    SKIP = "skip"              # Skip build (not feasible)


class EntryPointType(str, Enum):
    """Types of entry points."""

    MAIN = "main"        # Main entry point
    APP = "app"          # Application entry
    SERVER = "server"    # Server entry
    CLI = "cli"          # CLI entry
    LIBRARY = "library"  # Library (no direct entry)


@dataclass
class BuildTarget:
    """A buildable unit within a module."""

    name: str
    path: Path
    language: str
    build_system: BuildSystem
    build_command: str | None = None
    priority: int = 10  # 1 = highest priority
    is_entry_point: bool = False
    estimated_time_seconds: int = 60
    dependencies: list[str] = field(default_factory=list)
    source_dirs: list[Path] = field(default_factory=list)
    has_tests: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "language": self.language,
            "build_system": self.build_system.value,
            "build_command": self.build_command,
            "priority": self.priority,
            "is_entry_point": self.is_entry_point,
            "estimated_time_seconds": self.estimated_time_seconds,
            "dependencies": self.dependencies,
            "source_dirs": [str(d) for d in self.source_dirs],
            "has_tests": self.has_tests,
        }


@dataclass
class EntryPoint:
    """An entry point in the codebase."""

    name: str
    path: Path
    language: str
    entry_type: EntryPointType
    is_primary: bool = False
    line_number: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "language": self.language,
            "entry_type": self.entry_type.value,
            "is_primary": self.is_primary,
            "line_number": self.line_number,
        }


@dataclass
class BuildRecommendation:
    """Build recommendation for a module."""

    module_name: str
    module_path: Path
    targets: list[BuildTarget] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    recommended_order: list[str] = field(default_factory=list)
    build_strategy: BuildStrategy = BuildStrategy.NONE
    estimated_total_time: int = 0
    skip_reasons: dict[str, str] = field(default_factory=dict)
    primary_language: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "module_path": str(self.module_path),
            "targets": [t.to_dict() for t in self.targets],
            "entry_points": [e.to_dict() for e in self.entry_points],
            "recommended_order": self.recommended_order,
            "build_strategy": self.build_strategy.value,
            "estimated_total_time": self.estimated_total_time,
            "skip_reasons": self.skip_reasons,
            "primary_language": self.primary_language,
        }

    def get_primary_target(self) -> BuildTarget | None:
        """Get the primary (highest priority) build target."""
        if not self.targets:
            return None
        return min(self.targets, key=lambda t: t.priority)


class BuildTargetExtractor:
    """
    Extracts build targets from modules.

    Analyzes module structure to identify:
    - Buildable units (packages, modules, subprojects)
    - Entry points (main methods, main packages, CLI entry)
    - Optimal build strategy for CodeQL
    """

    # Languages that require compilation
    COMPILED_LANGUAGES = {"java", "go", "kotlin", "scala", "cpp", "c", "csharp", "swift", "rust"}

    # Languages that don't require compilation
    INTERPRETED_LANGUAGES = {"python", "javascript", "typescript", "ruby", "php"}

    def __init__(self, repo_path: Path):
        """
        Initialize the extractor.

        Args:
            repo_path: Root path of the repository.
        """
        self.repo_path = Path(repo_path)
        self._build_detector = BuildSystemDetector()

    def extract(self, module: ModuleSummary) -> BuildRecommendation:
        """
        Extract build targets from a module.

        Args:
            module: Module summary from ModuleDiscovery.

        Returns:
            BuildRecommendation with targets and entry points.
        """
        module_path = self.repo_path / module.path if module.path != "." else self.repo_path

        # Detect build system
        build_config = self._build_detector.detect(module_path, module.primary_language)

        # Extract targets based on language
        if module.primary_language == "java" or module.primary_language == "kotlin":
            targets = self._extract_java_targets(module_path, build_config)
            entry_points = self._detect_java_entry_points(module_path)
        elif module.primary_language == "go":
            targets = self._extract_go_targets(module_path, build_config)
            entry_points = self._detect_go_entry_points(module_path)
        elif module.primary_language in ("javascript", "typescript"):
            targets = self._extract_nodejs_targets(module_path, build_config)
            entry_points = self._detect_nodejs_entry_points(module_path)
        elif module.primary_language == "python":
            targets = self._extract_python_targets(module_path, build_config)
            entry_points = self._detect_python_entry_points(module_path)
        else:
            # Generic handling
            targets = [self._create_generic_target(module_path, build_config, module.primary_language)]
            entry_points = []

        # Determine build strategy
        build_strategy = self._determine_build_strategy(module.primary_language, build_config)

        # Calculate total time
        estimated_time = sum(t.estimated_time_seconds for t in targets)

        # Sort targets by priority
        targets.sort(key=lambda t: t.priority)
        recommended_order = [t.name for t in targets]

        return BuildRecommendation(
            module_name=module.name,
            module_path=module_path,
            targets=targets,
            entry_points=entry_points,
            recommended_order=recommended_order,
            build_strategy=build_strategy,
            estimated_total_time=estimated_time,
            primary_language=module.primary_language,
        )

    def extract_all(self, modules: list[ModuleSummary]) -> list[BuildRecommendation]:
        """
        Extract build targets from all modules.

        Args:
            modules: List of module summaries.

        Returns:
            List of BuildRecommendation for each module.
        """
        return [self.extract(module) for module in modules]

    # =========================================================================
    # Java Target Extraction
    # =========================================================================

    def _extract_java_targets(self, module_path: Path, build_config: BuildConfig) -> list[BuildTarget]:
        """Extract Java build targets."""
        targets = []

        if build_config.build_system == BuildSystem.MAVEN:
            targets.extend(self._extract_maven_targets(module_path, build_config))
        elif build_config.build_system in (BuildSystem.GRADLE, BuildSystem.GRADLEW):
            targets.extend(self._extract_gradle_targets(module_path, build_config))
        else:
            # Generic Java target
            targets.append(self._create_generic_target(module_path, build_config, "java"))

        return targets

    def _extract_maven_targets(self, module_path: Path, build_config: BuildConfig) -> list[BuildTarget]:
        """Extract Maven module targets."""
        targets = []
        pom_file = module_path / "pom.xml"

        if not pom_file.exists():
            return targets

        try:
            content = pom_file.read_text()

            # Check if this is a multi-module project
            if "<packaging>pom</packaging>" in content:
                # Parent POM - extract submodules
                module_match = re.search(r"<modules>(.*?)</modules>", content, re.DOTALL)
                if module_match:
                    for match in re.finditer(r"<module>([^<]+)</module>", module_match.group(1)):
                        submodule = match.group(1).strip()
                        submodule_path = module_path / submodule
                        if submodule_path.exists():
                            targets.append(BuildTarget(
                                name=submodule,
                                path=submodule_path,
                                language="java",
                                build_system=BuildSystem.MAVEN,
                                build_command=f"mvn compile -pl {submodule} -am",
                                priority=5,
                                source_dirs=[submodule_path / "src" / "main" / "java"],
                                estimated_time_seconds=120,
                            ))
            else:
                # Single module
                artifact_id = self._extract_maven_artifact_id(content)
                targets.append(BuildTarget(
                    name=artifact_id or "main",
                    path=module_path,
                    language="java",
                    build_system=BuildSystem.MAVEN,
                    build_command=build_config.build_command or "mvn compile -DskipTests",
                    priority=1,
                    source_dirs=[module_path / "src" / "main" / "java"],
                    estimated_time_seconds=180,
                ))

        except Exception as e:
            logger.warning(f"Failed to parse pom.xml: {e}")

        return targets

    def _extract_maven_artifact_id(self, content: str) -> str | None:
        """Extract artifact ID from pom.xml content."""
        match = re.search(r"<artifactId>([^<]+)</artifactId>", content)
        return match.group(1) if match else None

    def _extract_gradle_targets(self, module_path: Path, build_config: BuildConfig) -> list[BuildTarget]:
        """Extract Gradle subproject targets."""
        targets = []

        # Check settings.gradle for subprojects
        settings_file = None
        for sf in ["settings.gradle", "settings.gradle.kts"]:
            if (module_path / sf).exists():
                settings_file = module_path / sf
                break

        if settings_file:
            try:
                content = settings_file.read_text()
                # Parse include directives
                for match in re.finditer(r"include\s*[\"']([^\"']+)[\"']", content):
                    project_name = match.group(1).strip().replace(":", "")
                    project_path = module_path / project_name
                    if project_path.exists():
                        targets.append(BuildTarget(
                            name=project_name,
                            path=project_path,
                            language="java",
                            build_system=build_config.build_system,
                            build_command=f"./gradlew :{project_name}:compileJava",
                            priority=5,
                            source_dirs=[project_path / "src" / "main" / "java"],
                            estimated_time_seconds=120,
                        ))
            except Exception as e:
                logger.warning(f"Failed to parse settings.gradle: {e}")

        # If no subprojects, create main target
        if not targets:
            targets.append(BuildTarget(
                name="main",
                path=module_path,
                language="java",
                build_system=build_config.build_system,
                build_command=build_config.build_command or "./gradlew compileJava",
                priority=1,
                source_dirs=[module_path / "src" / "main" / "java"],
                estimated_time_seconds=180,
            ))

        return targets

    def _detect_java_entry_points(self, module_path: Path) -> list[EntryPoint]:
        """Detect Java main classes."""
        entry_points = []

        # Skip patterns for test directories
        skip_patterns = ["src/test", "/test/", "\\test\\"]

        # Scan for main classes
        for java_file in module_path.rglob("*.java"):
            # Skip test directories
            file_str = str(java_file)
            if any(p in file_str for p in skip_patterns):
                continue

            try:
                content = java_file.read_text()
                # Look for main method
                if re.search(r"public\s+static\s+void\s+main\s*\(", content):
                    # Extract class name
                    class_match = re.search(r"public\s+class\s+(\w+)", content)
                    class_name = class_match.group(1) if class_match else java_file.stem

                    entry_points.append(EntryPoint(
                        name=class_name,
                        path=java_file,
                        language="java",
                        entry_type=EntryPointType.MAIN,
                        is_primary=len(entry_points) == 0,
                    ))
            except Exception:
                pass

        return entry_points[:10]  # Limit to 10 entry points

    # =========================================================================
    # Go Target Extraction
    # =========================================================================

    def _extract_go_targets(self, module_path: Path, build_config: BuildConfig) -> list[BuildTarget]:
        """Extract Go package targets."""
        targets = []

        # Look for main packages
        main_packages = self._find_go_main_packages(module_path)

        if main_packages:
            for pkg_path in main_packages:
                targets.append(BuildTarget(
                    name=pkg_path.name,
                    path=pkg_path,
                    language="go",
                    build_system=build_config.build_system,
                    build_command=f"go build {pkg_path.relative_to(module_path)}",
                    priority=1,
                    is_entry_point=True,
                    estimated_time_seconds=60,
                ))
        else:
            # No main packages - library module
            targets.append(BuildTarget(
                name="library",
                path=module_path,
                language="go",
                build_system=build_config.build_system,
                build_command="go build ./...",
                priority=5,
                is_entry_point=False,
                estimated_time_seconds=90,
            ))

        return targets

    def _find_go_main_packages(self, module_path: Path) -> list[Path]:
        """Find Go main packages."""
        main_packages = []

        for go_file in module_path.rglob("*.go"):
            # Skip vendor and test directories
            if "vendor" in str(go_file).split("/") or "_test.go" in go_file.name:
                continue

            try:
                content = go_file.read_text()
                if re.search(r"package\s+main", content) and re.search(r"func\s+main\s*\(", content):
                    main_packages.append(go_file.parent)
            except Exception:
                pass

        return list(set(main_packages))

    def _detect_go_entry_points(self, module_path: Path) -> list[EntryPoint]:
        """Detect Go main functions."""
        entry_points = []

        for go_file in module_path.rglob("*.go"):
            if "vendor" in str(go_file).split("/") or "_test.go" in go_file.name:
                continue

            try:
                content = go_file.read_text()
                if re.search(r"package\s+main", content) and re.search(r"func\s+main\s*\(", content):
                    entry_points.append(EntryPoint(
                        name=go_file.stem,
                        path=go_file,
                        language="go",
                        entry_type=EntryPointType.MAIN,
                        is_primary=len(entry_points) == 0,
                    ))
            except Exception:
                pass

        return entry_points[:10]

    # =========================================================================
    # Node.js Target Extraction
    # =========================================================================

    def _extract_nodejs_targets(self, module_path: Path, build_config: BuildConfig) -> list[BuildTarget]:
        """Extract Node.js package targets."""
        targets = []

        package_json = module_path / "package.json"
        if not package_json.exists():
            return [self._create_generic_target(module_path, build_config, "javascript")]

        try:
            content = json.loads(package_json.read_text())

            # Check for build script
            has_build = "build" in content.get("scripts", {})
            build_command = None
            if has_build:
                build_command = "npm run build" if build_config.build_system == BuildSystem.NPM else \
                               "yarn build" if build_config.build_system == BuildSystem.YARN else \
                               "pnpm build"

            name = content.get("name", module_path.name)
            targets.append(BuildTarget(
                name=name,
                path=module_path,
                language="javascript",
                build_system=build_config.build_system,
                build_command=build_command,
                priority=1,
                estimated_time_seconds=30 if not has_build else 60,
                has_tests="test" in content.get("scripts", {}),
            ))

        except Exception as e:
            logger.warning(f"Failed to parse package.json: {e}")

        return targets

    def _detect_nodejs_entry_points(self, module_path: Path) -> list[EntryPoint]:
        """Detect Node.js entry points."""
        entry_points = []
        package_json = module_path / "package.json"

        if not package_json.exists():
            return entry_points

        try:
            content = json.loads(package_json.read_text())

            # Main field
            main = content.get("main")
            if main:
                main_path = module_path / main
                if main_path.exists():
                    entry_points.append(EntryPoint(
                        name=main,
                        path=main_path,
                        language="javascript",
                        entry_type=EntryPointType.MAIN,
                        is_primary=True,
                    ))

            # Bin field (CLI tools)
            bin = content.get("bin")
            if bin:
                if isinstance(bin, str):
                    bin_path = module_path / bin
                    if bin_path.exists():
                        entry_points.append(EntryPoint(
                            name=bin,
                            path=bin_path,
                            language="javascript",
                            entry_type=EntryPointType.CLI,
                        ))
                elif isinstance(bin, dict):
                    for name, path in bin.items():
                        bin_path = module_path / path
                        if bin_path.exists():
                            entry_points.append(EntryPoint(
                                name=name,
                                path=bin_path,
                                language="javascript",
                                entry_type=EntryPointType.CLI,
                            ))

        except Exception as e:
            logger.warning(f"Failed to parse package.json for entry points: {e}")

        return entry_points

    # =========================================================================
    # Python Target Extraction
    # =========================================================================

    def _extract_python_targets(self, module_path: Path, build_config: BuildConfig) -> list[BuildTarget]:
        """Extract Python package targets."""
        # Python doesn't require compilation
        targets = []

        targets.append(BuildTarget(
            name=module_path.name,
            path=module_path,
            language="python",
            build_system=build_config.build_system,
            build_command=None,  # No build required
            priority=1,
            estimated_time_seconds=10,
        ))

        return targets

    def _detect_python_entry_points(self, module_path: Path) -> list[EntryPoint]:
        """Detect Python entry points."""
        entry_points = []

        # Skip patterns for test directories
        skip_patterns = ["tests/", "test/", "/tests/", "\\tests\\"]

        for py_file in module_path.rglob("*.py"):
            # Skip test directories
            file_str = str(py_file)
            if any(p in file_str for p in skip_patterns) or py_file.name.startswith("test_"):
                continue

            try:
                content = py_file.read_text()
                if 'if __name__ == "__main__"' in content or "if __name__ == '__main__'" in content:
                    entry_points.append(EntryPoint(
                        name=py_file.stem,
                        path=py_file,
                        language="python",
                        entry_type=EntryPointType.MAIN,
                        is_primary=len(entry_points) == 0,
                    ))
            except Exception:
                pass

        return entry_points[:10]

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _create_generic_target(
        self,
        module_path: Path,
        build_config: BuildConfig,
        language: str,
    ) -> BuildTarget:
        """Create a generic build target."""
        requires_build = language in self.COMPILED_LANGUAGES

        return BuildTarget(
            name=module_path.name,
            path=module_path,
            language=language,
            build_system=build_config.build_system,
            build_command=build_config.build_command,
            priority=10,
            estimated_time_seconds=120 if requires_build else 10,
        )

    def _determine_build_strategy(
        self,
        language: str,
        build_config: BuildConfig,
    ) -> BuildStrategy:
        """Determine the build strategy for CodeQL."""
        if language in self.INTERPRETED_LANGUAGES:
            return BuildStrategy.NONE

        if not build_config.build_command:
            if language in self.COMPILED_LANGUAGES:
                return BuildStrategy.SKIP
            return BuildStrategy.NONE

        return BuildStrategy.FULL


def extract_build_targets(
    repo_path: Path,
    modules: list[ModuleSummary],
) -> list[BuildRecommendation]:
    """
    Convenience function to extract build targets.

    Args:
        repo_path: Root path of the repository.
        modules: List of module summaries.

    Returns:
        List of BuildRecommendation for each module.
    """
    extractor = BuildTargetExtractor(repo_path)
    return extractor.extract_all(modules)
