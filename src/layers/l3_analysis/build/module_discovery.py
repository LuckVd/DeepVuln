"""
Module Discovery for repository structure analysis.

Identifies monorepo patterns, module boundaries, and extracts module-level
information for CodeQL scanning optimization.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.build.detector import BuildSystemDetector
from src.layers.l3_analysis.decision.models import ModuleSummary

logger = get_logger(__name__)


class MonorepoType(str, Enum):
    """Types of monorepo structures."""

    GO_WORKSPACE = "go_workspace"
    MAVEN_MULTI_MODULE = "maven_multi_module"
    GRADLE_MULTI_PROJECT = "gradle_multi_project"
    PNPM_WORKSPACES = "pnpm_workspaces"
    LERNA = "lerna"
    DIRECTORY_CONVENTION = "directory_convention"
    NONE = "none"


@dataclass
class MonorepoInfo:
    """Information about monorepo structure."""

    is_monorepo: bool = False
    monorepo_type: MonorepoType = MonorepoType.NONE
    root_path: Path | None = None
    module_paths: list[Path] = field(default_factory=list)
    config_file: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_monorepo": self.is_monorepo,
            "monorepo_type": self.monorepo_type.value,
            "root_path": str(self.root_path) if self.root_path else None,
            "module_paths": [str(p) for p in self.module_paths],
            "config_file": self.config_file,
        }


# Directory patterns that suggest monorepo structure
MONOREPO_DIR_PATTERNS = [
    "packages",
    "apps",
    "services",
    "libs",
    "modules",
    "projects",
]

# Language detection by file extension
LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".c": "c",
    ".h": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".scala": "scala",
}


class ModuleDiscovery:
    """
    Discovers module structure in a repository.

    Supports detection of:
    - Go workspace (go.work)
    - Maven multi-module (parent pom.xml with modules)
    - Gradle multi-project (settings.gradle with include)
    - pnpm workspaces (pnpm-workspace.yaml)
    - Lerna (lerna.json)
    - Directory conventions (packages/, apps/, services/)
    """

    # Maximum depth to scan for modules
    MAX_SCAN_DEPTH = 3

    # Minimum files to consider a directory as a module
    MIN_MODULE_FILES = 3

    def __init__(self, repo_path: Path):
        """
        Initialize the module discovery.

        Args:
            repo_path: Root path of the repository.
        """
        self.repo_path = Path(repo_path)
        self._build_detector = BuildSystemDetector()
        self._cache: dict[str, Any] = {}

    def discover(self) -> list[ModuleSummary]:
        """
        Discover all modules in the repository.

        Returns:
            List of ModuleSummary for each detected module.
        """
        # Check cache
        cache_key = "modules"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Detect monorepo structure
        monorepo_info = self._detect_monorepo()

        if monorepo_info.is_monorepo and monorepo_info.module_paths:
            modules = self._analyze_modules(monorepo_info.module_paths)
        else:
            # Single project - return root as the only module
            modules = [self._analyze_single_module(self.repo_path)]

        self._cache[cache_key] = modules
        return modules

    def get_monorepo_info(self) -> MonorepoInfo:
        """
        Get monorepo detection info.

        Returns:
            MonorepoInfo with detection results.
        """
        return self._detect_monorepo()

    def _detect_monorepo(self) -> MonorepoInfo:
        """Detect if the repository is a monorepo."""
        # Check cache
        cache_key = "monorepo"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Try each monorepo type in order of specificity
        detectors = [
            self._detect_go_workspace,
            self._detect_maven_multi_module,
            self._detect_gradle_multi_project,
            self._detect_pnpm_workspaces,
            self._detect_lerna,
            self._detect_directory_convention,
        ]

        for detector in detectors:
            info = detector()
            if info.is_monorepo:
                self._cache[cache_key] = info
                return info

        # Not a monorepo
        info = MonorepoInfo(
            is_monorepo=False,
            monorepo_type=MonorepoType.NONE,
            root_path=self.repo_path,
        )
        self._cache[cache_key] = info
        return info

    def _detect_go_workspace(self) -> MonorepoInfo:
        """Detect Go workspace (go.work)."""
        go_work = self.repo_path / "go.work"
        if not go_work.exists():
            return MonorepoInfo(is_monorepo=False)

        try:
            content = go_work.read_text()
            # Parse use directives
            module_paths = []
            for match in re.finditer(r"use\s+\(([^)]+)\)", content, re.MULTILINE):
                uses = match.group(1)
                for line in uses.strip().split("\n"):
                    line = line.strip().strip('"').strip("'")
                    if line:
                        module_path = self.repo_path / line
                        if module_path.exists():
                            module_paths.append(module_path)

            # Also check for single-line use directives
            for match in re.finditer(r"use\s+(\S+)", content, re.MULTILINE):
                if "(" not in match.group(0):  # Skip already parsed multi-line
                    line = match.group(1).strip().strip('"').strip("'")
                    module_path = self.repo_path / line
                    if module_path.exists():
                        module_paths.append(module_path)

            if len(module_paths) > 1:
                return MonorepoInfo(
                    is_monorepo=True,
                    monorepo_type=MonorepoType.GO_WORKSPACE,
                    root_path=self.repo_path,
                    module_paths=module_paths,
                    config_file="go.work",
                )
        except Exception as e:
            logger.warning(f"Failed to parse go.work: {e}")

        return MonorepoInfo(is_monorepo=False)

    def _detect_maven_multi_module(self) -> MonorepoInfo:
        """Detect Maven multi-module project."""
        root_pom = self.repo_path / "pom.xml"
        if not root_pom.exists():
            return MonorepoInfo(is_monorepo=False)

        try:
            content = root_pom.read_text()
            # Check for packaging pom (parent pom)
            if "<packaging>pom</packaging>" not in content:
                return MonorepoInfo(is_monorepo=False)

            # Parse modules
            module_paths = []
            module_match = re.search(r"<modules>(.*?)</modules>", content, re.DOTALL)
            if module_match:
                modules_content = module_match.group(1)
                for match in re.finditer(r"<module>([^<]+)</module>", modules_content):
                    module_name = match.group(1).strip()
                    module_path = self.repo_path / module_name
                    if module_path.exists():
                        module_paths.append(module_path)

            if len(module_paths) > 1:
                return MonorepoInfo(
                    is_monorepo=True,
                    monorepo_type=MonorepoType.MAVEN_MULTI_MODULE,
                    root_path=self.repo_path,
                    module_paths=module_paths,
                    config_file="pom.xml",
                )
        except Exception as e:
            logger.warning(f"Failed to parse pom.xml: {e}")

        return MonorepoInfo(is_monorepo=False)

    def _detect_gradle_multi_project(self) -> MonorepoInfo:
        """Detect Gradle multi-project."""
        settings_gradle = self.repo_path / "settings.gradle"
        settings_gradle_kts = self.repo_path / "settings.gradle.kts"

        settings_file = None
        content = None

        if settings_gradle.exists():
            settings_file = settings_gradle
            content = settings_gradle.read_text()
        elif settings_gradle_kts.exists():
            settings_file = settings_gradle_kts
            content = settings_gradle_kts.read_text()
        else:
            return MonorepoInfo(is_monorepo=False)

        try:
            # Parse include directives
            module_paths = []

            # Match include 'module' or include(":module")
            for match in re.finditer(r"include\s*[\"']([^\"']+)[\"']", content):
                module_name = match.group(1).strip().replace(":", "/")
                if module_name:
                    module_path = self.repo_path / module_name
                    if module_path.exists():
                        module_paths.append(module_path)

            # Also check for includeBuild
            for match in re.finditer(r"includeBuild\s*[\"']([^\"']+)[\"']", content):
                module_name = match.group(1).strip()
                if module_name:
                    module_path = self.repo_path / module_name
                    if module_path.exists():
                        module_paths.append(module_path)

            if len(module_paths) > 1:
                return MonorepoInfo(
                    is_monorepo=True,
                    monorepo_type=MonorepoType.GRADLE_MULTI_PROJECT,
                    root_path=self.repo_path,
                    module_paths=module_paths,
                    config_file=settings_file.name,
                )
        except Exception as e:
            logger.warning(f"Failed to parse settings.gradle: {e}")

        return MonorepoInfo(is_monorepo=False)

    def _detect_pnpm_workspaces(self) -> MonorepoInfo:
        """Detect pnpm workspaces."""
        workspace_yaml = self.repo_path / "pnpm-workspace.yaml"
        if not workspace_yaml.exists():
            return MonorepoInfo(is_monorepo=False)

        try:
            content = yaml.safe_load(workspace_yaml.read_text())
            packages = content.get("packages", [])

            module_paths = []
            for pattern in packages:
                # Handle glob patterns like "packages/*"
                if "*" in pattern:
                    base_dir = self.repo_path / pattern.split("*")[0].rstrip("/")
                    if base_dir.exists():
                        for child in base_dir.iterdir():
                            if child.is_dir() and (child / "package.json").exists():
                                module_paths.append(child)
                else:
                    module_path = self.repo_path / pattern
                    if module_path.exists():
                        module_paths.append(module_path)

            if len(module_paths) > 1:
                return MonorepoInfo(
                    is_monorepo=True,
                    monorepo_type=MonorepoType.PNPM_WORKSPACES,
                    root_path=self.repo_path,
                    module_paths=module_paths,
                    config_file="pnpm-workspace.yaml",
                )
        except Exception as e:
            logger.warning(f"Failed to parse pnpm-workspace.yaml: {e}")

        return MonorepoInfo(is_monorepo=False)

    def _detect_lerna(self) -> MonorepoInfo:
        """Detect Lerna monorepo."""
        lerna_json = self.repo_path / "lerna.json"
        if not lerna_json.exists():
            return MonorepoInfo(is_monorepo=False)

        try:
            content = yaml.safe_load(lerna_json.read_text())
            packages = content.get("packages", [])

            module_paths = []
            for pattern in packages:
                if "*" in pattern:
                    base_dir = self.repo_path / pattern.split("*")[0].rstrip("/")
                    if base_dir.exists():
                        for child in base_dir.iterdir():
                            if child.is_dir() and (child / "package.json").exists():
                                module_paths.append(child)
                else:
                    module_path = self.repo_path / pattern
                    if module_path.exists():
                        module_paths.append(module_path)

            if len(module_paths) > 1:
                return MonorepoInfo(
                    is_monorepo=True,
                    monorepo_type=MonorepoType.LERNA,
                    root_path=self.repo_path,
                    module_paths=module_paths,
                    config_file="lerna.json",
                )
        except Exception as e:
            logger.warning(f"Failed to parse lerna.json: {e}")

        return MonorepoInfo(is_monorepo=False)

    def _detect_directory_convention(self) -> MonorepoInfo:
        """Detect monorepo by directory convention."""
        module_paths = []

        for pattern in MONOREPO_DIR_PATTERNS:
            dir_path = self.repo_path / pattern
            if dir_path.exists() and dir_path.is_dir():
                # Check for subdirectories with project files
                for child in dir_path.iterdir():
                    if child.is_dir() and self._is_project_directory(child):
                        module_paths.append(child)

        if len(module_paths) > 1:
            return MonorepoInfo(
                is_monorepo=True,
                monorepo_type=MonorepoType.DIRECTORY_CONVENTION,
                root_path=self.repo_path,
                module_paths=module_paths,
                config_file=f"{module_paths[0].parent.name}/",
            )

        return MonorepoInfo(is_monorepo=False)

    def _is_project_directory(self, path: Path) -> bool:
        """Check if a directory is a project/module."""
        project_files = [
            "package.json",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "go.mod",
            "Cargo.toml",
            "pyproject.toml",
            "setup.py",
            "requirements.txt",
        ]

        for pf in project_files:
            if (path / pf).exists():
                return True

        # Check for source files
        source_count = 0
        for ext in LANGUAGE_EXTENSIONS:
            files = list(path.rglob(f"*{ext}"))
            source_count += len(files)
            if source_count >= self.MIN_MODULE_FILES:
                return True

        return False

    def _analyze_modules(self, module_paths: list[Path]) -> list[ModuleSummary]:
        """Analyze multiple modules."""
        modules = []
        for path in module_paths:
            summary = self._analyze_single_module(path)
            modules.append(summary)
        return modules

    def _analyze_single_module(self, module_path: Path) -> ModuleSummary:
        """Analyze a single module."""
        # Get relative path
        try:
            rel_path = module_path.relative_to(self.repo_path)
        except ValueError:
            rel_path = module_path

        # Detect languages
        languages = self._detect_languages(module_path)
        primary_language = self._get_primary_language(languages)

        # Detect build signals
        build_signals = self._detect_build_signals(module_path)

        # Estimate LOC
        loc_estimate = self._estimate_loc(module_path)

        return ModuleSummary(
            name=module_path.name,
            path=str(rel_path),
            primary_language=primary_language,
            languages=list(languages.keys()),
            build_signals=build_signals,
            loc_estimate=loc_estimate,
        )

    def _detect_languages(self, path: Path) -> dict[str, int]:
        """Detect languages in a module by file extension."""
        languages: dict[str, int] = {}

        # Scan up to MAX_SCAN_DEPTH
        for ext, lang in LANGUAGE_EXTENSIONS.items():
            count = 0
            for file_path in path.rglob(f"*{ext}"):
                # Skip common non-source directories
                if any(p in file_path.parts for p in ["node_modules", "vendor", "target", "build", "dist", ".git"]):
                    continue
                count += 1

            if count > 0:
                languages[lang] = count

        return languages

    def _get_primary_language(self, languages: dict[str, int]) -> str:
        """Get the primary language by file count."""
        if not languages:
            return "unknown"
        return max(languages, key=languages.get)

    def _detect_build_signals(self, path: Path) -> list[str]:
        """Detect build configuration files."""
        signals = []

        build_files = [
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "go.mod",
            "go.sum",
            "package.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Cargo.toml",
            "pyproject.toml",
            "setup.py",
            "requirements.txt",
            "Makefile",
            "CMakeLists.txt",
            "compile_commands.json",
        ]

        for bf in build_files:
            if (path / bf).exists():
                signals.append(bf)

        return signals

    def _estimate_loc(self, path: Path) -> int:
        """Estimate lines of code in a module."""
        total_loc = 0

        for ext in LANGUAGE_EXTENSIONS:
            for file_path in path.rglob(f"*{ext}"):
                # Skip common non-source directories
                if any(p in file_path.parts for p in ["node_modules", "vendor", "target", "build", "dist", ".git"]):
                    continue

                try:
                    # Quick estimate: count lines
                    with open(file_path, "r", errors="ignore") as f:
                        total_loc += sum(1 for _ in f)
                except Exception:
                    pass

                # Limit scanning for performance
                if total_loc > 100000:
                    break

        return total_loc


def discover_modules(repo_path: Path) -> list[ModuleSummary]:
    """
    Convenience function to discover modules.

    Args:
        repo_path: Root path of the repository.

    Returns:
        List of ModuleSummary for each detected module.
    """
    discovery = ModuleDiscovery(repo_path)
    return discovery.discover()
