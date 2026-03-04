"""
File Filtering Engine - Dynamic Scan Surface Control.

This module provides intelligent file filtering for Semgrep scans based on
TechStack and AttackSurface analysis. It generates include/exclude patterns
to ensure only relevant files are scanned.

Target: Markdown never scanned, irrelevant directories excluded, language precision.
"""

from dataclasses import dataclass, field
from typing import Any

from src.core.logger.logger import get_logger


# ============================================================================
# Constants
# ============================================================================

# Directories to ALWAYS exclude (permanent exclusions)
DEFAULT_EXCLUDE_DIRS = [
    # Version control
    ".git",
    ".svn",
    ".hg",
    ".bzr",
    # Dependencies
    "node_modules",
    "vendor",
    "third_party",
    "thirdparty",
    "external",
    # Python virtual environments
    ".venv",
    "venv",
    "env",
    ".env",
    # Build artifacts
    "__pycache__",
    "dist",
    "build",
    "target",
    "out",
    "bin",
    ".output",
    # IDE/Editor
    ".idea",
    ".vscode",
    ".sublime",
    ".eclipse",
    # Cache
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
    # Coverage
    "coverage",
    ".coverage",
    "htmlcov",
    # Other
    ".github",
    ".gitlab",
    "site-packages",
]

# File patterns to ALWAYS exclude
DEFAULT_EXCLUDE_PATTERNS = [
    # Documentation files (MUST NEVER be scanned)
    "*.md",
    "*.rst",
    "*.txt",
    "*.adoc",
    "*.asciidoc",
    # Config files (usually not security relevant)
    "*.json",
    "*.yaml",
    "*.yml",
    "*.toml",
    "*.ini",
    "*.cfg",
    "*.conf",
    # Lock files
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Cargo.lock",
    # Generated files
    "*.min.js",
    "*.min.css",
    "*.map",
    # Binary/data files
    "*.svg",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.eot",
    "*.pdf",
]

# Directories to exclude when no HTTP attack surface
NO_HTTP_EXCLUDE_DIRS = [
    "routes",
    "controllers",
    "api",
    "views",
    "handlers",
    "endpoints",
    "servlets",
]

# Directories to exclude for CLI projects
CLI_EXCLUDE_DIRS = [
    "templates",
    "static",
    "assets",
    "public",
    "views",
    "pages",
    "components",
]

# Test directories (excluded by default, with exceptions)
TEST_EXCLUDE_DIRS = [
    "test",
    "tests",
    "spec",
    "specs",
    "__tests__",
    "__test__",
    "testdata",
    "test_data",
    "testfiles",
    "test_files",
    "integration",
    "e2e",
    "fixtures",
]

# Documentation directories
DOC_EXCLUDE_DIRS = [
    "docs",
    "doc",
    "documentation",
    "wiki",
    "man",
    "examples",
    "samples",
    "demo",
]

# Language to Semgrep language flag mapping
LANGUAGE_TO_SEMGREP_LANG: dict[str, str] = {
    "python": "python",
    "javascript": "js",
    "typescript": "ts",
    "jsx": "js",
    "tsx": "ts",
    "java": "java",
    "go": "go",
    "rust": "rust",
    "php": "php",
    "ruby": "ruby",
    "csharp": "csharp",
    "cpp": "cpp",
    "c": "c",
    "kotlin": "kotlin",
    "swift": "swift",
    "scala": "scala",
    "lua": "lua",
    "perl": "perl",
}


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class FileFilteringResult:
    """
    Result of file filtering analysis.

    Contains all patterns and flags for Semgrep command construction.
    """

    # Include patterns (--include)
    include_patterns: list[str] = field(default_factory=list)

    # Exclude patterns (--exclude)
    exclude_patterns: list[str] = field(default_factory=list)

    # Exclude directories (--exclude-dir)
    exclude_dirs: list[str] = field(default_factory=list)

    # Language flags (--lang)
    lang_flags: list[str] = field(default_factory=list)

    # Metadata about filtering decisions
    filtering_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "include_patterns": self.include_patterns,
            "exclude_patterns": self.exclude_patterns,
            "exclude_dirs": self.exclude_dirs,
            "lang_flags": self.lang_flags,
            "filtering_reasons": self.filtering_reasons,
        }


# ============================================================================
# File Filtering Engine
# ============================================================================

class FileFilteringEngine:
    """
    File Filtering Engine for Semgrep scan surface control.

    Generates include/exclude patterns and language flags based on
    TechStack and AttackSurface analysis.

    Three-layer filtering:
    1. Directory level: Exclude irrelevant directories
    2. File type level: Exclude docs, configs, etc.
    3. Language level: Only scan project languages
    """

    def __init__(
        self,
        tech_stack: Any | None = None,
        attack_surface: Any | None = None,
    ):
        """
        Initialize the File Filtering Engine.

        Args:
            tech_stack: TechStack object with language and project info.
            attack_surface: AttackSurfaceReport with entry point info.
        """
        self.logger = get_logger(__name__)
        self.tech_stack = tech_stack
        self.attack_surface = attack_surface

    def build(self) -> FileFilteringResult:
        """
        Build file filtering configuration.

        Returns:
            FileFilteringResult with all filtering patterns and flags.
        """
        result = FileFilteringResult()

        # Step 1: Apply permanent exclusions (always applied)
        self._apply_permanent_exclusions(result)

        # Step 2: Apply language filtering
        self._apply_language_filtering(result)

        # Step 3: Apply project type filtering
        self._apply_project_type_filtering(result)

        # Step 4: Apply attack surface filtering
        self._apply_attack_surface_filtering(result)

        # Step 5: Apply test filtering
        self._apply_test_filtering(result)

        # Log summary
        self.logger.info(
            f"File filtering built: "
            f"exclude_dirs={len(result.exclude_dirs)}, "
            f"exclude_patterns={len(result.exclude_patterns)}, "
            f"lang_flags={result.lang_flags}"
        )

        return result

    def _apply_permanent_exclusions(self, result: FileFilteringResult) -> None:
        """Apply permanent directory and file exclusions."""
        # Add permanent directory exclusions
        result.exclude_dirs.extend(DEFAULT_EXCLUDE_DIRS)

        # Add permanent file pattern exclusions
        result.exclude_patterns.extend(DEFAULT_EXCLUDE_PATTERNS)

        # Add documentation directories
        result.exclude_dirs.extend(DOC_EXCLUDE_DIRS)

        result.filtering_reasons.append("Applied permanent exclusions")

    def _apply_language_filtering(self, result: FileFilteringResult) -> None:
        """Apply language-based filtering."""
        if not self.tech_stack:
            result.filtering_reasons.append("No tech_stack provided, skipping language filtering")
            return

        # Check if monorepo - don't restrict languages
        is_monorepo = getattr(self.tech_stack, "is_monorepo", False)

        if is_monorepo:
            result.filtering_reasons.append("Monorepo detected, not restricting languages")
            return

        # Get languages from tech_stack
        languages = self._get_project_languages()

        if not languages:
            result.filtering_reasons.append("No languages detected, skipping language filtering")
            return

        # Convert to Semgrep language flags
        lang_flags = set()
        for lang in languages:
            lang_lower = lang.lower() if isinstance(lang, str) else lang.value.lower()
            semgrep_lang = LANGUAGE_TO_SEMGREP_LANG.get(lang_lower)
            if semgrep_lang:
                lang_flags.add(semgrep_lang)

        result.lang_flags = sorted(list(lang_flags))
        result.filtering_reasons.append(
            f"Language filtering: {result.lang_flags}"
        )

    def _get_project_languages(self) -> list[str]:
        """Get list of project languages from TechStack."""
        languages = []

        if not self.tech_stack:
            return languages

        # Try primary_language first
        primary = getattr(self.tech_stack, "primary_language", None)
        if primary:
            if hasattr(primary, "value"):
                languages.append(primary.value)
            else:
                languages.append(str(primary))

        # Add secondary languages
        secondary = getattr(self.tech_stack, "secondary_languages", [])
        for lang in secondary:
            if hasattr(lang, "value"):
                languages.append(lang.value)
            else:
                languages.append(str(lang))

        # Fallback: get from languages list
        if not languages:
            lang_list = getattr(self.tech_stack, "languages", [])
            for lang_info in lang_list:
                if hasattr(lang_info, "language"):
                    lang = lang_info.language
                    if hasattr(lang, "value"):
                        languages.append(lang.value)
                    else:
                        languages.append(str(lang))

        return languages

    def _apply_project_type_filtering(self, result: FileFilteringResult) -> None:
        """Apply project type-based filtering."""
        if not self.tech_stack:
            return

        project_type = getattr(self.tech_stack, "project_type", None)
        if not project_type:
            return

        # Get project type value
        if hasattr(project_type, "value"):
            project_type = project_type.value

        # CLI projects: exclude web-related directories
        if project_type == "cli":
            result.exclude_dirs.extend(CLI_EXCLUDE_DIRS)
            result.filtering_reasons.append("CLI project: excluding web directories")

    def _apply_attack_surface_filtering(self, result: FileFilteringResult) -> None:
        """Apply attack surface-based filtering."""
        if not self.attack_surface:
            return

        # Check HTTP endpoints
        http_endpoints = getattr(self.attack_surface, "http_endpoints", 0)

        if http_endpoints == 0:
            result.exclude_dirs.extend(NO_HTTP_EXCLUDE_DIRS)
            result.filtering_reasons.append("No HTTP endpoints: excluding web directories")

    def _apply_test_filtering(self, result: FileFilteringResult) -> None:
        """Apply test directory filtering."""
        if not self.tech_stack:
            # Default: exclude tests
            result.exclude_dirs.extend(TEST_EXCLUDE_DIRS)
            result.filtering_reasons.append("Default: excluding test directories")
            return

        has_tests = getattr(self.tech_stack, "has_tests", False)
        project_type = getattr(self.tech_stack, "project_type", None)

        if hasattr(project_type, "value"):
            project_type = project_type.value

        # Exception: library projects with tests - include tests
        if has_tests and project_type == "library":
            result.filtering_reasons.append("Library with tests: including test directories")
            return

        # Default: exclude test directories
        result.exclude_dirs.extend(TEST_EXCLUDE_DIRS)
        result.filtering_reasons.append("Excluding test directories")


def create_file_filtering_engine(
    tech_stack: Any | None = None,
    attack_surface: Any | None = None,
) -> FileFilteringEngine:
    """
    Factory function to create a FileFilteringEngine instance.

    Args:
        tech_stack: TechStack object for language/project info.
        attack_surface: AttackSurfaceReport for entry point info.

    Returns:
        Configured FileFilteringEngine instance.
    """
    return FileFilteringEngine(
        tech_stack=tech_stack,
        attack_surface=attack_surface,
    )
