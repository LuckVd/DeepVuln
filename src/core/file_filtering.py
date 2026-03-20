"""
File Filtering Engine - Dynamic Scan Surface Control.

This module provides intelligent file filtering for Semgrep scans based on
TechStack and AttackSurface analysis. It generates include/exclude patterns
to ensure only relevant files are scanned.

Target: Markdown never scanned, irrelevant directories excluded, language precision.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
import re

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
# P6-07: Directory Classification for Non-Production Code Downgrading
# =============================================================================

class DirectoryClass(str, Enum):
    """
    P6-07a: Directory classification for code categorization.

    Used for non-production code downgrading to reduce noise in reports.
    Each class has a corresponding score_multiplier that reduces the
    final score of findings in that directory.
    """

    PRODUCTION = "production_code"
    """生产代码 - 正常评分，score_multiplier = 1.0"""

    TEST = "test_code"
    """测试代码 - 降权 0.3（单元测试、集成测试、E2E测试）"""

    SAMPLE = "sample_code"
    """示例/演示代码 - 降权 0.1（examples、demos、samples）"""

    FIXTURE = "fixture_code"
    """测试夹具代码 - 降权 0.2（测试数据、mock数据）"""

    CHALLENGE = "challenge_code"
    """CTF/挑战代码 - 降权 0.1（vulnerable apps、CTF challenges）"""


# P6-07b: Directory classification rules - matched in priority order (highest first)
DIRECTORY_CLASSIFICATION_RULES: list[tuple[list[str], DirectoryClass]] = [
    # Challenge/CTF 代码（最高优先级，识别故意存在漏洞的代码）
    (
        [
            "challenges", "challenge", "ctf", "vulnerable", "vuln-apps",
            "juice-shop", "dvwa", "webgoat", "bwapp", "mutillidae",
            "vuln", "vulnerables", "deliberately-vulnerable",
        ],
        DirectoryClass.CHALLENGE,
    ),
    # 测试夹具代码（测试数据和 mock）
    (
        [
            "fixtures", "fixture", "testdata", "test_data", "testfiles",
            "test_files", "mocks", "mock", "stubs", "stub", "fake", "fakes",
            "factories", "factory", "__fixtures__",
        ],
        DirectoryClass.FIXTURE,
    ),
    # 示例/演示代码
    (
        [
            "examples", "example", "samples", "sample", "demo", "demos",
            "documentation-samples", "docs-samples", "tutorials", "tutorial",
        ],
        DirectoryClass.SAMPLE,
    ),
    # 测试代码（优先级较低，避免误匹配 challenge 下的 test）
    (
        [
            "tests", "test", "__tests__", "__test__", "spec", "specs",
            "__spec__", "integration", "e2e", "unit", "functional",
            "__mocks__", "testing",
        ],
        DirectoryClass.TEST,
    ),
]

# P6-07b: Filename pattern classification rules
FILENAME_CLASSIFICATION_RULES: list[tuple[str, DirectoryClass]] = [
    # Python test patterns
    (r"_test\.py$", DirectoryClass.TEST),
    (r"test_.*\.py$", DirectoryClass.TEST),
    (r"_spec\.py$", DirectoryClass.TEST),
    # JavaScript/TypeScript test patterns
    (r"\.test\.(js|ts|jsx|tsx)$", DirectoryClass.TEST),
    (r"\.spec\.(js|ts|jsx|tsx)$", DirectoryClass.TEST),
    (r".*_test\.(js|ts)$", DirectoryClass.TEST),
    # Go test patterns
    (r"_test\.go$", DirectoryClass.TEST),
    # Java test patterns
    (r"Test\.java$", DirectoryClass.TEST),
    (r"Tests\.java$", DirectoryClass.TEST),
    # Ruby test patterns
    (r"_test\.rb$", DirectoryClass.TEST),
    (r"_spec\.rb$", DirectoryClass.TEST),
    # Fixture patterns
    (r"fixture", DirectoryClass.FIXTURE),
    (r"\.fixture\.(py|js|ts|json|yaml|yml)$", DirectoryClass.FIXTURE),
    (r"mock.*\.(py|js|ts)$", DirectoryClass.FIXTURE),
    (r"stub.*\.(py|js|ts)$", DirectoryClass.FIXTURE),
]

# P6-07c: Score multipliers for directory classes
SCORE_MULTIPLIERS: dict[DirectoryClass, float] = {
    DirectoryClass.PRODUCTION: 1.0,   # 无降权
    DirectoryClass.TEST: 0.3,         # 降低 70%
    DirectoryClass.FIXTURE: 0.2,      # 降低 80%
    DirectoryClass.SAMPLE: 0.1,       # 降低 90%
    DirectoryClass.CHALLENGE: 0.1,    # 降低 90%
}


def classify_directory(
    file_path: str | Path,
    project_root: str | Path | None = None,
    *,
    custom_rules: dict[str, list[str]] | None = None,
) -> DirectoryClass:
    """
    P6-07b: Classify a file path into a directory class.

    Classification priority (highest to lowest):
    1. Custom rules (if provided)
    2. Challenge/CTF directories
    3. Fixture directories
    4. Sample/demo directories
    5. Test directories
    6. Filename patterns
    7. Production (default)

    Args:
        file_path: File path to classify.
        project_root: Project root for relative path calculation (unused, for future).
        custom_rules: Custom classification rules from config.
            Format: {"challenge_code": ["my-vuln-app"], "test_code": ["__tests__"]}

    Returns:
        DirectoryClass for the file.

    Example:
        >>> classify_directory("tests/test_main.py")
        DirectoryClass.TEST
        >>> classify_directory("examples/demo.py")
        DirectoryClass.SAMPLE
        >>> classify_directory("src/main.py")
        DirectoryClass.PRODUCTION
    """
    path = Path(file_path)
    path_str = str(path).lower().replace("\\", "/")
    path_parts = [p.lower() for p in path.parts]

    # 1. Check custom rules first (from config)
    if custom_rules:
        for class_name, dirs in custom_rules.items():
            for dir_pattern in dirs:
                if dir_pattern.lower() in path_str:
                    try:
                        return DirectoryClass(class_name)
                    except ValueError:
                        # Invalid class name, skip
                        continue

    # 2. Check directory rules (in priority order)
    for dir_patterns, dir_class in DIRECTORY_CLASSIFICATION_RULES:
        for pattern in dir_patterns:
            # Check if pattern matches any path component exactly
            if pattern.lower() in path_parts:
                return dir_class
            # Also check substring for compound directory names
            if pattern.lower() in path_str:
                return dir_class

    # 3. Check filename patterns
    filename = path.name.lower()
    for pattern, file_class in FILENAME_CLASSIFICATION_RULES:
        if re.search(pattern, filename, re.IGNORECASE):
            return file_class

    # 4. Default to production
    return DirectoryClass.PRODUCTION


def get_score_multiplier(
    directory_class: DirectoryClass,
    *,
    custom_multipliers: dict[str, float] | None = None,
) -> float:
    """
    P6-07c: Get score multiplier for a directory class.

    The multiplier is used to reduce the final score of findings in
    non-production code, making them less prominent in reports.

    Args:
        directory_class: The directory class.
        custom_multipliers: Custom multipliers from config.
            Format: {"test_code": 0.5, "challenge_code": 0.0}

    Returns:
        Score multiplier (0.0 - 1.0).

    Example:
        >>> get_score_multiplier(DirectoryClass.TEST)
        0.3
        >>> get_score_multiplier(DirectoryClass.PRODUCTION)
        1.0
        >>> get_score_multiplier(DirectoryClass.TEST, custom_multipliers={"test_code": 0.5})
        0.5
    """
    # Check custom multipliers first
    if custom_multipliers:
        class_name = directory_class.value
        if class_name in custom_multipliers:
            multiplier = custom_multipliers[class_name]
            # Clamp to valid range
            return max(0.0, min(1.0, multiplier))

    # Fall back to default multipliers
    return SCORE_MULTIPLIERS.get(directory_class, 1.0)


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

        result.lang_flags = sorted(lang_flags)
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

        # Fail-open: only apply aggressive filtering when attack surface confidence is high.
        confidence = 0.5
        files_scanned = getattr(self.attack_surface, "files_scanned", 0) or 0
        entry_points = getattr(self.attack_surface, "entry_points", []) or []
        errors = getattr(self.attack_surface, "errors", []) or []

        if files_scanned > 0:
            confidence += min(0.2, files_scanned / 1000 * 0.2)
        if entry_points:
            confidence += 0.2
        if errors:
            confidence -= 0.2
        confidence = min(1.0, max(0.0, confidence))

        if confidence < 0.7:
            result.filtering_reasons.append(
                f"Attack surface confidence low ({confidence:.2f}), skip HTTP-based directory exclusions"
            )
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
