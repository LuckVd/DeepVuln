"""
Data models for tech stack detection.

This module defines the data structures used for technology stack analysis,
including language information, project profiles, and detection results.
"""

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Language(str, Enum):
    """Programming languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    CSHARP = "csharp"
    CPP = "cpp"
    KOTLIN = "kotlin"
    SWIFT = "swift"
    SCALA = "scala"
    LUA = "lua"
    PERL = "perl"
    R = "r"
    SQL = "sql"
    C = "c"


class LanguageInfo(BaseModel):
    """
    Detailed information about a detected programming language.

    This model captures comprehensive statistics about a language's
    presence in the project, including file counts and line counts.
    """

    language: Language = Field(..., description="The programming language")
    file_count: int = Field(default=0, ge=0, description="Total number of source files")
    line_count: int = Field(default=0, ge=0, description="Total non-empty lines of code")
    test_file_count: int = Field(default=0, ge=0, description="Number of test files")
    doc_file_count: int = Field(default=0, ge=0, description="Number of documentation files")
    role: Literal["primary", "secondary"] = Field(
        default="secondary",
        description="Role of this language in the project",
    )
    loc_percentage: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Percentage of total LOC for this language",
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump()


class Framework(BaseModel):
    """Detected framework."""

    name: str
    category: str  # web, mobile, desktop, testing, etc.
    version: str | None = None
    confidence: float = 1.0
    source_file: str | None = None


class Database(BaseModel):
    """Detected database."""

    name: str
    category: str  # relational, nosql, cache, etc.
    confidence: float = 1.0


class Middleware(BaseModel):
    """Detected middleware/service."""

    name: str
    category: str  # cache, queue, proxy, etc.
    confidence: float = 1.0


class ProjectType(str, Enum):
    """Project type classification."""

    WEB = "web"
    API = "api"
    CLI = "cli"
    LIBRARY = "library"
    MOBILE = "mobile"
    DESKTOP = "desktop"
    UNKNOWN = "unknown"


class TechStack(BaseModel):
    """
    Detected technology stack with comprehensive project profile.

    This model provides a complete picture of the project's technology
    composition, including primary/secondary languages, project type,
    and structural characteristics.
    """

    # Language information (NEW: detailed language stats)
    languages: list[LanguageInfo] = Field(
        default_factory=list,
        description="Detailed information about each detected language",
    )

    # Primary/secondary language classification (NEW)
    primary_language: Language | None = Field(
        default=None,
        description="The dominant programming language by LOC",
    )
    secondary_languages: list[Language] = Field(
        default_factory=list,
        description="Languages with >10% LOC share",
    )

    # Project statistics (NEW)
    total_loc: int = Field(default=0, ge=0, description="Total lines of code")
    total_files: int = Field(default=0, ge=0, description="Total source files")

    # Project characteristics (NEW)
    project_type: ProjectType | None = Field(
        default=None,
        description="Classification of project type",
    )
    has_tests: bool = Field(default=False, description="Whether project has test files")
    has_docs: bool = Field(default=False, description="Whether project has documentation")
    is_monorepo: bool = Field(default=False, description="Whether project is a monorepo")

    # Frameworks, databases, middleware (existing)
    frameworks: list[Framework] = Field(default_factory=list)
    databases: list[Database] = Field(default_factory=list)
    middleware: list[Middleware] = Field(default_factory=list)

    # Build tools and package managers (existing)
    build_tools: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    ci_cd: list[str] = Field(default_factory=list)

    # Metadata (existing)
    confidence: float = Field(default=1.0, description="Overall detection confidence")
    source_path: str | None = None

    # Legacy compatibility: simple language list (existing)
    # Kept for backward compatibility with existing code
    _language_list: list[Language] | None = None

    def get_all_keywords(self) -> list[str]:
        """Get all searchable keywords for CVE lookup.

        Returns:
            List of keywords.
        """
        keywords = []

        # Add frameworks
        for fw in self.frameworks:
            keywords.append(fw.name)
            if fw.version:
                keywords.append(f"{fw.name} {fw.version}")

        # Add databases
        for db in self.databases:
            keywords.append(db.name)

        # Add middleware
        for mw in self.middleware:
            keywords.append(mw.name)

        return list(set(keywords))

    def get_language_list(self) -> list[Language]:
        """
        Get simple list of detected languages.

        This method provides backward compatibility with existing code
        that expects a simple list of languages.

        Returns:
            List of detected Language enums.
        """
        if self._language_list is not None:
            return self._language_list

        return [info.language for info in self.languages]

    def get_primary_language_info(self) -> LanguageInfo | None:
        """Get the LanguageInfo for the primary language."""
        for info in self.languages:
            if info.role == "primary":
                return info
        return None

    def get_language_info(self, language: Language) -> LanguageInfo | None:
        """Get LanguageInfo for a specific language."""
        for info in self.languages:
            if info.language == language:
                return info
        return None

    def to_summary(self) -> str:
        """Generate a human-readable summary."""
        lines = [
            f"Primary Language: {self.primary_language.value if self.primary_language else 'Unknown'}",
            f"Total LOC: {self.total_loc:,}",
            f"Total Files: {self.total_files}",
            f"Project Type: {self.project_type.value if self.project_type else 'Unknown'}",
            "",
            "Languages:",
        ]

        for info in sorted(self.languages, key=lambda x: x.line_count, reverse=True):
            role_marker = "[Primary]" if info.role == "primary" else ""
            lines.append(
                f"  - {info.language.value}: {info.file_count} files, "
                f"{info.line_count:,} LOC ({info.loc_percentage:.1f}%) {role_marker}"
            )

        if self.frameworks:
            lines.append("")
            lines.append("Frameworks:")
            for fw in self.frameworks:
                lines.append(f"  - {fw.name} ({fw.category})")

        flags = []
        if self.has_tests:
            flags.append("has_tests")
        if self.has_docs:
            flags.append("has_docs")
        if self.is_monorepo:
            flags.append("monorepo")

        if flags:
            lines.append("")
            lines.append(f"Flags: {', '.join(flags)}")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = self.model_dump()
        # Add backward compatibility field
        data["detected_languages"] = [l.value for l in self.get_language_list()]
        return data


# File extension to language mapping
EXTENSION_TO_LANGUAGE: dict[str, Language] = {
    # Python
    ".py": Language.PYTHON,
    ".pyw": Language.PYTHON,
    ".pyi": Language.PYTHON,
    # JavaScript
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    # TypeScript
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".mts": Language.TYPESCRIPT,
    # Java
    ".java": Language.JAVA,
    # Go
    ".go": Language.GO,
    # Rust
    ".rs": Language.RUST,
    # PHP
    ".php": Language.PHP,
    ".phtml": Language.PHP,
    # Ruby
    ".rb": Language.RUBY,
    ".rake": Language.RUBY,
    # C#
    ".cs": Language.CSHARP,
    # C/C++
    ".c": Language.C,
    ".cpp": Language.CPP,
    ".cc": Language.CPP,
    ".cxx": Language.CPP,
    ".hpp": Language.CPP,
    ".h": Language.C,  # Could be C or C++, default to C
    # Kotlin
    ".kt": Language.KOTLIN,
    ".kts": Language.KOTLIN,
    # Swift
    ".swift": Language.SWIFT,
    # Scala
    ".scala": Language.SCALA,
    ".sc": Language.SCALA,
    # Lua
    ".lua": Language.LUA,
    # Perl
    ".pl": Language.PERL,
    ".pm": Language.PERL,
    # R
    ".r": Language.R,
    ".R": Language.R,
    # SQL
    ".sql": Language.SQL,
}

# Test file patterns
TEST_FILE_PATTERNS = [
    # Python
    "test_",
    "_test.py",
    "tests.py",
    # JavaScript/TypeScript
    ".test.js",
    ".test.ts",
    ".spec.js",
    ".spec.ts",
    "_test.js",
    "_test.ts",
    "_spec.js",
    "_spec.ts",
    # Java
    "Test.java",
    "Tests.java",
    "IT.java",  # Integration tests
    # Go
    "_test.go",
    # Ruby
    "_test.rb",
    "_spec.rb",
    # PHP
    "Test.php",
    "Tests.php",
]

# Test directories
TEST_DIRECTORIES = {
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
}

# Documentation directories
DOC_DIRECTORIES = {
    "docs",
    "doc",
    "documentation",
    "wiki",
    "man",
}

# Documentation file patterns
DOC_FILE_PATTERNS = [
    ".md",
    ".rst",
    ".txt",
    ".adoc",
    ".asciidoc",
]

# Directories to skip during scanning
SKIP_DIRECTORIES = {
    # Version control
    ".git",
    ".svn",
    ".hg",
    ".bzr",
    # Dependencies
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "vendor",
    "third_party",
    "thirdparty",
    "external",
    # Build artifacts
    "__pycache__",
    ".pyc",
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
    # Other
    ".github",
    ".gitlab",
    "coverage",
    ".coverage",
    "htmlcov",
    "site-packages",
}

# Package manager files (for monorepo detection)
PACKAGE_FILES = {
    "package.json",
    "setup.py",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
}
