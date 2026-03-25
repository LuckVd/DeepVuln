"""
Base classes and protocol for language-specific builders.

Provides the common interface that all language builders must implement
for CodeQL database creation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class BuildResult(str, Enum):
    """Result of a build analysis or execution."""

    SUCCESS = "success"  # Build succeeded or will succeed
    FAILED = "failed"  # Build failed
    SKIPPED = "skipped"  # Build was skipped (intentional)
    PARTIAL = "partial"  # Partial success (some modules failed)


class FailureCategory(str, Enum):
    """Categories of build failures for diagnosis."""

    # Dependency issues
    DEPENDENCY_MISSING = "dependency_missing"  # Required dependency not found
    DEPENDENCY_RESOLUTION = "dependency_resolution"  # Dependency resolution failed
    PRIVATE_MODULE = "private_module"  # Private module inaccessible

    # Compilation issues
    COMPILATION_ERROR = "compilation_error"  # Source code compilation error
    BUILD_ERROR = "build_error"  # Generic build error

    # Environment issues
    VERSION_MISMATCH = "version_mismatch"  # Runtime version incompatible
    TOOL_MISSING = "tool_missing"  # Required tool not installed
    CGO_REQUIRED = "cgo_required"  # C compiler required for CGO

    # Project structure issues
    MULTI_MODULE_CYCLE = "multi_module_cycle"  # Circular dependency in modules
    CONFIG_ERROR = "config_error"  # Configuration file error

    # Permission issues
    PERMISSION_DENIED = "permission_denied"  # File or command permission issue
    WRAPPER_PERMISSION = "wrapper_permission"  # Wrapper script not executable

    # Unknown
    UNKNOWN = "unknown"


@dataclass
class BuilderOutput:
    """Output from a language builder analysis.

    Contains the build strategy, commands, environment variables,
    and any issues or warnings discovered during analysis.
    """

    result: BuildResult
    language: str
    build_command: str | None = None
    dependency_command: str | None = None
    env_vars: dict[str, str] = field(default_factory=dict)
    cwd: Path | None = None
    timeout: int = 300

    # Skip/failed information
    skip_reason: str | None = None
    failure_category: FailureCategory | None = None
    failure_details: str | None = None

    # Additional information
    warnings: list[str] = field(default_factory=list)
    detected_files: list[str] = field(default_factory=list)
    build_system: str | None = None
    module_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "result": self.result.value,
            "language": self.language,
            "build_command": self.build_command,
            "dependency_command": self.dependency_command,
            "env_vars": self.env_vars,
            "cwd": str(self.cwd) if self.cwd else None,
            "timeout": self.timeout,
            "skip_reason": self.skip_reason,
            "failure_category": self.failure_category.value if self.failure_category else None,
            "failure_details": self.failure_details,
            "warnings": self.warnings,
            "detected_files": self.detected_files,
            "build_system": self.build_system,
            "module_name": self.module_name,
        }

    @property
    def is_buildable(self) -> bool:
        """Check if this output can be built."""
        return self.result == BuildResult.SUCCESS and self.build_command is not None

    @property
    def is_skipped(self) -> bool:
        """Check if build was skipped."""
        return self.result == BuildResult.SKIPPED


@dataclass
class FailureDiagnosis:
    """Result of diagnosing a build failure."""

    category: FailureCategory
    message: str
    suggestion: str | None = None
    is_recoverable: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category.value,
            "message": self.message,
            "suggestion": self.suggestion,
            "is_recoverable": self.is_recoverable,
        }


class LanguageBuilder(ABC):
    """Abstract base class for language-specific builders.

    Each language (Go, Java, Python, etc.) should implement this interface
    to provide language-specific build analysis and failure diagnosis.
    """

    # Subclasses should define these
    LANGUAGE_NAME: str = "unknown"
    SUPPORTED_BUILD_SYSTEMS: list[str] = []

    @abstractmethod
    def analyze(self, project_path: Path) -> BuilderOutput:
        """Analyze a project and generate build strategy.

        Args:
            project_path: Path to the project root.

        Returns:
            BuilderOutput with build commands or skip reasons.
        """
        pass

    @abstractmethod
    def diagnose_failure(self, stdout: str, stderr: str, return_code: int) -> FailureDiagnosis:
        """Diagnose a build failure from command output.

        Args:
            stdout: Standard output from the build command.
            stderr: Standard error from the build command.
            return_code: Exit code from the build command.

        Returns:
            FailureDiagnosis with category and suggestions.
        """
        pass

    def is_available(self) -> bool:
        """Check if the builder's language tools are available.

        Returns:
            True if the language runtime/compiler is installed.
        """
        return True  # Default to available, subclasses should override

    def get_version(self) -> str | None:
        """Get the installed version of the language runtime.

        Returns:
            Version string or None if not available.
        """
        return None

    @classmethod
    def get_language_name(cls) -> str:
        """Get the language name for this builder."""
        return cls.LANGUAGE_NAME


class BuilderRegistry:
    """Registry for language builders.

    Allows registration and lookup of builders by language name.
    """

    _builders: dict[str, type[LanguageBuilder]] = {}

    @classmethod
    def register(cls, builder_class: type[LanguageBuilder]) -> type[LanguageBuilder]:
        """Register a builder class.

        Args:
            builder_class: The builder class to register.

        Returns:
            The same builder class (for decorator usage).
        """
        lang = builder_class.LANGUAGE_NAME.lower()
        cls._builders[lang] = builder_class
        return builder_class

    @classmethod
    def get(cls, language: str) -> LanguageBuilder | None:
        """Get a builder instance for a language.

        Args:
            language: Language name (case-insensitive).

        Returns:
            Builder instance or None if not registered.
        """
        builder_class = cls._builders.get(language.lower())
        if builder_class:
            return builder_class()
        return None

    @classmethod
    def list_languages(cls) -> list[str]:
        """List all registered languages.

        Returns:
            List of language names.
        """
        return list(cls._builders.keys())
