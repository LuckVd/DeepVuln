"""
CodeQL Health Management - Fail-Safe Degradation System.

This module provides health monitoring and fail-safe mechanisms for CodeQL
to ensure the main scanning workflow never fails due to CodeQL issues.

Target: CodeQL can fail, but the system stays stable.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.core.logger.logger import get_logger


class CodeQLStatus(str, Enum):
    """
    CodeQL execution status.

    Used to track the health of CodeQL operations and determine
    whether fallback is needed.
    """

    SUCCESS = "success"
    BUILD_FAILED = "build_failed"
    QUERY_FAILED = "query_failed"
    TIMEOUT = "timeout"
    UNSUPPORTED_LANGUAGE = "unsupported_language"
    RESOURCE_ERROR = "resource_error"
    SUBPROCESS_ERROR = "subprocess_error"
    NOT_INSTALLED = "not_installed"
    DATABASE_ERROR = "database_error"


@dataclass
class CodeQLHealthResult:
    """
    Result of CodeQL health check and execution.

    Contains status information, timing, and error details for
    monitoring and debugging CodeQL operations.
    """

    status: CodeQLStatus
    message: str
    duration: float = 0.0
    fallback_triggered: bool = False
    error_details: dict[str, Any] | None = None
    operation: str = "unknown"  # "build", "analyze", "scan"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "status": self.status.value,
            "message": self.message,
            "duration": round(self.duration, 2),
            "fallback_triggered": self.fallback_triggered,
            "error_details": self.error_details,
            "operation": self.operation,
        }

    @property
    def is_success(self) -> bool:
        """Check if the operation was successful."""
        return self.status == CodeQLStatus.SUCCESS

    @property
    def needs_fallback(self) -> bool:
        """Check if fallback to other engines is needed."""
        return self.status != CodeQLStatus.SUCCESS


# ============================================================================
# Constants
# ============================================================================

# Timeout configurations (in seconds)
DEFAULT_BUILD_TIMEOUT = 1800  # 30 minutes for database creation
DEFAULT_ANALYZE_TIMEOUT = 600  # 10 minutes for query execution
DEFAULT_QUERY_TIMEOUT = 300  # 5 minutes per query

# Memory limit (in MB)
DEFAULT_MEMORY_LIMIT = 8192  # 8GB

# Languages supported by CodeQL
CODEQL_SUPPORTED_LANGUAGES = {
    "python",
    "java",
    "javascript",
    "typescript",
    "csharp",
    "cpp",
    "c",
    "go",
    "ruby",
    "swift",
    "kotlin",  # Via Java analysis
    "scala",  # Via Java analysis
}

# Language mapping for CodeQL
CODEQL_LANGUAGE_MAP: dict[str, str] = {
    "python": "python",
    "java": "java",
    "javascript": "javascript",
    "typescript": "javascript",  # TypeScript uses JavaScript analysis
    "csharp": "csharp",
    "c#": "csharp",
    "cpp": "cpp",
    "c++": "cpp",
    "c": "cpp",  # C is analyzed with C++ extractor
    "go": "go",
    "ruby": "ruby",
    "swift": "swift",
    "kotlin": "java",  # Kotlin analyzed with Java
    "scala": "java",  # Scala analyzed with Java
}

# Error patterns to detect specific failures
BUILD_ERROR_PATTERNS = {
    "no code could be extracted": "No extractable code found",
    "out of memory": "Memory exhausted",
    "timeout": "Operation timed out",
    "unsupported language": "Language not supported",
    "permission denied": "Permission error",
    "build failed": "Build process failed",
    "compilation failed": "Compilation error",
    "database already exists": "Database conflict",
}

QUERY_ERROR_PATTERNS = {
    "no queries found": "Query pack not available",
    "database not found": "Database missing",
    "out of memory": "Memory exhausted",
    "timeout": "Query timed out",
    "sarif": "SARIF output error",
    "invalid query": "Query syntax error",
}


class CodeQLHealthManager:
    """
    Manager for CodeQL health monitoring and fail-safe operations.

    Provides methods to check CodeQL availability, validate language support,
    and create health results for various failure scenarios.
    """

    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    @staticmethod
    def is_language_supported(language: str) -> bool:
        """
        Check if a language is supported by CodeQL.

        Args:
            language: Language name to check.

        Returns:
            True if the language is supported.
        """
        lang_lower = language.lower()
        return lang_lower in CODEQL_SUPPORTED_LANGUAGES

    @staticmethod
    def normalize_language(language: str) -> str | None:
        """
        Normalize a language name to CodeQL format.

        Args:
            language: Language name (e.g., "python", "TypeScript").

        Returns:
            CodeQL language name, or None if not supported.
        """
        lang_lower = language.lower()
        return CODEQL_LANGUAGE_MAP.get(lang_lower)

    @staticmethod
    def create_success_result(
        operation: str,
        duration: float,
        message: str = "Operation completed successfully",
    ) -> CodeQLHealthResult:
        """Create a successful health result."""
        return CodeQLHealthResult(
            status=CodeQLStatus.SUCCESS,
            message=message,
            duration=duration,
            fallback_triggered=False,
            operation=operation,
        )

    @staticmethod
    def create_error_result(
        status: CodeQLStatus,
        operation: str,
        message: str,
        duration: float = 0.0,
        error_details: dict[str, Any] | None = None,
    ) -> CodeQLHealthResult:
        """Create an error health result with fallback triggered."""
        return CodeQLHealthResult(
            status=status,
            message=message,
            duration=duration,
            fallback_triggered=True,
            error_details=error_details,
            operation=operation,
        )

    @staticmethod
    def create_timeout_result(
        operation: str,
        duration: float,
        timeout_seconds: int,
    ) -> CodeQLHealthResult:
        """Create a timeout health result."""
        return CodeQLHealthResult(
            status=CodeQLStatus.TIMEOUT,
            message=f"Operation timed out after {timeout_seconds}s",
            duration=duration,
            fallback_triggered=True,
            error_details={"timeout_seconds": timeout_seconds},
            operation=operation,
        )

    @staticmethod
    def create_unsupported_language_result(language: str) -> CodeQLHealthResult:
        """Create an unsupported language health result."""
        return CodeQLHealthResult(
            status=CodeQLStatus.UNSUPPORTED_LANGUAGE,
            message=f"Language '{language}' is not supported by CodeQL",
            duration=0.0,
            fallback_triggered=True,
            error_details={
                "requested_language": language,
                "supported_languages": list(CODEQL_SUPPORTED_LANGUAGES),
            },
            operation="language_check",
        )

    @staticmethod
    def create_not_installed_result() -> CodeQLHealthResult:
        """Create a not installed health result."""
        return CodeQLHealthResult(
            status=CodeQLStatus.NOT_INSTALLED,
            message="CodeQL CLI is not installed or not in PATH",
            duration=0.0,
            fallback_triggered=True,
            error_details={
                "install_url": "https://github.com/github/codeql-cli-binaries/releases"
            },
            operation="availability_check",
        )

    @staticmethod
    def parse_build_error(stderr: str) -> tuple[str, dict[str, Any] | None]:
        """
        Parse build error output to identify the cause.

        Args:
            stderr: Standard error output from CodeQL.

        Returns:
            Tuple of (error_message, error_details).
        """
        if not stderr:
            return "Unknown build error", None

        stderr_lower = stderr.lower()

        for pattern, description in BUILD_ERROR_PATTERNS.items():
            if pattern in stderr_lower:
                return description, {
                    "pattern_matched": pattern,
                    "stderr_preview": stderr[:500] if stderr else None,
                }

        return "Build failed", {"stderr_preview": stderr[:500] if stderr else None}

    @staticmethod
    def parse_query_error(stderr: str) -> tuple[str, dict[str, Any] | None]:
        """
        Parse query error output to identify the cause.

        Args:
            stderr: Standard error output from CodeQL.

        Returns:
            Tuple of (error_message, error_details).
        """
        if not stderr:
            return "Unknown query error", None

        stderr_lower = stderr.lower()

        for pattern, description in QUERY_ERROR_PATTERNS.items():
            if pattern in stderr_lower:
                return description, {
                    "pattern_matched": pattern,
                    "stderr_preview": stderr[:500] if stderr else None,
                }

        return "Query execution failed", {"stderr_preview": stderr[:500] if stderr else None}


def create_health_manager() -> CodeQLHealthManager:
    """
    Factory function to create a CodeQLHealthManager instance.

    Returns:
        Configured CodeQLHealthManager instance.
    """
    return CodeQLHealthManager()
