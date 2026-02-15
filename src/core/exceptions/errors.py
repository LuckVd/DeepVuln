"""Custom exception definitions for DeepVuln."""

from typing import Any


class DeepVulnError(Exception):
    """Base exception for all DeepVuln errors."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            message: Error message.
            details: Additional error details.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.details:
            return f"{self.message} - Details: {self.details}"
        return self.message


class GitError(DeepVulnError):
    """Exception raised for Git operation errors."""

    def __init__(
        self,
        message: str,
        repo_url: str | None = None,
        git_ref: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize Git error.

        Args:
            message: Error message.
            repo_url: Repository URL that caused the error.
            git_ref: Git reference (branch/tag/commit) involved.
            details: Additional error details.
        """
        details = details or {}
        if repo_url:
            details["repo_url"] = repo_url
        if git_ref:
            details["git_ref"] = git_ref
        super().__init__(message, details)


class WorkspaceError(DeepVulnError):
    """Exception raised for workspace management errors."""

    def __init__(
        self,
        message: str,
        workspace_name: str | None = None,
        workspace_path: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize workspace error.

        Args:
            message: Error message.
            workspace_name: Name of the workspace.
            workspace_path: Path to the workspace.
            details: Additional error details.
        """
        details = details or {}
        if workspace_name:
            details["workspace_name"] = workspace_name
        if workspace_path:
            details["workspace_path"] = workspace_path
        super().__init__(message, details)


class FetchError(DeepVulnError):
    """Exception raised for asset fetching errors."""

    def __init__(
        self,
        message: str,
        source_type: str | None = None,
        source_path: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize fetch error.

        Args:
            message: Error message.
            source_type: Type of source (git/local).
            source_path: Path or URL of the source.
            details: Additional error details.
        """
        details = details or {}
        if source_type:
            details["source_type"] = source_type
        if source_path:
            details["source_path"] = source_path
        super().__init__(message, details)


class ConfigurationError(DeepVulnError):
    """Exception raised for configuration errors."""

    def __init__(
        self,
        message: str,
        config_key: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize configuration error.

        Args:
            message: Error message.
            config_key: Configuration key that caused the error.
            details: Additional error details.
        """
        details = details or {}
        if config_key:
            details["config_key"] = config_key
        super().__init__(message, details)
