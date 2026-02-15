"""Fetcher-related data models."""

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class AssetSource(str, Enum):
    """Asset source type enumeration."""

    GIT = "git"
    LOCAL = "local"


class GitRefType(str, Enum):
    """Git reference type enumeration."""

    BRANCH = "branch"
    TAG = "tag"
    COMMIT = "commit"


class GitRef(BaseModel):
    """Git reference specification."""

    ref_type: GitRefType = Field(
        default=GitRefType.BRANCH,
        description="Type of Git reference",
    )
    ref_value: str = Field(
        description="Value of the reference (branch name, tag, or commit hash)",
    )

    def __str__(self) -> str:
        """Return string representation."""
        return f"{self.ref_type.value}:{self.ref_value}"


class AssetConfig(BaseModel):
    """Configuration for asset fetching."""

    source_type: AssetSource = Field(
        description="Type of asset source",
    )
    repo_url: str | None = Field(
        default=None,
        description="Git repository URL (required if source_type is GIT)",
    )
    git_ref: GitRef | None = Field(
        default=None,
        description="Git reference to checkout",
    )
    local_path: Path | None = Field(
        default=None,
        description="Local path (required if source_type is LOCAL)",
    )
    depth: int = Field(
        default=0,
        ge=0,
        description="Clone depth (0 = full clone)",
    )

    model_config = {
        "arbitrary_types_allowed": True,
    }


class FetchResult(BaseModel):
    """Result of an asset fetch operation."""

    success: bool = Field(description="Whether the fetch operation succeeded")
    source_path: Path | None = Field(
        default=None,
        description="Path to the fetched source code",
    )
    workspace_name: str | None = Field(
        default=None,
        description="Name of the workspace containing the source",
    )
    source_type: AssetSource | None = Field(
        default=None,
        description="Type of source that was fetched",
    )
    error_message: str | None = Field(
        default=None,
        description="Error message if fetch failed",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata about the fetch",
    )

    model_config = {
        "arbitrary_types_allowed": True,
    }

    @classmethod
    def success_result(
        cls,
        source_path: Path,
        workspace_name: str | None,
        source_type: AssetSource,
        metadata: dict[str, Any] | None = None,
    ) -> "FetchResult":
        """Create a successful fetch result.

        Args:
            source_path: Path to the fetched source.
            workspace_name: Name of the workspace.
            source_type: Type of source.
            metadata: Additional metadata.

        Returns:
            Successful FetchResult instance.
        """
        return cls(
            success=True,
            source_path=source_path,
            workspace_name=workspace_name,
            source_type=source_type,
            metadata=metadata or {},
        )

    @classmethod
    def failure_result(
        cls,
        error_message: str,
        source_type: AssetSource | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "FetchResult":
        """Create a failed fetch result.

        Args:
            error_message: Error description.
            source_type: Type of source (if known).
            metadata: Additional metadata.

        Returns:
            Failed FetchResult instance.
        """
        return cls(
            success=False,
            error_message=error_message,
            source_type=source_type,
            metadata=metadata or {},
        )
