"""Workspace-related data models."""

from datetime import datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class WorkspaceStatus(str, Enum):
    """Workspace status enumeration."""

    CREATING = "creating"
    ACTIVE = "active"
    CLEANUP = "cleanup"
    DISPOSED = "disposed"


class WorkspaceConfig(BaseModel):
    """Configuration for workspace management."""

    base_dir: Path | None = Field(
        default=None,
        description="Base directory for workspaces (None = system temp)",
    )
    max_workspaces: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum number of concurrent workspaces",
    )
    auto_cleanup: bool = Field(
        default=True,
        description="Automatically cleanup workspaces on exit",
    )
    prefix: str = Field(
        default="deepvuln_",
        description="Prefix for workspace directory names",
    )


class WorkspaceInfo(BaseModel):
    """Information about a workspace."""

    name: str = Field(description="Unique workspace name")
    path: Path = Field(description="Absolute path to workspace directory")
    status: WorkspaceStatus = Field(
        default=WorkspaceStatus.CREATING,
        description="Current workspace status",
    )
    created_at: datetime = Field(
        default_factory=datetime.now,
        description="Workspace creation timestamp",
    )
    source_type: str | None = Field(
        default=None,
        description="Type of source (git/local)",
    )
    source_path: str | None = Field(
        default=None,
        description="Original source path or URL",
    )

    model_config = {
        "arbitrary_types_allowed": True,
        "use_enum_values": False,
    }

    def mark_active(self) -> None:
        """Mark workspace as active."""
        self.status = WorkspaceStatus.ACTIVE

    def mark_cleanup(self) -> None:
        """Mark workspace as being cleaned up."""
        self.status = WorkspaceStatus.CLEANUP

    def mark_disposed(self) -> None:
        """Mark workspace as disposed."""
        self.status = WorkspaceStatus.DISPOSED
