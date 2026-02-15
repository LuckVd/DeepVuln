"""Workspace management for temporary directories."""

import shutil
import tempfile
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from src.core.config.settings import get_settings
from src.core.exceptions.errors import WorkspaceError
from src.core.logger.logger import get_logger
from src.models.workspace import WorkspaceConfig, WorkspaceInfo, WorkspaceStatus

logger = get_logger(__name__)


class WorkspaceManager:
    """Manages temporary workspaces for source code analysis."""

    def __init__(self, config: WorkspaceConfig | None = None) -> None:
        """Initialize the workspace manager.

        Args:
            config: Workspace configuration. Uses global settings if not provided.
        """
        if config is None:
            settings = get_settings()
            config = WorkspaceConfig(
                base_dir=settings.workspace.base_dir,
                max_workspaces=settings.workspace.max_workspaces,
                auto_cleanup=settings.workspace.auto_cleanup,
                prefix=settings.workspace.prefix,
            )

        self.config = config
        self._workspaces: dict[str, WorkspaceInfo] = {}

    @property
    def active_count(self) -> int:
        """Return count of active workspaces."""
        return sum(
            1
            for ws in self._workspaces.values()
            if ws.status == WorkspaceStatus.ACTIVE
        )

    @property
    def workspaces(self) -> dict[str, WorkspaceInfo]:
        """Return all workspace info."""
        return self._workspaces.copy()

    def _generate_name(self) -> str:
        """Generate a unique workspace name.

        Returns:
            Unique workspace name.
        """
        return f"{self.config.prefix}{uuid.uuid4().hex[:8]}"

    def _get_base_dir(self) -> Path:
        """Get the base directory for workspaces.

        Returns:
            Base directory path.
        """
        if self.config.base_dir:
            base_dir = self.config.base_dir
            base_dir.mkdir(parents=True, exist_ok=True)
            return base_dir
        return Path(tempfile.gettempdir())

    def create(
        self,
        name: str | None = None,
        source_type: str | None = None,
        source_path: str | None = None,
    ) -> WorkspaceInfo:
        """Create a new workspace.

        Args:
            name: Optional workspace name. Auto-generated if not provided.
            source_type: Type of source being stored.
            source_path: Original source path/URL.

        Returns:
            WorkspaceInfo for the created workspace.

        Raises:
            WorkspaceError: If workspace cannot be created.
        """
        # Check workspace limit
        if self.active_count >= self.config.max_workspaces:
            raise WorkspaceError(
                f"Maximum workspace limit reached ({self.config.max_workspaces})",
                details={"active_count": self.active_count},
            )

        # Generate name if not provided
        workspace_name = name or self._generate_name()

        # Check for duplicate name
        if workspace_name in self._workspaces:
            raise WorkspaceError(
                f"Workspace already exists: {workspace_name}",
                workspace_name=workspace_name,
            )

        # Create workspace directory
        base_dir = self._get_base_dir()
        workspace_path = base_dir / workspace_name

        try:
            workspace_path.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created workspace directory: {workspace_path}")
        except OSError as e:
            raise WorkspaceError(
                f"Failed to create workspace directory: {workspace_path}",
                workspace_name=workspace_name,
                workspace_path=str(workspace_path),
                details={"error": str(e)},
            ) from e

        # Create workspace info
        info = WorkspaceInfo(
            name=workspace_name,
            path=workspace_path,
            status=WorkspaceStatus.ACTIVE,
            source_type=source_type,
            source_path=source_path,
        )

        self._workspaces[workspace_name] = info
        logger.info(f"Created workspace: {workspace_name} at {workspace_path}")

        return info

    def get(self, name: str) -> WorkspaceInfo | None:
        """Get workspace info by name.

        Args:
            name: Workspace name.

        Returns:
            WorkspaceInfo if found, None otherwise.
        """
        return self._workspaces.get(name)

    def cleanup(self, name: str) -> bool:
        """Clean up a workspace.

        Args:
            name: Workspace name to clean up.

        Returns:
            True if cleanup succeeded.

        Raises:
            WorkspaceError: If workspace not found or cleanup fails.
        """
        info = self._workspaces.get(name)
        if not info:
            raise WorkspaceError(
                f"Workspace not found: {name}",
                workspace_name=name,
            )

        if info.status == WorkspaceStatus.DISPOSED:
            return True

        info.mark_cleanup()

        try:
            if info.path.exists():
                shutil.rmtree(info.path)
                logger.debug(f"Removed workspace directory: {info.path}")
        except OSError as e:
            logger.warning(f"Failed to remove workspace directory: {info.path} - {e}")
            # Still mark as disposed even if cleanup fails
        finally:
            info.mark_disposed()
            del self._workspaces[name]

        logger.info(f"Cleaned up workspace: {name}")
        return True

    def cleanup_all(self) -> int:
        """Clean up all workspaces.

        Returns:
            Number of workspaces cleaned up.
        """
        names = list(self._workspaces.keys())
        cleaned = 0

        for name in names:
            try:
                self.cleanup(name)
                cleaned += 1
            except WorkspaceError as e:
                logger.warning(f"Failed to cleanup workspace {name}: {e}")

        logger.info(f"Cleaned up {cleaned} workspaces")
        return cleaned

    @contextmanager
    def workspace(
        self,
        name: str | None = None,
        source_type: str | None = None,
        source_path: str | None = None,
    ) -> Generator[WorkspaceInfo, None, None]:
        """Context manager for automatic workspace cleanup.

        Args:
            name: Optional workspace name.
            source_type: Type of source.
            source_path: Source path/URL.

        Yields:
            WorkspaceInfo for the created workspace.
        """
        info = self.create(name, source_type, source_path)
        try:
            yield info
        finally:
            if self.config.auto_cleanup:
                try:
                    self.cleanup(info.name)
                except WorkspaceError as e:
                    logger.warning(f"Failed to cleanup workspace {info.name}: {e}")

    def __enter__(self) -> "WorkspaceManager":
        """Enter context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        """Exit context manager and cleanup all workspaces."""
        if self.config.auto_cleanup:
            self.cleanup_all()
