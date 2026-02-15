"""Asset fetcher - unified entry point for source code acquisition."""

import shutil
from pathlib import Path

from src.core.config.settings import get_settings
from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.git_operations import GitOperations
from src.layers.l1_intelligence.workspace import WorkspaceManager
from src.models.fetcher import AssetSource, FetchResult, GitRef
from src.models.workspace import WorkspaceConfig

logger = get_logger(__name__)


class AssetFetcher:
    """Unified interface for fetching source code from various sources."""

    def __init__(
        self,
        workspace_manager: WorkspaceManager | None = None,
        git_operations: GitOperations | None = None,
        default_depth: int | None = None,
    ) -> None:
        """Initialize the asset fetcher.

        Args:
            workspace_manager: Workspace manager instance.
            git_operations: Git operations instance.
            default_depth: Default clone depth for Git operations.
        """
        settings = get_settings()

        self.workspace_manager = workspace_manager or WorkspaceManager(
            WorkspaceConfig(
                base_dir=settings.workspace.base_dir,
                max_workspaces=settings.workspace.max_workspaces,
                auto_cleanup=settings.workspace.auto_cleanup,
                prefix=settings.workspace.prefix,
            )
        )
        self.git_operations = git_operations or GitOperations()
        self.default_depth = default_depth or settings.git.default_depth

    def fetch_from_git(
        self,
        repo_url: str,
        git_ref: GitRef | None = None,
        depth: int | None = None,
        workspace_name: str | None = None,
    ) -> FetchResult:
        """Fetch source code from a Git repository.

        Args:
            repo_url: URL of the Git repository.
            git_ref: Git reference to checkout (branch/tag/commit).
            depth: Clone depth (0 = full clone).
            workspace_name: Optional name for the workspace.

        Returns:
            FetchResult with source path or error.
        """
        clone_depth = depth if depth is not None else self.default_depth

        logger.info(f"Fetching from Git: {repo_url}")
        if git_ref:
            logger.info(f"Target ref: {git_ref}")

        try:
            # Create workspace
            workspace = self.workspace_manager.create(
                name=workspace_name,
                source_type="git",
                source_path=repo_url,
            )

            # Clone repository
            repo = self.git_operations.clone(
                repo_url=repo_url,
                target_path=workspace.path,
                depth=clone_depth,
                git_ref=git_ref,
            )

            # Get metadata
            commit_info = self.git_operations.get_commit_info(repo)
            current_ref = self.git_operations.get_current_ref(repo)

            metadata = {
                "repo_url": repo_url,
                "git_ref": str(git_ref) if git_ref else None,
                "current_ref": current_ref,
                "commit_info": commit_info,
                "clone_depth": clone_depth,
            }

            logger.info(f"Successfully fetched from Git to {workspace.path}")

            return FetchResult.success_result(
                source_path=workspace.path,
                workspace_name=workspace.name,
                source_type=AssetSource.GIT,
                metadata=metadata,
            )

        except Exception as e:
            error_msg = f"Failed to fetch from Git: {repo_url} - {e}"
            logger.error(error_msg)

            # Cleanup workspace on failure
            if workspace_name and self.workspace_manager.get(workspace_name):
                try:
                    self.workspace_manager.cleanup(workspace_name)
                except Exception:
                    pass

            return FetchResult.failure_result(
                error_message=error_msg,
                source_type=AssetSource.GIT,
                metadata={"repo_url": repo_url, "error_type": type(e).__name__},
            )

    def fetch_from_local(
        self,
        local_path: Path,
        workspace_name: str | None = None,
        copy_to_workspace: bool = True,
    ) -> FetchResult:
        """Fetch source code from a local path.

        Args:
            local_path: Path to the local source code.
            workspace_name: Optional name for the workspace.
            copy_to_workspace: Whether to copy files to a workspace.

        Returns:
            FetchResult with source path or error.
        """
        logger.info(f"Fetching from local path: {local_path}")

        # Validate input path
        if not local_path.exists():
            return FetchResult.failure_result(
                error_message=f"Local path does not exist: {local_path}",
                source_type=AssetSource.LOCAL,
            )

        if not local_path.is_dir():
            return FetchResult.failure_result(
                error_message=f"Local path is not a directory: {local_path}",
                source_type=AssetSource.LOCAL,
            )

        try:
            if copy_to_workspace:
                # Create workspace and copy files
                workspace = self.workspace_manager.create(
                    name=workspace_name,
                    source_type="local",
                    source_path=str(local_path),
                )

                # Copy all files
                shutil.copytree(
                    local_path,
                    workspace.path,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(
                        ".git",
                        "__pycache__",
                        "*.pyc",
                        ".pytest_cache",
                        "*.egg-info",
                    ),
                )

                source_path = workspace.path
                workspace_name_result = workspace.name
            else:
                # Use the local path directly (no copy)
                source_path = local_path
                workspace_name_result = None

            # Check if it's a Git repo for metadata
            metadata = {"original_path": str(local_path), "copied": copy_to_workspace}

            if self.git_operations.is_git_repo(local_path):
                try:
                    repo = self.git_operations.open_repo(local_path)
                    commit_info = self.git_operations.get_commit_info(repo)
                    current_ref = self.git_operations.get_current_ref(repo)
                    metadata["is_git_repo"] = True
                    metadata["current_ref"] = current_ref
                    metadata["commit_info"] = commit_info
                except Exception:
                    metadata["is_git_repo"] = False
            else:
                metadata["is_git_repo"] = False

            logger.info(f"Successfully loaded from local path to {source_path}")

            return FetchResult.success_result(
                source_path=source_path,
                workspace_name=workspace_name_result,
                source_type=AssetSource.LOCAL,
                metadata=metadata,
            )

        except Exception as e:
            error_msg = f"Failed to fetch from local path: {local_path} - {e}"
            logger.error(error_msg)

            return FetchResult.failure_result(
                error_message=error_msg,
                source_type=AssetSource.LOCAL,
                metadata={"local_path": str(local_path), "error_type": type(e).__name__},
            )

    def fetch(
        self,
        source: str,
        git_ref: GitRef | None = None,
        depth: int | None = None,
        workspace_name: str | None = None,
    ) -> FetchResult:
        """Auto-detect source type and fetch.

        Args:
            source: URL or local path.
            git_ref: Git reference (only for Git sources).
            depth: Clone depth (only for Git sources).
            workspace_name: Optional workspace name.

        Returns:
            FetchResult with source path or error.
        """
        source_path = Path(source)

        # Check if it's a local path
        if source_path.exists() and source_path.is_dir():
            return self.fetch_from_local(
                local_path=source_path,
                workspace_name=workspace_name,
            )

        # Otherwise, treat as Git URL
        return self.fetch_from_git(
            repo_url=source,
            git_ref=git_ref,
            depth=depth,
            workspace_name=workspace_name,
        )

    def cleanup(self, workspace_name: str) -> bool:
        """Clean up a workspace.

        Args:
            workspace_name: Name of the workspace to clean up.

        Returns:
            True if cleanup succeeded.
        """
        return self.workspace_manager.cleanup(workspace_name)

    def cleanup_all(self) -> int:
        """Clean up all workspaces.

        Returns:
            Number of workspaces cleaned.
        """
        return self.workspace_manager.cleanup_all()

    # Context manager support
    def __enter__(self) -> "AssetFetcher":
        """Enter context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        """Exit context manager and cleanup."""
        self.cleanup_all()
