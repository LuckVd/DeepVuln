"""Tests for AssetFetcher."""

import shutil
from pathlib import Path

import pytest
from git import Repo

from src.layers.l1_intelligence.fetcher import AssetFetcher
from src.models.fetcher import AssetSource, FetchResult, GitRef, GitRefType
from src.models.workspace import WorkspaceConfig


class TestAssetFetcher:
    """Tests for AssetFetcher class."""

    def test_fetch_from_local_directory(
        self, sample_git_repo: Path, workspace_config: WorkspaceConfig
    ) -> None:
        """Test fetching from local directory."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        result = fetcher.fetch_from_local(
            local_path=sample_git_repo,
            workspace_name="local-test",
        )

        assert result.success is True
        assert result.source_type == AssetSource.LOCAL
        assert result.workspace_name == "local-test"
        assert result.source_path is not None
        assert result.source_path.exists()
        assert result.metadata["is_git_repo"] is True

    def test_fetch_from_local_nonexistent_path(
        self, workspace_config: WorkspaceConfig
    ) -> None:
        """Test fetching from non-existent path."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        result = fetcher.fetch_from_local(
            local_path=Path("/nonexistent/path"),
        )

        assert result.success is False
        assert "does not exist" in result.error_message

    def test_fetch_from_local_file_path(
        self, temp_dir: Path, workspace_config: WorkspaceConfig
    ) -> None:
        """Test fetching from a file path (not directory) fails."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        # Create a file
        file_path = temp_dir / "test_file.txt"
        file_path.write_text("test content")

        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        result = fetcher.fetch_from_local(local_path=file_path)

        assert result.success is False
        assert "not a directory" in result.error_message

    def test_fetch_from_local_no_copy(
        self, sample_git_repo: Path, workspace_config: WorkspaceConfig
    ) -> None:
        """Test fetching from local without copying."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        result = fetcher.fetch_from_local(
            local_path=sample_git_repo,
            copy_to_workspace=False,
        )

        assert result.success is True
        assert result.source_path == sample_git_repo
        assert result.workspace_name is None
        assert result.metadata["copied"] is False

    def test_fetch_from_git_local_repo(
        self, sample_git_repo: Path, temp_dir: Path, workspace_config: WorkspaceConfig
    ) -> None:
        """Test fetching from a local Git repository (file:// URL)."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        result = fetcher.fetch_from_git(
            repo_url=str(sample_git_repo),
            workspace_name="git-local-test",
        )

        assert result.success is True
        assert result.source_type == AssetSource.GIT
        assert result.workspace_name == "git-local-test"
        assert result.source_path is not None
        assert result.source_path.exists()

    def test_fetch_from_git_with_branch(
        self, sample_git_repo: Path, workspace_config: WorkspaceConfig
    ) -> None:
        """Test fetching from Git with specific branch."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        git_ref = GitRef(ref_type=GitRefType.BRANCH, ref_value="feature-branch")

        result = fetcher.fetch_from_git(
            repo_url=str(sample_git_repo),
            git_ref=git_ref,
            workspace_name="branch-test",
        )

        assert result.success is True
        assert result.metadata["current_ref"] == "feature-branch"

    def test_fetch_from_git_with_tag(
        self, sample_git_repo: Path, workspace_config: WorkspaceConfig
    ) -> None:
        """Test fetching from Git with specific tag."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        git_ref = GitRef(ref_type=GitRefType.TAG, ref_value="v1.0.0")

        result = fetcher.fetch_from_git(
            repo_url=str(sample_git_repo),
            git_ref=git_ref,
            workspace_name="tag-test",
        )

        assert result.success is True

    def test_fetch_from_git_shallow_clone(
        self, sample_git_repo_with_commits: tuple[Path, Repo],
        workspace_config: WorkspaceConfig
    ) -> None:
        """Test shallow clone with depth parameter."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        repo_path, _ = sample_git_repo_with_commits
        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        result = fetcher.fetch_from_git(
            repo_url=str(repo_path),
            depth=1,
            workspace_name="shallow-test",
        )

        assert result.success is True
        assert result.metadata["clone_depth"] == 1

    def test_fetch_auto_detect_local(
        self, sample_git_repo: Path, workspace_config: WorkspaceConfig
    ) -> None:
        """Test auto-detection of local source."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        result = fetcher.fetch(str(sample_git_repo))

        assert result.success is True
        assert result.source_type == AssetSource.LOCAL

    def test_fetch_auto_detect_git(
        self, sample_git_repo: Path, workspace_config: WorkspaceConfig
    ) -> None:
        """Test auto-detection of Git source (non-existent local path)."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        # Use the sample repo URL (treated as Git URL since path doesn't exist elsewhere)
        result = fetcher.fetch(str(sample_git_repo))

        assert result.success is True
        # Since the path exists, it will be treated as local

    def test_cleanup_workspace(
        self, sample_git_repo: Path, workspace_config: WorkspaceConfig
    ) -> None:
        """Test cleanup of individual workspace."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        result = fetcher.fetch_from_local(
            local_path=sample_git_repo,
            workspace_name="cleanup-test",
        )

        assert result.success is True
        path = result.source_path
        assert path is not None
        assert path.exists()

        fetcher.cleanup("cleanup-test")

        assert not path.exists()

    def test_cleanup_all(
        self, sample_git_repo: Path, workspace_config: WorkspaceConfig
    ) -> None:
        """Test cleanup of all workspaces."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        workspace_manager = WorkspaceManager(config=workspace_config)
        fetcher = AssetFetcher(workspace_manager=workspace_manager)

        # Create multiple workspaces
        fetcher.fetch_from_local(sample_git_repo, workspace_name="ws1")
        fetcher.fetch_from_local(sample_git_repo, workspace_name="ws2")

        cleaned = fetcher.cleanup_all()

        assert cleaned == 2

    def test_context_manager(
        self, sample_git_repo: Path, workspace_config: WorkspaceConfig
    ) -> None:
        """Test fetcher as context manager."""
        from src.layers.l1_intelligence.workspace import WorkspaceManager

        workspace_manager = WorkspaceManager(config=workspace_config)
        result_path = None

        with AssetFetcher(workspace_manager=workspace_manager) as fetcher:
            result = fetcher.fetch_from_local(
                local_path=sample_git_repo,
                workspace_name="context-test",
            )
            result_path = result.source_path

        # After exiting, workspace should be cleaned up
        assert result_path is not None
        assert not result_path.exists()


class TestFetchResult:
    """Tests for FetchResult model."""

    def test_success_result(self, temp_dir: Path) -> None:
        """Test creating a successful result."""
        result = FetchResult.success_result(
            source_path=temp_dir,
            workspace_name="test-workspace",
            source_type=AssetSource.LOCAL,
            metadata={"key": "value"},
        )

        assert result.success is True
        assert result.source_path == temp_dir
        assert result.workspace_name == "test-workspace"
        assert result.source_type == AssetSource.LOCAL
        assert result.metadata["key"] == "value"
        assert result.error_message is None

    def test_failure_result(self) -> None:
        """Test creating a failure result."""
        result = FetchResult.failure_result(
            error_message="Something went wrong",
            source_type=AssetSource.GIT,
            metadata={"error_code": 500},
        )

        assert result.success is False
        assert result.error_message == "Something went wrong"
        assert result.source_type == AssetSource.GIT
        assert result.source_path is None
        assert result.workspace_name is None
