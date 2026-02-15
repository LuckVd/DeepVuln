"""Tests for WorkspaceManager."""

import shutil
from pathlib import Path

import pytest

from src.core.exceptions.errors import WorkspaceError
from src.layers.l1_intelligence.workspace import WorkspaceManager
from src.models.workspace import WorkspaceConfig, WorkspaceStatus


class TestWorkspaceManager:
    """Tests for WorkspaceManager class."""

    def test_create_workspace(self, workspace_manager: WorkspaceManager) -> None:
        """Test basic workspace creation."""
        workspace = workspace_manager.create()

        assert workspace.name is not None
        assert workspace.path.exists()
        assert workspace.status == WorkspaceStatus.ACTIVE
        assert workspace.name in workspace_manager.workspaces

    def test_create_workspace_with_name(self, workspace_manager: WorkspaceManager) -> None:
        """Test workspace creation with custom name."""
        workspace = workspace_manager.create(name="my-workspace")

        assert workspace.name == "my-workspace"
        assert workspace.path.name == "my-workspace"

    def test_create_workspace_with_source_info(self, workspace_manager: WorkspaceManager) -> None:
        """Test workspace creation with source information."""
        workspace = workspace_manager.create(
            name="source-workspace",
            source_type="git",
            source_path="https://github.com/user/repo.git",
        )

        assert workspace.source_type == "git"
        assert workspace.source_path == "https://github.com/user/repo.git"

    def test_create_duplicate_workspace_raises_error(
        self, workspace_manager: WorkspaceManager
    ) -> None:
        """Test that creating duplicate workspace raises error."""
        workspace_manager.create(name="duplicate")

        with pytest.raises(WorkspaceError, match="already exists"):
            workspace_manager.create(name="duplicate")

    def test_workspace_limit(self, workspace_config: WorkspaceConfig, temp_dir: Path) -> None:
        """Test workspace limit enforcement."""
        config = WorkspaceConfig(
            base_dir=workspace_config.base_dir,
            max_workspaces=2,
            auto_cleanup=True,
            prefix="test_",
        )
        manager = WorkspaceManager(config=config)

        # Create max allowed workspaces
        manager.create(name="ws1")
        manager.create(name="ws2")

        # Should raise error when limit is reached
        with pytest.raises(WorkspaceError, match="Maximum workspace limit"):
            manager.create(name="ws3")

    def test_cleanup_workspace(self, workspace_manager: WorkspaceManager) -> None:
        """Test workspace cleanup."""
        workspace = workspace_manager.create(name="to-cleanup")
        path = workspace.path

        assert path.exists()
        assert "to-cleanup" in workspace_manager.workspaces

        result = workspace_manager.cleanup("to-cleanup")

        assert result is True
        assert not path.exists()
        assert "to-cleanup" not in workspace_manager.workspaces

    def test_cleanup_nonexistent_workspace_raises_error(
        self, workspace_manager: WorkspaceManager
    ) -> None:
        """Test that cleaning up non-existent workspace raises error."""
        with pytest.raises(WorkspaceError, match="not found"):
            workspace_manager.cleanup("nonexistent")

    def test_cleanup_all(self, workspace_manager: WorkspaceManager) -> None:
        """Test cleanup of all workspaces."""
        ws1 = workspace_manager.create(name="ws1")
        ws2 = workspace_manager.create(name="ws2")
        ws3 = workspace_manager.create(name="ws3")

        assert workspace_manager.active_count == 3

        cleaned = workspace_manager.cleanup_all()

        assert cleaned == 3
        assert workspace_manager.active_count == 0
        assert not ws1.path.exists()
        assert not ws2.path.exists()
        assert not ws3.path.exists()

    def test_get_workspace(self, workspace_manager: WorkspaceManager) -> None:
        """Test getting workspace info."""
        workspace_manager.create(name="test-get")
        info = workspace_manager.get("test-get")

        assert info is not None
        assert info.name == "test-get"

    def test_get_nonexistent_workspace(self, workspace_manager: WorkspaceManager) -> None:
        """Test getting non-existent workspace returns None."""
        info = workspace_manager.get("nonexistent")
        assert info is None

    def test_context_manager(self, workspace_config: WorkspaceConfig) -> None:
        """Test workspace manager as context manager."""
        with WorkspaceManager(config=workspace_config) as manager:
            workspace = manager.create(name="context-ws")
            assert workspace.path.exists()

        # After exiting, workspace should be cleaned up
        assert not workspace.path.exists()

    def test_workspace_context(self, workspace_manager: WorkspaceManager) -> None:
        """Test individual workspace context manager."""
        path = None
        with workspace_manager.workspace() as workspace:
            path = workspace.path
            assert path.exists()
            assert workspace.status == WorkspaceStatus.ACTIVE

        # After exiting, workspace should be cleaned up
        assert path is not None
        assert not path.exists()

    def test_auto_cleanup_disabled(self, temp_dir: Path) -> None:
        """Test workspace manager with auto_cleanup disabled."""
        config = WorkspaceConfig(
            base_dir=temp_dir / "workspaces",
            max_workspaces=5,
            auto_cleanup=False,
            prefix="test_",
        )
        manager = WorkspaceManager(config=config)
        workspace = manager.create(name="no-auto-cleanup")
        path = workspace.path

        # Manually exit context (simulate __exit__)
        manager.__exit__(None, None, None)

        # Workspace should still exist since auto_cleanup is False
        assert path.exists()

        # Manual cleanup
        shutil.rmtree(temp_dir / "workspaces", ignore_errors=True)

    def test_unique_name_generation(self, workspace_manager: WorkspaceManager) -> None:
        """Test that auto-generated names are unique."""
        ws1 = workspace_manager.create()
        ws2 = workspace_manager.create()
        ws3 = workspace_manager.create()

        names = [ws1.name, ws2.name, ws3.name]
        assert len(set(names)) == 3  # All names are unique

    def test_prefix_applied(self, workspace_manager: WorkspaceManager) -> None:
        """Test that prefix is applied to workspace names."""
        workspace = workspace_manager.create()
        assert workspace.name.startswith("test_")


class TestWorkspaceInfo:
    """Tests for WorkspaceInfo model."""

    def test_mark_active(self, workspace_manager: WorkspaceManager) -> None:
        """Test marking workspace as active."""
        workspace = workspace_manager.create(name="status-test")
        workspace.mark_active()
        assert workspace.status == WorkspaceStatus.ACTIVE

    def test_mark_cleanup(self, workspace_manager: WorkspaceManager) -> None:
        """Test marking workspace for cleanup."""
        workspace = workspace_manager.create(name="cleanup-status-test")
        workspace.mark_cleanup()
        assert workspace.status == WorkspaceStatus.CLEANUP

    def test_mark_disposed(self, workspace_manager: WorkspaceManager) -> None:
        """Test marking workspace as disposed."""
        workspace = workspace_manager.create(name="disposed-status-test")
        workspace.mark_disposed()
        assert workspace.status == WorkspaceStatus.DISPOSED
