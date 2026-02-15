"""Pytest configuration and shared fixtures."""

import shutil
import tempfile
from pathlib import Path
from typing import Generator

import pytest
from git import Repo

from src.layers.l1_intelligence.workspace import WorkspaceManager
from src.models.workspace import WorkspaceConfig


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory that is cleaned up after the test.

    Yields:
        Path to the temporary directory.
    """
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def workspace_config(temp_dir: Path) -> WorkspaceConfig:
    """Create a workspace configuration for testing.

    Args:
        temp_dir: Temporary directory fixture.

    Returns:
        WorkspaceConfig instance.
    """
    return WorkspaceConfig(
        base_dir=temp_dir / "workspaces",
        max_workspaces=5,
        auto_cleanup=True,
        prefix="test_",
    )


@pytest.fixture
def workspace_manager(workspace_config: WorkspaceConfig) -> WorkspaceManager:
    """Create a workspace manager for testing.

    Args:
        workspace_config: Workspace configuration fixture.

    Returns:
        WorkspaceManager instance.
    """
    return WorkspaceManager(config=workspace_config)


@pytest.fixture
def sample_git_repo(temp_dir: Path) -> Generator[Path, None, None]:
    """Create a sample Git repository for testing.

    Args:
        temp_dir: Temporary directory fixture.

    Yields:
        Path to the sample Git repository.
    """
    repo_path = temp_dir / "sample_repo"
    repo_path.mkdir()

    # Initialize repository
    repo = Repo.init(repo_path)

    # Create a sample file
    sample_file = repo_path / "README.md"
    sample_file.write_text("# Sample Repository\n\nThis is a test repository.\n")

    # Create src directory
    src_dir = repo_path / "src"
    src_dir.mkdir()
    (src_dir / "__init__.py").write_text('"""Sample package."""\n')
    (src_dir / "main.py").write_text('def main():\n    print("Hello, World!")\n')

    # Commit
    repo.index.add(["README.md", "src/__init__.py", "src/main.py"])
    repo.index.commit("Initial commit")

    # Create a branch
    repo.create_head("feature-branch")
    repo.create_head("develop")

    # Create a tag
    repo.create_tag("v1.0.0")

    yield repo_path

    # Cleanup is handled by temp_dir fixture


@pytest.fixture
def sample_git_repo_with_commits(temp_dir: Path) -> Generator[tuple[Path, Repo], None, None]:
    """Create a Git repository with multiple commits.

    Args:
        temp_dir: Temporary directory fixture.

    Yields:
        Tuple of (path, repo) for the repository.
    """
    repo_path = temp_dir / "multi_commit_repo"
    repo_path.mkdir()

    repo = Repo.init(repo_path)

    # First commit
    (repo_path / "file1.txt").write_text("Content 1\n")
    repo.index.add(["file1.txt"])
    commit1 = repo.index.commit("First commit")

    # Second commit
    (repo_path / "file2.txt").write_text("Content 2\n")
    repo.index.add(["file2.txt"])
    commit2 = repo.index.commit("Second commit")

    # Third commit
    (repo_path / "file3.txt").write_text("Content 3\n")
    repo.index.add(["file3.txt"])
    commit3 = repo.index.commit("Third commit")

    yield repo_path, repo

    # Cleanup handled by temp_dir


@pytest.fixture
def empty_temp_dir(temp_dir: Path) -> Path:
    """Create an empty directory for testing.

    Args:
        temp_dir: Temporary directory fixture.

    Returns:
        Path to empty directory.
    """
    empty_dir = temp_dir / "empty"
    empty_dir.mkdir()
    return empty_dir
