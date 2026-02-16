"""Tests for GitOperations."""

from pathlib import Path

import pytest
from git import Repo

from src.core.exceptions.errors import GitError
from src.layers.l1_intelligence.git_operations import GitOperations
from src.models.fetcher import GitRef, GitRefType


class TestGitOperations:
    """Tests for GitOperations class."""

    def test_is_git_repo_true(self, sample_git_repo: Path) -> None:
        """Test detecting a Git repository."""
        git_ops = GitOperations()
        assert git_ops.is_git_repo(sample_git_repo) is True

    def test_is_git_repo_false(self, empty_temp_dir: Path) -> None:
        """Test detecting non-Git directory."""
        git_ops = GitOperations()
        assert git_ops.is_git_repo(empty_temp_dir) is False

    def test_open_repo(self, sample_git_repo: Path) -> None:
        """Test opening an existing repository."""
        git_ops = GitOperations()
        repo = git_ops.open_repo(sample_git_repo)
        assert repo is not None
        assert not repo.bare

    def test_open_repo_invalid_path(self, empty_temp_dir: Path) -> None:
        """Test opening invalid repository raises error."""
        git_ops = GitOperations()
        with pytest.raises(GitError, match="Not a valid Git repository"):
            git_ops.open_repo(empty_temp_dir)

    def test_get_current_ref_branch(
        self, sample_git_repo_with_commits: tuple[Path, Repo]
    ) -> None:
        """Test getting current branch name."""
        repo_path, repo = sample_git_repo_with_commits
        git_ops = GitOperations()

        current_ref = git_ops.get_current_ref(repo)
        assert current_ref == "master" or current_ref == "main"

    def test_get_commit_info(
        self, sample_git_repo_with_commits: tuple[Path, Repo]
    ) -> None:
        """Test getting commit information."""
        repo_path, repo = sample_git_repo_with_commits
        git_ops = GitOperations()

        info = git_ops.get_commit_info(repo)

        assert "sha" in info
        assert "short_sha" in info
        assert "message" in info
        assert len(info["short_sha"]) == 8

    def test_checkout_branch(
        self, sample_git_repo: Path, temp_dir: Path
    ) -> None:
        """Test checking out a branch."""
        git_ops = GitOperations()

        # Clone to a new location
        clone_path = temp_dir / "cloned_repo"
        repo = git_ops.clone(str(sample_git_repo), clone_path)

        # Checkout feature branch
        git_ref = GitRef(ref_type=GitRefType.BRANCH, ref_value="feature-branch")
        git_ops.checkout(repo, git_ref)

        current_ref = git_ops.get_current_ref(repo)
        assert current_ref == "feature-branch"

    def test_checkout_tag(self, sample_git_repo: Path, temp_dir: Path) -> None:
        """Test checking out a tag."""
        git_ops = GitOperations()

        # Clone to a new location
        clone_path = temp_dir / "cloned_repo_tag"
        repo = git_ops.clone(str(sample_git_repo), clone_path)

        # Checkout tag
        git_ref = GitRef(ref_type=GitRefType.TAG, ref_value="v1.0.0")
        git_ops.checkout(repo, git_ref)

        # Should be in detached HEAD state
        assert repo.head.is_detached

    def test_checkout_commit(
        self, sample_git_repo_with_commits: tuple[Path, Repo], temp_dir: Path
    ) -> None:
        """Test checking out a specific commit."""
        repo_path, original_repo = sample_git_repo_with_commits
        git_ops = GitOperations()

        # Clone to a new location
        clone_path = temp_dir / "cloned_repo_commit"
        repo = git_ops.clone(str(repo_path), clone_path)

        # Get the first commit hash
        first_commit = list(original_repo.iter_commits())[-1].hexsha

        # Checkout specific commit
        git_ref = GitRef(ref_type=GitRefType.COMMIT, ref_value=first_commit)
        git_ops.checkout(repo, git_ref)

        assert repo.head.is_detached
        assert repo.head.commit.hexsha == first_commit

    def test_checkout_nonexistent_branch_raises_error(
        self, sample_git_repo: Path, temp_dir: Path
    ) -> None:
        """Test that checking out non-existent branch raises error."""
        git_ops = GitOperations()

        clone_path = temp_dir / "cloned_repo_error"
        repo = git_ops.clone(str(sample_git_repo), clone_path)

        git_ref = GitRef(ref_type=GitRefType.BRANCH, ref_value="nonexistent-branch")

        with pytest.raises(GitError, match="Branch not found"):
            git_ops.checkout(repo, git_ref)

    def test_checkout_nonexistent_tag_raises_error(
        self, sample_git_repo: Path, temp_dir: Path
    ) -> None:
        """Test that checking out non-existent tag raises error."""
        git_ops = GitOperations()

        clone_path = temp_dir / "cloned_repo_tag_error"
        repo = git_ops.clone(str(sample_git_repo), clone_path)

        git_ref = GitRef(ref_type=GitRefType.TAG, ref_value="v99.0.0")

        with pytest.raises(GitError, match="Tag not found"):
            git_ops.checkout(repo, git_ref)

    def test_clone_with_depth(
        self, sample_git_repo_with_commits: tuple[Path, Repo], temp_dir: Path
    ) -> None:
        """Test shallow clone with depth parameter."""
        repo_path, _ = sample_git_repo_with_commits
        git_ops = GitOperations()

        clone_path = temp_dir / "shallow_clone"
        # Use file:// prefix to force a proper shallow clone
        repo = git_ops.clone(f"file://{repo_path}", clone_path, depth=1)

        # Shallow clone should only have limited history
        commit_count = sum(1 for _ in repo.iter_commits())
        assert commit_count == 1

    def test_clone_full(
        self, sample_git_repo_with_commits: tuple[Path, Repo], temp_dir: Path
    ) -> None:
        """Test full clone (depth=0)."""
        repo_path, _ = sample_git_repo_with_commits
        git_ops = GitOperations()

        clone_path = temp_dir / "full_clone"
        repo = git_ops.clone(f"file://{repo_path}", clone_path, depth=0)

        # Full clone should have all commits
        commit_count = sum(1 for _ in repo.iter_commits())
        assert commit_count == 3


class TestGitRef:
    """Tests for GitRef model."""

    def test_git_ref_branch(self) -> None:
        """Test GitRef for branch."""
        ref = GitRef(ref_type=GitRefType.BRANCH, ref_value="main")
        assert str(ref) == "branch:main"

    def test_git_ref_tag(self) -> None:
        """Test GitRef for tag."""
        ref = GitRef(ref_type=GitRefType.TAG, ref_value="v1.0.0")
        assert str(ref) == "tag:v1.0.0"

    def test_git_ref_commit(self) -> None:
        """Test GitRef for commit."""
        ref = GitRef(ref_type=GitRefType.COMMIT, ref_value="abc123")
        assert str(ref) == "commit:abc123"
