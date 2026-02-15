"""Git operations wrapper with retry support."""

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from git import Repo
from git.exc import GitCommandError, InvalidGitRepositoryError

from src.core.config.settings import get_settings
from src.core.exceptions.errors import GitError as DeepVulnGitError
from src.core.logger.logger import get_logger
from src.models.fetcher import GitRef, GitRefType

T = TypeVar("T")

logger = get_logger(__name__)


class GitOperations:
    """Handles Git clone and checkout operations."""

    def __init__(
        self,
        clone_timeout: int | None = None,
        retry_attempts: int | None = None,
        retry_delay: int | None = None,
        verify_ssl: bool | None = None,
    ) -> None:
        """Initialize Git operations.

        Args:
            clone_timeout: Timeout for clone operations in seconds.
            retry_attempts: Number of retry attempts for failed operations.
            retry_delay: Delay between retries in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        settings = get_settings()

        self.clone_timeout = clone_timeout or settings.git.clone_timeout
        self.retry_attempts = retry_attempts or settings.git.retry_attempts
        self.retry_delay = retry_delay or settings.git.retry_delay
        self.verify_ssl = verify_ssl if verify_ssl is not None else settings.git.verify_ssl

    def _retry_operation(
        self,
        operation: Callable[..., T],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Execute an operation with retry logic.

        Args:
            operation: Callable to execute.
            *args: Positional arguments for the operation.
            **kwargs: Keyword arguments for the operation.

        Returns:
            Result of the operation.

        Raises:
            DeepVulnGitError: If all retries fail.
        """
        last_error: Exception | None = None

        for attempt in range(1, self.retry_attempts + 1):
            try:
                return operation(*args, **kwargs)
            except (GitCommandError, Exception) as e:
                last_error = e
                logger.warning(
                    f"Git operation failed (attempt {attempt}/{self.retry_attempts}): {e}"
                )
                if attempt < self.retry_attempts:
                    logger.info(f"Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)

        raise DeepVulnGitError(
            f"Git operation failed after {self.retry_attempts} attempts",
            details={"last_error": str(last_error)},
        )

    def is_git_repo(self, path: Path) -> bool:
        """Check if a path is a Git repository.

        Args:
            path: Path to check.

        Returns:
            True if path is a Git repository.
        """
        try:
            Repo(path)
            return True
        except (InvalidGitRepositoryError, Exception):
            return False

    def clone(
        self,
        repo_url: str,
        target_path: Path,
        depth: int = 0,
        git_ref: GitRef | None = None,
    ) -> Repo:
        """Clone a Git repository.

        Args:
            repo_url: URL of the repository to clone.
            target_path: Local path to clone into.
            depth: Clone depth (0 = full clone).
            git_ref: Optional Git reference to checkout after clone.

        Returns:
            Cloned Repo object.

        Raises:
            GitError: If clone fails.
        """
        logger.info(f"Cloning repository: {repo_url}")

        clone_kwargs: dict[str, Any] = {
            "url": repo_url,
            "to_path": str(target_path),
        }

        # Set clone depth
        if depth > 0:
            clone_kwargs["depth"] = depth

        # For specific refs, we may need to adjust clone strategy
        if git_ref and git_ref.ref_type == GitRefType.TAG:
            # For tags, clone with --single-branch if depth is set
            if depth > 0:
                clone_kwargs["branch"] = git_ref.ref_value

        def _clone() -> Repo:
            return Repo.clone_from(**clone_kwargs)

        repo = self._retry_operation(_clone)
        logger.info(f"Successfully cloned {repo_url} to {target_path}")

        # Checkout specific ref if provided
        if git_ref:
            self.checkout(repo, git_ref)

        return repo

    def checkout(self, repo: Repo, git_ref: GitRef) -> None:
        """Checkout a specific Git reference.

        Args:
            repo: Repo object.
            git_ref: Git reference to checkout.

        Raises:
            GitError: If checkout fails.
        """
        ref_value = git_ref.ref_value
        ref_type = git_ref.ref_type

        logger.info(f"Checking out {ref_type.value}: {ref_value}")

        try:
            if ref_type == GitRefType.BRANCH:
                # Check if branch exists locally, otherwise track from origin
                branch_name = ref_value
                if branch_name not in [h.name for h in repo.heads]:
                    # Try to checkout from remote
                    origin = repo.remote(name="origin")
                    origin.fetch()

                    # Check if remote branch exists
                    remote_branch = f"origin/{branch_name}"
                    if remote_branch in [ref.name for ref in repo.refs]:
                        repo.git.checkout(remote_branch, b=branch_name)
                    else:
                        raise DeepVulnGitError(
                            f"Branch not found: {branch_name}",
                            git_ref=str(git_ref),
                        )
                else:
                    repo.heads[branch_name].checkout()

            elif ref_type == GitRefType.TAG:
                # Fetch tags first
                repo.git.fetch("--tags")
                # Checkout the tag
                if ref_value in [t.name for t in repo.tags]:
                    repo.git.checkout(ref_value)
                else:
                    raise DeepVulnGitError(
                        f"Tag not found: {ref_value}",
                        git_ref=str(git_ref),
                    )

            elif ref_type == GitRefType.COMMIT:
                # Checkout specific commit
                repo.git.checkout(ref_value)

            logger.info(f"Successfully checked out {ref_type.value}: {ref_value}")

        except GitCommandError as e:
            raise DeepVulnGitError(
                f"Failed to checkout {ref_type.value}: {ref_value}",
                git_ref=str(git_ref),
                details={"error": str(e)},
            ) from e

    def get_current_ref(self, repo: Repo) -> str:
        """Get the current Git reference (branch/commit/tag).

        Args:
            repo: Repo object.

        Returns:
            Current reference name.
        """
        try:
            # Check if on a branch
            if repo.head.is_detached:
                return repo.head.commit.hexsha[:8]
            return repo.active_branch.name
        except (TypeError, Exception):
            return repo.head.commit.hexsha[:8]

    def get_commit_info(self, repo: Repo) -> dict:
        """Get current commit information.

        Args:
            repo: Repo object.

        Returns:
            Dictionary with commit information.
        """
        commit = repo.head.commit
        return {
            "sha": commit.hexsha,
            "short_sha": commit.hexsha[:8],
            "message": commit.message.strip() if commit.message else "",
            "author": str(commit.author) if commit.author else "",
            "committed_date": commit.committed_datetime.isoformat() if commit.committed_datetime else None,
        }

    def open_repo(self, path: Path) -> Repo:
        """Open an existing Git repository.

        Args:
            path: Path to the repository.

        Returns:
            Repo object.

        Raises:
            GitError: If repository cannot be opened.
        """
        try:
            return Repo(path)
        except (InvalidGitRepositoryError, Exception) as e:
            raise DeepVulnGitError(
                f"Not a valid Git repository: {path}",
                details={"path": str(path), "error": str(e)},
            ) from e
