"""
Change Detector - Git change detection for incremental analysis.

Detects file changes between commits/branches to enable incremental scanning
by identifying what files have been added, modified, or deleted.
"""

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class ChangeType(str, Enum):
    """Type of file change."""

    ADDED = "added"  # New file
    MODIFIED = "modified"  # Existing file modified
    DELETED = "deleted"  # File removed
    RENAMED = "renamed"  # File renamed (old_path -> new_path)
    COPIED = "copied"  # File copied (old_path -> new_path)
    TYPE_CHANGED = "type_changed"  # File type changed (e.g., symlink to regular)


@dataclass
class ChangeInfo:
    """Information about a single file change."""

    path: str  # Relative file path (new path for renamed)
    change_type: ChangeType
    old_path: str | None = None  # Original path for renamed/copied files
    additions: int = 0  # Lines added
    deletions: int = 0  # Lines deleted
    binary: bool = False  # Is this a binary file?
    similarity: float | None = None  # Similarity index for renames (0-100)

    # Content hashes for cache invalidation
    old_hash: str | None = None  # Hash of old content (if available)
    new_hash: str | None = None  # Hash of new content (if available)

    # Hunk information for partial change detection
    hunks: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_renamed(self) -> bool:
        """Check if this is a rename."""
        return self.change_type in (ChangeType.RENAMED, ChangeType.COPIED)

    @property
    def net_lines(self) -> int:
        """Get net line change."""
        return self.additions - self.deletions

    @property
    def total_changes(self) -> int:
        """Get total lines changed."""
        return self.additions + self.deletions


@dataclass
class DiffResult:
    """Result of a diff operation."""

    base_ref: str  # Base commit/branch
    head_ref: str  # Head commit/branch
    changes: list[ChangeInfo] = field(default_factory=list)
    files_added: int = 0
    files_modified: int = 0
    files_deleted: int = 0
    files_renamed: int = 0
    total_additions: int = 0
    total_deletions: int = 0

    # Timing
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    duration_ms: float = 0.0

    @property
    def total_files_changed(self) -> int:
        """Get total number of files changed."""
        return len(self.changes)

    @property
    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return len(self.changes) > 0

    def get_changes_by_type(self, change_type: ChangeType) -> list[ChangeInfo]:
        """Get changes filtered by type."""
        return [c for c in self.changes if c.change_type == change_type]

    def get_changed_paths(self, include_deleted: bool = True) -> list[str]:
        """Get list of all changed file paths."""
        paths = []
        for change in self.changes:
            if change.change_type == ChangeType.DELETED:
                if include_deleted:
                    paths.append(change.path)
            elif change.is_renamed:
                paths.append(change.path)
                if change.old_path:
                    paths.append(change.old_path)
            else:
                paths.append(change.path)
        return list(set(paths))

    def get_file_extensions(self) -> dict[str, int]:
        """Get count of changes by file extension."""
        extensions: dict[str, int] = {}
        for change in self.changes:
            path = change.path
            if "." in path:
                ext = path.rsplit(".", 1)[-1].lower()
                extensions[ext] = extensions.get(ext, 0) + 1
        return extensions


class ChangeDetector:
    """
    Detects git changes for incremental analysis.

    Uses git diff to identify file changes between commits, branches,
    or working directory states. Provides detailed change information
    for intelligent incremental scanning.
    """

    # File patterns to ignore by default
    DEFAULT_IGNORE_PATTERNS = [
        # Version control
        r"^\.git/",
        r"^\.gitignore$",
        r"^\.gitattributes$",
        # IDE and editor
        r"^\.idea/",
        r"^\.vscode/",
        r"\.swp$",
        r"\.swo$",
        r"~$",
        # Build outputs
        r"^build/",
        r"^dist/",
        r"^target/",
        r"^node_modules/",
        r"^\.venv/",
        r"^venv/",
        r"^__pycache__/",
        r"\.pyc$",
        r"\.pyo$",
        r"\.class$",
        r"\.o$",
        r"\.so$",
        r"\.dylib$",
        r"\.dll$",
        r"\.exe$",
        # Generated files
        r"\.min\.js$",
        r"\.min\.css$",
        r"\.map$",
        # Lock files (usually don't affect security)
        r"^package-lock\.json$",
        r"^yarn\.lock$",
        r"^pnpm-lock\.yaml$",
        r"^Cargo\.lock$",
        r"^composer\.lock$",
        # Documentation (no code)
        r"^docs?/",
        r"\.md$",
        r"\.rst$",
        r"\.txt$",
        # Test files (configurable)
        # r"_test\.py$",
        # r"\.test\.js$",
        # r"\.spec\.ts$",
        # CI/CD configs
        r"^\.github/",
        r"^\.gitlab-ci\.yml$",
        r"^\.travis\.yml$",
        r"^Jenkinsfile$",
        # Docker
        r"^Dockerfile",
        r"^docker-compose",
        r"^\.dockerignore$",
    ]

    def __init__(
        self,
        repo_path: str | Path,
        ignore_patterns: list[str] | None = None,
        include_patterns: list[str] | None = None,
        detect_renames: bool = True,
        detect_copies: bool = False,
        similarity_threshold: int = 50,
    ):
        """
        Initialize the change detector.

        Args:
            repo_path: Path to the git repository.
            ignore_patterns: Additional patterns to ignore (regex).
            include_patterns: Patterns to include even if ignored (regex).
            detect_renames: Whether to detect renamed files.
            detect_copies: Whether to detect copied files.
            similarity_threshold: Similarity threshold for rename detection (0-100).
        """
        self.repo_path = Path(repo_path).resolve()
        self.ignore_patterns = list(self.DEFAULT_IGNORE_PATTERNS)
        if ignore_patterns:
            self.ignore_patterns.extend(ignore_patterns)
        self.include_patterns = include_patterns or []
        self.detect_renames = detect_renames
        self.detect_copies = detect_copies
        self.similarity_threshold = similarity_threshold

        self._compiled_ignore: list[re.Pattern] | None = None
        self._compiled_include: list[re.Pattern] | None = None

        # Validate repo
        if not (self.repo_path / ".git").exists():
            raise ValueError(f"Not a git repository: {repo_path}")

    def _compile_patterns(self) -> None:
        """Compile regex patterns for filtering."""
        if self._compiled_ignore is None:
            self._compiled_ignore = [
                re.compile(p) for p in self.ignore_patterns
            ]
        if self._compiled_include is None:
            self._compiled_include = [
                re.compile(p) for p in self.include_patterns
            ]

    def _should_ignore(self, path: str) -> bool:
        """Check if a path should be ignored."""
        self._compile_patterns()

        # Check include patterns first (they override ignore)
        for pattern in self._compiled_include:
            if pattern.search(path):
                return False

        # Check ignore patterns
        for pattern in self._compiled_ignore:
            if pattern.search(path):
                return True

        return False

    async def _run_git_command(
        self,
        args: list[str],
        timeout: int = 60,
    ) -> tuple[str, str, int]:
        """
        Run a git command asynchronously.

        Args:
            args: Git command arguments.
            timeout: Command timeout in seconds.

        Returns:
            Tuple of (stdout, stderr, return_code).
        """
        cmd = ["git"] + args
        logger.debug(f"Running git command: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=self.repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            return (
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
                proc.returncode or 0,
            )
        except asyncio.TimeoutError:
            logger.error(f"Git command timed out: {' '.join(cmd)}")
            raise TimeoutError(f"Git command timed out: {' '.join(cmd)}")

    def _parse_diff_status(self, status_line: str) -> tuple[ChangeType, str | None]:
        """
        Parse git diff status line.

        Args:
            status_line: Line from git diff --raw or --name-status.

        Returns:
            Tuple of (ChangeType, old_path_for_rename).
        """
        if not status_line.strip():
            return ChangeType.MODIFIED, None

        # Parse status code (first character or two)
        parts = status_line.strip().split("\t")
        if not parts:
            return ChangeType.MODIFIED, None

        # Handle raw format: :old_mode new_mode old_sha new_sha status\tpath
        if parts[0].startswith(":"):
            # Raw format
            status_match = re.match(r"^:\d+ \d+ [a-f0-9]+ [a-f0-9]+ ([AMDRTXC])\t", status_line)
            if status_match:
                status = status_match.group(1)
                path_parts = parts[1:]
            else:
                return ChangeType.MODIFIED, None
        else:
            # Name-status format
            status = parts[0][0] if parts[0] else "M"
            path_parts = parts[1:]

        status_map = {
            "A": ChangeType.ADDED,
            "M": ChangeType.MODIFIED,
            "D": ChangeType.DELETED,
            "R": ChangeType.RENAMED,
            "C": ChangeType.COPIED,
            "T": ChangeType.TYPE_CHANGED,
            "X": ChangeType.MODIFIED,  # Unknown change
        }

        change_type = status_map.get(status, ChangeType.MODIFIED)
        old_path = None

        # For renames and copies, path_parts contains old_path and new_path
        if change_type in (ChangeType.RENAMED, ChangeType.COPIED) and len(path_parts) >= 2:
            old_path = path_parts[0]
            new_path = path_parts[1]

        return change_type, old_path

    def _parse_numstat_line(self, line: str) -> tuple[int, int, str]:
        """
        Parse git diff --numstat line.

        Args:
            line: Line from git diff --numstat.

        Returns:
            Tuple of (additions, deletions, path).
        """
        parts = line.strip().split("\t")
        if len(parts) >= 3:
            try:
                additions = int(parts[0]) if parts[0] != "-" else 0
                deletions = int(parts[1]) if parts[1] != "-" else 0
                path = parts[2]
                return additions, deletions, path
            except ValueError:
                pass
        return 0, 0, ""

    async def detect_changes(
        self,
        base_ref: str = "HEAD~1",
        head_ref: str = "HEAD",
        include_untracked: bool = False,
    ) -> DiffResult:
        """
        Detect changes between two git references.

        Args:
            base_ref: Base commit/branch (default: previous commit).
            head_ref: Head commit/branch (default: current commit).
            include_untracked: Include untracked files in working directory.

        Returns:
            DiffResult containing all detected changes.
        """
        start_time = datetime.now(UTC)
        logger.info(f"Detecting changes: {base_ref}..{head_ref}")

        result = DiffResult(base_ref=base_ref, head_ref=head_ref)

        try:
            # Build diff arguments
            diff_args = [
                "diff",
                "--raw",  # Get detailed status
                "--numstat",  # Get line counts
                "--find-renames", f"-M{self.similarity_threshold}%",
            ]

            if self.detect_copies:
                diff_args.append("--find-copies")
                diff_args.append(f"-C{self.similarity_threshold}%")

            # Get diff between refs
            if base_ref and head_ref:
                diff_args.extend([base_ref, head_ref])
            else:
                diff_args.append("HEAD")

            stdout, stderr, returncode = await self._run_git_command(diff_args)

            if returncode != 0:
                logger.warning(f"Git diff returned non-zero: {stderr}")

            # Parse the diff output
            changes = await self._parse_diff_output(stdout)
            result.changes = [c for c in changes if not self._should_ignore(c.path)]

            # Include untracked files if requested
            if include_untracked:
                untracked = await self._get_untracked_files()
                for path in untracked:
                    if not self._should_ignore(path):
                        result.changes.append(ChangeInfo(
                            path=path,
                            change_type=ChangeType.ADDED,
                            new_hash=await self._compute_file_hash(path),
                        ))

            # Calculate statistics
            for change in result.changes:
                if change.change_type == ChangeType.ADDED:
                    result.files_added += 1
                elif change.change_type == ChangeType.MODIFIED:
                    result.files_modified += 1
                elif change.change_type == ChangeType.DELETED:
                    result.files_deleted += 1
                elif change.is_renamed:
                    result.files_renamed += 1

                result.total_additions += change.additions
                result.total_deletions += change.deletions

        except Exception as e:
            logger.error(f"Error detecting changes: {e}")
            raise

        result.duration_ms = (datetime.now(UTC) - start_time).total_seconds() * 1000
        logger.info(
            f"Detected {result.total_files_changed} changes: "
            f"{result.files_added} added, {result.files_modified} modified, "
            f"{result.files_deleted} deleted, {result.files_renamed} renamed"
        )

        return result

    async def _parse_diff_output(self, diff_output: str) -> list[ChangeInfo]:
        """Parse git diff output into ChangeInfo objects."""
        changes: dict[str, ChangeInfo] = {}

        # Parse raw diff output
        lines = diff_output.strip().split("\n")

        for line in lines:
            if not line.strip():
                continue

            # Parse raw format lines
            if line.startswith(":"):
                change_type, old_path = self._parse_diff_status(line)

                # Extract path from raw line
                match = re.match(r"^:\d+ \d+ [a-f0-9]+ [a-f0-9]+ [AMDRTXC]\t(.+)$", line)
                if match:
                    paths = match.group(1).split("\t")

                    if change_type in (ChangeType.RENAMED, ChangeType.COPIED) and len(paths) >= 2:
                        path = paths[1]  # New path
                        old_path = paths[0]  # Old path
                    else:
                        path = paths[0]
                        old_path = None

                    if path not in changes:
                        changes[path] = ChangeInfo(
                            path=path,
                            change_type=change_type,
                            old_path=old_path,
                        )

            # Parse numstat lines
            elif line[0].isdigit() or line[0] == "-":
                additions, deletions, path = self._parse_numstat_line(line)
                if path and path in changes:
                    changes[path].additions = additions
                    changes[path].deletions = deletions

        return list(changes.values())

    async def _get_untracked_files(self) -> list[str]:
        """Get list of untracked files in working directory."""
        stdout, _, _ = await self._run_git_command(
            ["ls-files", "--others", "--exclude-standard"]
        )
        return [f.strip() for f in stdout.strip().split("\n") if f.strip()]

    async def _compute_file_hash(self, relative_path: str) -> str:
        """Compute hash of a file for cache invalidation."""
        file_path = self.repo_path / relative_path
        if not file_path.exists():
            return ""

        try:
            content = await asyncio.to_thread(file_path.read_bytes)
            return hashlib.sha256(content).hexdigest()[:16]
        except Exception as e:
            logger.debug(f"Error computing hash for {relative_path}: {e}")
            return ""

    async def detect_working_directory_changes(
        self,
        include_staged: bool = True,
        include_unstaged: bool = True,
        include_untracked: bool = False,
    ) -> DiffResult:
        """
        Detect changes in the working directory (not yet committed).

        Args:
            include_staged: Include staged changes.
            include_unstaged: Include unstaged changes.
            include_untracked: Include untracked files.

        Returns:
            DiffResult containing all detected changes.
        """
        start_time = datetime.now(UTC)
        result = DiffResult(base_ref="INDEX", head_ref="WORKDIR")
        changes: dict[str, ChangeInfo] = {}

        try:
            # Get staged changes (diff --cached)
            if include_staged:
                stdout, _, _ = await self._run_git_command(
                    ["diff", "--cached", "--name-status", "--numstat"]
                )
                staged_changes = await self._parse_diff_output(stdout)
                for c in staged_changes:
                    changes[c.path] = c

            # Get unstaged changes
            if include_unstaged:
                stdout, _, _ = await self._run_git_command(
                    ["diff", "--name-status", "--numstat"]
                )
                unstaged_changes = await self._parse_diff_output(stdout)
                for c in unstaged_changes:
                    if c.path in changes:
                        # Merge changes
                        existing = changes[c.path]
                        existing.additions += c.additions
                        existing.deletions += c.deletions
                    else:
                        changes[c.path] = c

            # Get untracked files
            if include_untracked:
                untracked = await self._get_untracked_files()
                for path in untracked:
                    if path not in changes:
                        changes[path] = ChangeInfo(
                            path=path,
                            change_type=ChangeType.ADDED,
                        )

            # Filter and add to result
            result.changes = [
                c for c in changes.values()
                if not self._should_ignore(c.path)
            ]

            # Calculate statistics
            for change in result.changes:
                if change.change_type == ChangeType.ADDED:
                    result.files_added += 1
                elif change.change_type == ChangeType.MODIFIED:
                    result.files_modified += 1
                elif change.change_type == ChangeType.DELETED:
                    result.files_deleted += 1

                result.total_additions += change.additions
                result.total_deletions += change.deletions

        except Exception as e:
            logger.error(f"Error detecting working directory changes: {e}")
            raise

        result.duration_ms = (datetime.now(UTC) - start_time).total_seconds() * 1000
        return result

    async def get_changed_files_since(
        self,
        commit_hash: str,
    ) -> list[str]:
        """
        Get list of files changed since a specific commit.

        Args:
            commit_hash: Commit hash to compare against.

        Returns:
            List of changed file paths.
        """
        stdout, _, returncode = await self._run_git_command(
            ["diff", "--name-only", f"{commit_hash}..HEAD"]
        )

        if returncode != 0:
            logger.warning(f"Failed to get changed files since {commit_hash}")
            return []

        files = [f.strip() for f in stdout.strip().split("\n") if f.strip()]
        return [f for f in files if not self._should_ignore(f)]

    async def get_commit_info(self, ref: str = "HEAD") -> dict[str, Any]:
        """
        Get information about a commit.

        Args:
            ref: Git reference (commit hash, branch, etc.).

        Returns:
            Dictionary with commit information.
        """
        stdout, _, returncode = await self._run_git_command(
            ["log", "-1", "--format=%H%n%T%n%an%n%ae%n%s%n%ct", ref]
        )

        if returncode != 0:
            return {}

        lines = stdout.strip().split("\n")
        if len(lines) >= 6:
            return {
                "hash": lines[0],
                "tree_hash": lines[1],
                "author_name": lines[2],
                "author_email": lines[3],
                "subject": lines[4],
                "timestamp": int(lines[5]),
            }

        return {}

    def get_scan_eligible_files(
        self,
        diff_result: DiffResult,
        extensions: list[str] | None = None,
    ) -> list[str]:
        """
        Get list of files eligible for scanning from a diff result.

        Args:
            diff_result: DiffResult from detect_changes.
            extensions: Optional list of file extensions to include.

        Returns:
            List of file paths eligible for scanning.
        """
        eligible = []

        for change in diff_result.changes:
            # Skip deleted files
            if change.change_type == ChangeType.DELETED:
                continue

            path = change.path

            # Check extension filter
            if extensions:
                if "." in path:
                    ext = path.rsplit(".", 1)[-1].lower()
                    if ext not in [e.lower().lstrip(".") for e in extensions]:
                        continue
                else:
                    continue

            # Check if file exists
            full_path = self.repo_path / path
            if full_path.exists() and full_path.is_file():
                eligible.append(path)

        return eligible
