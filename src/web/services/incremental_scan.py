"""Incremental scan service for analyzing only changed files.

P11-05: This module provides incremental scan functionality that compares
file changes between two Git references and only analyzes modified files.
"""

import hashlib
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from sqlalchemy.ext.asyncio import AsyncSession

from src.web.models.scan import Scan, ScanStatus
from src.web.models.database import get_session_local

logger = logging.getLogger(__name__)


# ============================================================================
# Models
# ============================================================================

class FileChange:
    """Represents a file change in Git."""

    def __init__(
        self,
        path: str,
        change_type: str,  # added, modified, deleted, renamed
        old_hash: Optional[str] = None,
        new_hash: Optional[str] = None,
    ):
        self.path = path
        self.change_type = change_type
        self.old_hash = old_hash
        self.new_hash = new_hash

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "path": self.path,
            "change_type": self.change_type,
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
        }


class IncrementalScanContext:
    """Context for incremental scan execution."""

    def __init__(
        self,
        scan_id: int,
        base_ref: str,
        head_ref: str,
        source_path: Path,
    ):
        self.scan_id = scan_id
        self.base_ref = base_ref
        self.head_ref = head_ref
        self.source_path = source_path

        # Analysis results
        self.changed_files: List[FileChange] = []
        self.files_to_scan: Set[str] = set()
        self.deleted_files: Set[str] = set()
        self.renamed_files: Dict[str, str] = {}  # old_path -> new_path

        # Statistics
        self.total_files_analyzed = 0
        self.added_files = 0
        self.modified_files = 0
        self.deleted_files_count = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "scan_id": self.scan_id,
            "base_ref": self.base_ref,
            "head_ref": self.head_ref,
            "changed_files_count": len(self.changed_files),
            "files_to_scan_count": len(self.files_to_scan),
            "deleted_files_count": len(self.deleted_files),
            "renamed_files_count": len(self.renamed_files),
            "statistics": {
                "total_files_analyzed": self.total_files_analyzed,
                "added_files": self.added_files,
                "modified_files": self.modified_files,
                "deleted_files": self.deleted_files_count,
            },
        }


# ============================================================================
# Git Utilities
# ============================================================================

class GitUtils:
    """Git utility functions for incremental scanning."""

    @staticmethod
    def run_git_command(
        repo_path: Path,
        args: List[str],
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run a Git command.

        Args:
            repo_path: Path to the Git repository
            args: Git command arguments
            capture_output: Whether to capture stdout/stderr

        Returns:
            Completed process result
        """
        cmd = ["git"] + args
        logger.debug(f"Running: {' '.join(cmd)}")

        return subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=capture_output,
            text=True,
        )

    @staticmethod
    def is_git_repository(repo_path: Path) -> bool:
        """Check if a path is a Git repository.

        Args:
            repo_path: Path to check

        Returns:
            True if path is a Git repository
        """
        git_dir = repo_path / ".git"
        return git_dir.exists() and git_dir.is_dir()

    @staticmethod
    def get_changed_files(
        repo_path: Path,
        base_ref: str,
        head_ref: str,
    ) -> List[FileChange]:
        """Get list of changed files between two Git references.

        Args:
            repo_path: Path to the Git repository
            base_ref: Base Git reference (e.g., "HEAD~1", "main")
            head_ref: Head Git reference (e.g., "HEAD", "feature-branch")

        Returns:
            List of FileChange objects

        Raises:
            subprocess.CalledProcessError: If Git command fails
        """
        logger.info(f"Getting changed files between {base_ref} and {head_ref}")

        # Get diff with rename detection
        result = GitUtils.run_git_command(
            repo_path,
            [
                "diff",
                "--name-status",
                "-M",  # Detect renames
                "-C",  # Detect copies
                f"{base_ref}...{head_ref}",
            ],
        )

        if result.returncode != 0:
            logger.error(f"Git diff failed: {result.stderr}")
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stderr)

        changes = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue

            parts = line.split("\t")
            if len(parts) < 2:
                continue

            status_code = parts[0]
            file_path = parts[1]

            # Parse status code
            change_type = "modified"
            if status_code.startswith("A"):
                change_type = "added"
            elif status_code.startswith("D"):
                change_type = "deleted"
            elif status_code.startswith("R"):
                change_type = "renamed"
            elif status_code.startswith("M"):
                change_type = "modified"

            # Handle renamed files (format: R100\told\tnew)
            if change_type == "renamed" and len(parts) >= 3:
                old_path = file_path
                new_path = parts[2]
                changes.append(FileChange(
                    path=old_path,
                    change_type=change_type,
                    new_hash=new_path,  # Use new_hash to store new path
                ))
            else:
                changes.append(FileChange(path=file_path, change_type=change_type))

        logger.info(f"Found {len(changes)} changed files")
        return changes

    @staticmethod
    def get_file_hash_at_commit(
        repo_path: Path,
        file_path: str,
        ref: str,
    ) -> Optional[str]:
        """Get Git object hash for a file at a specific reference.

        Args:
            repo_path: Path to the Git repository
            file_path: Path to the file (relative to repo root)
            ref: Git reference

        Returns:
            Git object hash or None if file doesn't exist at ref
        """
        try:
            result = GitUtils.run_git_command(
                repo_path,
                ["ls-tree", ref, file_path],
            )
            if result.returncode != 0:
                return None

            # Output format: mode type hash\tpath
            parts = result.stdout.split()
            if len(parts) >= 3:
                return parts[2]

        except Exception as e:
            logger.warning(f"Failed to get hash for {file_path} at {ref}: {e}")

        return None

    @staticmethod
    def checkout_ref(repo_path: Path, ref: str) -> bool:
        """Checkout a Git reference.

        Args:
            repo_path: Path to the Git repository
            ref: Git reference to checkout

        Returns:
            True if checkout succeeded
        """
        try:
            result = GitUtils.run_git_command(
                repo_path,
                ["checkout", "--force", ref],
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to checkout {ref}: {e}")
            return False


# ============================================================================
# File Hash Utilities
# ============================================================================

class FileHashUtils:
    """File hash calculation utilities."""

    @staticmethod
    def calculate_file_hash(file_path: Path) -> Optional[str]:
        """Calculate SHA-256 hash of a file.

        Args:
            file_path: Path to the file

        Returns:
            Hex digest of SHA-256 hash or None if file doesn't exist
        """
        if not file_path.exists() or not file_path.is_file():
            return None

        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.warning(f"Failed to calculate hash for {file_path}: {e}")
            return None

    @staticmethod
    def calculate_file_hash_content(content: str) -> str:
        """Calculate SHA-256 hash of file content.

        Args:
            content: File content as string

        Returns:
            Hex digest of SHA-256 hash
        """
        return hashlib.sha256(content.encode()).hexdigest()

    @staticmethod
    def compare_file_hashes(
        file_path: Path,
        expected_hash: Optional[str],
    ) -> bool:
        """Compare file hash with expected value.

        Args:
            file_path: Path to the file
            expected_hash: Expected hash value

        Returns:
            True if hashes match (or if expected_hash is None)
        """
        if expected_hash is None:
            return True

        actual_hash = FileHashUtils.calculate_file_hash(file_path)
        return actual_hash == expected_hash


# ============================================================================
# Incremental Scan Service
# ============================================================================

class IncrementalScanService:
    """Service for managing incremental scans."""

    def __init__(self, scan_id: int):
        """Initialize the incremental scan service.

        Args:
            scan_id: ID of the scan
        """
        self.scan_id = scan_id
        self.context: Optional[IncrementalScanContext] = None

    async def analyze_incremental_changes(
        self,
        source_path: Path,
        base_ref: str,
        head_ref: str,
    ) -> IncrementalScanContext:
        """Analyze changes between two Git references.

        Args:
            source_path: Path to the source code
            base_ref: Base Git reference
            head_ref: Head Git reference

        Returns:
            IncrementalScanContext with change analysis
        """
        logger.info(
            f"Analyzing incremental changes for scan {self.scan_id}: "
            f"{base_ref}...{head_ref}"
        )

        # Validate Git repository
        if not GitUtils.is_git_repository(source_path):
            raise ValueError(f"Not a Git repository: {source_path}")

        # Get changed files
        changed_files = GitUtils.get_changed_files(
            source_path, base_ref, head_ref
        )

        # Build context
        context = IncrementalScanContext(
            scan_id=self.scan_id,
            base_ref=base_ref,
            head_ref=head_ref,
            source_path=source_path,
        )
        context.changed_files = changed_files

        # Categorize changes
        for change in changed_files:
            if change.change_type == "added":
                context.files_to_scan.add(change.path)
                context.added_files += 1
            elif change.change_type == "modified":
                context.files_to_scan.add(change.path)
                context.modified_files += 1
            elif change.change_type == "deleted":
                context.deleted_files.add(change.path)
                context.deleted_files_count += 1
            elif change.change_type == "renamed":
                # Track rename: old_path -> new_path
                new_path = change.new_hash or ""
                context.renamed_files[change.path] = new_path
                context.files_to_scan.add(new_path)

        context.total_files_analyzed = len(changed_files)

        logger.info(
            f"Incremental analysis complete: "
            f"{context.added_files} added, {context.modified_files} modified, "
            f"{context.deleted_files_count} deleted, {len(context.renamed_files)} renamed"
        )

        return context

    async def filter_files_by_language(
        self,
        context: IncrementalScanContext,
        extensions: Optional[Set[str]] = None,
    ) -> List[str]:
        """Filter files to scan by programming language.

        Args:
            context: Incremental scan context
            extensions: Set of file extensions to include (e.g., {".py", ".js"})

        Returns:
            List of file paths to scan
        """
        if extensions is None:
            # Default to common source code extensions
            extensions = {
                ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp",
                ".cs", ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".scala",
            }

        filtered = []
        for file_path in context.files_to_scan:
            if Path(file_path).suffix in extensions:
                filtered.append(file_path)

        logger.info(f"Filtered {len(filtered)} files by language from {len(context.files_to_scan)} total")
        return filtered

    def get_files_to_scan(
        self,
        context: Optional[IncrementalScanContext] = None,
    ) -> Set[str]:
        """Get the set of files to scan for incremental mode.

        Args:
            context: Optional context (uses self.context if not provided)

        Returns:
            Set of file paths to scan
        """
        ctx = context or self.context
        if ctx is None:
            raise ValueError("No context available - call analyze_incremental_changes first")

        return ctx.files_to_scan

    def get_incremental_stats_dict(
        self,
        context: Optional[IncrementalScanContext] = None,
    ) -> Dict[str, Any]:
        """Get incremental statistics as a dictionary for storage.

        Args:
            context: Optional context (uses self.context if not provided)

        Returns:
            Dictionary with incremental scan statistics
        """
        ctx = context or self.context
        if ctx is None:
            return {}

        return {
            "base_ref": ctx.base_ref,
            "head_ref": ctx.head_ref,
            "changed_files_count": len(ctx.changed_files),
            "files_to_scan_count": len(ctx.files_to_scan),
            "added_files": ctx.added_files,
            "modified_files": ctx.modified_files,
            "deleted_files_count": ctx.deleted_files_count,
            "renamed_files_count": len(ctx.renamed_files),
        }

    async def update_scan_with_incremental_stats(
        self,
        db: AsyncSession,
        context: IncrementalScanContext,
    ) -> None:
        """Update scan record with incremental statistics.

        Args:
            db: Database session
            context: Incremental scan context
        """
        from sqlalchemy import update

        # Store incremental metadata in scan config
        metadata = {
            "incremental": True,
            "base_ref": context.base_ref,
            "head_ref": context.head_ref,
            "changed_files_count": len(context.changed_files),
            "files_to_scan_count": len(context.files_to_scan),
            "added_files": context.added_files,
            "modified_files": context.modified_files,
            "deleted_files": context.deleted_files_count,
            "renamed_files": context.renamed_files,
        }

        await db.execute(
            update(Scan)
            .where(Scan.id == self.scan_id)
            .values(
                config=metadata,
                total_files=context.total_files_analyzed,
            )
        )
        await db.commit()

        logger.info(f"Updated scan {self.scan_id} with incremental stats")


# ============================================================================
# Factory Function
# ============================================================================

def get_incremental_scan_service(
    scan_id: int,
) -> IncrementalScanService:
    """Get or create an incremental scan service instance.

    Args:
        scan_id: ID of the scan

    Returns:
        IncrementalScanService instance
    """
    return IncrementalScanService(scan_id)
