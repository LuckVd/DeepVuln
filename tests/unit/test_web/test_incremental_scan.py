"""Unit tests for incremental scan service.

P11-05: Tests for incremental scan functionality including Git diff analysis
and file hash calculation.
"""

import hashlib
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
import pytest

from src.web.services.incremental_scan import (
    FileChange,
    IncrementalScanContext,
    GitUtils,
    FileHashUtils,
    IncrementalScanService,
    get_incremental_scan_service,
)


# ============================================================================
# Test FileChange
# ============================================================================

class TestFileChange:
    """Test FileChange model."""

    def test_file_change_creation(self):
        """Test creating a FileChange object."""
        change = FileChange(
            path="test.py",
            change_type="modified",
            old_hash="abc123",
            new_hash="def456",
        )
        assert change.path == "test.py"
        assert change.change_type == "modified"
        assert change.old_hash == "abc123"
        assert change.new_hash == "def456"

    def test_file_change_to_dict(self):
        """Test converting FileChange to dictionary."""
        change = FileChange(path="test.py", change_type="added")
        data = change.to_dict()
        assert data["path"] == "test.py"
        assert data["change_type"] == "added"
        assert data["old_hash"] is None
        assert data["new_hash"] is None


# ============================================================================
# Test IncrementalScanContext
# ============================================================================

class TestIncrementalScanContext:
    """Test IncrementalScanContext model."""

    def test_context_creation(self):
        """Test creating an IncrementalScanContext."""
        context = IncrementalScanContext(
            scan_id=1,
            project_id=100,
            base_ref="HEAD~1",
            head_ref="HEAD",
            source_path=Path("/tmp/project"),
        )
        assert context.scan_id == 1
        assert context.project_id == 100
        assert context.base_ref == "HEAD~1"
        assert context.head_ref == "HEAD"
        assert len(context.changed_files) == 0
        assert len(context.files_to_scan) == 0

    def test_context_to_dict(self):
        """Test converting context to dictionary."""
        context = IncrementalScanContext(
            scan_id=1,
            project_id=100,
            base_ref="main",
            head_ref="feature",
            source_path=Path("/tmp/project"),
        )
        # Add some test data
        context.changed_files = [
            FileChange(path="test.py", change_type="added")
        ]
        context.files_to_scan.add("test.py")
        context.added_files = 1

        data = context.to_dict()
        assert data["scan_id"] == 1
        assert data["base_ref"] == "main"
        assert data["changed_files_count"] == 1
        assert data["files_to_scan_count"] == 1
        assert data["statistics"]["added_files"] == 1


# ============================================================================
# Test GitUtils
# ============================================================================

class TestGitUtils:
    """Test Git utility functions."""

    @patch("src.web.services.incremental_scan.subprocess.run")
    def test_run_git_command(self, mock_run):
        """Test running a Git command."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "test output"
        mock_run.return_value = mock_result

        result = GitUtils.run_git_command(
            Path("/tmp/repo"),
            ["status"],
        )

        assert result.returncode == 0
        mock_run.assert_called_once()

    @patch("src.web.services.incremental_scan.Path.is_dir")
    @patch("src.web.services.incremental_scan.Path.exists")
    def test_is_git_repository_true(self, mock_exists, mock_is_dir):
        """Test checking if path is a Git repository (True case)."""
        mock_exists.return_value = True
        mock_is_dir.return_value = True

        result = GitUtils.is_git_repository(Path("/tmp/repo"))
        assert result is True

    @patch("src.web.services.incremental_scan.Path.exists")
    def test_is_git_repository_false(self, mock_exists):
        """Test checking if path is a Git repository (False case)."""
        mock_exists.return_value = False

        result = GitUtils.is_git_repository(Path("/tmp/repo"))
        assert result is False

    @patch("src.web.services.incremental_scan.GitUtils.run_git_command")
    def test_get_changed_files_success(self, mock_run):
        """Test getting changed files successfully."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "M\tmodified.py\nA\tadded.py\nD\tdeleted.py\n"
        mock_run.return_value = mock_result

        changes = GitUtils.get_changed_files(
            Path("/tmp/repo"),
            "main",
            "feature",
        )

        assert len(changes) == 3
        assert changes[0].path == "modified.py"
        assert changes[0].change_type == "modified"
        assert changes[1].change_type == "added"
        assert changes[2].change_type == "deleted"

    @patch("src.web.services.incremental_scan.GitUtils.run_git_command")
    def test_get_changed_files_with_rename(self, mock_run):
        """Test getting changed files with rename detection."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        # Rename format: R100\told.py\tnew.py
        mock_result.stdout = "R100\told.py\tnew.py\nM\tmodified.py\n"
        mock_run.return_value = mock_result

        changes = GitUtils.get_changed_files(
            Path("/tmp/repo"),
            "main",
            "feature",
        )

        assert len(changes) == 2
        assert changes[0].change_type == "renamed"
        assert changes[0].path == "old.py"
        assert changes[0].new_hash == "new.py"

    @patch("src.web.services.incremental_scan.GitUtils.run_git_command")
    def test_get_changed_files_error(self, mock_run):
        """Test getting changed files with Git error."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "fatal: bad revision"
        mock_run.return_value = mock_result

        with pytest.raises(subprocess.CalledProcessError):
            GitUtils.get_changed_files(
                Path("/tmp/repo"),
                "invalid",
                "HEAD",
            )

    @patch("src.web.services.incremental_scan.GitUtils.run_git_command")
    def test_get_file_hash_at_commit_success(self, mock_run):
        """Test getting file hash at commit."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "100644 blob abc123def456\ttest.py\n"
        mock_run.return_value = mock_result

        hash_value = GitUtils.get_file_hash_at_commit(
            Path("/tmp/repo"),
            "test.py",
            "HEAD",
        )

        assert hash_value == "abc123def456"

    @patch("src.web.services.incremental_scan.GitUtils.run_git_command")
    def test_get_file_hash_at_commit_not_found(self, mock_run):
        """Test getting file hash for non-existent file."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        hash_value = GitUtils.get_file_hash_at_commit(
            Path("/tmp/repo"),
            "nonexistent.py",
            "HEAD",
        )

        assert hash_value is None

    @patch("src.web.services.incremental_scan.GitUtils.run_git_command")
    def test_checkout_ref_success(self, mock_run):
        """Test checking out a Git reference."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        result = GitUtils.checkout_ref(Path("/tmp/repo"), "main")
        assert result is True

    @patch("src.web.services.incremental_scan.GitUtils.run_git_command")
    def test_checkout_ref_failure(self, mock_run):
        """Test checkout failure."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        result = GitUtils.checkout_ref(Path("/tmp/repo"), "invalid-ref")
        assert result is False


# ============================================================================
# Test FileHashUtils
# ============================================================================

class TestFileHashUtils:
    """Test file hash utilities."""

    def test_calculate_file_hash_success(self, tmp_path):
        """Test calculating file hash successfully."""
        # Create a temporary file
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        result = FileHashUtils.calculate_file_hash(test_file)
        assert result is not None
        assert len(result) == 64  # SHA-256 hex length
        # Verify it matches expected hash
        expected = hashlib.sha256(b"test content").hexdigest()
        assert result == expected

    @patch("src.web.services.incremental_scan.Path.exists")
    def test_calculate_file_hash_not_found(self, mock_exists):
        """Test calculating hash for non-existent file."""
        mock_exists.return_value = False

        result = FileHashUtils.calculate_file_hash(Path("/tmp/nonexistent.txt"))
        assert result is None

    def test_calculate_file_hash_content(self):
        """Test calculating hash from content string."""
        content = "test content"
        result = FileHashUtils.calculate_file_hash_content(content)

        expected = hashlib.sha256(content.encode()).hexdigest()
        assert result == expected

    @patch("src.web.services.incremental_scan.FileHashUtils.calculate_file_hash")
    def test_compare_file_hashes_match(self, mock_calc_hash):
        """Test comparing file hashes with match."""
        mock_calc_hash.return_value = "abc123"

        result = FileHashUtils.compare_file_hashes(
            Path("/tmp/test.txt"),
            "abc123",
        )
        assert result is True

    @patch("src.web.services.incremental_scan.FileHashUtils.calculate_file_hash")
    def test_compare_file_hashes_no_match(self, mock_calc_hash):
        """Test comparing file hashes with no match."""
        mock_calc_hash.return_value = "def456"

        result = FileHashUtils.compare_file_hashes(
            Path("/tmp/test.txt"),
            "abc123",
        )
        assert result is False

    def test_compare_file_hashes_none_expected(self):
        """Test comparing hashes when expected is None."""
        result = FileHashUtils.compare_file_hashes(
            Path("/tmp/test.txt"),
            None,
        )
        assert result is True


# ============================================================================
# Test IncrementalScanService
# ============================================================================

class TestIncrementalScanService:
    """Test incremental scan service."""

    @patch("src.web.services.incremental_scan.AsyncSessionLocal")
    @patch.object(GitUtils, "is_git_repository")
    @patch.object(GitUtils, "get_changed_files")
    @pytest.mark.asyncio
    async def test_analyze_incremental_changes_success(
        self,
        mock_get_changed,
        mock_is_repo,
        mock_session_local,
    ):
        """Test analyzing incremental changes successfully."""
        mock_is_repo.return_value = True
        mock_get_changed.return_value = [
            FileChange(path="added.py", change_type="added"),
            FileChange(path="modified.py", change_type="modified"),
            FileChange(path="deleted.py", change_type="deleted"),
        ]

        service = IncrementalScanService(scan_id=1, project_id=100)
        context = await service.analyze_incremental_changes(
            source_path=Path("/tmp/repo"),
            base_ref="main",
            head_ref="feature",
        )

        assert context.scan_id == 1
        assert context.base_ref == "main"
        assert context.head_ref == "feature"
        assert context.added_files == 1
        assert context.modified_files == 1
        assert context.deleted_files_count == 1
        assert "added.py" in context.files_to_scan
        assert "modified.py" in context.files_to_scan
        assert "deleted.py" in context.deleted_files

    @patch.object(GitUtils, "is_git_repository")
    @pytest.mark.asyncio
    async def test_analyze_incremental_changes_not_repo(self, mock_is_repo):
        """Test analyzing changes when path is not a Git repository."""
        mock_is_repo.return_value = False

        service = IncrementalScanService(scan_id=1, project_id=100)

        with pytest.raises(ValueError, match="Not a Git repository"):
            await service.analyze_incremental_changes(
                source_path=Path("/tmp/not-repo"),
                base_ref="main",
                head_ref="feature",
            )

    @patch.object(GitUtils, "is_git_repository")
    @patch.object(GitUtils, "get_changed_files")
    @pytest.mark.asyncio
    async def test_filter_files_by_language(
        self,
        mock_get_changed,
        mock_is_repo,
    ):
        """Test filtering files by language extension."""
        mock_is_repo.return_value = True
        mock_get_changed.return_value = [
            FileChange(path="test.py", change_type="modified"),
            FileChange(path="test.js", change_type="modified"),
            FileChange(path="test.txt", change_type="modified"),
            FileChange(path="README.md", change_type="added"),
        ]

        service = IncrementalScanService(scan_id=1, project_id=100)
        context = await service.analyze_incremental_changes(
            source_path=Path("/tmp/repo"),
            base_ref="main",
            head_ref="feature",
        )

        # Filter for Python and JavaScript files only
        filtered = await service.filter_files_by_language(
            context,
            extensions={".py", ".js"},
        )

        assert len(filtered) == 2
        assert "test.py" in filtered
        assert "test.js" in filtered
        assert "test.txt" not in filtered

    @pytest.mark.asyncio
    async def test_update_scan_with_incremental_stats(self):
        """Test updating scan with incremental statistics."""
        from src.web.models.scan import Scan

        context = IncrementalScanContext(
            scan_id=1,
            project_id=100,
            base_ref="main",
            head_ref="feature",
            source_path=Path("/tmp/repo"),
        )
        context.added_files = 5
        context.modified_files = 3
        context.deleted_files_count = 1

        mock_db = MagicMock()
        mock_db.execute = AsyncMock()
        mock_db.commit = AsyncMock()

        service = IncrementalScanService(scan_id=1, project_id=100)
        await service.update_scan_with_incremental_stats(mock_db, context)

        mock_db.execute.assert_called_once()
        mock_db.commit.assert_called_once()


# ============================================================================
# Test Factory Function
# ============================================================================

class TestFactoryFunction:
    """Test factory function."""

    def test_get_incremental_scan_service(self):
        """Test getting incremental scan service."""
        service = get_incremental_scan_service(scan_id=1, project_id=100)
        assert isinstance(service, IncrementalScanService)
        assert service.scan_id == 1
        assert service.project_id == 100
