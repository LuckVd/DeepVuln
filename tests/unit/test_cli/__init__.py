"""Tests for CLI display module."""

from unittest.mock import patch

import pytest

from src.cli.display import (
    create_progress,
    show_banner,
    show_error,
    show_fetch_result,
    show_goodbye,
    show_info,
    show_success,
    show_summary,
    show_welcome,
)


class TestDisplayFunctions:
    """Test display functions."""

    def test_show_banner(self, capsys: pytest.CaptureFixture) -> None:
        """Test banner display."""
        with patch("src.cli.display.console"):
            show_banner()
            # Should not raise any errors

    def test_show_welcome(self, capsys: pytest.CaptureFixture) -> None:
        """Test welcome display."""
        with patch("src.cli.display.console"):
            show_welcome()
            # Should not raise any errors

    def test_show_success(self) -> None:
        """Test success message display."""
        with patch("src.cli.display.console"):
            show_success("Test Title", "Test message")
            # Should not raise any errors

    def test_show_error(self) -> None:
        """Test error message display."""
        with patch("src.cli.display.console"):
            show_error("Error Title", "Error message")
            # Should not raise any errors

    def test_show_info(self) -> None:
        """Test info message display."""
        with patch("src.cli.display.console"):
            show_info("Info Title", "Info message")
            # Should not raise any errors

    def test_create_progress(self) -> None:
        """Test progress bar creation."""
        progress = create_progress()
        assert progress is not None

    def test_show_fetch_result_success(self) -> None:
        """Test fetch result display for success case."""
        result = {
            "success": True,
            "source_path": "/path/to/source",
            "workspace_name": "test-workspace",
            "source_type": "git",
            "metadata": {
                "current_ref": "main",
                "commit_info": {
                    "short_sha": "abc12345",
                    "message": "Test commit",
                    "author": "Test Author",
                },
            },
        }

        with patch("src.cli.display.console"):
            show_fetch_result(result)
            # Should not raise any errors

    def test_show_fetch_result_failure(self) -> None:
        """Test fetch result display for failure case."""
        result = {
            "success": False,
            "error_message": "Clone failed",
            "source_type": "git",
            "metadata": {},
        }

        with patch("src.cli.display.console"):
            show_fetch_result(result)
            # Should not raise any errors

    def test_show_summary_git(self) -> None:
        """Test summary display for Git source."""
        config = {
            "repo_url": "https://github.com/user/repo.git",
            "git_ref": "branch:main",
            "depth": 1,
        }

        with patch("src.cli.display.console"):
            show_summary("git", config)
            # Should not raise any errors

    def test_show_summary_local(self) -> None:
        """Test summary display for local source."""
        config = {
            "local_path": "/path/to/project",
            "copy_to_workspace": True,
        }

        with patch("src.cli.display.console"):
            show_summary("local", config)
            # Should not raise any errors

    def test_show_goodbye(self) -> None:
        """Test goodbye message display."""
        with patch("src.cli.display.console"):
            show_goodbye()
            # Should not raise any errors
