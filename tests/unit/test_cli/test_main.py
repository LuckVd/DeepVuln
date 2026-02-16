"""Tests for CLI main module."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from src.cli.main import clean, git, local, main, run_interactive_fetch


class TestMainCommand:
    """Test main CLI command."""

    def test_version_flag(self) -> None:
        """Test version flag."""
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    @patch("src.cli.main.run_interactive_mode")
    def test_interactive_flag(self, mock_interactive: MagicMock) -> None:
        """Test interactive flag."""
        runner = CliRunner()
        runner.invoke(main, ["--interactive"])
        mock_interactive.assert_called_once()

    @patch("src.cli.main.run_interactive_mode")
    def test_default_interactive(self, mock_interactive: MagicMock) -> None:
        """Test default behavior (interactive mode)."""
        runner = CliRunner()
        runner.invoke(main, [])
        mock_interactive.assert_called_once()


class TestGitCommand:
    """Test git subcommand."""

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    @patch("src.cli.main.show_summary")
    def test_git_basic(
        self,
        mock_summary: MagicMock,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
    ) -> None:
        """Test basic git command."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": "/test/path"}
        }

        runner = CliRunner()
        result = runner.invoke(git, ["--url", "https://github.com/user/repo.git"])

        assert result.exit_code == 0
        mock_banner.assert_called_once()
        mock_summary.assert_called_once()

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    def test_git_with_branch(
        self,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
    ) -> None:
        """Test git command with branch."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": "/test/path"}
        }

        runner = CliRunner()
        result = runner.invoke(
            git,
            ["--url", "https://github.com/user/repo.git", "--branch", "develop"],
        )

        assert result.exit_code == 0

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    def test_git_with_tag(
        self,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
    ) -> None:
        """Test git command with tag."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": "/test/path"}
        }

        runner = CliRunner()
        result = runner.invoke(
            git,
            ["--url", "https://github.com/user/repo.git", "--tag", "v1.0.0"],
        )

        assert result.exit_code == 0

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    def test_git_with_commit(
        self,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
    ) -> None:
        """Test git command with commit."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": "/test/path"}
        }

        runner = CliRunner()
        result = runner.invoke(
            git,
            ["--url", "https://github.com/user/repo.git", "--commit", "abc12345"],
        )

        assert result.exit_code == 0

    def test_git_missing_url(self) -> None:
        """Test git command without URL."""
        runner = CliRunner()
        result = runner.invoke(git, [])
        assert result.exit_code != 0


class TestLocalCommand:
    """Test local subcommand."""

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    @patch("src.cli.main.show_summary")
    def test_local_basic(
        self,
        mock_summary: MagicMock,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test basic local command."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": str(tmp_path)}
        }

        runner = CliRunner()
        result = runner.invoke(local, ["--path", str(tmp_path)])

        assert result.exit_code == 0
        mock_banner.assert_called_once()
        mock_summary.assert_called_once()

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    def test_local_no_copy(
        self,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test local command without copy."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": str(tmp_path)}
        }

        runner = CliRunner()
        result = runner.invoke(local, ["--path", str(tmp_path), "--no-copy"])

        assert result.exit_code == 0

    def test_local_missing_path(self) -> None:
        """Test local command without path."""
        runner = CliRunner()
        result = runner.invoke(local, [])
        assert result.exit_code != 0

    def test_local_invalid_path(self) -> None:
        """Test local command with invalid path."""
        runner = CliRunner()
        result = runner.invoke(local, ["--path", "/nonexistent/path"])
        assert result.exit_code != 0


class TestCleanCommand:
    """Test clean subcommand."""

    @patch("src.cli.main.AssetFetcher")
    @patch("src.cli.main.show_banner")
    @patch("src.cli.main.show_success")
    def test_clean(
        self,
        mock_success: MagicMock,
        mock_banner: MagicMock,
        mock_fetcher_class: MagicMock,
    ) -> None:
        """Test clean command."""
        mock_fetcher = MagicMock()
        mock_fetcher.cleanup_all.return_value = 5
        mock_fetcher_class.return_value = mock_fetcher

        runner = CliRunner()
        result = runner.invoke(clean, [])

        assert result.exit_code == 0
        mock_banner.assert_called_once()
        mock_fetcher.cleanup_all.assert_called_once()
        mock_success.assert_called_once()


class TestRunInteractiveFetch:
    """Test interactive fetch function."""

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_summary")
    @patch("src.cli.main.get_git_config")
    @patch("src.cli.main.select_source_type")
    def test_git_fetch_success(
        self,
        mock_select: MagicMock,
        mock_config: MagicMock,
        mock_summary: MagicMock,
        mock_execute: MagicMock,
    ) -> None:
        """Test successful Git fetch."""
        mock_select.return_value = "git"
        mock_config.return_value = {
            "repo_url": "https://github.com/user/repo.git",
            "git_ref": None,
            "depth": 1,
            "workspace_name": None,
        }
        mock_execute.return_value = {"result": {"success": True}}

        result = run_interactive_fetch()

        assert result is not None
        mock_summary.assert_called_once()

    @patch("src.cli.main.show_summary")
    @patch("src.cli.main.get_local_config")
    @patch("src.cli.main.select_source_type")
    def test_local_fetch_success(
        self,
        mock_select: MagicMock,
        mock_config: MagicMock,
        mock_summary: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test successful local fetch."""
        mock_select.return_value = "local"
        mock_config.return_value = {
            "local_path": tmp_path,
            "copy_to_workspace": True,
            "workspace_name": None,
        }

        with patch("src.cli.main.execute_fetch") as mock_execute:
            mock_execute.return_value = {"result": {"success": True}}
            result = run_interactive_fetch()

        assert result is not None

    @patch("src.cli.main.select_source_type")
    def test_cancelled_selection(
        self,
        mock_select: MagicMock,
    ) -> None:
        """Test cancelled source selection."""
        mock_select.return_value = None
        result = run_interactive_fetch()
        assert result is None

    @patch("src.cli.main.get_git_config")
    @patch("src.cli.main.select_source_type")
    def test_cancelled_config(
        self,
        mock_select: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test cancelled configuration."""
        mock_select.return_value = "git"
        mock_config.return_value = {}
        result = run_interactive_fetch()
        assert result is None
