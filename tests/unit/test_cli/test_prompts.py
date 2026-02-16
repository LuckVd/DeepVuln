"""Tests for CLI prompts module."""

from pathlib import Path
from unittest.mock import patch

from src.cli.prompts import (
    ask_next_action,
    get_git_config,
    get_local_config,
    prompt_clone_depth,
    prompt_copy_to_workspace,
    prompt_git_ref,
    prompt_git_url,
    prompt_local_path,
    prompt_workspace_name,
    select_source_type,
)
from src.models.fetcher import GitRef, GitRefType


class TestSelectSourceType:
    """Test source type selection."""

    def test_select_git(self) -> None:
        """Test selecting Git source."""
        with patch("questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = "git"
            result = select_source_type()
            assert result == "git"

    def test_select_local(self) -> None:
        """Test selecting local source."""
        with patch("questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = "local"
            result = select_source_type()
            assert result == "local"

    def test_cancel_selection(self) -> None:
        """Test canceling selection."""
        with patch("questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = None
            result = select_source_type()
            assert result is None


class TestPromptGitUrl:
    """Test Git URL prompt."""

    def test_valid_url(self) -> None:
        """Test valid Git URL input."""
        with patch("questionary.text") as mock_text:
            mock_text.return_value.ask.return_value = "https://github.com/user/repo.git"
            result = prompt_git_url()
            assert result == "https://github.com/user/repo.git"

    def test_ssh_url(self) -> None:
        """Test SSH Git URL input."""
        with patch("questionary.text") as mock_text:
            mock_text.return_value.ask.return_value = "git@github.com:user/repo.git"
            result = prompt_git_url()
            assert result == "git@github.com:user/repo.git"

    def test_cancel(self) -> None:
        """Test canceling URL input."""
        with patch("questionary.text") as mock_text:
            mock_text.return_value.ask.return_value = None
            result = prompt_git_url()
            assert result is None


class TestPromptGitRef:
    """Test Git reference prompt."""

    def test_skip_ref(self) -> None:
        """Test skipping Git reference."""
        with patch("questionary.confirm") as mock_confirm:
            mock_confirm.return_value.ask.return_value = False
            result = prompt_git_ref()
            assert result is None

    def test_select_branch(self) -> None:
        """Test selecting a branch."""
        with (
            patch("questionary.confirm") as mock_confirm,
            patch("questionary.select") as mock_select,
            patch("questionary.text") as mock_text,
        ):
            mock_confirm.return_value.ask.return_value = True
            mock_select.return_value.ask.return_value = "branch"
            mock_text.return_value.ask.return_value = "main"

            result = prompt_git_ref()
            assert result is not None
            assert result.ref_type == GitRefType.BRANCH
            assert result.ref_value == "main"

    def test_select_tag(self) -> None:
        """Test selecting a tag."""
        with (
            patch("questionary.confirm") as mock_confirm,
            patch("questionary.select") as mock_select,
            patch("questionary.text") as mock_text,
        ):
            mock_confirm.return_value.ask.return_value = True
            mock_select.return_value.ask.return_value = "tag"
            mock_text.return_value.ask.return_value = "v1.0.0"

            result = prompt_git_ref()
            assert result is not None
            assert result.ref_type == GitRefType.TAG
            assert result.ref_value == "v1.0.0"

    def test_select_commit(self) -> None:
        """Test selecting a commit."""
        with (
            patch("questionary.confirm") as mock_confirm,
            patch("questionary.select") as mock_select,
            patch("questionary.text") as mock_text,
        ):
            mock_confirm.return_value.ask.return_value = True
            mock_select.return_value.ask.return_value = "commit"
            mock_text.return_value.ask.return_value = "abc12345"

            result = prompt_git_ref()
            assert result is not None
            assert result.ref_type == GitRefType.COMMIT
            assert result.ref_value == "abc12345"


class TestPromptCloneDepth:
    """Test clone depth prompt."""

    def test_full_clone(self) -> None:
        """Test full clone (no depth limit)."""
        with patch("questionary.confirm") as mock_confirm:
            mock_confirm.return_value.ask.return_value = False
            result = prompt_clone_depth()
            assert result == 0

    def test_shallow_clone_default(self) -> None:
        """Test shallow clone with default depth."""
        with (
            patch("questionary.confirm") as mock_confirm,
            patch("questionary.text") as mock_text,
        ):
            mock_confirm.return_value.ask.return_value = True
            mock_text.return_value.ask.return_value = "1"

            result = prompt_clone_depth()
            assert result == 1

    def test_shallow_clone_custom(self) -> None:
        """Test shallow clone with custom depth."""
        with (
            patch("questionary.confirm") as mock_confirm,
            patch("questionary.text") as mock_text,
        ):
            mock_confirm.return_value.ask.return_value = True
            mock_text.return_value.ask.return_value = "5"

            result = prompt_clone_depth()
            assert result == 5


class TestPromptLocalPath:
    """Test local path prompt."""

    def test_valid_path(self, tmp_path: Path) -> None:
        """Test valid local path."""
        with patch("questionary.path") as mock_path:
            mock_path.return_value.ask.return_value = str(tmp_path)
            result = prompt_local_path()
            assert result == tmp_path

    def test_cancel(self) -> None:
        """Test canceling path input."""
        with patch("questionary.path") as mock_path:
            mock_path.return_value.ask.return_value = None
            result = prompt_local_path()
            assert result is None


class TestPromptCopyToWorkspace:
    """Test copy to workspace prompt."""

    def test_copy_true(self) -> None:
        """Test choosing to copy."""
        with patch("questionary.confirm") as mock_confirm:
            mock_confirm.return_value.ask.return_value = True
            result = prompt_copy_to_workspace()
            assert result is True

    def test_copy_false(self) -> None:
        """Test choosing not to copy."""
        with patch("questionary.confirm") as mock_confirm:
            mock_confirm.return_value.ask.return_value = False
            result = prompt_copy_to_workspace()
            assert result is False


class TestPromptWorkspaceName:
    """Test workspace name prompt."""

    def test_use_default(self) -> None:
        """Test using default workspace name."""
        with patch("questionary.confirm") as mock_confirm:
            mock_confirm.return_value.ask.return_value = False
            result = prompt_workspace_name()
            assert result is None

    def test_custom_name(self) -> None:
        """Test custom workspace name."""
        with (
            patch("questionary.confirm") as mock_confirm,
            patch("questionary.text") as mock_text,
        ):
            mock_confirm.return_value.ask.return_value = True
            mock_text.return_value.ask.return_value = "my-workspace"

            result = prompt_workspace_name()
            assert result == "my-workspace"


class TestAskNextAction:
    """Test next action prompt."""

    def test_analyze(self) -> None:
        """Test selecting analyze action."""
        with patch("questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = "analyze"
            result = ask_next_action()
            assert result == "analyze"

    def test_new(self) -> None:
        """Test selecting new project action."""
        with patch("questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = "new"
            result = ask_next_action()
            assert result == "new"

    def test_exit(self) -> None:
        """Test selecting exit action."""
        with patch("questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = "exit"
            result = ask_next_action()
            assert result == "exit"


class TestGetGitConfig:
    """Test Git config collection."""

    def test_full_config(self) -> None:
        """Test collecting full Git configuration."""
        with (
            patch("src.cli.prompts.prompt_git_url") as mock_url,
            patch("src.cli.prompts.prompt_git_ref") as mock_ref,
            patch("src.cli.prompts.prompt_clone_depth") as mock_depth,
            patch("src.cli.prompts.prompt_workspace_name") as mock_workspace,
        ):
            mock_url.return_value = "https://github.com/user/repo.git"
            mock_ref.return_value = GitRef(ref_type=GitRefType.BRANCH, ref_value="main")
            mock_depth.return_value = 1
            mock_workspace.return_value = "test-workspace"

            config = get_git_config()

            assert config["repo_url"] == "https://github.com/user/repo.git"
            assert config["git_ref"].ref_value == "main"
            assert config["depth"] == 1
            assert config["workspace_name"] == "test-workspace"

    def test_cancel_early(self) -> None:
        """Test canceling early in Git config."""
        with patch("src.cli.prompts.prompt_git_url") as mock_url:
            mock_url.return_value = None
            config = get_git_config()
            assert config == {}


class TestGetLocalConfig:
    """Test local config collection."""

    def test_full_config(self, tmp_path: Path) -> None:
        """Test collecting full local configuration."""
        with (
            patch("src.cli.prompts.prompt_local_path") as mock_path,
            patch("src.cli.prompts.prompt_copy_to_workspace") as mock_copy,
            patch("src.cli.prompts.prompt_workspace_name") as mock_workspace,
        ):
            mock_path.return_value = tmp_path
            mock_copy.return_value = True
            mock_workspace.return_value = "test-workspace"

            config = get_local_config()

            assert config["local_path"] == tmp_path
            assert config["copy_to_workspace"] is True
            assert config["workspace_name"] == "test-workspace"

    def test_cancel_early(self) -> None:
        """Test canceling early in local config."""
        with patch("src.cli.prompts.prompt_local_path") as mock_path:
            mock_path.return_value = None
            config = get_local_config()
            assert config == {}
