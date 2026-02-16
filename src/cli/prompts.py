"""Interactive prompts for CLI using questionary."""

from pathlib import Path
from typing import Any

import questionary
from questionary import Style

from src.models.fetcher import GitRef, GitRefType

# Custom style for questionary prompts
CUSTOM_STYLE = Style(
    [
        ("qmark", "fg:cyan bold"),
        ("question", "bold"),
        ("answer", "fg:green bold"),
        ("pointer", "fg:cyan bold"),
        ("highlighted", "fg:cyan bold"),
        ("selected", "fg:green"),
        ("separator", "fg:gray"),
        ("instruction", "fg:gray"),
        ("text", ""),
    ]
)


def select_source_type() -> str:
    """Ask user to select source code type.

    Returns:
        Selected source type: 'git' or 'local'.
    """
    return questionary.select(
        "Where is your source code located?",
        choices=[
            questionary.Choice("Git Repository (clone from URL)", value="git"),
            questionary.Choice("Local Directory (existing path)", value="local"),
        ],
        style=CUSTOM_STYLE,
    ).ask()


def prompt_git_url() -> str:
    """Ask user for Git repository URL.

    Returns:
        Git repository URL.
    """
    return questionary.text(
        "Enter the Git repository URL:",
        instruction="(e.g., https://github.com/user/repo.git)",
        validate=lambda x: len(x) > 0 and (x.startswith("http") or x.startswith("git@")),
        style=CUSTOM_STYLE,
    ).ask()


def prompt_git_ref() -> GitRef | None:
    """Ask user for Git reference (branch/tag/commit).

    Returns:
        GitRef if specified, None for default branch.
    """
    use_ref = questionary.confirm(
        "Do you want to checkout a specific branch, tag, or commit?",
        default=False,
        style=CUSTOM_STYLE,
    ).ask()

    if not use_ref:
        return None

    ref_type_str = questionary.select(
        "Select reference type:",
        choices=[
            questionary.Choice("Branch", value="branch"),
            questionary.Choice("Tag", value="tag"),
            questionary.Choice("Commit SHA", value="commit"),
        ],
        style=CUSTOM_STYLE,
    ).ask()

    if ref_type_str is None:
        return None

    ref_value = questionary.text(
        f"Enter the {ref_type_str} name:",
        instruction=f"(e.g., {'main, develop' if ref_type_str == 'branch' else 'v1.0.0' if ref_type_str == 'tag' else 'abc12345'})",
        validate=lambda x: len(x) > 0,
        style=CUSTOM_STYLE,
    ).ask()

    if ref_value is None:
        return None

    ref_type_map = {
        "branch": GitRefType.BRANCH,
        "tag": GitRefType.TAG,
        "commit": GitRefType.COMMIT,
    }

    return GitRef(ref_type=ref_type_map[ref_type_str], ref_value=ref_value)


def prompt_clone_depth() -> int:
    """Ask user for clone depth.

    Returns:
        Clone depth (0 for full clone).
    """
    use_shallow = questionary.confirm(
        "Use shallow clone (faster, less history)?",
        default=True,
        style=CUSTOM_STYLE,
    ).ask()

    if not use_shallow:
        return 0  # Full clone

    depth = questionary.text(
        "Clone depth:",
        instruction="(number of commits, default: 1)",
        default="1",
        validate=lambda x: x.isdigit() and int(x) > 0,
        style=CUSTOM_STYLE,
    ).ask()

    return int(depth) if depth else 1


def prompt_local_path() -> Path | None:
    """Ask user for local source code path.

    Returns:
        Path object if valid, None otherwise.
    """
    path_str = questionary.path(
        "Enter the path to your source code:",
        only_directories=True,
        validate=lambda x: len(x) > 0,
        style=CUSTOM_STYLE,
    ).ask()

    if path_str is None:
        return None

    path = Path(path_str)
    if not path.exists():
        questionary.print(f"[red]Error: Path does not exist: {path}[/]")
        return None

    if not path.is_dir():
        questionary.print(f"[red]Error: Path is not a directory: {path}[/]")
        return None

    return path


def prompt_copy_to_workspace() -> bool:
    """Ask user whether to copy local files to workspace.

    Returns:
        True to copy, False to use in place.
    """
    return questionary.confirm(
        "Copy files to a workspace directory?",
        instruction="(Recommended for isolation. Original files will not be modified.)",
        default=True,
        style=CUSTOM_STYLE,
    ).ask()


def prompt_workspace_name(default_name: str | None = None) -> str | None:
    """Ask user for custom workspace name.

    Args:
        default_name: Default workspace name to suggest.

    Returns:
        Custom workspace name or None to use auto-generated.
    """
    use_custom = questionary.confirm(
        "Specify a custom workspace name?",
        default=False,
        style=CUSTOM_STYLE,
    ).ask()

    if not use_custom:
        return None

    return questionary.text(
        "Workspace name:",
        default=default_name or "",
        validate=lambda x: len(x) > 0 and all(c.isalnum() or c in "-_" for c in x),
        style=CUSTOM_STYLE,
    ).ask()


def confirm_configuration(config_summary: str) -> bool:
    """Ask user to confirm the configuration.

    Args:
        config_summary: Summary of configuration to display.

    Returns:
        True if confirmed, False otherwise.
    """
    questionary.print(f"\n{config_summary}\n")
    return questionary.confirm(
        "Proceed with this configuration?",
        default=True,
        style=CUSTOM_STYLE,
    ).ask()


def ask_next_action() -> str:
    """Ask user what to do next after fetching.

    Returns:
        Selected action: 'analyze', 'new', or 'exit'.
    """
    return questionary.select(
        "What would you like to do next?",
        choices=[
            questionary.Choice("Start vulnerability analysis", value="analyze"),
            questionary.Choice("Fetch another project", value="new"),
            questionary.Choice("Exit", value="exit"),
        ],
        style=CUSTOM_STYLE,
    ).ask()


def prompt_continue_on_error() -> bool:
    """Ask user whether to continue after an error.

    Returns:
        True to continue, False to exit.
    """
    return questionary.confirm(
        "Would you like to try again?",
        default=True,
        style=CUSTOM_STYLE,
    ).ask()


def get_git_config() -> dict[str, Any]:
    """Collect all Git-related configuration from user.

    Returns:
        Dictionary with Git configuration.
    """
    repo_url = prompt_git_url()
    if repo_url is None:
        return {}

    git_ref = prompt_git_ref()
    depth = prompt_clone_depth()
    workspace_name = prompt_workspace_name()

    return {
        "repo_url": repo_url,
        "git_ref": git_ref,
        "depth": depth,
        "workspace_name": workspace_name,
    }


def get_local_config() -> dict[str, Any]:
    """Collect all local path configuration from user.

    Returns:
        Dictionary with local configuration.
    """
    local_path = prompt_local_path()
    if local_path is None:
        return {}

    copy_to_workspace = prompt_copy_to_workspace()
    workspace_name = None
    if copy_to_workspace:
        workspace_name = prompt_workspace_name()

    return {
        "local_path": local_path,
        "copy_to_workspace": copy_to_workspace,
        "workspace_name": workspace_name,
    }
