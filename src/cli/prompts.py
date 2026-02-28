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


def select_main_menu_action() -> str | None:
    """Ask user to select main menu action.

    Returns:
        Selected action: 'fetch', 'intel', 'clean', or 'exit'.
    """
    return questionary.select(
        "What would you like to do?",
        choices=[
            questionary.Choice("📥 Fetch Source Code (Git/Local)", value="fetch"),
            questionary.Choice("🔍 Threat Intelligence (CVE/KEV/PoC)", value="intel"),
            questionary.Choice("🧹 Clean Workspaces", value="clean"),
            questionary.Choice("🚪 Exit", value="exit"),
        ],
        style=CUSTOM_STYLE,
    ).ask()


def select_intel_menu_action() -> str | None:
    """Ask user to select threat intelligence action.

    Returns:
        Selected action: 'search', 'sync', 'kev', 'stats', or 'back'.
    """
    return questionary.select(
        "Threat Intelligence Menu",
        choices=[
            questionary.Choice("🔍 Search CVEs", value="search"),
            questionary.Choice("📥 Sync Latest Data", value="sync"),
            questionary.Choice("🔔 View KEV Alerts", value="kev"),
            questionary.Choice("📊 View Statistics", value="stats"),
            questionary.Choice("◀ Back to Main Menu", value="back"),
        ],
        style=CUSTOM_STYLE,
    ).ask()


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


def ask_next_action_with_scan() -> str:
    """Ask user what to do next after fetching, with scan option.

    Returns:
        Selected action: 'scan', 'analyze', 'new', or 'exit'.
    """
    return questionary.select(
        "What would you like to do next?",
        choices=[
            questionary.Choice("🔒 Run security scan (recommended)", value="scan"),
            questionary.Choice("🔍 Start vulnerability analysis", value="analyze"),
            questionary.Choice("📥 Fetch another project", value="new"),
            questionary.Choice("🚪 Exit", value="exit"),
        ],
        style=CUSTOM_STYLE,
    ).ask()


def prompt_scan_options() -> dict[str, Any]:
    """Ask user for scan options.

    Returns:
        Dictionary with scan options.
    """
    # Read model from config file
    resolved_model = None
    try:
        from src.core.config import get_llm_config
        llm_config = get_llm_config()
        resolved_model = llm_config.get("model")
    except Exception:
        pass

    # Ask scan type first
    scan_type = questionary.select(
        "Select scan type:",
        choices=[
            questionary.Choice("🔍 Dependency Scan (CVE check)", value="deps"),
            questionary.Choice("⚡ Quick Code Scan (Semgrep only)", value="quick"),
            questionary.Choice("🔧 Custom Scan (select engines)", value="custom"),
            questionary.Choice("🚀 Full Scan (all engines + LLM verify)", value="full"),
        ],
        style=CUSTOM_STYLE,
    ).ask()

    if scan_type is None:
        return {}

    options = {
        "include_low_severity": False,
        "detailed": False,
        "full_scan": False,
        "engines": None,
        "llm_verify": False,
        "llm_detect": False,
        "llm_full_detect": False,
        "batch_size": 20,
        "batch_max_chars": 30000,
        "model": resolved_model,
    }

    if scan_type == "deps":
        # Original dependency scan
        pass

    elif scan_type == "quick":
        # Semgrep only
        options["engines"] = ["semgrep"]

    elif scan_type == "custom":
        # Custom engine selection
        engines = questionary.checkbox(
            "Select analysis engines:",
            choices=[
                questionary.Choice("Semgrep (fast pattern matching)", value="semgrep", checked=True),
                questionary.Choice("CodeQL (deep dataflow analysis)", value="codeql"),
                questionary.Choice("Agent (AI-powered analysis)", value="agent"),
            ],
            style=CUSTOM_STYLE,
        ).ask()

        if engines:
            options["engines"] = engines

        # Ask about LLM verification
        if "agent" in (engines or []):
            llm_verify = questionary.confirm(
                "Enable LLM-assisted exploitability verification?",
                default=True,
                style=CUSTOM_STYLE,
            ).ask()
            options["llm_verify"] = llm_verify or False

        # Ask about LLM-assisted detection
        llm_detect = questionary.confirm(
            "Enable LLM-assisted attack surface detection?",
            default=False,
            style=CUSTOM_STYLE,
        ).ask()
        options["llm_detect"] = llm_detect or False

        # If LLM detect is enabled, ask about full LLM mode
        if llm_detect:
            llm_full_detect = questionary.confirm(
                "Use FULL LLM mode? (no static detectors, supports any language/framework)",
                default=False,
                style=CUSTOM_STYLE,
            ).ask()
            options["llm_full_detect"] = llm_full_detect or False
            # If full LLM mode is enabled, disable regular llm_detect
            if llm_full_detect:
                options["llm_detect"] = False
                # Ask about batch max chars for LLM full mode
                batch_max_chars = questionary.text(
                    "Max characters per batch for LLM analysis? (default: 30000)",
                    default="30000",
                    style=CUSTOM_STYLE,
                    validate=lambda x: x.isdigit() and int(x) > 0 or "Please enter a positive number",
                ).ask()
                options["batch_max_chars"] = int(batch_max_chars) if batch_max_chars else 30000
            else:
                options["batch_max_chars"] = 30000
        else:
            options["llm_full_detect"] = False
            options["batch_max_chars"] = 30000

    elif scan_type == "full":
        # Full scan with all engines
        options["full_scan"] = True
        options["llm_verify"] = True

        # Ask about LLM-assisted detection
        llm_detect = questionary.confirm(
            "Enable LLM-assisted attack surface detection?",
            default=True,
            style=CUSTOM_STYLE,
        ).ask()
        options["llm_detect"] = llm_detect or False

        # If LLM detect is enabled, ask about full LLM mode
        if llm_detect:
            llm_full_detect = questionary.confirm(
                "Use FULL LLM mode? (no static detectors, supports any language/framework)",
                default=False,
                style=CUSTOM_STYLE,
            ).ask()
            options["llm_full_detect"] = llm_full_detect or False
            # If full LLM mode is enabled, disable regular llm_detect
            if llm_full_detect:
                options["llm_detect"] = False
                # Ask about batch max chars for LLM full mode
                batch_max_chars = questionary.text(
                    "Max characters per batch for LLM analysis? (default: 30000)",
                    default="30000",
                    style=CUSTOM_STYLE,
                    validate=lambda x: x.isdigit() and int(x) > 0 or "Please enter a positive number",
                ).ask()
                options["batch_max_chars"] = int(batch_max_chars) if batch_max_chars else 30000
            else:
                options["batch_max_chars"] = 30000
        else:
            options["llm_full_detect"] = False
            options["batch_max_chars"] = 30000

    # Common options
    include_low = questionary.confirm(
        "Include low severity vulnerabilities?",
        default=False,
        style=CUSTOM_STYLE,
    ).ask()
    options["include_low_severity"] = include_low or False

    detailed = questionary.confirm(
        "Show detailed report?",
        default=False,
        style=CUSTOM_STYLE,
    ).ask()
    options["detailed"] = detailed or False

    return options


def ask_scan_action_after_result(has_issues: bool) -> str:
    """Ask user what to do after seeing scan results.

    Args:
        has_issues: Whether vulnerabilities were found.

    Returns:
        Selected action: 'details', 'export', 'new', or 'exit'.
    """
    choices = []

    if has_issues:
        choices.append(questionary.Choice("📋 View detailed vulnerability list", value="details"))

    choices.extend([
        questionary.Choice("📄 Export report", value="export"),
        questionary.Choice("📥 Scan another project", value="new"),
        questionary.Choice("🚪 Exit", value="exit"),
    ])

    return questionary.select(
        "What would you like to do?",
        choices=choices,
        style=CUSTOM_STYLE,
    ).ask()


def prompt_export_path(default_name: str = "security_report.txt") -> str | None:
    """Ask user for export file path.

    Args:
        default_name: Default file name.

    Returns:
        File path or None to skip.
    """
    return questionary.path(
        "Enter export file path:",
        default=default_name,
        style=CUSTOM_STYLE,
    ).ask()


def prompt_skip_auto_scan() -> bool:
    """Ask user whether to skip automatic security scan.

    Returns:
        True to skip, False to run scan.
    """
    return questionary.confirm(
        "Skip automatic security scan?",
        instruction="(Scan will check dependencies for known vulnerabilities)",
        default=False,
        style=CUSTOM_STYLE,
    ).ask()
