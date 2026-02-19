"""Display components for CLI using Rich."""

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

console = Console()

# DeepVuln ASCII Art Banner
BANNER = r"""
[bold cyan]
    ___  ______________  __  ________
   / _ |/ ___/ ___/ __ \/ / / / ____/
  / __ / /__/ /__/ /_/ / /_/ / /__
 / / | |\___/\___/\__, /__,__/\___/
/_/  |_|          /____/
[/bold cyan]
[dim]Seven-Layer Intelligent Vulnerability Analysis System[/dim]
"""


def show_banner() -> None:
    """Display the DeepVuln banner."""
    console.print()
    console.print(Panel(BANNER, border_style="cyan", padding=(0, 2)))
    console.print()


def show_welcome() -> None:
    """Display welcome message and quick start guide."""
    console.print()
    console.print(
        Panel(
            "[bold]Welcome to DeepVuln![/bold]\n\n"
            "This interactive wizard will guide you through:\n"
            "  [cyan]1.[/] Select source code location (Git or Local)\n"
            "  [cyan]2.[/] Configure workspace settings\n"
            "  [cyan]3.[/] Fetch and prepare source code for analysis\n\n"
            "[dim]Press Ctrl+C at any time to exit[/dim]",
            title="[bold green]Getting Started[/]",
            border_style="green",
        )
    )
    console.print()


def show_success(title: str, message: str) -> None:
    """Display a success message."""
    console.print()
    console.print(
        Panel(
            f"[bold green]{message}[/]",
            title=f"[bold]{title}[/]",
            border_style="green",
        )
    )


def show_error(title: str, message: str) -> None:
    """Display an error message."""
    from rich.markup import escape
    console.print()
    console.print(
        Panel(
            f"[bold red]{escape(message)}[/]",
            title=f"[bold]{escape(title)}[/]",
            border_style="red",
        )
    )


def show_info(title: str, message: str) -> None:
    """Display an info message."""
    console.print()
    console.print(
        Panel(
            message,
            title=f"[bold]{title}[/]",
            border_style="blue",
        )
    )


def create_progress() -> Progress:
    """Create a progress bar instance."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    )


def show_fetch_result(result: dict) -> None:
    """Display the fetch result in a formatted table.

    Args:
        result: Dictionary containing fetch result information.
    """
    console.print()

    # Main result table
    table = Table(title="[bold]Fetch Result[/]", show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    if result.get("success"):
        table.add_row("Status", "[bold green]SUCCESS[/]")
        table.add_row("Source Path", str(result.get("source_path", "N/A")))
        table.add_row("Workspace", result.get("workspace_name", "N/A"))
        table.add_row("Source Type", result.get("source_type", "N/A"))

        # Add metadata if available
        metadata = result.get("metadata", {})
        if metadata:
            table.add_section()
            if metadata.get("current_ref"):
                table.add_row("Current Ref", metadata["current_ref"])
            if metadata.get("commit_info"):
                commit = metadata["commit_info"]
                table.add_row("Commit SHA", commit.get("short_sha", "N/A"))
                if commit.get("message"):
                    # Truncate long commit messages
                    msg = commit["message"]
                    if len(msg) > 50:
                        msg = msg[:47] + "..."
                    table.add_row("Commit Message", msg)
                if commit.get("author"):
                    table.add_row("Author", commit["author"])
    else:
        table.add_row("Status", "[bold red]FAILED[/]")
        table.add_row("Error", result.get("error_message", "Unknown error"))

    console.print(Panel(table, border_style="green" if result.get("success") else "red"))


def show_summary(source_type: str, config: dict) -> None:
    """Display a summary of the configuration before fetching.

    Args:
        source_type: Type of source (git/local).
        config: Configuration dictionary.
    """
    console.print()
    table = Table(title="[bold]Configuration Summary[/]", show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Source Type", source_type.upper())

    if source_type == "git":
        table.add_row("Repository URL", config.get("repo_url", "N/A"))
        if config.get("git_ref"):
            table.add_row("Git Reference", str(config["git_ref"]))
        table.add_row("Clone Depth", str(config.get("depth", "Full")))
    else:
        local_path = config.get("local_path", "N/A")
        table.add_row("Local Path", str(local_path) if local_path else "N/A")
        table.add_row("Copy to Workspace", str(config.get("copy_to_workspace", True)))

    console.print(Panel(table, border_style="yellow"))
    console.print()


def confirm_action(message: str) -> bool:
    """Ask for confirmation with a styled prompt.

    Args:
        message: The confirmation message.

    Returns:
        True if confirmed, False otherwise.
    """
    from rich.prompt import Confirm

    return Confirm.ask(f"[bold]{message}[/]")


def show_goodbye() -> None:
    """Display goodbye message."""
    console.print()
    console.print(
        Panel(
            "[bold]Thank you for using DeepVuln![/bold]\n\n"
            "[dim]Your source code is ready for analysis.[/dim]",
            border_style="cyan",
        )
    )
    console.print()
