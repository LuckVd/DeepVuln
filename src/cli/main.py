"""Main CLI entry point for DeepVuln."""

import asyncio
from typing import Any

import click

from src.cli.display import (
    console,
    create_progress,
    show_banner,
    show_fetch_result,
    show_goodbye,
    show_info,
    show_success,
    show_summary,
    show_welcome,
)
from src.cli.intel import intel as intel_group
from src.cli.prompts import (
    ask_next_action,
    get_git_config,
    get_local_config,
    prompt_continue_on_error,
    select_intel_menu_action,
    select_main_menu_action,
    select_source_type,
)
from src.layers.l1_intelligence import AssetFetcher
from src.models.fetcher import FetchResult


def run_interactive_fetch() -> dict[str, Any] | None:
    """Run the interactive fetch wizard.

    Returns:
        Fetch result dictionary if successful, None otherwise.
    """
    # Select source type
    source_type = select_source_type()

    if source_type is None:
        return None

    # Collect configuration based on source type
    if source_type == "git":
        config = get_git_config()
        if not config:
            return None
        show_summary("git", config)
    else:
        config = get_local_config()
        if not config:
            return None
        show_summary("local", config)

    # Execute fetch
    return execute_fetch(source_type, config)


def execute_fetch(source_type: str, config: dict[str, Any]) -> dict[str, Any] | None:
    """Execute the fetch operation with progress display.

    Args:
        source_type: Type of source (git/local).
        config: Configuration dictionary.

    Returns:
        Fetch result dictionary if successful, None otherwise.
    """
    fetcher = AssetFetcher()
    result: FetchResult

    with create_progress() as progress:
        if source_type == "git":
            task = progress.add_task("[cyan]Cloning repository...", total=None)

            result = fetcher.fetch_from_git(
                repo_url=config["repo_url"],
                git_ref=config.get("git_ref"),
                depth=config.get("depth", 1),
                workspace_name=config.get("workspace_name"),
            )
        else:
            task = progress.add_task("[cyan]Loading local files...", total=None)

            result = fetcher.fetch_from_local(
                local_path=config["local_path"],
                workspace_name=config.get("workspace_name"),
                copy_to_workspace=config.get("copy_to_workspace", True),
            )

        progress.update(task, completed=True, description="[green]Complete!")

    # Convert result to dict for display
    result_dict = {
        "success": result.success,
        "source_path": result.source_path,
        "workspace_name": result.workspace_name,
        "source_type": result.source_type.value if result.source_type else None,
        "error_message": result.error_message,
        "metadata": result.metadata,
    }

    show_fetch_result(result_dict)

    if result.success:
        return {"result": result_dict, "fetcher": fetcher}

    return None


def run_interactive_mode() -> None:
    """Run the full interactive CLI mode with main menu."""
    show_banner()
    show_welcome()

    while True:
        try:
            # Main menu selection
            action = select_main_menu_action()

            if action is None or action == "exit":
                show_goodbye()
                break

            elif action == "fetch":
                # Source code fetch workflow
                console.print()
                console.rule("[bold cyan]Source Code Acquisition[/]")
                console.print()

                fetch_outcome = run_interactive_fetch()

                if fetch_outcome is None:
                    if not prompt_continue_on_error():
                        break
                    continue

                # Ask what to do next after fetch
                next_action = ask_next_action()
                if next_action == "exit":
                    show_goodbye()
                    break
                elif next_action == "analyze":
                    show_info(
                        "Analysis Mode",
                        "Vulnerability analysis is not yet implemented.\n"
                        "This feature will be available in a future version.",
                    )
                    show_goodbye()
                    break
                # else continue to main menu

            elif action == "intel":
                # Threat intelligence workflow
                run_intel_interactive()

            elif action == "clean":
                # Clean workspaces
                console.print()
                console.rule("[bold cyan]Workspace Cleanup[/]")
                console.print()
                fetcher = AssetFetcher()
                cleaned = fetcher.cleanup_all()
                show_success("Cleanup Complete", f"Cleaned up {cleaned} workspace(s)")

        except KeyboardInterrupt:
            console.print()
            show_info("Interrupted", "Operation cancelled by user.")
            break


def run_intel_interactive() -> None:
    """Run interactive threat intelligence workflow."""
    console.print()
    console.rule("[bold cyan]Threat Intelligence[/]")
    console.print()

    while True:
        try:
            action = select_intel_menu_action()

            if action is None or action == "back":
                break

            elif action == "search":
                run_intel_search_interactive()

            elif action == "sync":
                run_intel_sync_interactive()

            elif action == "kev":
                run_intel_kev_interactive()

            elif action == "stats":
                run_intel_stats_interactive()

        except KeyboardInterrupt:
            console.print()
            show_info("Interrupted", "Operation cancelled.")
            break


def run_intel_search_interactive() -> None:
    """Run interactive CVE search."""
    from questionary import text

    query = text(
        "Enter search query:",
        instruction="(e.g., 'apache struts', 'rce', 'sql injection')",
    ).ask()

    if not query:
        return

    async def _search():
        from src.layers.l1_intelligence.threat_intel import IntelService

        async with IntelService() as service:
            cves = await service.search_cves(query, limit=20)
            return cves

    cves = asyncio.get_event_loop().run_until_complete(_search())

    if cves:
        from src.cli.intel_display import show_cve_table

        show_cve_table(cves, title=f"Search Results: '{query}'")

        # Ask if user wants to see details
        from questionary import confirm, text

        if confirm("View CVE details?", default=False).ask():
            cve_id = text("Enter CVE ID:").ask()
            if cve_id:
                run_intel_show_interactive(cve_id)
    else:
        show_info("No Results", f"No CVEs found matching '{query}'")


def run_intel_show_interactive(cve_id: str) -> None:
    """Show CVE details interactively.

    Args:
        cve_id: CVE identifier.
    """
    # Normalize CVE ID
    cve_id = cve_id.upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    async def _show():
        from src.layers.l1_intelligence.threat_intel import IntelService

        async with IntelService() as service:
            cve = await service.get_cve(cve_id)
            pocs = await service.get_pocs_for_cve(cve_id) if cve else []
            return cve, pocs

    cve, pocs = asyncio.get_event_loop().run_until_complete(_show())

    if cve:
        from src.cli.intel_display import show_cve_detail

        show_cve_detail(cve, pocs)
    else:
        show_info(
            "CVE Not Found",
            f"'{cve_id}' was not found.\n"
            "Try syncing first: deepvuln intel sync",
        )


def run_intel_sync_interactive() -> None:
    """Run interactive sync."""
    from questionary import select

    sync_type = select(
        "What would you like to sync?",
        choices=[
            "Recent CVEs (last 7 days)",
            "Full sync (last 30 days)",
            "KEV catalog only",
            "Cancel",
        ],
    ).ask()

    if sync_type == "Cancel" or sync_type is None:
        return

    async def _sync():
        from src.layers.l1_intelligence.threat_intel import IntelService

        async with IntelService() as service:
            with create_progress() as progress:
                task = progress.add_task("[cyan]Syncing...", total=None)

                if "Recent" in sync_type:
                    await service.sync_cves(days=7)
                    await service.sync_kev()
                elif "Full" in sync_type:
                    await service.sync_all(days=30)
                elif "KEV" in sync_type:
                    await service.sync_kev()

                progress.update(task, completed=True, description="[green]Done!")

    asyncio.get_event_loop().run_until_complete(_sync())
    show_success("Sync Complete", "Synced threat intelligence data")


def run_intel_kev_interactive() -> None:
    """Show KEV alerts interactively."""
    async def _kev():
        from src.layers.l1_intelligence.threat_intel import IntelService

        async with IntelService() as service:
            kevs = await service.get_kev_cves(limit=20)
            return kevs

    kevs = asyncio.get_event_loop().run_until_complete(_kev())

    if kevs:
        from src.cli.intel_display import show_kev_alerts

        show_kev_alerts(kevs, title="Known Exploited Vulnerabilities")
    else:
        show_info("No KEVs", "No KEV data available. Try syncing first.")


def run_intel_stats_interactive() -> None:
    """Show statistics interactively."""
    async def _stats():
        from src.layers.l1_intelligence.threat_intel import IntelService

        async with IntelService() as service:
            return await service.get_stats()

    stats = asyncio.get_event_loop().run_until_complete(_stats())

    from src.cli.intel_display import show_stats

    show_stats(stats)


@click.group(invoke_without_command=True)
@click.option("--interactive", "-i", is_flag=True, help="Run in interactive mode")
@click.option("--version", "-v", is_flag=True, help="Show version")
@click.pass_context
def main(ctx: click.Context, interactive: bool, version: bool) -> None:
    """DeepVuln - Seven-Layer Intelligent Vulnerability Analysis System.

    Run without arguments to start interactive mode.
    """
    if version:
        from src import __version__

        click.echo(f"DeepVuln version {__version__}")
        return

    if interactive or ctx.invoked_subcommand is None:
        run_interactive_mode()


@main.command()
@click.option("--url", "-u", required=True, help="Git repository URL")
@click.option("--branch", "-b", help="Branch to checkout")
@click.option("--tag", "-t", help="Tag to checkout")
@click.option("--commit", "-c", help="Commit SHA to checkout")
@click.option("--depth", "-d", default=1, help="Clone depth (0 for full)")
@click.option("--workspace", "-w", help="Workspace name")
def git(
    url: str,
    branch: str | None,
    tag: str | None,
    commit: str | None,
    depth: int,
    workspace: str | None,
) -> None:
    """Fetch source code from a Git repository.

    Example:
        deepvuln git --url https://github.com/user/repo.git --branch main
    """
    from src.models.fetcher import GitRef, GitRefType

    show_banner()

    git_ref = None
    if branch:
        git_ref = GitRef(ref_type=GitRefType.BRANCH, ref_value=branch)
    elif tag:
        git_ref = GitRef(ref_type=GitRefType.TAG, ref_value=tag)
    elif commit:
        git_ref = GitRef(ref_type=GitRefType.COMMIT, ref_value=commit)

    config = {
        "repo_url": url,
        "git_ref": git_ref,
        "depth": depth,
        "workspace_name": workspace,
    }

    show_summary("git", config)

    result = execute_fetch("git", config)

    if result and result.get("result", {}).get("success"):
        show_success("Success", "Source code fetched successfully!")


@main.command()
@click.option("--path", "-p", required=True, type=click.Path(exists=True), help="Local path")
@click.option("--copy/--no-copy", default=True, help="Copy to workspace")
@click.option("--workspace", "-w", help="Workspace name")
def local(path: str, copy: bool, workspace: str | None) -> None:
    """Fetch source code from a local directory.

    Example:
        deepvuln local --path /path/to/project
    """
    from pathlib import Path

    show_banner()

    config = {
        "local_path": Path(path),
        "copy_to_workspace": copy,
        "workspace_name": workspace,
    }

    show_summary("local", config)

    result = execute_fetch("local", config)

    if result and result.get("result", {}).get("success"):
        show_success("Success", "Source code loaded successfully!")


@main.command()
def clean() -> None:
    """Clean up all workspaces."""
    show_banner()

    fetcher = AssetFetcher()
    cleaned = fetcher.cleanup_all()

    show_success("Cleanup Complete", f"Cleaned up {cleaned} workspace(s)")


# Add intel command group
main.add_command(intel_group, name="intel")


if __name__ == "__main__":
    main()
