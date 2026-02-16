"""Main CLI entry point for DeepVuln."""

import asyncio
from pathlib import Path
from typing import Any

import click

from src.cli.display import (
    console,
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
from src.cli.intel import intel as intel_group
from src.cli.prompts import (
    ask_next_action_with_scan,
    ask_scan_action_after_result,
    get_git_config,
    get_local_config,
    prompt_continue_on_error,
    prompt_export_path,
    prompt_scan_options,
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

                # Ask what to do next after fetch (with scan option)
                next_action = ask_next_action_with_scan()
                if next_action == "exit":
                    show_goodbye()
                    break
                elif next_action == "scan":
                    # Run security scan
                    source_path = Path(fetch_outcome["result"]["source_path"])
                    run_security_scan_interactive(source_path)
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

    cves = asyncio.run(_search())

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

    cve, pocs = asyncio.run(_show())

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

    asyncio.run(_sync())
    show_success("Sync Complete", "Synced threat intelligence data")


def run_intel_kev_interactive() -> None:
    """Show KEV alerts interactively."""
    async def _kev():
        from src.layers.l1_intelligence.threat_intel import IntelService

        async with IntelService() as service:
            kevs = await service.get_kev_cves(limit=20)
            return kevs

    kevs = asyncio.run(_kev())

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

    stats = asyncio.run(_stats())

    from src.cli.intel_display import show_stats

    show_stats(stats)


def run_security_scan_interactive(source_path: Path, options: dict[str, Any] | None = None) -> None:
    """Run interactive security scan on source code.

    Args:
        source_path: Path to the source code.
        options: Optional scan options.
    """
    from src.cli.scan_display import (
        export_report_text,
        show_kev_warning,
        show_quick_scan_result,
        show_scan_progress,
        show_security_report,
    )
    from src.layers.l1_intelligence.workflow import AutoSecurityScanner, ScanConfig

    console.print()
    console.rule("[bold cyan]Security Scan[/]")
    console.print()

    # Get options if not provided
    if options is None:
        options = prompt_scan_options() or {}

    # Create scan config
    config = ScanConfig(
        include_low_severity=options.get("include_low_severity", False),
    )

    async def _scan():
        from src.layers.l1_intelligence.threat_intel import IntelService

        async with IntelService() as service:
            scanner = AutoSecurityScanner(intel_service=service, config=config)

            # First do a quick scan
            show_scan_progress("Running quick scan...")
            quick_result = await scanner.quick_scan(source_path)

            return scanner, quick_result

    # Run scan
    with create_progress() as progress:
        task = progress.add_task("[cyan]Scanning for vulnerabilities...", total=None)
        scanner, quick_result = asyncio.run(_scan())
        progress.update(task, completed=True, description="[green]Scan complete!")

    # Show quick result first
    show_quick_scan_result(quick_result)

    if not quick_result.get("success"):
        show_info("Scan Failed", "\n".join(quick_result.get("errors", ["Unknown error"])))
        return

    # If issues found, show detailed report
    if quick_result.get("has_issues"):
        # Get full report
        async def _full_scan():
            from src.layers.l1_intelligence.threat_intel import IntelService

            async with IntelService() as service:
                scanner = AutoSecurityScanner(intel_service=service, config=config)
                result = await scanner.scan(source_path)
                return result

        show_scan_progress("Getting detailed report...")
        scan_result = asyncio.run(_full_scan())

        if scan_result.success and scan_result.report:
            # Show KEV warning first if applicable
            show_kev_warning(scan_result.report)

            # Show full report
            show_security_report(scan_result.report, detailed=options.get("detailed", False))

            # Ask what to do next
            while True:
                action = ask_scan_action_after_result(scan_result.report.has_vulnerabilities)

                if action == "exit":
                    break
                elif action == "details":
                    from src.cli.scan_display import show_vulnerability_list

                    show_vulnerability_list(scan_result.report, show_all=True)
                elif action == "export":
                    export_path = prompt_export_path()
                    if export_path:
                        report_text = export_report_text(scan_result.report)
                        Path(export_path).write_text(report_text, encoding="utf-8")
                        show_success("Export Complete", f"Report saved to {export_path}")
                elif action == "new":
                    return  # Return to main flow

            show_goodbye()
    else:
        show_success("Scan Complete", "No security issues detected!")
        show_goodbye()


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


@main.command()
@click.option("--path", "-p", required=True, type=click.Path(exists=True), help="Path to source code")
@click.option("--include-low", is_flag=True, help="Include low severity vulnerabilities")
@click.option("--detailed", "-d", is_flag=True, help="Show detailed report")
@click.option("--export", "-e", "export_path", help="Export report to file")
def scan(path: str, include_low: bool, detailed: bool, export_path: str | None) -> None:
    """Run security scan on source code.

    This command scans the source code for known vulnerabilities by:
    - Detecting dependency files (package.json, requirements.txt, etc.)
    - Identifying the technology stack (frameworks, databases, etc.)
    - Correlating dependencies with known CVEs

    Example:
        deepvuln scan --path /path/to/project
        deepvuln scan -p . --detailed --export report.txt
    """
    show_banner()

    source_path = Path(path)
    options = {
        "include_low_severity": include_low,
        "detailed": detailed,
    }

    if export_path:
        # Non-interactive mode for export
        run_security_scan_export(source_path, export_path, options)
    else:
        run_security_scan_interactive(source_path, options)


def run_security_scan_export(source_path: Path, export_path: str, options: dict[str, Any]) -> None:
    """Run security scan and export to file.

    Args:
        source_path: Path to the source code.
        export_path: Path to export file.
        options: Scan options.
    """
    from src.cli.scan_display import export_report_text
    from src.layers.l1_intelligence.workflow import AutoSecurityScanner, ScanConfig

    config = ScanConfig(
        include_low_severity=options.get("include_low_severity", False),
    )

    async def _scan():
        from src.layers.l1_intelligence.threat_intel import IntelService

        async with IntelService() as service:
            scanner = AutoSecurityScanner(intel_service=service, config=config)
            result = await scanner.scan(source_path)
            return result

    console.print(f"[cyan]Scanning {source_path}...[/]")

    with create_progress() as progress:
        task = progress.add_task("[cyan]Analyzing...", total=None)
        scan_result = asyncio.run(_scan())
        progress.update(task, completed=True, description="[green]Done!")

    if scan_result.success and scan_result.report:
        # Export report
        report_text = export_report_text(scan_result.report)
        Path(export_path).write_text(report_text, encoding="utf-8")

        console.print()
        console.print(f"[green]Report exported to: {export_path}[/]")
        console.print(f"  Dependencies scanned: {scan_result.report.dependencies_scanned}")
        console.print(f"  Vulnerabilities found: {scan_result.report.total_vulnerabilities}")
        console.print(f"  KEV (known exploited): {scan_result.report.kev_count}")
    else:
        show_error("Scan Failed", "\n".join(scan_result.errors or ["Unknown error"]))


# Add intel command group
main.add_command(intel_group, name="intel")


if __name__ == "__main__":
    main()
