"""Main CLI entry point for DeepVuln."""

import asyncio
from pathlib import Path
from typing import Any

import click

from src.cli.config_display import export_config_report_json, export_config_report_text, show_config_report
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


def _check_and_prompt_sync() -> None:
    """Check database status and prompt user to sync if needed."""
    from questionary import confirm, select

    async def check_status():
        from src.layers.l1_intelligence.threat_intel import IntelService
        async with IntelService() as service:
            return await service.check_database_status()

    status = asyncio.run(check_status())

    # Skip if database is ok
    if status["recommendation"] == "ok":
        return

    # Show warning based on status
    if status["recommendation"] == "first_sync":
        console.print()
        console.print("[yellow]⚠ CVE database is empty![/]")
        console.print("[dim]Security scans require CVE data to detect vulnerabilities.[/]")
        console.print()

        choices = [
            "Sync now (recommended - takes a few minutes)",
            "Skip for now",
        ]
    elif status["recommendation"] == "update":
        days = status.get("days_since_sync", "?")
        console.print()
        console.print(f"[yellow]⚠ CVE database is outdated ({days} days since last sync)[/]")
        console.print("[dim]New vulnerabilities may have been published.[/]")
        console.print()

        choices = [
            "Update now (recommended)",
            "Skip for now",
        ]
    else:
        return

    choice = select(
        "What would you like to do?",
        choices=choices,
    ).ask()

    if choice is None or "Skip" in choice:
        console.print("[dim]You can sync later using: deepvuln intel sync[/]")
        return

    # Perform sync
    _run_sync(status["recommendation"] == "first_sync")


def _run_sync(is_first_sync: bool) -> None:
    """Run the CVE sync process."""
    from src.layers.l1_intelligence.threat_intel import IntelService

    async def do_sync():
        async with IntelService() as service:
            with create_progress() as progress:
                task = progress.add_task("[cyan]Syncing CVE data...", total=None)

                if is_first_sync:
                    # First sync: get last 30 days
                    result = await service.sync_all(days=30)
                else:
                    # Update: get last 7 days
                    result = await service.sync_cves(days=7)
                    await service.sync_kev()

                progress.update(task, completed=True, description="[green]Sync complete!")
                return result

    console.print()
    console.print("[cyan]Starting sync...[/]")

    try:
        result = asyncio.run(do_sync())

        cves_synced = result.get("cves_synced", 0)
        kev_synced = result.get("kev_synced", 0)
        errors = result.get("errors", [])

        if errors:
            console.print(f"[yellow]Sync completed with {len(errors)} warnings[/]")

        show_success(
            "Sync Complete",
            f"Synced {cves_synced} CVEs, {kev_synced} KEV entries\n"
            f"You can now run security scans.",
        )
    except Exception as e:
        show_error("Sync Failed", str(e))
        console.print("[dim]You can try again later: deepvuln intel sync[/]")


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

    # Check database status and prompt for sync if needed
    _check_and_prompt_sync()

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


@main.command("config-analyze")
@click.option("--path", "-p", required=True, type=click.Path(exists=True), help="Path to source code")
@click.option("--output", "-o", "output_path", type=click.Path(), help="Output file for report")
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json"]), default="text", help="Output format")
@click.option("--detailed", "-d", is_flag=True, help="Show detailed findings")
@click.option("--show-evidence", is_flag=True, help="Show evidence (secrets will be masked)")
def config_analyze(
    path: str,
    output_path: str | None,
    output_format: str,
    detailed: bool,
    show_evidence: bool,
) -> None:
    """Analyze build configurations for security issues.

    This command scans build configuration files for security issues:
    - Hardcoded secrets (API keys, passwords, tokens)
    - Dockerfile security misconfigurations
    - CI/CD pipeline security issues
    - Maven/Gradle/Python build file issues

    Examples:
        deepvuln config-analyze --path /path/to/project
        deepvuln config-analyze -p . --detailed --show-evidence
        deepvuln config-analyze -p . -f json -o report.json
    """
    from src.layers.l1_intelligence.build_config.analyzer import BuildConfigAnalyzer

    show_banner()
    source_path = Path(path)

    console.print(f"[cyan]Analyzing build configurations in {source_path}...[/]\n")

    # Run analysis
    analyzer = BuildConfigAnalyzer()
    report = analyzer.analyze(source_path)

    console.print("[green]Analysis complete![/]\n")

    # Output results
    if output_path:
        # Export to file
        if output_format == "json":
            content = export_config_report_json(report)
        else:
            content = export_config_report_text(report)

        Path(output_path).write_text(content, encoding="utf-8")
        console.print(f"\n[green]Report exported to: {output_path}[/]")
        console.print(f"  Files scanned: {len(report.scanned_files)}")
        console.print(f"  Total findings: {len(report.findings)}")
    else:
        # Display to console
        show_config_report(report, detailed=detailed, show_evidence=show_evidence)


# Add intel command group
main.add_command(intel_group, name="intel")


@main.command()
@click.option("--path", "-p", required=True, type=click.Path(exists=True), help="Path to source file or directory")
@click.option("--output", "-o", type=click.Path(), help="Output file for JSON report")
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json"]), default="text", help="Output format")
@click.option("--call-graph", "-c", is_flag=True, help="Show call graph")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def parse(path: str, output: str | None, output_format: str, call_graph: bool, verbose: bool) -> None:
    """Parse source code structure.

    Extract classes, functions, imports, and call graphs from source code.
    Supports Java, Python, and Go files.

    Examples:
        deepvuln parse --path src/main.py
        deepvuln parse -p ./src -f json -o structure.json
        deepvuln parse -p . --call-graph --verbose
    """
    from pathlib import Path

    from src.layers.l1_intelligence.code_structure import (
        ParseOptions,
        parse_file,
        parse_project,
    )

    source_path = Path(path)

    if source_path.is_file():
        # Parse single file
        options = ParseOptions(build_call_graph=call_graph)
        module = parse_file(source_path, options)

        if output_format == "json":
            output_result = _format_module_json(module)
        else:
            output_result = _format_module_text(module, verbose)

        if output:
            Path(output).write_text(output_result if isinstance(output_result, str) else json.dumps(output_result, indent=2), encoding="utf-8")
            console.print(f"[green]Output written to: {output}[/]")
        else:
            if output_format == "json":
                import json
                console.print_json(json.dumps(output_result, indent=2))
            else:
                console.print(output_result)

    elif source_path.is_dir():
        # Parse project
        options = ParseOptions(build_call_graph=call_graph)
        project = parse_project(source_path, options)

        if output_format == "json":
            output_result = _format_project_json(project)
        else:
            output_result = _format_project_text(project, verbose, call_graph)

        if output:
            import json
            Path(output).write_text(output_result if isinstance(output_result, str) else json.dumps(output_result, indent=2), encoding="utf-8")
            console.print(f"[green]Output written to: {output}[/]")
        else:
            if output_format == "json":
                import json
                console.print_json(json.dumps(output_result, indent=2))
            else:
                console.print(output_result)
    else:
        show_error("Invalid Path", f"Path does not exist: {source_path}")


def _format_module_text(module, verbose: bool) -> str:
    """Format module info as text."""
    from rich.table import Table
    from io import StringIO

    output = StringIO()

    # Header
    output.write(f"\n[bold cyan]Module: {module.file_path}[/]\n")
    output.write(f"[dim]Language: {module.language} | Lines: {module.line_count}[/]\n\n")

    # Package/Module name
    if module.package:
        output.write(f"[yellow]Package:[/] {module.package}\n")
    if module.module_name:
        output.write(f"[yellow]Module:[/] {module.module_name}\n")

    # Imports
    if module.imports:
        output.write(f"\n[green]Imports ({len(module.imports)}):[/]\n")
        for imp in module.imports[:10]:  # Limit display
            if imp.is_wildcard:
                output.write(f"  from {imp.module} import *\n")
            elif imp.names:
                output.write(f"  from {imp.module} import {', '.join(imp.names)}\n")
            else:
                alias = f" as {imp.alias}" if imp.alias else ""
                output.write(f"  import {imp.module}{alias}\n")
        if len(module.imports) > 10:
            output.write(f"  [dim]... and {len(module.imports) - 10} more[/]\n")

    # Classes
    if module.classes:
        output.write(f"\n[green]Classes ({len(module.classes)}):[/]\n")
        for cls in module.classes:
            output.write(f"  [bold]{cls.name}[/] ({cls.type.value})\n")
            if cls.bases:
                output.write(f"    [dim]extends: {', '.join(cls.bases)}[/]\n")
            if verbose and cls.methods:
                output.write(f"    [dim]methods: {', '.join(m.name for m in cls.methods[:5])}[/]\n")
            if verbose and cls.fields:
                output.write(f"    [dim]fields: {', '.join(f.name for f in cls.fields[:5])}[/]\n")

    # Functions
    if module.functions:
        output.write(f"\n[green]Functions ({len(module.functions)}):[/]\n")
        for func in module.functions[:10]:
            params = ", ".join(p.name for p in func.parameters[:3])
            if len(func.parameters) > 3:
                params += "..."
            ret = f" -> {func.return_type}" if func.return_type else ""
            output.write(f"  [bold]{func.name}[/]({params}){ret}\n")
        if len(module.functions) > 10:
            output.write(f"  [dim]... and {len(module.functions) - 10} more[/]\n")

    # Call graph
    if module.call_graph.edges:
        output.write(f"\n[green]Call Graph ({len(module.call_graph.edges)} edges):[/]\n")
        for edge in module.call_graph.edges[:10]:
            output.write(f"  {edge.caller} -> {edge.callee} (line {edge.line})\n")
        if len(module.call_graph.edges) > 10:
            output.write(f"  [dim]... and {len(module.call_graph.edges) - 10} more[/]\n")

    # Errors
    if module.parse_errors:
        output.write(f"\n[red]Errors ({len(module.parse_errors)}):[/]\n")
        for err in module.parse_errors:
            output.write(f"  {err}\n")

    return output.getvalue()


def _format_project_text(project, verbose: bool, show_call_graph: bool) -> str:
    """Format project structure as text."""
    from io import StringIO

    output = StringIO()

    # Header
    output.write(f"\n[bold cyan]Project: {project.root_path}[/]\n")
    output.write(f"[dim]Files: {project.total_files} | Lines: {project.total_lines}[/]\n")
    output.write(f"[dim]Languages: {', '.join(project.languages)}[/]\n\n")

    # Statistics
    output.write("[green]Statistics:[/]\n")
    output.write(f"  Classes: {len(project.all_classes)}\n")
    output.write(f"  Functions: {len(project.all_functions)}\n")
    output.write(f"  Call Graph Edges: {len(project.global_call_graph.edges)}\n")

    # Classes summary by language
    if project.all_classes and verbose:
        output.write(f"\n[green]Classes ({len(project.all_classes)}):[/]\n")
        for name, cls in list(project.all_classes.items())[:15]:
            output.write(f"  [bold]{name}[/] ({cls.type.value})\n")
        if len(project.all_classes) > 15:
            output.write(f"  [dim]... and {len(project.all_classes) - 15} more[/]\n")

    # Functions summary
    if project.all_functions and verbose:
        output.write(f"\n[green]Functions ({len(project.all_functions)}):[/]\n")
        for name, func in list(project.all_functions.items())[:15]:
            output.write(f"  [bold]{name}[/]\n")
        if len(project.all_functions) > 15:
            output.write(f"  [dim]... and {len(project.all_functions) - 15} more[/]\n")

    # Call graph
    if show_call_graph and project.global_call_graph.edges:
        output.write(f"\n[green]Call Graph ({len(project.global_call_graph.edges)} edges):[/]\n")
        for edge in project.global_call_graph.edges[:20]:
            output.write(f"  {edge.caller} -> {edge.callee}\n")
        if len(project.global_call_graph.edges) > 20:
            output.write(f"  [dim]... and {len(project.global_call_graph.edges) - 20} more[/]\n")

    # Parse errors
    if project.parse_errors:
        output.write(f"\n[red]Parse Errors ({len(project.parse_errors)} files):[/]\n")
        for file_path, error in list(project.parse_errors.items())[:5]:
            output.write(f"  {file_path}: {error[:50]}...\n")
        if len(project.parse_errors) > 5:
            output.write(f"  [dim]... and {len(project.parse_errors) - 5} more[/]\n")

    return output.getvalue()


def _format_module_json(module) -> dict:
    """Format module info as JSON-serializable dict."""
    return {
        "file_path": module.file_path,
        "language": module.language,
        "package": module.package,
        "module_name": module.module_name,
        "line_count": module.line_count,
        "imports": [
            {
                "module": imp.module,
                "names": imp.names,
                "alias": imp.alias,
                "is_wildcard": imp.is_wildcard,
                "line": imp.line,
            }
            for imp in module.imports
        ],
        "classes": [
            {
                "name": cls.name,
                "full_name": cls.full_name,
                "type": cls.type.value,
                "bases": cls.bases,
                "methods": [
                    {
                        "name": m.name,
                        "full_name": m.full_name,
                        "parameters": [{"name": p.name, "type": p.type} for p in m.parameters],
                        "return_type": m.return_type,
                        "visibility": m.visibility.value,
                    }
                    for m in cls.methods
                ],
                "fields": [
                    {
                        "name": f.name,
                        "type": f.type,
                        "visibility": f.visibility.value,
                    }
                    for f in cls.fields
                ],
            }
            for cls in module.classes
        ],
        "functions": [
            {
                "name": func.name,
                "full_name": func.full_name,
                "parameters": [{"name": p.name, "type": p.type} for p in func.parameters],
                "return_type": func.return_type,
                "visibility": func.visibility.value,
                "decorators": func.decorators,
            }
            for func in module.functions
        ],
        "call_graph": {
            "edges": [
                {
                    "caller": edge.caller,
                    "callee": edge.callee,
                    "line": edge.line,
                }
                for edge in module.call_graph.edges
            ]
        },
        "parse_errors": module.parse_errors,
    }


def _format_project_json(project) -> dict:
    """Format project structure as JSON-serializable dict."""
    return {
        "root_path": project.root_path,
        "primary_language": project.primary_language,
        "languages": project.languages,
        "total_files": project.total_files,
        "total_lines": project.total_lines,
        "statistics": {
            "classes": len(project.all_classes),
            "functions": len(project.all_functions),
            "call_graph_edges": len(project.global_call_graph.edges),
        },
        "classes": [
            {
                "name": cls.name,
                "full_name": cls.full_name,
                "type": cls.type.value,
                "file_path": cls.file_path,
            }
            for cls in project.all_classes.values()
        ],
        "functions": [
            {
                "name": func.name,
                "full_name": func.full_name,
                "file_path": func.file_path,
            }
            for func in project.all_functions.values()
        ],
        "call_graph": {
            "edges": [
                {
                    "caller": edge.caller,
                    "callee": edge.callee,
                    "file_path": edge.file_path,
                    "line": edge.line,
                }
                for edge in project.global_call_graph.edges
            ]
        },
        "parse_errors": {
            path: error
            for path, error in project.parse_errors.items()
        },
    }


if __name__ == "__main__":
    main()
