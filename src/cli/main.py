"""Main CLI entry point for DeepVuln."""

import asyncio
from pathlib import Path
from typing import Any

import click

from src.cli.config_display import (
    export_config_report_json,
    export_config_report_text,
    show_config_report,
)
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
    from questionary import select

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


@main.command("semgrep")
@click.option("--path", "-p", required=True, type=click.Path(exists=True), help="Path to source code")
@click.option("--rules", "-r", multiple=True, help="Custom rule files or directories")
@click.option("--rule-sets", "-s", multiple=True, help="Official rule sets (security, owasp-top-ten, java, python, etc.)")
@click.option("--auto", "-a", is_flag=True, help="Auto-detect rules based on project")
@click.option("--severity", multiple=True, type=click.Choice(["critical", "high", "medium", "low", "info"]), help="Filter by severity")
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json", "markdown"]), default="text", help="Output format")
@click.option("--lang", "languages", multiple=True, help="Restrict to specific languages")
def semgrep_scan(
    path: str,
    rules: tuple[str, ...],
    rule_sets: tuple[str, ...],
    auto: bool,
    severity: tuple[str, ...],
    output: str | None,
    output_format: str,
    languages: tuple[str, ...],
) -> None:
    """Run Semgrep static analysis scan.

    Semgrep is a fast static analysis tool that finds bugs and vulnerabilities
    using pattern matching. This command integrates Semgrep into DeepVuln.

    Rule Sets:
        security      - General security rules
        owasp-top-ten - OWASP Top 10 vulnerabilities
        java          - Java-specific rules
        python        - Python-specific rules
        go            - Go-specific rules
        secrets       - Secret detection rules

    Examples:
        deepvuln semgrep --path ./src
        deepvuln semgrep -p . --auto
        deepvuln semgrep -p . -s security -s owasp-top-ten
        deepvuln semgrep -p . -r rules/custom.yaml --severity high
        deepvuln semgrep -p . -f json -o report.json
    """
    from src.layers.l3_analysis import SemgrepEngine, SeverityLevel

    show_banner()
    source_path = Path(path)

    console.print(f"[cyan]Running Semgrep scan on {source_path}...[/]\n")

    # Create engine
    engine = SemgrepEngine()

    # Check availability
    if not engine.is_available():
        show_error(
            "Semgrep Not Available",
            "Semgrep is not installed or not found in PATH.\n"
            "Install with: pip install semgrep",
        )
        return

    # Build severity filter
    severity_filter = None
    if severity:
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        severity_filter = [severity_map[s] for s in severity]

    # Run scan
    async def _scan():
        return await engine.scan(
            source_path=source_path,
            rules=list(rules) if rules else None,
            rule_sets=list(rule_sets) if rule_sets else None,
            languages=list(languages) if languages else None,
            severity_filter=severity_filter,
            use_auto_config=auto,
        )

    with create_progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=None)
        result = asyncio.run(_scan())
        progress.update(task, completed=True, description="[green]Scan complete!")

    # Handle scan failure
    if not result.success:
        show_error("Scan Failed", result.error_message or "Unknown error")
        return

    # Deduplicate findings
    duplicates = result.deduplicate_findings()
    if duplicates > 0:
        console.print(f"[dim]Removed {duplicates} duplicate findings[/]")

    # Output results
    if output:
        _export_semgrep_result(result, output, output_format)
        console.print(f"\n[green]Report exported to: {output}[/]")
    else:
        _display_semgrep_result(result, output_format)


def _display_semgrep_result(result, output_format: str) -> None:
    """Display Semgrep scan results."""
    from rich.table import Table

    console.print()
    console.rule("[bold cyan]Scan Results[/]")
    console.print()

    # Summary
    console.print(f"[dim]Source:[/] {result.source_path}")
    console.print(f"[dim]Engine:[/] {result.engine}")
    console.print(f"[dim]Duration:[/] {result.duration_seconds:.2f}s")
    console.print(f"[dim]Rules Used:[/] {', '.join(result.rules_used) or 'default'}")
    console.print()

    # Statistics
    console.print(f"[bold]Total Findings:[/] {result.total_findings}")

    if result.total_findings > 0:
        # Severity breakdown
        sev_table = Table(title="By Severity", show_header=True)
        sev_table.add_column("Severity", style="cyan")
        sev_table.add_column("Count", justify="right")

        severity_colors = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = result.by_severity.get(sev, 0)
            if count > 0:
                color = severity_colors.get(sev, "white")
                sev_table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))

        console.print(sev_table)
        console.print()

    if output_format == "json":
        console.print_json(result.to_json())
    elif output_format == "markdown":
        console.print(result.to_markdown())
    else:
        # Text format - show findings
        if result.findings:
            findings_table = Table(title="Findings", show_header=True)
            findings_table.add_column("Severity", width=10)
            findings_table.add_column("Location", width=30)
            findings_table.add_column("Title", width=50)
            findings_table.add_column("Rule", width=25)

            for finding in result.findings[:50]:  # Limit display
                color = severity_colors.get(finding.severity.value, "white")
                findings_table.add_row(
                    f"[{color}]{finding.severity.value.upper()}[/{color}]",
                    finding.location.to_display(),
                    finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
                    finding.rule_id or "-",
                )

            console.print(findings_table)

            if len(result.findings) > 50:
                console.print(f"\n[dim]... and {len(result.findings) - 50} more findings[/]")
        else:
            console.print("[green]No findings![/]")


def _export_semgrep_result(result, output_path: str, output_format: str) -> None:
    """Export Semgrep results to file."""
    if output_format == "json":
        content = result.to_json()
    elif output_format == "markdown":
        content = result.to_markdown()
    else:
        content = result.to_summary()
        if result.findings:
            content += "\n\n## Findings\n\n"
            for finding in result.findings:
                content += f"- [{finding.severity.value.upper()}] {finding.title}\n"
                content += f"  Location: {finding.location.to_display()}\n"
                content += f"  Rule: {finding.rule_id or 'N/A'}\n"
                if finding.description:
                    content += f"  Description: {finding.description}\n"
                content += "\n"

    Path(output_path).write_text(content, encoding="utf-8")


@main.command("codeql")
@click.option("--path", "-p", required=True, type=click.Path(exists=True), help="Path to source code")
@click.option("--language", "-l", type=click.Choice(["java", "python", "go", "javascript", "typescript", "c", "cpp", "csharp", "ruby"]), help="Programming language (auto-detected if not specified)")
@click.option("--queries", "-q", multiple=True, help="Custom query files to run")
@click.option("--suite", "-s", help="Query suite name (e.g., java-security-extended)")
@click.option("--database", "-d", type=click.Path(), help="Path to store/load CodeQL database")
@click.option("--severity", multiple=True, type=click.Choice(["critical", "high", "medium", "low", "info"]), help="Filter by severity")
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json", "markdown"]), default="text", help="Output format")
@click.option("--overwrite", is_flag=True, default=True, help="Overwrite existing database (default: True)")
def codeql_scan(
    path: str,
    language: str | None,
    queries: tuple[str, ...],
    suite: str | None,
    database: str | None,
    severity: tuple[str, ...],
    output: str | None,
    output_format: str,
    overwrite: bool,
) -> None:
    """Run CodeQL deep dataflow analysis scan.

    CodeQL is a powerful code analysis engine that performs deep dataflow
    analysis to find complex vulnerabilities. This command integrates
    CodeQL into DeepVuln.

    CodeQL requires the CodeQL CLI to be installed separately:
        https://github.com/github/codeql-cli-binaries/releases

    Query Suites:
        java-security-extended    - Extended Java security rules
        python-security-extended  - Extended Python security rules
        go-security-extended      - Extended Go security rules
        javascript-security-extended - Extended JavaScript security rules

    Examples:
        deepvuln codeql --path ./src
        deepvuln codeql -p . --language java
        deepvuln codeql -p . -s java-security-extended
        deepvuln codeql -p . -q custom.ql --severity high
        deepvuln codeql -p . -d ./codeql-db -f json -o report.json
    """
    from src.layers.l3_analysis import CodeQLEngine, SeverityLevel

    show_banner()
    source_path = Path(path)

    console.print(f"[cyan]Running CodeQL analysis on {source_path}...[/]\n")

    # Create engine
    engine = CodeQLEngine()

    # Check availability
    if not engine.is_available():
        show_error(
            "CodeQL Not Available",
            "CodeQL CLI is not installed or not found in PATH.\n\n"
            "Install CodeQL CLI from:\n"
            "  https://github.com/github/codeql-cli-binaries/releases\n\n"
            "After installation, ensure 'codeql' is in your PATH.",
        )
        return

    # Build severity filter
    severity_filter = None
    if severity:
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        severity_filter = [severity_map[s] for s in severity]

    # Run scan
    async def _scan():
        return await engine.scan(
            source_path=source_path,
            language=language,
            queries=list(queries) if queries else None,
            query_suite=suite,
            severity_filter=severity_filter,
            database_path=Path(database) if database else None,
            overwrite_database=overwrite,
        )

    with create_progress() as progress:
        task = progress.add_task("[cyan]Creating database and analyzing...", total=None)
        result = asyncio.run(_scan())
        progress.update(task, completed=True, description="[green]Analysis complete!")

    # Handle scan failure
    if not result.success:
        show_error("Scan Failed", result.error_message or "Unknown error")
        return

    # Deduplicate findings
    duplicates = result.deduplicate_findings()
    if duplicates > 0:
        console.print(f"[dim]Removed {duplicates} duplicate findings[/]")

    # Output results
    if output:
        _export_codeql_result(result, output, output_format)
        console.print(f"\n[green]Report exported to: {output}[/]")
    else:
        _display_codeql_result(result, output_format)


def _display_codeql_result(result, output_format: str) -> None:
    """Display CodeQL scan results."""
    from rich.table import Table

    console.print()
    console.rule("[bold cyan]CodeQL Results[/]")
    console.print()

    # Summary
    console.print(f"[dim]Source:[/] {result.source_path}")
    console.print(f"[dim]Engine:[/] {result.engine}")
    console.print(f"[dim]Duration:[/] {result.duration_seconds:.2f}s")
    console.print(f"[dim]Queries Used:[/] {', '.join(result.rules_used) or 'default'}")
    console.print()

    # Statistics
    console.print(f"[bold]Total Findings:[/] {result.total_findings}")

    if result.total_findings > 0:
        # Severity breakdown
        sev_table = Table(title="By Severity", show_header=True)
        sev_table.add_column("Severity", style="cyan")
        sev_table.add_column("Count", justify="right")

        severity_colors = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = result.by_severity.get(sev, 0)
            if count > 0:
                color = severity_colors.get(sev, "white")
                sev_table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))

        console.print(sev_table)
        console.print()

    if output_format == "json":
        console.print_json(result.to_json())
    elif output_format == "markdown":
        console.print(result.to_markdown())
    else:
        # Text format - show findings
        if result.findings:
            findings_table = Table(title="Findings", show_header=True)
            findings_table.add_column("Severity", width=10)
            findings_table.add_column("Location", width=30)
            findings_table.add_column("Title", width=50)
            findings_table.add_column("Rule", width=30)

            for finding in result.findings[:50]:  # Limit display
                color = severity_colors.get(finding.severity.value, "white")
                findings_table.add_row(
                    f"[{color}]{finding.severity.value.upper()}[/{color}]",
                    finding.location.to_display(),
                    finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
                    finding.rule_id or "-",
                )

            console.print(findings_table)

            if len(result.findings) > 50:
                console.print(f"\n[dim]... and {len(result.findings) - 50} more findings[/]")
        else:
            console.print("[green]No findings![/]")


def _export_codeql_result(result, output_path: str, output_format: str) -> None:
    """Export CodeQL results to file."""
    if output_format == "json":
        content = result.to_json()
    elif output_format == "markdown":
        content = result.to_markdown()
    else:
        content = result.to_summary()
        if result.findings:
            content += "\n\n## Findings\n\n"
            for finding in result.findings:
                content += f"- [{finding.severity.value.upper()}] {finding.title}\n"
                content += f"  Location: {finding.location.to_display()}\n"
                content += f"  Rule: {finding.rule_id or 'N/A'}\n"
                if finding.cwe:
                    content += f"  CWE: {finding.cwe}\n"
                if finding.description:
                    content += f"  Description: {finding.description}\n"
                content += "\n"

    Path(output_path).write_text(content, encoding="utf-8")


@main.command("agent")
@click.option("--path", "-p", required=True, type=click.Path(exists=True), help="Path to source code")
@click.option("--provider", type=click.Choice(["openai", "azure", "ollama"]), default="openai", help="LLM provider")
@click.option("--model", "-m", help="Model name (e.g., gpt-4, llama2)")
@click.option("--language", "-l", help="Programming language (auto-detected if not specified)")
@click.option("--files", "-f", "target_files", multiple=True, help="Specific files to analyze")
@click.option("--focus", multiple=True, type=click.Choice(["sql_injection", "xss", "command_injection", "path_traversal", "ssrf", "xxe", "deserialization", "hardcoded_secrets", "crypto_weakness", "auth_bypass", "idor", "open_redirect"]), help="Vulnerability types to focus on")
@click.option("--severity", multiple=True, type=click.Choice(["critical", "high", "medium", "low", "info"]), help="Filter by severity")
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "markdown"]), default="text", help="Output format")
@click.option("--max-files", type=int, default=50, help="Maximum number of files to analyze")
@click.option("--max-concurrent", type=int, default=3, help="Maximum concurrent LLM requests")
def agent_scan(
    path: str,
    provider: str,
    model: str | None,
    language: str | None,
    target_files: tuple[str, ...],
    focus: tuple[str, ...],
    severity: tuple[str, ...],
    output: str | None,
    output_format: str,
    max_files: int,
    max_concurrent: int,
) -> None:
    """Run AI-powered deep security audit using LLM.

    This command uses Large Language Models to perform semantic code analysis
    for security vulnerabilities. It complements pattern-based tools like
    Semgrep and CodeQL with deeper understanding of code context.

    LLM Configuration:
        OPENAI_API_KEY    - API key for OpenAI (required for openai provider)
        AZURE_OPENAI_KEY  - API key for Azure OpenAI (required for azure provider)
        OLLAMA_BASE_URL   - Ollama server URL (default: http://localhost:11434)

    Vulnerability Focus Options:
        sql_injection      - SQL injection vulnerabilities
        xss               - Cross-site scripting
        command_injection - Command/OS injection
        path_traversal    - Path traversal attacks
        ssrf              - Server-side request forgery
        xxe               - XML external entity
        deserialization   - Unsafe deserialization
        hardcoded_secrets - Hardcoded credentials
        crypto_weakness   - Cryptographic weaknesses
        auth_bypass       - Authentication bypass
        idor              - Insecure direct object reference
        open_redirect     - Open redirect vulnerabilities

    Examples:
        deepvuln agent --path ./src
        deepvuln agent -p . --provider ollama --model llama2
        deepvuln agent -p . --focus sql_injection --focus xss
        deepvuln agent -p . -f src/api.py -f src/db.py --severity high
        deepvuln agent -p . --max-files 20 -f json -o report.json
    """
    from src.layers.l3_analysis import OpenCodeAgent, SeverityLevel

    show_banner()
    source_path = Path(path)

    console.print(f"[cyan]Running AI security audit on {source_path}...[/]")
    console.print(f"[dim]Provider: {provider} | Model: {model or 'default'}[/]\n")

    # Create engine
    engine = OpenCodeAgent(
        provider=provider,
        model=model,
        max_files=max_files,
        max_concurrent=max_concurrent,
    )

    # Check availability
    if not engine.is_available():
        if provider == "openai":
            show_error(
                "LLM Not Available",
                "OpenAI API key not configured.\n\n"
                "Set the OPENAI_API_KEY environment variable:\n"
                "  export OPENAI_API_KEY=sk-...",
            )
        elif provider == "azure":
            show_error(
                "LLM Not Available",
                "Azure OpenAI not configured.\n\n"
                "Set the required environment variables:\n"
                "  export AZURE_OPENAI_KEY=...\n"
                "  export AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/",
            )
        elif provider == "ollama":
            show_error(
                "LLM Not Available",
                "Ollama server is not running.\n\n"
                "Start Ollama:\n"
                "  ollama serve\n\n"
                "Or install from: https://ollama.ai",
            )
        else:
            show_error("LLM Not Available", "LLM client is not configured.")
        return

    # Build severity filter
    severity_filter = None
    if severity:
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        severity_filter = [severity_map[s] for s in severity]

    # Build vulnerability focus
    vuln_focus = list(focus) if focus else None

    # Run scan
    async def _scan():
        return await engine.scan(
            source_path=source_path,
            language=language,
            files=list(target_files) if target_files else None,
            vulnerability_focus=vuln_focus,
            severity_filter=severity_filter,
        )

    with create_progress() as progress:
        task = progress.add_task("[cyan]Analyzing code with AI...", total=None)
        result = asyncio.run(_scan())
        progress.update(task, completed=True, description="[green]Analysis complete!")

    # Handle scan failure
    if not result.success:
        show_error("Scan Failed", result.error_message or "Unknown error")
        return

    # Output results
    if output:
        _export_agent_result(result, output, output_format)
        console.print(f"\n[green]Report exported to: {output}[/]")
    else:
        _display_agent_result(result, output_format, engine)


def _display_agent_result(result, output_format: str, engine) -> None:
    """Display AI agent scan results."""
    from rich.table import Table

    console.print()
    console.rule("[bold cyan]AI Security Audit Results[/]")
    console.print()

    # Summary
    console.print(f"[dim]Source:[/] {result.source_path}")
    console.print(f"[dim]Engine:[/] {result.engine}")
    console.print(f"[dim]Duration:[/] {result.duration_seconds:.2f}s")

    # Token usage
    if result.raw_output:
        tokens = result.raw_output.get("total_tokens", 0)
        provider = result.raw_output.get("provider", "unknown")
        model = result.raw_output.get("model", "unknown")
        console.print(f"[dim]Tokens Used:[/] {tokens} | [dim]Provider:[/] {provider} | [dim]Model:[/] {model}")

    console.print()

    # Statistics
    console.print(f"[bold]Total Findings:[/] {result.total_findings}")

    if result.total_findings > 0:
        # Severity breakdown
        sev_table = Table(title="By Severity", show_header=True)
        sev_table.add_column("Severity", style="cyan")
        sev_table.add_column("Count", justify="right")

        severity_colors = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = result.by_severity.get(sev, 0)
            if count > 0:
                color = severity_colors.get(sev, "white")
                sev_table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))

        console.print(sev_table)
        console.print()

    if output_format == "json":
        console.print_json(result.to_json())
    elif output_format == "markdown":
        console.print(result.to_markdown())
    else:
        # Text format - show findings
        if result.findings:
            findings_table = Table(title="Findings", show_header=True)
            findings_table.add_column("Severity", width=10)
            findings_table.add_column("Confidence", width=10)
            findings_table.add_column("Location", width=30)
            findings_table.add_column("Title", width=45)

            for finding in result.findings[:50]:  # Limit display
                color = severity_colors.get(finding.severity.value, "white")
                conf = f"{finding.confidence:.0%}"
                findings_table.add_row(
                    f"[{color}]{finding.severity.value.upper()}[/{color}]",
                    conf,
                    finding.location.to_display(),
                    finding.title[:45] + "..." if len(finding.title) > 45 else finding.title,
                )

            console.print(findings_table)

            if len(result.findings) > 50:
                console.print(f"\n[dim]... and {len(result.findings) - 50} more findings[/]")

            # Show detailed descriptions for high severity
            from src.layers.l3_analysis import SeverityLevel as SL
            high_severity = [f for f in result.findings if f.severity in (SL.CRITICAL, SL.HIGH)]
            if high_severity:
                console.print()
                console.rule("[bold red]High Severity Details[/]")
                for finding in high_severity[:5]:
                    console.print(f"\n[bold]{finding.title}[/]")
                    console.print(f"[dim]Location:[/] {finding.location.to_display()}")
                    if finding.cwe:
                        console.print(f"[dim]CWE:[/] {finding.cwe}")
                    console.print(f"\n{finding.description}")
                    if finding.fix_suggestion:
                        console.print(f"\n[green]Recommendation:[/] {finding.fix_suggestion}")
        else:
            console.print("[green]No findings![/]")


def _export_agent_result(result, output_path: str, output_format: str) -> None:
    """Export AI agent results to file."""
    if output_format == "json":
        content = result.to_json()
    elif output_format == "markdown":
        content = result.to_markdown()
    else:
        content = result.to_summary()
        content += f"\n\nToken Usage: {result.raw_output.get('total_tokens', 'N/A') if result.raw_output else 'N/A'}"
        if result.findings:
            content += "\n\n## Findings\n\n"
            for finding in result.findings:
                content += f"- [{finding.severity.value.upper()}] (Confidence: {finding.confidence:.0%}) {finding.title}\n"
                content += f"  Location: {finding.location.to_display()}\n"
                if finding.cwe:
                    content += f"  CWE: {finding.cwe}\n"
                if finding.description:
                    content += f"  Description: {finding.description}\n"
                if finding.fix_suggestion:
                    content += f"  Recommendation: {finding.fix_suggestion}\n"
                content += "\n"

    Path(output_path).write_text(content, encoding="utf-8")


@main.command("strategy")
@click.option("--path", "-p", required=True, type=click.Path(exists=True), help="Path to source code")
@click.option("--output", "-o", type=click.Path(), help="Output file for strategy report")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "yaml"]), default="text", help="Output format")
@click.option("--engines", multiple=True, type=click.Choice(["semgrep", "codeql", "agent"]), help="Available engines")
@click.option("--time-budget", type=int, help="Time budget in seconds")
@click.option("--token-budget", type=int, help="LLM token budget")
def generate_strategy(
    path: str,
    output: str | None,
    output_format: str,
    engines: tuple[str, ...],
    time_budget: int | None,
    token_budget: int | None,
) -> None:
    """Generate audit strategy with priority-based analysis plan.

    This command analyzes the project's attack surface and generates
    a priority-based audit strategy. It helps you understand which
    parts of the codebase should be audited first and with which engines.

    The strategy considers:
    - Attack surface exposure (entry points, HTTP methods)
    - Technology stack risks (frameworks, dependencies)
    - Code complexity (cyclomatic complexity, LOC)
    - Historical vulnerability patterns

    Examples:
        deepvuln strategy --path ./src
        deepvuln strategy -p . --format yaml -o strategy.yaml
        deepvuln strategy -p . --engines semgrep --engines agent
        deepvuln strategy -p . --time-budget 1800  # 30 minutes
    """
    from src.layers.l1_intelligence.attack_surface import AttackSurfaceDetector
    from src.layers.l3_analysis import StrategyEngine

    show_banner()
    source_path = Path(path)

    console.print(f"[cyan]Generating audit strategy for {source_path}...[/]\n")

    # Detect attack surface
    console.print("[dim]Step 1: Detecting attack surface...[/]")
    detector = AttackSurfaceDetector()
    attack_surface = detector.detect(source_path)

    console.print(f"[dim]  Found {attack_surface.total_entry_points} entry points[/]")
    console.print(f"[dim]  HTTP: {attack_surface.http_endpoints}, RPC: {attack_surface.rpc_services}, gRPC: {attack_surface.grpc_services}[/]")

    # Create strategy engine
    available_engines = list(engines) if engines else ["semgrep", "codeql", "agent"]
    strategy_engine = StrategyEngine(available_engines=available_engines)

    # Generate strategy
    console.print("[dim]Step 2: Calculating priorities...[/]")
    strategy = strategy_engine.create_strategy(
        source_path=source_path,
        project_name=source_path.name,
        attack_surface=attack_surface,
    )

    # Optimize if budgets specified
    if time_budget or token_budget:
        console.print("[dim]Step 3: Optimizing for resource constraints...[/]")
        strategy = strategy_engine.optimize_strategy(
            strategy=strategy,
            time_budget_seconds=time_budget,
            token_budget=token_budget,
        )

    # Display or export results
    console.print()
    console.rule("[bold cyan]Audit Strategy[/]")
    console.print()

    if output_format == "json":
        content = strategy.model_dump_json(indent=2)
        if output:
            Path(output).write_text(content, encoding="utf-8")
            console.print(f"[green]Strategy exported to: {output}[/]")
        else:
            console.print_json(content)
    elif output_format == "yaml":
        content = strategy.to_yaml_config()
        if output:
            Path(output).write_text(content, encoding="utf-8")
            console.print(f"[green]Strategy exported to: {output}[/]")
        else:
            console.print(content)
    else:
        _display_strategy_text(strategy, attack_surface)
        if output:
            content = strategy.to_yaml_config()
            Path(output).write_text(content, encoding="utf-8")
            console.print(f"\n[green]Strategy exported to: {output}[/]")


def _display_strategy_text(strategy, attack_surface) -> None:
    """Display strategy in text format."""
    from rich.table import Table

    # Summary
    console.print(f"[dim]Project:[/] {strategy.project_name}")
    console.print(f"[dim]Source:[/] {strategy.source_path}")
    console.print(f"[dim]Total Targets:[/] {strategy.total_targets}")
    console.print()

    # Priority distribution
    dist = strategy.get_summary()["by_priority"]
    if any(v > 0 for v in dist.values()):
        priority_table = Table(title="Priority Distribution", show_header=True)
        priority_table.add_column("Priority", style="cyan")
        priority_table.add_column("Count", justify="right")
        priority_table.add_column("Engines", style="dim")

        priority_colors = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "blue",
            "skip": "dim",
        }

        engine_info = {
            "critical": "agent + semgrep + codeql",
            "high": "agent + semgrep",
            "medium": "semgrep + codeql",
            "low": "semgrep",
            "skip": "-",
        }

        for level in ["critical", "high", "medium", "low", "skip"]:
            count = dist.get(level, 0)
            if count > 0:
                color = priority_colors.get(level, "white")
                priority_table.add_row(
                    f"[{color}]{level.upper()}[/{color}]",
                    str(count),
                    engine_info.get(level, ""),
                )

        console.print(priority_table)
        console.print()

    # Entry point summary
    if attack_surface and attack_surface.total_entry_points > 0:
        entry_table = Table(title="Attack Surface Summary", show_header=True)
        entry_table.add_column("Type", style="cyan")
        entry_table.add_column("Count", justify="right")
        entry_table.add_column("Unauthenticated", justify="right")

        entry_types = [
            ("HTTP", attack_surface.http_endpoints),
            ("RPC", attack_surface.rpc_services),
            ("gRPC", attack_surface.grpc_services),
            ("MQ", attack_surface.mq_consumers),
            ("Cron", attack_surface.cron_jobs),
        ]

        for type_name, count in entry_types:
            if count > 0:
                entry_table.add_row(type_name, str(count), "-")

        # Add unauthenticated count
        unauth_count = len(attack_surface.get_unauthenticated())
        if unauth_count > 0:
            entry_table.add_row("[red]Unauthenticated[/]", str(unauth_count), "")

        console.print(entry_table)
        console.print()

    # Top targets
    sorted_targets = strategy.get_sorted_targets()[:10]
    if sorted_targets:
        target_table = Table(title="Top 10 Priority Targets", show_header=True)
        target_table.add_column("Priority", width=10)
        target_table.add_column("Score", justify="right", width=6)
        target_table.add_column("Target", width=40)
        target_table.add_column("Type", width=12)

        for target in sorted_targets:
            if target.priority:
                color = priority_colors.get(target.priority.level.value, "white")
                score = f"{target.priority.final_score:.2f}"
                target_table.add_row(
                    f"[{color}]{target.priority.level.value.upper()}[/{color}]",
                    score,
                    target.to_display()[:40],
                    target.target_type,
                )

        console.print(target_table)
        console.print()

    # Execution plan
    console.print("[bold]Execution Plan:[/]")
    console.print("[dim]1. Scan CRITICAL targets with all engines[/]")
    console.print("[dim]2. Scan HIGH targets with agent + semgrep[/]")
    console.print("[dim]3. Scan MEDIUM targets with semgrep + codeql[/]")
    console.print("[dim]4. Scan LOW targets with semgrep only[/]")

    if strategy.stop_on_critical:
        console.print("\n[yellow]Stop on critical: enabled[/]")


if __name__ == "__main__":
    main()
