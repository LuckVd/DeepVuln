"""Display components for security scanning CLI."""


from rich.columns import Columns
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cli.display import console
from src.cli.intel_display import get_severity_badge
from src.layers.l1_intelligence.security_analyzer.analyzer import (
    SecurityReport,
)
from src.layers.l1_intelligence.tech_stack_detector.detector import TechStack
from src.layers.l1_intelligence.threat_intel.core.data_models import SeverityLevel


def show_security_summary(report: SecurityReport) -> None:
    """Display a summary of security scan results.

    Args:
        report: Security report to display.
    """
    # Create header
    has_issues = report.has_vulnerabilities
    border_color = "red" if has_issues else "green"

    console.print()
    console.print(
        Panel(
            f"[bold]Security Scan Results[/]\n"
            f"[dim]{report.source_path}[/]",
            border_style=border_color,
        )
    )

    # Create stats panels
    stats_panels = []

    # Dependencies panel
    dep_text = Text()
    dep_text.append(f"{report.dependencies_scanned}", style="bold cyan")
    dep_text.append(" dependencies\n")
    dep_text.append(f"{report.frameworks_detected}", style="bold cyan")
    dep_text.append(" frameworks")
    stats_panels.append(Panel(dep_text, title="[bold]Scanned[/]", border_style="blue"))

    # Vulnerabilities panel
    vuln_text = Text()
    vuln_text.append(f"{report.total_vulnerabilities}", style="bold red" if has_issues else "bold green")
    vuln_text.append(" vulnerabilities\n")
    if report.critical_count > 0:
        vuln_text.append(f"{report.critical_count} critical ", style="red")
    if report.high_count > 0:
        vuln_text.append(f"{report.high_count} high", style="orange1")
    stats_panels.append(Panel(vuln_text, title="[bold]Vulnerabilities[/]", border_style=border_color))

    # KEV panel
    kev_color = "red" if report.kev_count > 0 else "green"
    kev_text = Text()
    kev_text.append(f"{report.kev_count}", style=f"bold {kev_color}")
    kev_text.append(" known exploited\n")
    kev_text.append("vulnerabilities", style="dim")
    stats_panels.append(Panel(kev_text, title="[bold]KEV[/]", border_style=kev_color))

    console.print(Columns(stats_panels))
    console.print()


def show_severity_breakdown(report: SecurityReport) -> None:
    """Display severity breakdown as a bar chart.

    Args:
        report: Security report to display.
    """
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Severity", width=12)
    table.add_column("Count", width=6, justify="right")
    table.add_column("Bar", width=30)

    total = report.total_vulnerabilities or 1

    severities = [
        (SeverityLevel.CRITICAL, report.critical_count, "red"),
        (SeverityLevel.HIGH, report.high_count, "orange1"),
        (SeverityLevel.MEDIUM, report.medium_count, "yellow"),
        (SeverityLevel.LOW, report.low_count, "green"),
        (SeverityLevel.INFO, report.info_count, "blue"),
    ]

    for severity, count, color in severities:
        if count > 0:
            pct = count / total
            bar = "█" * int(pct * 30)
            table.add_row(
                get_severity_badge(severity),
                str(count),
                f"[{color}]{bar}[/]",
            )

    console.print(table)
    console.print()


def show_vulnerability_list(report: SecurityReport, show_all: bool = False) -> None:
    """Display list of vulnerabilities.

    Args:
        report: Security report to display.
        show_all: Whether to show all vulnerabilities or just critical/high.
    """
    if not report.has_vulnerabilities:
        console.print("[green]No vulnerabilities found![/]")
        return

    # Filter to critical/high unless show_all
    dep_vulns = report.dependency_vulns
    fw_vulns = report.framework_vulns

    if not show_all:
        dep_vulns = [dv for dv in dep_vulns if dv.highest_severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
        fw_vulns = [fv for fv in fw_vulns if fv.highest_severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]

    # Create table
    table = Table(title="[bold]Vulnerabilities[/]", show_lines=True)
    table.add_column("Package/Framework", style="cyan", width=25)
    table.add_column("Severity", width=10)
    table.add_column("CVEs", width=8)
    table.add_column("KEV", width=5)
    table.add_column("Details", width=35)

    # Add dependency vulnerabilities
    for dv in dep_vulns:
        severity_badge = get_severity_badge(dv.highest_severity)
        kev = "[red]YES[/]" if dv.has_kev else "[dim]No[/]"

        # Build details
        details = []
        for cve in dv.cves[:2]:
            details.append(f"{cve.cve_id}")
        if len(dv.cves) > 2:
            details.append(f"... +{len(dv.cves) - 2} more")
        details_str = "\n".join(details)

        table.add_row(
            f"{dv.dependency.name}@{dv.dependency.version}",
            severity_badge,
            str(dv.cve_count),
            kev,
            details_str,
        )

    # Add framework vulnerabilities
    for fv in fw_vulns:
        severity_badge = get_severity_badge(fv.highest_severity)
        kev = "[red]YES[/]" if fv.has_kev else "[dim]No[/]"

        details = []
        for cve in fv.cves[:2]:
            details.append(f"{cve.cve_id}")
        if len(fv.cves) > 2:
            details.append(f"... +{len(fv.cves) - 2} more")
        details_str = "\n".join(details)

        fw_name = fv.framework.name
        if fv.framework.version:
            fw_name += f"@{fv.framework.version}"

        table.add_row(
            f"[dim]{fw_name}[/]",
            severity_badge,
            str(fv.cve_count),
            kev,
            details_str,
        )

    console.print()
    console.print(table)
    console.print()


def show_tech_stack(tech_stack: TechStack) -> None:
    """Display detected technology stack.

    Args:
        tech_stack: Detected tech stack.
    """
    console.print(Panel("[bold]Detected Technology Stack[/]", border_style="cyan"))

    # Languages
    if tech_stack.languages:
        lang_str = ", ".join(f"[cyan]{lang.value}[/]" for lang in tech_stack.languages)
        console.print(f"[bold]Languages:[/] {lang_str}")

    # Frameworks
    if tech_stack.frameworks:
        fw_table = Table(show_header=False, box=None, padding=(0, 2))
        fw_table.add_column("Framework", style="cyan", width=20)
        fw_table.add_column("Category", width=15)
        fw_table.add_column("Confidence", width=10)

        for fw in tech_stack.frameworks:
            confidence_bar = "█" * int(fw.confidence * 5)
            fw_table.add_row(
                fw.name,
                fw.category,
                f"[green]{confidence_bar}[/] {fw.confidence:.0%}",
            )

        console.print("[bold]Frameworks:[/]")
        console.print(fw_table)

    # Databases
    if tech_stack.databases:
        db_str = ", ".join(f"[yellow]{db.name}[/]" for db in tech_stack.databases)
        console.print(f"[bold]Databases:[/] {db_str}")

    # Middleware
    if tech_stack.middleware:
        mw_str = ", ".join(f"[magenta]{mw.name}[/]" for mw in tech_stack.middleware)
        console.print(f"[bold]Middleware:[/] {mw_str}")

    # Build tools
    if tech_stack.build_tools:
        tools_str = ", ".join(f"[dim]{tool}[/]" for tool in tech_stack.build_tools)
        console.print(f"[bold]Build Tools:[/] {tools_str}")

    # Package managers
    if tech_stack.package_managers:
        pm_str = ", ".join(f"[blue]{pm}[/]" for pm in tech_stack.package_managers)
        console.print(f"[bold]Package Managers:[/] {pm_str}")

    console.print()


def show_security_report(report: SecurityReport, detailed: bool = False) -> None:
    """Display full security report.

    Args:
        report: Security report to display.
        detailed: Whether to show detailed information.
    """
    # Show summary
    show_security_summary(report)

    # Show severity breakdown
    if report.has_vulnerabilities:
        show_severity_breakdown(report)

    # Show tech stack
    if report.tech_stack:
        show_tech_stack(report.tech_stack)

    # Show vulnerabilities
    if report.has_vulnerabilities:
        show_vulnerability_list(report, show_all=detailed)

    # Show scan info
    console.print(f"[dim]Scan duration: {report.scan_duration_seconds:.2f}s[/]")
    if report.errors:
        console.print(f"[yellow]Warnings: {len(report.errors)}[/]")
        for error in report.errors[:3]:
            console.print(f"  [dim]- {error}[/]")
    console.print()


def show_kev_warning(report: SecurityReport) -> None:
    """Display KEV warning if any known exploited vulnerabilities.

    Args:
        report: Security report to display.
    """
    if not report.has_known_exploited:
        return

    console.print()
    console.print(
        Panel(
            f"[bold red]WARNING: {report.kev_count} Known Exploited Vulnerabilities Detected![/]\n\n"
            f"The following packages have known exploits in the wild:\n"
            + "\n".join(f"  • [bold]{pkg}[/]" for pkg in report.kev_packages[:5])
            + (f"\n  [dim]... and {len(report.kev_packages) - 5} more[/]" if len(report.kev_packages) > 5 else ""),
            title="[bold]Active Exploitation Warning[/]",
            border_style="red",
        )
    )
    console.print()


def show_quick_scan_result(result: dict) -> None:
    """Display quick scan result.

    Args:
        result: Quick scan result dictionary.
    """
    if not result.get("success"):
        console.print(f"[red]Scan failed: {result.get('errors', ['Unknown error'])}[/]")
        return

    # Create status indicator
    needs_attention = result.get("needs_attention", False)
    status_color = "red" if needs_attention else "green"
    status_icon = "!" if needs_attention else "✓"

    console.print()
    console.print(
        Panel(
            f"[bold {status_color}]{status_icon} Quick Scan Complete[/]\n\n"
            f"Dependencies: [cyan]{result.get('dependencies', 0)}[/]\n"
            f"Frameworks: [cyan]{result.get('frameworks', 0)}[/]\n"
            f"Critical/High: [{status_color}]{result.get('critical_high', 0)}[/]\n"
            f"KEV: [{status_color}]{result.get('kev_count', 0)}[/]\n\n"
            f"[dim]Duration: {result.get('duration', 0):.2f}s[/]",
            border_style=status_color,
        )
    )
    console.print()


def show_scan_progress(message: str) -> None:
    """Display scan progress message.

    Args:
        message: Progress message.
    """
    console.print(f"[dim]→ {message}[/]")


def export_report_text(report: SecurityReport) -> str:
    """Export report as plain text.

    Args:
        report: Security report to export.

    Returns:
        Plain text report.
    """
    lines = [
        "=" * 60,
        "DeepVuln Security Report",
        "=" * 60,
        "",
        f"Source: {report.source_path}",
        f"Scanned: {report.scanned_at}",
        f"Duration: {report.scan_duration_seconds:.2f}s",
        "",
        "-" * 60,
        "Summary",
        "-" * 60,
        f"Dependencies scanned: {report.dependencies_scanned}",
        f"Frameworks detected: {report.frameworks_detected}",
        f"Total vulnerabilities: {report.total_vulnerabilities}",
        f"  Critical: {report.critical_count}",
        f"  High: {report.high_count}",
        f"  Medium: {report.medium_count}",
        f"  Low: {report.low_count}",
        f"Known exploited (KEV): {report.kev_count}",
        "",
    ]

    # Tech stack
    if report.tech_stack:
        lines.extend([
            "-" * 60,
            "Technology Stack",
            "-" * 60,
        ])
        if report.tech_stack.languages:
            lines.append(f"Languages: {', '.join(lang.value for lang in report.tech_stack.languages)}")
        if report.tech_stack.frameworks:
            lines.append("Frameworks:")
            for fw in report.tech_stack.frameworks:
                lines.append(f"  - {fw.name} ({fw.category})")
        if report.tech_stack.databases:
            lines.append(f"Databases: {', '.join(db.name for db in report.tech_stack.databases)}")
        lines.append("")

    # Vulnerabilities
    if report.has_vulnerabilities:
        lines.extend([
            "-" * 60,
            "Vulnerabilities",
            "-" * 60,
        ])

        for dv in report.dependency_vulns:
            lines.append(f"\n{dv.dependency.name}@{dv.dependency.version} ({dv.highest_severity.value})")
            for cve in dv.cves:
                lines.append(f"  - {cve.cve_id}: {cve.description[:80]}...")

        for fv in report.framework_vulns:
            lines.append(f"\n{fv.framework.name} ({fv.highest_severity.value})")
            for cve in fv.cves:
                lines.append(f"  - {cve.cve_id}: {cve.description[:80]}...")

    lines.extend([
        "",
        "=" * 60,
        "End of Report",
        "=" * 60,
    ])

    return "\n".join(lines)
