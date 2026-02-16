"""Display components for threat intelligence CLI."""

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cli.display import console
from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    PoCInfo,
    SeverityLevel,
)


def get_severity_color(severity: SeverityLevel) -> str:
    """Get color for severity level.

    Args:
        severity: Severity level.

    Returns:
        Color string.
    """
    colors = {
        SeverityLevel.CRITICAL: "bold red",
        SeverityLevel.HIGH: "bold orange1",
        SeverityLevel.MEDIUM: "bold yellow",
        SeverityLevel.LOW: "bold green",
        SeverityLevel.INFO: "bold blue",
    }
    return colors.get(severity, "white")


def get_severity_badge(severity: SeverityLevel) -> str:
    """Get colored badge for severity.

    Args:
        severity: Severity level.

    Returns:
        Colored badge string.
    """
    badges = {
        SeverityLevel.CRITICAL: "[bold red]CRITICAL[/]",
        SeverityLevel.HIGH: "[bold orange1]HIGH[/]",
        SeverityLevel.MEDIUM: "[bold yellow]MEDIUM[/]",
        SeverityLevel.LOW: "[bold green]LOW[/]",
        SeverityLevel.INFO: "[bold blue]INFO[/]",
    }
    return badges.get(severity, str(severity))


def show_cve_table(cves: list[CVEInfo], title: str = "CVE Results") -> None:
    """Display a table of CVEs.

    Args:
        cves: List of CVEs to display.
        title: Table title.
    """
    if not cves:
        console.print("[yellow]No CVEs to display[/]")
        return

    table = Table(title=f"[bold]{title}[/]", show_lines=True)
    table.add_column("CVE ID", style="cyan", no_wrap=True, width=18)
    table.add_column("Severity", width=10)
    table.add_column("CVSS", width=5)
    table.add_column("KEV", width=4)
    table.add_column("PoC", width=4)
    table.add_column("Description", width=50)

    for cve in cves:
        # Truncate description
        desc = cve.description
        if len(desc) > 47:
            desc = desc[:44] + "..."

        severity_badge = get_severity_badge(cve.severity)
        cvss = f"{cve.cvss_v3_score:.1f}" if cve.cvss_v3_score else "-"
        kev = "[red]YES[/]" if cve.kev else "[dim]No[/]"
        poc = "[green]YES[/]" if cve.has_poc else "[dim]No[/]"

        table.add_row(
            cve.cve_id,
            severity_badge,
            cvss,
            kev,
            poc,
            desc,
        )

    console.print()
    console.print(table)
    console.print()


def show_cve_detail(cve: CVEInfo, pocs: list[PoCInfo] | None = None) -> None:
    """Display detailed CVE information.

    Args:
        cve: CVE to display.
        pocs: Related PoCs (optional).
    """
    # Header with severity
    severity_color = get_severity_color(cve.severity)
    header = Text()
    header.append(cve.cve_id, style="bold cyan")
    header.append(" ")
    header.append(f"[{cve.severity.value.upper()}]", style=severity_color)

    if cve.kev:
        header.append(" ")
        header.append("[KEV]", style="bold red")

    console.print()
    console.print(Panel(header, border_style=severity_color))

    # Main info table
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Field", style="cyan", width=15)
    info_table.add_column("Value", style="white")

    info_table.add_row("Source", cve.source)
    info_table.add_row("Severity", get_severity_badge(cve.severity))

    if cve.cvss_v3_score:
        cvss_str = f"{cve.cvss_v3_score:.1f}"
        if cve.cvss_v3_vector:
            cvss_str += f" ({cve.cvss_v3_vector})"
        info_table.add_row("CVSS v3", cvss_str)

    if cve.cvss_v2_score:
        info_table.add_row("CVSS v2", f"{cve.cvss_v2_score:.1f}")

    if cve.published_date:
        info_table.add_row("Published", cve.published_date.strftime("%Y-%m-%d"))

    if cve.modified_date:
        info_table.add_row("Modified", cve.modified_date.strftime("%Y-%m-%d"))

    if cve.cwe_ids:
        info_table.add_row("CWE IDs", ", ".join(cve.cwe_ids[:3]))
        if len(cve.cwe_ids) > 3:
            info_table.add_row("", f"[dim]... and {len(cve.cwe_ids) - 3} more[/]")

    console.print(info_table)
    console.print()

    # Description
    console.print(Panel(cve.description, title="[bold]Description[/]", border_style="blue"))
    console.print()

    # Tags
    if cve.tags:
        tags_str = " ".join(f"[cyan]#{tag}[/]" for tag in cve.tags[:10])
        console.print(f"[bold]Tags:[/] {tags_str}")
        console.print()

    # Affected Products
    if cve.affected_products:
        console.print("[bold]Affected Products:[/]")
        for product in cve.affected_products[:5]:
            console.print(f"  - {product}")
        if len(cve.affected_products) > 5:
            console.print(f"  [dim]... and {len(cve.affected_products) - 5} more[/]")
        console.print()

    # References
    if cve.references:
        console.print("[bold]References:[/]")
        for ref in cve.references[:5]:
            console.print(f"  - [link={ref}]{ref}[/]")
        if len(cve.references) > 5:
            console.print(f"  [dim]... and {len(cve.references) - 5} more[/]")
        console.print()

    # PoCs
    if pocs:
        show_poc_table(pocs, title="Related PoCs/Exploits")

    # KEV Warning
    if cve.kev:
        console.print(
            Panel(
                "[bold red]This vulnerability is known to be actively exploited![/]\n\n"
                "This CVE is listed in CISA's Known Exploited Vulnerabilities (KEV) catalog.\n"
                "Priority remediation is strongly recommended.",
                title="[bold]Active Exploitation Warning[/]",
                border_style="red",
            )
        )
        console.print()


def show_poc_table(pocs: list[PoCInfo], title: str = "PoCs/Exploits") -> None:
    """Display a table of PoCs.

    Args:
        pocs: List of PoCs to display.
        title: Table title.
    """
    if not pocs:
        console.print("[yellow]No PoCs to display[/]")
        return

    table = Table(title=f"[bold]{title}[/]")
    table.add_column("ID", style="cyan", width=15)
    table.add_column("Source", width=12)
    table.add_column("Verified", width=8)
    table.add_column("Language", width=10)
    table.add_column("Title/URL", width=45)

    for poc in pocs:
        verified = "[green]Yes[/]" if poc.verified else "[dim]No[/]"
        lang = poc.language or "-"
        title_text = poc.title
        if len(title_text) > 42:
            title_text = title_text[:39] + "..."

        table.add_row(
            poc.poc_id,
            poc.source,
            verified,
            lang,
            title_text,
        )

    console.print()
    console.print(table)

    # Show URLs if available
    console.print("\n[bold]Details:[/]")
    for poc in pocs[:5]:
        if poc.code_url:
            console.print(f"  [{poc.poc_id}] [link={poc.code_url}]{poc.code_url}[/]")

    console.print()


def show_kev_alerts(cves: list[CVEInfo], title: str = "KEV Alerts") -> None:
    """Display KEV alerts with emphasis.

    Args:
        cves: List of KEV CVEs.
        title: Panel title.
    """
    if not cves:
        console.print("[yellow]No KEV alerts to display[/]")
        return

    console.print()
    console.print(
        Panel(
            f"[bold red]{len(cves)} Known Exploited Vulnerabilities[/]",
            title=f"[bold]{title}[/]",
            border_style="red",
        )
    )

    table = Table(show_lines=True)
    table.add_column("CVE ID", style="cyan", width=18)
    table.add_column("Severity", width=10)
    table.add_column("CVSS", width=5)
    table.add_column("Description", width=50)

    for cve in cves:
        desc = cve.description
        if len(desc) > 47:
            desc = desc[:44] + "..."

        severity_badge = get_severity_badge(cve.severity)
        cvss = f"{cve.cvss_v3_score:.1f}" if cve.cvss_v3_score else "-"

        table.add_row(cve.cve_id, severity_badge, cvss, desc)

    console.print(table)
    console.print()


def show_stats(stats_data: dict) -> None:
    """Display threat intelligence statistics.

    Args:
        stats_data: Statistics dictionary.
    """
    console.print()
    console.print(Panel("[bold]Threat Intelligence Statistics[/]", border_style="cyan"))

    # Overview table
    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="cyan", width=25)
    table.add_column("Value", style="white")

    table.add_row("Total CVEs", f"{stats_data.get('total_cves', 0):,}")
    table.add_row("Known Exploited (KEV)", f"{stats_data.get('kev_count', 0):,}")
    table.add_row("With PoC Available", f"{stats_data.get('poc_count', 0):,}")
    table.add_row("Total PoCs", f"{stats_data.get('total_pocs', 0):,}")

    console.print(table)
    console.print()

    # Severity distribution
    if "severity_distribution" in stats_data:
        sev_dist = stats_data["severity_distribution"]
        console.print("[bold]Severity Distribution:[/]")

        sev_table = Table(show_header=False, box=None)
        sev_table.add_column("Severity", width=15)
        sev_table.add_column("Count", width=10)
        sev_table.add_column("Bar", width=30)

        total = sum(sev_dist.values()) or 1
        for severity in ["critical", "high", "medium", "low"]:
            count = sev_dist.get(severity, 0)
            if count > 0:
                pct = count / total
                bar = "█" * int(pct * 30)
                sev_table.add_row(
                    f"[bold]{severity.upper()}[/]",
                    str(count),
                    f"[{get_severity_color(SeverityLevel(severity))}]{bar}[/]",
                )

        console.print(sev_table)
        console.print()

    # Last sync info
    if "last_sync" in stats_data:
        console.print(f"[dim]Last sync: {stats_data['last_sync']}[/]")
        console.print()


def show_sync_result(result: dict) -> None:
    """Display sync operation results.

    Args:
        result: Sync result dictionary.
    """
    console.print()
    console.print(Panel("[bold]Sync Results[/]", border_style="green"))

    table = Table(show_header=False, box=None)
    table.add_column("Source", style="cyan", width=20)
    table.add_column("Status", width=10)
    table.add_column("Count", width=10)
    table.add_column("Details", width=30)

    # NVD sync
    if "cves_synced" in result:
        status = "[green]OK[/]" if result.get("nvd_success", True) else "[red]FAILED[/]"
        table.add_row("NVD CVEs", status, str(result.get("cves_synced", 0)), f"{result.get('days', 7)} days")

    # KEV sync
    if "kev" in result:
        kev = result["kev"]
        status = "[green]OK[/]" if kev.get("success", False) else "[red]FAILED[/]"
        table.add_row("CISA KEV", status, str(kev.get("count", 0)), "Known exploited")

    # Errors
    if result.get("errors"):
        table.add_row("Errors", "[red]![/]", str(len(result["errors"])), result["errors"][0][:25] + "...")

    console.print(table)
    console.print()
