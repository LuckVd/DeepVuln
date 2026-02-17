"""Display components for build configuration security analysis."""

import json
from pathlib import Path

from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    FindingCategory,
    SecurityFinding,
    SecurityRisk,
)

console = Console()


# Risk level colors and labels
RISK_STYLES = {
    SecurityRisk.CRITICAL: ("critical", "red", "CRITICAL"),
    SecurityRisk.HIGH: ("high", "orange1", "HIGH"),
    SecurityRisk.MEDIUM: ("medium", "yellow", "MEDIUM"),
    SecurityRisk.LOW: ("low", "blue", "LOW"),
    SecurityRisk.INFO: ("info", "dim", "INFO"),
}

# Category icons (ASCII-safe for Windows compatibility)
CATEGORY_ICONS = {
    FindingCategory.SECRETS: "[red][KEY][/]",
    FindingCategory.CI_CD: "[cyan][CI/CD][/]",
    FindingCategory.DOCKERFILE: "[blue][DOCKER][/]",
    FindingCategory.DEPENDENCY: "[green][DEP][/]",
    FindingCategory.MAVEN_CONFIG: "[yellow][MAVEN][/]",
    FindingCategory.GRADLE_CONFIG: "[green][GRADLE][/]",
    FindingCategory.PYTHON_CONFIG: "[blue][PYTHON][/]",
    FindingCategory.GENERAL: "[dim][CONFIG][/]",
}


def show_config_report(
    report: BuildConfigReport,
    detailed: bool = False,
    show_evidence: bool = False,
) -> None:
    """Display build configuration security report.

    Args:
        report: The build configuration report.
        detailed: Whether to show detailed findings.
        show_evidence: Whether to show evidence (may contain masked secrets).
    """
    console.print()

    # Show summary header
    _show_summary_header(report)

    if not report.findings:
        console.print()
        console.print(
            Panel(
                "[bold green]No security issues found in build configurations![/]\n\n"
                f"[dim]Scanned {len(report.scanned_files)} configuration files[/]",
                title="[bold green]Clean[/]",
                border_style="green",
            )
        )
        return

    # Group findings by category
    by_category: dict[FindingCategory, list[SecurityFinding]] = {}
    for finding in report.findings:
        if finding.category not in by_category:
            by_category[finding.category] = []
        by_category[finding.category].append(finding)

    # Show findings by category
    for category, findings in by_category.items():
        _show_category_findings(category, findings, detailed, show_evidence)

    # Show scan statistics
    _show_scan_stats(report)

    # Show scan errors if any
    if report.scan_errors:
        _show_scan_errors(report.scan_errors)


def _show_summary_header(report: BuildConfigReport) -> None:
    """Show the summary header for the report."""
    # Count by risk level
    risk_counts: dict[SecurityRisk, int] = {}
    for finding in report.findings:
        risk_counts[finding.risk_level] = risk_counts.get(finding.risk_level, 0) + 1

    # Build summary text
    summary_parts = []
    for risk in [SecurityRisk.CRITICAL, SecurityRisk.HIGH, SecurityRisk.MEDIUM, SecurityRisk.LOW]:
        count = risk_counts.get(risk, 0)
        if count > 0:
            _, color, label = RISK_STYLES[risk]
            summary_parts.append(f"[{color}]{count} {label}[/{color}]")

    if summary_parts:
        summary = " | ".join(summary_parts)
    else:
        summary = "[green]No issues found[/]"

    # Create header
    header_text = Text()
    header_text.append("Build Configuration Security Report\n", style="bold cyan")
    header_text.append(f"Source: ", style="dim")
    header_text.append(f"{report.source_path}\n", style="white")
    header_text.append(f"Total Findings: ", style="dim")
    header_text.append(f"{len(report.findings)}", style="bold")

    console.print(Panel(header_text, border_style="cyan"))

    # Show quick summary
    console.print(f"\n{summary}\n")


def _show_category_findings(
    category: FindingCategory,
    findings: list[SecurityFinding],
    detailed: bool,
    show_evidence: bool,
) -> None:
    """Show findings for a specific category."""
    icon = CATEGORY_ICONS.get(category, ":warning:")
    category_name = category.value.replace("_", " ").title()

    # Create table for this category
    table = Table(
        title=f"{icon} {category_name}",
        box=ROUNDED,
        show_header=True,
        header_style="bold",
    )
    table.add_column("Risk", style="bold", width=10)
    table.add_column("Finding", style="white", no_wrap=False)
    table.add_column("File", style="cyan", no_wrap=False)

    if detailed:
        table.add_column("Line", style="dim", width=6, justify="right")

    # Add findings
    for finding in findings:
        _, color, label = RISK_STYLES[finding.risk_level]
        risk_text = f"[{color}]{label}[/{color}]"

        # Truncate title if too long
        title = finding.title
        if len(title) > 60 and not detailed:
            title = title[:57] + "..."

        # Get relative file path
        try:
            file_path = str(Path(finding.file_path).name)
        except Exception:
            file_path = finding.file_path

        if detailed:
            line_str = str(finding.line_start) if finding.line_start else "-"
            table.add_row(risk_text, title, file_path, line_str)
        else:
            table.add_row(risk_text, title, file_path)

    console.print(table)

    # Show details if requested
    if detailed:
        for finding in findings:
            _show_finding_detail(finding, show_evidence)


def _show_finding_detail(finding: SecurityFinding, show_evidence: bool) -> None:
    """Show detailed information for a finding."""
    _, color, _ = RISK_STYLES[finding.risk_level]

    detail_table = Table(show_header=False, box=None, padding=(0, 2))
    detail_table.add_column("Field", style="dim")
    detail_table.add_column("Value", style="white")

    detail_table.add_row("Description:", finding.description)
    detail_table.add_row("File:", finding.file_path)

    if finding.line_start:
        line_info = str(finding.line_start)
        if finding.line_end and finding.line_end != finding.line_start:
            line_info += f"-{finding.line_end}"
        detail_table.add_row("Lines:", line_info)

    if finding.cwe:
        detail_table.add_row("CWE:", finding.cwe)

    if show_evidence and finding.evidence:
        detail_table.add_row("Evidence:", f"[dim]{finding.evidence}[/]")

    if finding.recommendation:
        # Truncate long recommendations
        rec = finding.recommendation
        if len(rec) > 100:
            rec = rec[:97] + "..."
        detail_table.add_row("Recommendation:", rec)

    console.print(
        Panel(
            detail_table,
            title=f"[{color}]{finding.title}[/{color}]",
            border_style="dim",
            padding=(0, 1),
        )
    )


def _show_scan_stats(report: BuildConfigReport) -> None:
    """Show scan statistics."""
    stats_table = Table(show_header=False, box=None)
    stats_table.add_column("Stat", style="dim")
    stats_table.add_column("Value", style="white")

    stats_table.add_row("Files Scanned:", str(len(report.scanned_files)))
    stats_table.add_row("Total Findings:", str(len(report.findings)))

    # Count by risk
    risk_counts: dict[SecurityRisk, int] = {}
    for finding in report.findings:
        risk_counts[finding.risk_level] = risk_counts.get(finding.risk_level, 0) + 1

    for risk in [SecurityRisk.CRITICAL, SecurityRisk.HIGH, SecurityRisk.MEDIUM, SecurityRisk.LOW]:
        count = risk_counts.get(risk, 0)
        if count > 0:
            _, color, label = RISK_STYLES[risk]
            stats_table.add_row(f"{label}:", f"[{color}]{count}[/{color}]")

    console.print("\n")
    console.print(Panel(stats_table, title="[bold]Scan Statistics[/]", border_style="dim"))


def _show_scan_errors(errors: list[str]) -> None:
    """Show scan errors."""
    console.print()
    error_text = "\n".join(f"- {err}" for err in errors[:5])
    if len(errors) > 5:
        error_text += f"\n[dim]... and {len(errors) - 5} more errors[/]"

    console.print(
        Panel(
            error_text,
            title="[bold red]Scan Errors[/]",
            border_style="red",
        )
    )


def export_config_report_json(report: BuildConfigReport) -> str:
    """Export report as JSON.

    Args:
        report: The build configuration report.

    Returns:
        JSON string of the report.
    """
    data = {
        "source_path": report.source_path,
        "scanned_files": report.scanned_files,
        "findings": [
            {
                "category": finding.category.value,
                "risk_level": finding.risk_level.value,
                "title": finding.title,
                "description": finding.description,
                "file_path": finding.file_path,
                "line_start": finding.line_start,
                "line_end": finding.line_end,
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
                "cwe": finding.cwe,
                "references": finding.references,
            }
            for finding in report.findings
        ],
        "summary": {
            "total_findings": len(report.findings),
            "by_risk": _count_by_risk(report),
            "by_category": _count_by_category(report),
        },
        "scan_errors": report.scan_errors,
    }
    return json.dumps(data, indent=2)


def export_config_report_text(report: BuildConfigReport) -> str:
    """Export report as plain text.

    Args:
        report: The build configuration report.

    Returns:
        Plain text string of the report.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("BUILD CONFIGURATION SECURITY REPORT")
    lines.append("=" * 60)
    lines.append(f"Source: {report.source_path}")
    lines.append(f"Total Findings: {len(report.findings)}")
    lines.append("")

    if not report.findings:
        lines.append("No security issues found.")
        return "\n".join(lines)

    # Group by risk
    by_risk: dict[SecurityRisk, list[SecurityFinding]] = {}
    for finding in report.findings:
        by_risk.setdefault(finding.risk_level, []).append(finding)

    for risk in [SecurityRisk.CRITICAL, SecurityRisk.HIGH, SecurityRisk.MEDIUM, SecurityRisk.LOW]:
        findings = by_risk.get(risk, [])
        if findings:
            _, _, label = RISK_STYLES[risk]
            lines.append(f"\n{label} ({len(findings)})")
            lines.append("-" * 40)
            for f in findings:
                lines.append(f"[{f.category.value}] {f.title}")
                lines.append(f"  File: {f.file_path}")
                if f.line_start:
                    lines.append(f"  Line: {f.line_start}")
                if f.recommendation:
                    lines.append(f"  Fix: {f.recommendation[:100]}")
                lines.append("")

    # Summary
    lines.append("\n" + "=" * 60)
    lines.append("SUMMARY")
    lines.append("=" * 60)
    lines.append(f"Files scanned: {len(report.scanned_files)}")
    for risk, count in _count_by_risk(report).items():
        lines.append(f"{risk.upper()}: {count}")

    return "\n".join(lines)


def _count_by_risk(report: BuildConfigReport) -> dict[str, int]:
    """Count findings by risk level."""
    counts: dict[str, int] = {}
    for finding in report.findings:
        key = finding.risk_level.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def _count_by_category(report: BuildConfigReport) -> dict[str, int]:
    """Count findings by category."""
    counts: dict[str, int] = {}
    for finding in report.findings:
        key = finding.category.value
        counts[key] = counts.get(key, 0) + 1
    return counts
