"""Report export service – generates JSON / CSV / HTML reports from scan data."""

import csv
import io
import json
from datetime import datetime, timezone
from html import escape
from typing import Any


# ---------------------------------------------------------------------------
# Severity colour mapping for HTML
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(val: datetime | None) -> str | None:
    """Return ISO-8601 string or None."""
    if val is None:
        return None
    return val.isoformat()


def _fmt_dt(val: datetime | None) -> str:
    """Human-readable datetime."""
    if val is None:
        return "N/A"
    try:
        return val.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(val)


def _severity_sort_key(severity: str) -> int:
    """Numeric key for severity ordering (higher = more severe)."""
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return order.get(severity.lower(), 0)


def _count_by_severity(findings: list) -> dict[str, int]:
    """Count findings per severity level."""
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        key = getattr(f, "severity", "info").lower()
        if key in counts:
            counts[key] += 1
    return counts


def _finding_to_dict(f: Any) -> dict[str, Any]:
    """Convert a Finding ORM object (or mock) to a plain dict."""
    return {
        "id": f.id,
        "scan_id": f.scan_id,
        "vuln_type": f.vuln_type,
        "severity": f.severity,
        "confidence": f.confidence,
        "file_path": f.file_path,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "function_name": f.function_name,
        "title": f.title,
        "description": f.description,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "status": f.status,
        "engine": f.engine,
        "extra_metadata": f.extra_metadata,
        "cpg_path": f.cpg_path,
        "created_at": _iso(f.created_at),
    }


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def build_json_report(scan: Any, findings: list) -> dict[str, Any]:
    """Build a complete JSON report for a scan.

    Returns a dict ready to be serialised with ``json.dumps``.
    """
    severity_counts = _count_by_severity(findings)

    return {
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "source_type": scan.source_type,
            "source_path": scan.source_path,
            "branch": scan.branch,
            "status": scan.status,
            "scan_type": scan.scan_type,
            "progress_percent": scan.progress_percent,
            "total_files": scan.total_files,
            "files_scanned": scan.files_scanned,
            "engines_completed": scan.engines_completed,
            "engines_total": scan.engines_total,
            "tokens_used": scan.tokens_used,
            "quality_score": scan.quality_score,
            "coverage_score": scan.coverage_score,
            "created_at": _iso(scan.created_at),
            "started_at": _iso(scan.started_at),
            "completed_at": _iso(scan.completed_at),
        },
        "summary": {
            "total": len(findings),
            **severity_counts,
        },
        "findings": [_finding_to_dict(f) for f in findings],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# CSV report
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "ID",
    "Severity",
    "Confidence",
    "Vulnerability Type",
    "Title",
    "File Path",
    "Line Start",
    "Line End",
    "Function",
    "Engine",
    "Status",
    "Description",
    "Evidence",
    "Remediation",
    "Created At",
]


def build_csv_report(scan: Any, findings: list) -> bytes:
    """Build a CSV report and return as UTF-8 encoded bytes.

    The CSV contains all findings with full descriptions (no truncation).
    """
    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow(_CSV_COLUMNS)

    for f in findings:
        writer.writerow([
            f.id,
            f.severity,
            f"{f.confidence:.2f}" if f.confidence is not None else "",
            f.vuln_type,
            f.title or "",
            f.file_path,
            f.line_start if f.line_start is not None else "",
            f.line_end if f.line_end is not None else "",
            f.function_name or "",
            f.engine,
            f.status,
            f.description or "",
            f.evidence or "",
            f.remediation or "",
            _iso(f.created_at) or "",
        ])

    return buf.getvalue().encode("utf-8")


# ---------------------------------------------------------------------------
# HTML report (print-friendly, can be saved as PDF from browser)
# ---------------------------------------------------------------------------

def build_html_report(scan: Any, findings: list) -> str:
    """Build a self-contained HTML report with embedded CSS.

    The HTML is designed to be print-friendly so users can Ctrl+P to save
    as PDF directly from the browser.
    """
    severity_counts = _count_by_severity(findings)
    sorted_findings = sorted(findings, key=lambda f: _severity_sort_key(f.severity), reverse=True)

    scan_name = escape(scan.name)
    scan_id = scan.id
    status = escape(scan.status)
    scan_type = escape(scan.scan_type)
    created = _fmt_dt(scan.created_at)
    started = _fmt_dt(scan.started_at)
    completed = _fmt_dt(scan.completed_at)
    duration = ""
    if scan.started_at and scan.completed_at:
        delta = scan.completed_at - scan.started_at
        minutes, seconds = divmod(int(delta.total_seconds()), 60)
        duration = f"{minutes}m {seconds}s"
    else:
        duration = "N/A"

    # Build severity badges in summary
    severity_badges = ""
    for sev in _SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        color = _SEVERITY_COLORS.get(sev, "#6b7280")
        severity_badges += (
            f'<div class="sev-badge" style="border-left:4px solid {color}">'
            f'<span class="sev-label">{sev.upper()}</span>'
            f'<span class="sev-count">{count}</span>'
            f"</div>\n"
        )

    # Build findings rows
    finding_rows = ""
    if not sorted_findings:
        finding_rows = '<tr><td colspan="7" class="empty">No findings discovered during this scan.</td></tr>'
    else:
        for idx, f in enumerate(sorted_findings, 1):
            color = _SEVERITY_COLORS.get(f.severity.lower(), "#6b7280")
            desc = escape((f.description or "")[:300])
            remediation_html = escape(f.remediation or "")
            location = escape(f.file_path)
            if f.line_start:
                location += f":{f.line_start}"

            finding_rows += f"""<tr>
    <td class="center">{idx}</td>
    <td><span class="sev-tag" style="background:{color}">{escape(f.severity.upper())}</span></td>
    <td>{escape(f.vuln_type)}</td>
    <td class="mono">{location}</td>
    <td>{desc}</td>
    <td class="center">{escape(f.engine)}</td>
    <td class="center">{escape(f.status)}</td>
</tr>
"""
            if remediation_html:
                finding_rows += f"""<tr class="remediation-row">
    <td></td><td colspan="6"><strong>Remediation:</strong> {remediation_html}</td>
</tr>
"""

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DeepVuln Report - {scan_name}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; color: #1a1a2e; background: #fff; line-height: 1.6; padding: 40px; max-width: 1200px; margin: 0 auto; }}
h1 {{ font-size: 28px; margin-bottom: 4px; color: #0f172a; }}
h2 {{ font-size: 20px; margin: 32px 0 16px; color: #1e293b; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }}
.subtitle {{ color: #64748b; font-size: 14px; margin-bottom: 24px; }}
.meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 24px; }}
.meta-item {{ background: #f8fafc; border-radius: 6px; padding: 12px 16px; }}
.meta-item .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #94a3b8; margin-bottom: 2px; }}
.meta-item .value {{ font-size: 14px; font-weight: 600; color: #1e293b; }}
.sev-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-bottom: 24px; }}
.sev-badge {{ background: #f8fafc; border-radius: 6px; padding: 12px 16px; display: flex; justify-content: space-between; align-items: center; }}
.sev-label {{ font-size: 12px; font-weight: 700; text-transform: uppercase; }}
.sev-count {{ font-size: 24px; font-weight: 800; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 32px; }}
th {{ background: #0f172a; color: #fff; text-align: left; padding: 10px 12px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
td {{ padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
tr:nth-child(even) {{ background: #fafbfc; }}
tr:hover {{ background: #f1f5f9; }}
.center {{ text-align: center; }}
.mono {{ font-family: "SF Mono", "Fira Code", "Fira Mono", Menlo, Consolas, monospace; font-size: 12px; }}
.sev-tag {{ color: #fff; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 3px; text-transform: uppercase; }}
.remediation-row td {{ background: #f0fdf4; font-size: 12px; padding: 8px 12px 8px 48px; }}
.empty {{ text-align: center; color: #94a3b8; padding: 40px 12px; font-style: italic; }}
.footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center; }}
@media print {{
    body {{ padding: 20px; font-size: 11px; }}
    h1 {{ font-size: 22px; }}
    th {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .sev-tag {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    table {{ font-size: 10px; }}
    tr {{ page-break-inside: avoid; }}
}}
</style>
</head>
<body>
<h1>DeepVuln Security Scan Report</h1>
<p class="subtitle">Scan #{scan_id} &middot; {scan_name}</p>

<h2>Scan Information</h2>
<div class="meta-grid">
  <div class="meta-item"><div class="label">Status</div><div class="value">{status}</div></div>
  <div class="meta-item"><div class="label">Scan Type</div><div class="value">{scan_type}</div></div>
  <div class="meta-item"><div class="label">Created</div><div class="value">{created}</div></div>
  <div class="meta-item"><div class="label">Started</div><div class="value">{started}</div></div>
  <div class="meta-item"><div class="label">Completed</div><div class="value">{completed}</div></div>
  <div class="meta-item"><div class="label">Duration</div><div class="value">{duration}</div></div>
  <div class="meta-item"><div class="label">Files Scanned</div><div class="value">{scan.files_scanned}</div></div>
  <div class="meta-item"><div class="label">Tokens Used</div><div class="value">{scan.tokens_used:,}</div></div>
</div>

<h2>Findings Summary</h2>
<div class="sev-grid">
{severity_badges}
  <div class="sev-badge" style="border-left:4px solid #0f172a">
    <span class="sev-label">TOTAL</span>
    <span class="sev-count">{len(findings)}</span>
  </div>
</div>

<h2>Detailed Findings</h2>
<table>
<thead>
<tr>
  <th>#</th>
  <th>Severity</th>
  <th>Vulnerability</th>
  <th>Location</th>
  <th>Description</th>
  <th>Engine</th>
  <th>Status</th>
</tr>
</thead>
<tbody>
{finding_rows}
</tbody>
</table>

<div class="footer">
  Generated by DeepVuln &middot; {generated}
</div>
</body>
</html>"""
