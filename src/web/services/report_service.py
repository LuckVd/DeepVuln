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
# HTML report (cyberpunk dark theme, print-friendly)
# ---------------------------------------------------------------------------

def build_html_report(scan: Any, findings: list) -> str:
    """Build a self-contained HTML report with embedded CSS.

    Cyberpunk dark theme with print-friendly fallback.
    Ctrl+P to save as PDF — auto switches to light theme.
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

    total = len(findings)

    # Build severity distribution bars
    severity_bars = ""
    max_count = max(severity_counts.values()) if total > 0 else 1
    for sev in _SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        color = _SEVERITY_COLORS.get(sev, "#6b7280")
        pct = (count / max_count * 100) if max_count > 0 else 0
        severity_bars += (
            f'<div class="sev-row">'
            f'<span class="sev-label" style="color:{color}">{sev.upper()}</span>'
            f'<div class="sev-bar-track">'
            f'<div class="sev-bar-fill" style="width:{pct:.0f}%;background:{color}"></div>'
            f'</div>'
            f'<span class="sev-num">{count}</span>'
            f'</div>\n'
        )

    # Critical + High percentage
    crit_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
    crit_high_pct = (crit_high / total * 100) if total > 0 else 0

    # Build finding cards
    finding_cards = ""
    if not sorted_findings:
        finding_cards = '<div class="empty-state">No findings discovered during this scan.</div>'
    else:
        for idx, f in enumerate(sorted_findings, 1):
            color = _SEVERITY_COLORS.get(f.severity.lower(), "#6b7280")
            desc = escape(f.description or "")
            remediation_html = escape(f.remediation or "")
            location = escape(f.file_path)
            if f.line_start:
                location += f":{f.line_start}"

            # Confidence display
            conf = f.confidence
            conf_str = f"{conf:.0%}" if conf is not None else "—"

            finding_cards += f"""<div class="finding-card" style="border-left-color:{color}">
<div class="finding-header">
  <span class="finding-idx">#{idx}</span>
  <span class="sev-tag" style="background:{color}">{escape(f.severity.upper())}</span>
  <span class="finding-vuln">{escape(f.vuln_type)}</span>
  <span class="finding-meta">{escape(f.engine)} · {escape(f.status)} · conf {conf_str}</span>
</div>
<div class="finding-location">{location}</div>
<div class="finding-desc">{desc}</div>
"""
            if remediation_html:
                finding_cards += f"""<div class="finding-remediation"><span class="remediation-label">REMEDIATION</span>{remediation_html}</div>\n"""
            finding_cards += "</div>\n"

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DeepVuln Report - {scan_name}</title>
<style>
/* ===== Reset & Base ===== */
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: "SF Mono", "Fira Code", "Fira Mono", Menlo, Consolas, "Courier New", monospace;
  color: #c8d6e5; background: #0a0e1a; line-height: 1.65;
  padding: 0; max-width: 1200px; margin: 0 auto;
}}

/* ===== Header ===== */
.report-header {{
  background: linear-gradient(135deg, #0a0e1a 0%, #0d1526 100%);
  border-bottom: 1px solid rgba(0,229,255,0.15);
  padding: 40px 48px 32px;
}}
.logo {{ color: #00e5ff; font-size: 11px; line-height: 1.2; margin-bottom: 16px; white-space: pre; letter-spacing: 0; }}
.report-title {{ font-size: 24px; font-weight: 700; color: #fff; letter-spacing: 2px; margin-bottom: 4px; }}
.report-subtitle {{ color: #4a90b8; font-size: 13px; letter-spacing: 1px; }}

/* ===== Sections ===== */
.section {{ padding: 32px 48px; }}
.section-title {{
  font-size: 12px; font-weight: 700; color: #00e5ff;
  text-transform: uppercase; letter-spacing: 3px;
  margin-bottom: 20px; padding-bottom: 8px;
  border-bottom: 1px solid rgba(0,229,255,0.2);
}}

/* ===== Meta Grid ===== */
.meta-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
.meta-item {{
  background: #111827; border-radius: 4px; padding: 14px 16px;
  border: 1px solid #1e293b;
}}
.meta-item .label {{ font-size: 9px; text-transform: uppercase; letter-spacing: 1.5px; color: #4a5568; margin-bottom: 6px; }}
.meta-item .value {{ font-size: 14px; font-weight: 600; color: #e2e8f0; }}

/* ===== Severity Distribution ===== */
.sev-chart {{ margin-bottom: 20px; }}
.sev-row {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }}
.sev-label {{ width: 72px; font-size: 11px; font-weight: 700; text-align: right; flex-shrink: 0; }}
.sev-bar-track {{ flex: 1; height: 20px; background: #111827; border-radius: 2px; overflow: hidden; border: 1px solid #1e293b; }}
.sev-bar-fill {{ height: 100%; border-radius: 1px; transition: width 0.3s; opacity: 0.85; }}
.sev-num {{ width: 36px; font-size: 14px; font-weight: 800; color: #e2e8f0; text-align: right; }}
.sev-total-row {{
  display: flex; justify-content: space-between; align-items: center;
  margin-top: 12px; padding-top: 12px;
  border-top: 1px solid #1e293b;
}}
.sev-total-label {{ font-size: 12px; color: #4a5568; letter-spacing: 2px; text-transform: uppercase; }}
.sev-total-num {{ font-size: 28px; font-weight: 900; color: #00e5ff; }}
.sev-crit-high {{ font-size: 11px; color: #ea580c; margin-top: 8px; letter-spacing: 1px; }}

/* ===== Finding Cards ===== */
.findings-grid {{ display: flex; flex-direction: column; gap: 12px; }}
.finding-card {{
  background: #111827; border-radius: 4px; padding: 16px 20px;
  border: 1px solid #1e293b; border-left: 4px solid;
  page-break-inside: avoid;
}}
.finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }}
.finding-idx {{ font-size: 12px; color: #4a5568; font-weight: 700; }}
.sev-tag {{
  color: #fff; font-size: 9px; font-weight: 800;
  padding: 2px 8px; border-radius: 2px;
  text-transform: uppercase; letter-spacing: 1px;
}}
.finding-vuln {{ font-size: 14px; font-weight: 700; color: #e2e8f0; }}
.finding-meta {{ font-size: 11px; color: #4a5568; margin-left: auto; }}
.finding-location {{
  font-size: 12px; color: #00e5ff; margin-bottom: 10px;
  background: rgba(0,229,255,0.06); display: inline-block;
  padding: 2px 8px; border-radius: 2px;
}}
.finding-desc {{
  font-size: 12.5px; color: #94a3b8; line-height: 1.7;
  max-height: 4.4em; overflow: hidden; position: relative;
  cursor: pointer;
}}
.finding-desc.expanded {{ max-height: none; }}
.finding-desc:not(.expanded)::after {{
  content: ""; position: absolute; bottom: 0; left: 0; right: 0;
  height: 2em;
  background: linear-gradient(transparent, #111827);
  pointer-events: none;
}}
.finding-remediation {{
  margin-top: 10px; padding: 10px 14px;
  background: rgba(0, 229, 255, 0.04); border-radius: 3px;
  border: 1px solid rgba(0, 229, 255, 0.1);
  font-size: 12px; color: #64748b; line-height: 1.7;
}}
.remediation-label {{
  display: inline-block; font-size: 9px; font-weight: 800;
  color: #00e5ff; letter-spacing: 2px; margin-right: 8px;
  text-transform: uppercase;
}}
.empty-state {{ text-align: center; color: #4a5568; padding: 60px 20px; font-size: 14px; font-style: italic; }}

/* ===== Footer ===== */
.report-footer {{
  padding: 24px 48px; border-top: 1px solid #1e293b;
  font-size: 10px; color: #334155; letter-spacing: 1px;
  display: flex; justify-content: space-between;
}}

/* ===== Print ===== */
@media print {{
  body {{ background: #fff; color: #1a1a2e; font-size: 10px; padding: 0; }}
  .report-header {{ background: #fff; border-bottom: 2px solid #0f172a; padding: 20px 24px; }}
  .logo {{ color: #0f172a; }}
  .report-title {{ color: #0f172a; }}
  .section {{ padding: 16px 24px; }}
  .meta-item {{ background: #f8fafc; border: 1px solid #e2e8f0; }}
  .meta-item .value {{ color: #0f172a; }}
  .finding-card {{ background: #fff; border: 1px solid #e2e8f0; }}
  .finding-vuln {{ color: #0f172a; }}
  .finding-location {{ color: #0369a1; background: #f0f9ff; }}
  .finding-desc {{ color: #334155; max-height: none; -webkit-line-clamp: unset; }}
  .finding-desc::after {{ display: none; }}
  .finding-remediation {{ background: #f0fdf4; border-color: #bbf7d0; color: #166534; }}
  .sev-bar-track {{ background: #f1f5f9; border-color: #e2e8f0; }}
  .report-footer {{ border-top-color: #e2e8f0; color: #94a3b8; }}
  .sev-tag, .sev-bar-fill {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
}}
</style>
</head>
<body>

<!-- Header -->
<div class="report-header">
<pre class="logo">  ██████╗ ███████╗██████╗ ██╗   ██╗██╗     ██╗   ██╗███╗   ██╗██████╗
 ██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝██║     ██║   ██║████╗  ██║██╔══██╗
 ██║  ██║█████╗  ██████╔╝ ╚████╔╝ ██║     ██║   ██║██╔██╗ ██║██║  ██║
 ██║  ██║██╔══╝  ██╔══██╗  ╚██╔╝  ██║     ██║   ██║██║╚██╗██║██║  ██║
 ██████╔╝███████╗██║  ██║   ██║   ███████╗╚██████╔╝██║ ╚████║██████╔╝
 ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝</pre>
  <div class="report-title">SECURITY SCAN REPORT</div>
  <div class="report-subtitle">Scan #{scan_id} &middot; {scan_name}</div>
</div>

<!-- Scan Information -->
<div class="section">
  <div class="section-title">Scan Information</div>
  <div class="meta-grid">
    <div class="meta-item"><div class="label">Status</div><div class="value">{status}</div></div>
    <div class="meta-item"><div class="label">Scan Type</div><div class="value">{scan_type}</div></div>
    <div class="meta-item"><div class="label">Duration</div><div class="value">{duration}</div></div>
    <div class="meta-item"><div class="label">Files Scanned</div><div class="value">{scan.files_scanned}</div></div>
    <div class="meta-item"><div class="label">Created</div><div class="value">{created}</div></div>
    <div class="meta-item"><div class="label">Started</div><div class="value">{started}</div></div>
    <div class="meta-item"><div class="label">Completed</div><div class="value">{completed}</div></div>
    <div class="meta-item"><div class="label">Tokens Used</div><div class="value">{scan.tokens_used:,}</div></div>
  </div>
</div>

<!-- Findings Summary -->
<div class="section">
  <div class="section-title">Findings Summary</div>
  <div class="sev-chart">
{severity_bars}
    <div class="sev-total-row">
      <span class="sev-total-label">Total Findings</span>
      <span class="sev-total-num">{total}</span>
    </div>
    <div class="sev-crit-high">{crit_high_pct:.0f}% CRITICAL + HIGH ({crit_high}/{total})</div>
  </div>
</div>

<!-- Detailed Findings -->
<div class="section">
  <div class="section-title">Detailed Findings</div>
  <div class="findings-grid">
{finding_cards}
  </div>
</div>

<!-- Footer -->
<div class="report-footer">
  <span>Generated by DeepVuln</span>
  <span>{generated}</span>
</div>

<script>
document.querySelectorAll('.finding-desc').forEach(function(el) {{
  if (el.scrollHeight > el.clientHeight + 4) {{
    el.addEventListener('click', function() {{ el.classList.toggle('expanded'); }});
  }}
}});
</script>
</body>
</html>"""
