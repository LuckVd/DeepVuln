"""Unit tests for report export service."""

import csv
import io
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Fixtures – lightweight mock objects mimicking ORM Scan / Finding
# ---------------------------------------------------------------------------

def _make_scan(**overrides):
    """Create a mock Scan object with sensible defaults."""
    defaults = dict(
        id=1,
        name="test-scan",
        source_type="local",
        source_path="/tmp/repo",
        branch="main",
        status="completed",
        scan_type="full",
        config={},
        progress_percent=100,
        current_phase=None,
        current_step=None,
        current_engine=None,
        total_files=10,
        indexed_files=10,
        analyzed_files=10,
        files_scanned=10,
        files_with_findings=3,
        engines_completed=3,
        engines_total=3,
        tokens_used=5000,
        tokens_budget=100000,
        llm_requests_count=10,
        findings_count=3,
        verified_count=2,
        false_positive_count=0,
        critical_count=1,
        high_count=1,
        medium_count=1,
        low_count=0,
        info_count=0,
        quality_score=0.85,
        coverage_score=0.90,
        created_at=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
        started_at=datetime(2026, 4, 15, 10, 0, 5, tzinfo=timezone.utc),
        completed_at=datetime(2026, 4, 15, 10, 5, 0, tzinfo=timezone.utc),
        estimated_completion=None,
        error_message=None,
        failed_engines=[],
        checkpoint_data=None,
        task_id="celery-001",
        attack_surface=None,
        adjudication_summary=None,
        adversarial_summary=None,
        incremental_stats=None,
        report_path=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_finding(**overrides):
    """Create a mock Finding object with sensible defaults."""
    defaults = dict(
        id=1,
        scan_id=1,
        phase_id=None,
        vuln_type="SQL Injection",
        severity="critical",
        confidence=0.95,
        file_path="src/app/db.py",
        line_start=42,
        line_end=45,
        function_name="execute_query",
        title="SQL Injection in database query",
        description="User input is directly interpolated into SQL query string without parameterization.",
        evidence='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        remediation="Use parameterized queries or an ORM to prevent SQL injection.",
        status="verified",
        engine="semgrep",
        extra_metadata={
            "rule_id": "python.sql.security.a1",
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
            "tags": ["security", "injection"],
        },
        cpg_path={
            "source": {"file": "src/app/routes.py", "line": 10, "function": "get_user"},
            "propagation": [
                {"file": "src/app/routes.py", "line": 12},
                {"file": "src/app/db.py", "line": 40},
            ],
            "sink": {"file": "src/app/db.py", "line": 42, "function": "execute_query"},
        },
        created_at=datetime(2026, 4, 15, 10, 2, 30, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# Test: JSON report generation
# ---------------------------------------------------------------------------

class TestJsonReport:
    """Tests for JSON report generation."""

    def test_json_report_contains_scan_metadata(self):
        """JSON report includes scan name, status, timestamps."""
        from src.web.services.report_service import build_json_report

        scan = _make_scan()
        findings = [_make_finding()]
        report = build_json_report(scan, findings)

        assert report["scan"]["id"] == 1
        assert report["scan"]["name"] == "test-scan"
        assert report["scan"]["status"] == "completed"
        assert report["scan"]["scan_type"] == "full"

    def test_json_report_contains_full_findings(self):
        """JSON report includes complete findings list with all fields."""
        from src.web.services.report_service import build_json_report

        scan = _make_scan()
        findings = [
            _make_finding(id=1, severity="critical"),
            _make_finding(id=2, severity="high", vuln_type="XSS"),
            _make_finding(id=3, severity="medium", vuln_type="Info Leak"),
        ]
        report = build_json_report(scan, findings)

        assert len(report["findings"]) == 3
        assert report["findings"][0]["id"] == 1
        assert report["findings"][0]["severity"] == "critical"
        assert report["findings"][1]["vuln_type"] == "XSS"

    def test_json_report_finding_has_extra_metadata(self):
        """JSON findings include extra_metadata."""
        from src.web.services.report_service import build_json_report

        scan = _make_scan()
        findings = [_make_finding()]
        report = build_json_report(scan, findings)

        f = report["findings"][0]
        assert f["extra_metadata"]["rule_id"] == "python.sql.security.a1"
        assert f["evidence"] is not None
        assert f["remediation"] is not None

    def test_json_report_contains_severity_summary(self):
        """JSON report includes severity summary."""
        from src.web.services.report_service import build_json_report

        scan = _make_scan()
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
        ]
        report = build_json_report(scan, findings)

        assert report["summary"]["critical"] == 2
        assert report["summary"]["high"] == 1
        assert report["summary"]["medium"] == 0

    def test_json_report_empty_findings(self):
        """JSON report works with zero findings."""
        from src.web.services.report_service import build_json_report

        scan = _make_scan()
        report = build_json_report(scan, [])

        assert report["findings"] == []
        assert report["summary"]["total"] == 0


# ---------------------------------------------------------------------------
# Test: CSV report generation
# ---------------------------------------------------------------------------

class TestCsvReport:
    """Tests for CSV report generation."""

    def test_csv_has_enhanced_columns(self):
        """CSV includes remediation and evidence columns."""
        from src.web.services.report_service import build_csv_report

        scan = _make_scan()
        findings = [_make_finding()]
        csv_bytes = build_csv_report(scan, findings)

        reader = csv.reader(io.StringIO(csv_bytes.decode("utf-8")))
        header = next(reader)

        assert "Remediation" in header
        assert "Evidence" in header
        assert "Confidence" in header

    def test_csv_rows_match_findings(self):
        """CSV contains correct number of data rows."""
        from src.web.services.report_service import build_csv_report

        scan = _make_scan()
        findings = [
            _make_finding(id=1),
            _make_finding(id=2, vuln_type="XSS"),
            _make_finding(id=3, vuln_type="CSRF"),
        ]
        csv_bytes = build_csv_report(scan, findings)

        reader = csv.reader(io.StringIO(csv_bytes.decode("utf-8")))
        header = next(reader)
        rows = list(reader)

        assert len(rows) == 3

    def test_csv_description_not_truncated(self):
        """CSV does not truncate description to 200 chars."""
        from src.web.services.report_service import build_csv_report

        long_desc = "A" * 500
        scan = _make_scan()
        findings = [_make_finding(description=long_desc)]
        csv_bytes = build_csv_report(scan, findings)

        reader = csv.reader(io.StringIO(csv_bytes.decode("utf-8")))
        header = next(reader)
        rows = list(reader)

        # description column should be the full text
        desc_idx = header.index("Description")
        assert len(rows[0][desc_idx]) == 500

    def test_csv_empty_findings(self):
        """CSV with zero findings returns only header."""
        from src.web.services.report_service import build_csv_report

        scan = _make_scan()
        csv_bytes = build_csv_report(scan, [])

        reader = csv.reader(io.StringIO(csv_bytes.decode("utf-8")))
        header = next(reader)
        rows = list(reader)

        assert len(rows) == 0
        assert len(header) > 0

    def test_csv_handles_none_fields(self):
        """CSV handles None values gracefully."""
        from src.web.services.report_service import build_csv_report

        scan = _make_scan()
        findings = [_make_finding(
            function_name=None,
            line_start=None,
            line_end=None,
            evidence=None,
            remediation=None,
        )]
        csv_bytes = build_csv_report(scan, findings)

        reader = csv.reader(io.StringIO(csv_bytes.decode("utf-8")))
        header = next(reader)
        rows = list(reader)

        assert len(rows) == 1

    def test_csv_handles_special_characters(self):
        """CSV properly handles quotes, commas and newlines."""
        from src.web.services.report_service import build_csv_report

        scan = _make_scan()
        findings = [_make_finding(
            description='He said "hello", then left\nNew line here',
            file_path="path/with,comma.py",
        )]
        csv_bytes = build_csv_report(scan, findings)

        reader = csv.reader(io.StringIO(csv_bytes.decode("utf-8")))
        header = next(reader)
        rows = list(reader)

        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Test: HTML report generation
# ---------------------------------------------------------------------------

class TestHtmlReport:
    """Tests for HTML report generation."""

    def test_html_report_valid_html(self):
        """HTML report is valid HTML with proper structure."""
        from src.web.services.report_service import build_html_report

        scan = _make_scan()
        findings = [_make_finding()]
        html = build_html_report(scan, findings)

        assert "<!DOCTYPE html>" in html or "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html

    def test_html_report_contains_scan_name(self):
        """HTML report displays scan name."""
        from src.web.services.report_service import build_html_report

        scan = _make_scan(name="my-project-scan")
        findings = [_make_finding()]
        html = build_html_report(scan, findings)

        assert "my-project-scan" in html

    def test_html_report_contains_severity_summary(self):
        """HTML report shows severity breakdown."""
        from src.web.services.report_service import build_html_report

        scan = _make_scan()
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
        ]
        html = build_html_report(scan, findings)

        assert "critical" in html.lower()
        assert "2" in html  # 2 critical

    def test_html_report_contains_finding_details(self):
        """HTML report includes each finding's details."""
        from src.web.services.report_service import build_html_report

        scan = _make_scan()
        findings = [
            _make_finding(
                vuln_type="SQL Injection",
                file_path="src/db.py",
                remediation="Use parameterized queries",
            ),
        ]
        html = build_html_report(scan, findings)

        assert "SQL Injection" in html
        assert "src/db.py" in html
        assert "Use parameterized queries" in html

    def test_html_report_contains_all_findings(self):
        """HTML report includes all findings, not just 50."""
        from src.web.services.report_service import build_html_report

        scan = _make_scan()
        findings = [
            _make_finding(id=i, vuln_type=f"Vuln-{i}")
            for i in range(1, 61)
        ]
        html = build_html_report(scan, findings)

        assert "Vuln-1" in html
        assert "Vuln-60" in html

    def test_html_report_empty_findings(self):
        """HTML report handles zero findings gracefully."""
        from src.web.services.report_service import build_html_report

        scan = _make_scan()
        html = build_html_report(scan, [])

        assert "No findings" in html or "0" in html

    def test_html_report_has_print_styles(self):
        """HTML report includes print-friendly CSS."""
        from src.web.services.report_service import build_html_report

        scan = _make_scan()
        findings = [_make_finding()]
        html = build_html_report(scan, findings)

        assert "@media print" in html or "print" in html.lower()

    def test_html_report_escapes_xss(self):
        """HTML report escapes user content to prevent XSS."""
        from src.web.services.report_service import build_html_report

        scan = _make_scan(name='<script>alert("xss")</script>')
        findings = [_make_finding(description='<img src=x onerror=alert(1)>')]
        html = build_html_report(scan, findings)

        # script tags must be escaped in content areas
        assert "&lt;script&gt;" in html
        # onerror attribute must be escaped, not rendered as live HTML
        assert "&lt;img src=x onerror=alert(1)&gt;" in html
