"""
L3 Analysis Data Models

Unified data models for vulnerability findings across all analysis engines.
"""

from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class FindingType(str, Enum):
    """Type of finding."""

    VULNERABILITY = "vulnerability"  # Confirmed security issue
    SUSPICIOUS = "suspicious"  # Requires manual review
    INFO = "info"  # Informational, not a security issue
    FALSE_POSITIVE = "false_positive"  # Confirmed as not a real issue


class SeverityLevel(str, Enum):
    """Severity level for findings."""

    CRITICAL = "critical"  # Immediate exploitation possible
    HIGH = "high"  # Significant security impact
    MEDIUM = "medium"  # Moderate security impact
    LOW = "low"  # Limited security impact
    INFO = "info"  # No security impact


class CodeLocation(BaseModel):
    """Location of a finding in source code."""

    file: str = Field(..., description="Relative file path from project root")
    line: int = Field(..., ge=1, description="Start line number (1-indexed)")
    column: int | None = Field(default=None, ge=1, description="Start column (1-indexed)")
    end_line: int | None = Field(default=None, ge=1, description="End line number")
    end_column: int | None = Field(default=None, ge=1, description="End column")
    snippet: str | None = Field(default=None, description="Code snippet at the location")
    function: str | None = Field(default=None, description="Containing function/method name")
    class_name: str | None = Field(default=None, description="Containing class name")

    @field_validator("end_line")
    @classmethod
    def validate_end_line(cls, v: int | None, info) -> int | None:
        """Ensure end_line >= line."""
        if v is not None and "line" in info.data and v < info.data["line"]:
            raise ValueError("end_line must be >= line")
        return v

    def to_display(self) -> str:
        """Format location for display."""
        loc = f"{self.file}:{self.line}"
        if self.column:
            loc += f":{self.column}"
        return loc


class Finding(BaseModel):
    """
    Unified vulnerability finding model.

    This model standardizes findings from different analysis engines
    (Semgrep, CodeQL, Agent) into a common format.
    """

    # Identity
    id: str = Field(..., description="Unique finding identifier")
    rule_id: str | None = Field(default=None, description="Rule that triggered this finding")

    # Classification
    type: FindingType = Field(default=FindingType.VULNERABILITY, description="Type of finding")
    severity: SeverityLevel = Field(..., description="Severity level")
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Confidence score (0.0-1.0)",
    )

    # Content
    title: str = Field(..., description="Short title/summary")
    description: str = Field(..., description="Detailed description")
    fix_suggestion: str | None = Field(
        default=None,
        description="Suggested fix or remediation",
    )

    # Location
    location: CodeLocation = Field(..., description="Code location")

    # Source tracking
    source: Literal["semgrep", "codeql", "agent"] = Field(
        ...,
        description="Analysis engine that produced this finding",
    )

    # Classification references
    cwe: str | None = Field(default=None, description="CWE identifier (e.g., 'CWE-79')")
    owasp: str | None = Field(
        default=None,
        description="OWASP category (e.g., 'A03:2021')",
    )
    cve: str | None = Field(default=None, description="Related CVE identifier")

    # Additional context
    references: list[str] = Field(
        default_factory=list,
        description="Reference URLs for more information",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags for categorization",
    )

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Engine-specific metadata",
    )

    # Timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this finding was created",
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump()

    def to_summary(self) -> str:
        """Generate a one-line summary."""
        return f"[{self.severity.value.upper()}] {self.title} at {self.location.to_display()}"


class ScanResult(BaseModel):
    """
    Result of a scan operation.

    Contains all findings from a single scan, plus metadata about the scan itself.
    """

    # Scan info
    source_path: str = Field(..., description="Path that was scanned")
    engine: str = Field(..., description="Engine that performed the scan")
    rules_used: list[str] = Field(
        default_factory=list,
        description="Rules/Rule sets used in the scan",
    )

    # Findings
    findings: list[Finding] = Field(
        default_factory=list,
        description="All findings from the scan",
    )

    # Statistics
    total_findings: int = Field(default=0, description="Total number of findings")
    by_severity: dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        description="Findings count by severity",
    )
    by_type: dict[str, int] = Field(
        default_factory=lambda: {
            "vulnerability": 0,
            "suspicious": 0,
            "info": 0,
            "false_positive": 0,
        },
        description="Findings count by type",
    )

    # Timing
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When the scan started",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="When the scan completed",
    )
    duration_seconds: float | None = Field(
        default=None,
        description="Scan duration in seconds",
    )

    # Status
    success: bool = Field(default=True, description="Whether the scan completed successfully")
    error_message: str | None = Field(
        default=None,
        description="Error message if scan failed",
    )

    # Raw output
    raw_output: dict[str, Any] | None = Field(
        default=None,
        description="Raw output from the engine (for debugging)",
    )

    def add_finding(self, finding: Finding) -> None:
        """Add a finding and update statistics."""
        self.findings.append(finding)
        self.total_findings += 1
        self.by_severity[finding.severity.value] = (
            self.by_severity.get(finding.severity.value, 0) + 1
        )
        self.by_type[finding.type.value] = (
            self.by_type.get(finding.type.value, 0) + 1
        )

    def get_findings_by_severity(
        self,
        severities: list[SeverityLevel],
    ) -> list[Finding]:
        """Filter findings by severity levels."""
        severity_values = [s.value for s in severities]
        return [f for f in self.findings if f.severity.value in severity_values]

    def get_findings_above_severity(
        self,
        min_severity: SeverityLevel,
    ) -> list[Finding]:
        """Get findings at or above the specified severity."""
        severity_order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO,
        ]
        min_index = severity_order.index(min_severity)
        allowed = severity_order[: min_index + 1]
        return self.get_findings_by_severity(allowed)

    def to_summary(self) -> str:
        """Generate a summary of the scan result."""
        lines = [
            f"Scan Results for: {self.source_path}",
            f"Engine: {self.engine}",
            f"Total Findings: {self.total_findings}",
            "",
            "By Severity:",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = self.by_severity.get(sev, 0)
            if count > 0:
                lines.append(f"  {sev.upper()}: {count}")

        if self.duration_seconds:
            lines.append(f"\nDuration: {self.duration_seconds:.2f}s")

        return "\n".join(lines)

    def deduplicate_findings(self) -> int:
        """
        Remove duplicate findings based on rule_id, file, and line.

        Returns:
            Number of duplicates removed.
        """
        seen: set[tuple[str | None, str, int]] = set()
        unique_findings: list[Finding] = []
        duplicates_removed = 0

        for finding in self.findings:
            # Create a key for deduplication
            key = (
                finding.rule_id,
                finding.location.file,
                finding.location.line,
            )

            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
            else:
                duplicates_removed += 1

        if duplicates_removed > 0:
            self.findings = unique_findings
            self.total_findings = len(unique_findings)
            # Recalculate statistics
            self._recalculate_stats()

        return duplicates_removed

    def _recalculate_stats(self) -> None:
        """Recalculate statistics from current findings."""
        self.by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        self.by_type = {
            "vulnerability": 0,
            "suspicious": 0,
            "info": 0,
            "false_positive": 0,
        }

        for finding in self.findings:
            self.by_severity[finding.severity.value] = (
                self.by_severity.get(finding.severity.value, 0) + 1
            )
            self.by_type[finding.type.value] = (
                self.by_type.get(finding.type.value, 0) + 1
            )

    def merge_results(self, other: "ScanResult") -> None:
        """
        Merge another ScanResult into this one.

        Args:
            other: Another ScanResult to merge.
        """
        for finding in other.findings:
            self.add_finding(finding)

    def get_unique_files(self) -> list[str]:
        """Get list of unique files with findings."""
        return sorted(set(f.location.file for f in self.findings))

    def get_findings_by_file(self, file_path: str) -> list[Finding]:
        """Get all findings for a specific file."""
        return [f for f in self.findings if f.location.file == file_path]

    def sort_by_severity(self) -> None:
        """Sort findings by severity (highest first)."""
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    def to_json(self) -> str:
        """Export results as JSON string."""
        return self.model_dump_json(indent=2)

    def to_markdown(self) -> str:
        """Export results as Markdown report."""
        lines = [
            f"# Scan Report",
            "",
            f"**Source:** {self.source_path}",
            f"**Engine:** {self.engine}",
            f"**Status:** {'Success' if self.success else 'Failed'}",
            f"**Duration:** {self.duration_seconds:.2f}s" if self.duration_seconds else "",
            "",
            "## Summary",
            "",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = self.by_severity.get(sev, 0)
            if count > 0:
                lines.append(f"| {sev.upper()} | {count} |")

        lines.extend([
            "",
            "## Findings",
            "",
        ])

        for finding in self.findings:
            lines.extend([
                f"### {finding.title}",
                "",
                f"- **Severity:** {finding.severity.value.upper()}",
                f"- **Location:** {finding.location.to_display()}",
                f"- **Rule:** {finding.rule_id or 'N/A'}",
            ])

            if finding.cwe:
                lines.append(f"- **CWE:** {finding.cwe}")
            if finding.owasp:
                lines.append(f"- **OWASP:** {finding.owasp}")

            lines.extend([
                "",
                f"**Description:**",
                f"{finding.description}",
                "",
            ])

        return "\n".join(lines)
