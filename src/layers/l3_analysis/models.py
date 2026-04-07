"""
L3 Analysis Data Models

Unified data models for vulnerability findings across all analysis engines.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class ScanStatus(str, Enum):
    """
    P6-01: Top-level status for full scan results.

    This enum provides clear result boundaries so users can immediately
    understand the completeness of a scan without reading the entire report.
    """

    COMPLETE_SUCCESS = "complete_success"      # All requested engines succeeded
    PARTIAL_SUCCESS = "partial_success"        # Non-core capabilities failed, main results still complete
    DEGRADED_SUCCESS = "degraded_success"      # Core evidence engine (codeql) failed, but other engines have results
    FAILED = "failed"                          # All core scan engines failed or no valid results


class FailedEngineInfo(BaseModel):
    """
    P6-01: Structured information about a failed engine.

    This model provides actionable diagnostics when an engine fails,
    replacing the previous simple string-based error messages.
    """

    name: str = Field(..., description="Engine name (semgrep/codeql/agent)")
    error_type: str = Field(
        ...,
        description="Error type: unavailable/exception/engine_failed/build_failed/analyze_failed/timeout/unknown",
    )
    message: str = Field(..., description="Human-readable error message")
    languages: list[str] | None = Field(
        default=None,
        description="Languages that failed (for multi-language CodeQL scans)",
    )
    is_core_engine: bool = Field(
        default=False,
        description="Whether this is a core evidence engine (codeql is core)",
    )
    phase: str | None = Field(
        default=None,
        description="Which phase this engine was running in",
    )


# =============================================================================
# P6-02: CodeQL Structured Error Diagnostics
# =============================================================================


class CodeQLErrorType(str, Enum):
    """
    P6-02: Structured error types for CodeQL failures.

    These error types map directly to P6-01's FailedEngineInfo.error_type field,
    providing fine-grained diagnostics for CodeQL failures.
    """

    NOT_INSTALLED = "not_installed"
    """CodeQL CLI is not installed or not in PATH."""

    UNSUPPORTED_LANGUAGE = "unsupported_language"
    """The language is not supported by CodeQL."""

    DB_CREATE_FAILED = "db_create_failed"
    """Failed to create CodeQL database (extraction failed)."""

    BUILD_FAILED = "build_failed"
    """Build process failed during database creation."""

    ANALYZE_FAILED = "analyze_failed"
    """Analysis phase failed (query execution)."""

    TIMEOUT = "timeout"
    """Operation timed out."""

    PACK_ERROR = "pack_error"
    """Query pack error (missing or invalid pack)."""

    RESOURCE_ERROR = "resource_error"
    """Resource error (memory, disk, etc.)."""

    UNKNOWN = "unknown"
    """Unknown or unclassified error."""


# Mapping from CodeQLErrorType to human-readable suggestions
# Defined here (before CodeQLLanguageStatus) so the validator can use it
CODEQL_ERROR_SUGGESTIONS: dict[CodeQLErrorType, str] = {
    CodeQLErrorType.NOT_INSTALLED: (
        "Install CodeQL CLI from https://github.com/github/codeql-cli-binaries/releases"
    ),
    CodeQLErrorType.UNSUPPORTED_LANGUAGE: (
        "Check if the language is in CodeQL's supported languages list"
    ),
    CodeQLErrorType.DB_CREATE_FAILED: (
        "Ensure the project has valid source files for the target language"
    ),
    CodeQLErrorType.BUILD_FAILED: (
        "Check build configuration and ensure project can be compiled"
    ),
    CodeQLErrorType.ANALYZE_FAILED: (
        "Check CodeQL query packs are installed (run 'codeql pack download')"
    ),
    CodeQLErrorType.TIMEOUT: (
        "Consider increasing timeout or scanning a smaller scope"
    ),
    CodeQLErrorType.PACK_ERROR: (
        "Install missing query packs or check pack configuration"
    ),
    CodeQLErrorType.RESOURCE_ERROR: (
        "Increase available memory or reduce parallel operations"
    ),
    CodeQLErrorType.UNKNOWN: (
        "Check logs for details and consider reporting this issue"
    ),
}


class CodeQLLanguageStatus(BaseModel):
    """
    P6-02: Status for a single language in a multi-language CodeQL scan.

    For multi-language projects, each language has its own status,
    allowing users to see which specific languages failed.
    """

    language: str = Field(..., description="Language name (e.g., 'java', 'python')")
    status: Literal["success", "failed", "skipped"] = Field(
        ...,
        description="Scan status for this language",
    )
    stage: str | None = Field(
        default=None,
        description="Stage where the operation stopped (availability_check/language_check/build/db_create/analyze)",
    )
    error_type: CodeQLErrorType | None = Field(
        default=None,
        description="Structured error type if failed",
    )
    error_message: str | None = Field(
        default=None,
        description="Human-readable error message",
    )
    suggestion: str | None = Field(
        default=None,
        description="Suggested action to resolve the issue",
    )
    findings_count: int = Field(
        default=0,
        ge=0,
        description="Number of findings for this language",
    )
    duration_seconds: float | None = Field(
        default=None,
        description="Duration of the scan for this language",
    )

    def model_post_init(self, __context: Any) -> None:
        """Auto-fill suggestion from error_type after model is initialized."""
        if self.suggestion is None and self.error_type is not None and self.status != "success":
            if self.error_type in CODEQL_ERROR_SUGGESTIONS:
                # Use object.__setattr__ to bypass frozen model
                object.__setattr__(self, "suggestion", CODEQL_ERROR_SUGGESTIONS[self.error_type])


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


# =============================================================================
# P6-03: Evidence Strength (Anti-Hallucination Integration)
# =============================================================================


class EvidenceStrength(str, Enum):
    """
    P6-03: Evidence strength for vulnerability findings.

    Based on code-audit anti-hallucination rules and coverage matrix.
    Indicates how well the finding is supported by verifiable evidence.
    """

    STRONG = "strong"
    """
    Strong evidence:
    - Multi-engine cross-validation (len(related_engines) >= 2)
    - Or multiple detections merged (duplicate_count >= 2)
    - Or high confidence (>= 0.9) + all hallucination checks passed
    """

    MEDIUM = "medium"
    """
    Medium evidence:
    - Single engine with high confidence (>= 0.8)
    - Or merged at least once (duplicate_count >= 1)
    - Core validations passed
    """

    WEAK = "weak"
    """
    Weak evidence:
    - Single engine with moderate confidence (0.5 <= confidence < 0.8)
    - No cross-engine confirmation
    - Requires manual verification
    """

    SPECULATIVE = "speculative"
    """
    Speculative evidence:
    - FindingType.SUSPICIOUS type
    - Or confidence < 0.5
    - Or hallucination check failed
    - Likely false positive, needs special attention
    """


# =============================================================================
# P6-04: Status Subtypes (Taint Analysis + Verification Methodology Integration)
# =============================================================================


class ConditionalSubtype(str, Enum):
    """
    P6-04a: Conditional status subtypes.

    Based on code-audit taint_analysis.md and verification_methodology.md.
    Provides fine-grained classification for conditional findings.
    """

    STRONG = "conditional-strong"
    """
    Conditional-Strong: High confidence but needs environment verification.
    - evidence_strength = strong/medium
    - exploitability = likely/possible
    - Has traceable dataflow but needs runtime confirmation
    """

    WEAK = "conditional-weak"
    """
    Conditional-Weak: Lower confidence, needs manual confirmation.
    - evidence_strength = weak
    - exploitability = possible/unlikely
    - Incomplete dataflow or potential false positive
    """


class InformationalSubtype(str, Enum):
    """
    P6-04b: Informational status subtypes.

    Based on code-audit verification_methodology.md confidence scoring.
    Distinguishes different types of non-exploitable findings.
    """

    NOT_EXPLOITABLE = "not_exploitable"
    """
    Not Exploitable: Confirmed as not exploitable.
    - exploitability = not_exploitable
    - Valid finding but no real-world attack vector
    - May be protected by framework or sanitization
    """

    SPECULATIVE_SIGNAL = "speculative_signal"
    """
    Speculative Signal: Speculative finding, likely false positive.
    - evidence_strength = speculative
    - Or FindingType.SUSPICIOUS
    - Low confidence, may be hallucination
    """

    ENVIRONMENTAL_RISK = "environmental_risk"
    """
    Environmental Risk: Requires specific conditions to exploit.
    - Needs specific configuration/permissions/environment
    - Exploitable only in certain deployment scenarios
    - Example: Debug mode enabled, specific feature flag
    """


class HallucinationCheckResult(BaseModel):
    """
    P6-03: Anti-hallucination check result.

    Based on code-audit anti_hallucination.md rules:
    - Rule 1: File existence verification
    - Rule 3: Line number validity verification
    """

    file_exists: bool = Field(..., description="File exists (Rule 1)")
    code_authentic: bool = Field(default=True, description="Code is authentic (Rule 2)")
    line_number_valid: bool = Field(..., description="Line number is valid (Rule 3)")
    tech_stack_match: bool = Field(default=True, description="Tech stack matches (Rule 4)")

    # Detailed info
    file_path: str = Field(..., description="Checked file path")
    actual_line_count: int | None = Field(default=None, description="Actual line count of file")
    reported_line: int | None = Field(default=None, description="Reported line number")

    @property
    def all_passed(self) -> bool:
        """All checks passed."""
        return all([
            self.file_exists,
            self.code_authentic,
            self.line_number_valid,
            self.tech_stack_match,
        ])

    @property
    def has_failure(self) -> bool:
        """Any check failed."""
        return not self.all_passed

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for metadata storage."""
        return {
            "all_passed": self.all_passed,
            "file_exists": self.file_exists,
            "line_number_valid": self.line_number_valid,
            "tech_stack_match": self.tech_stack_match,
        }


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
    source: Literal["semgrep", "codeql", "agent", "ast_engine"] = Field(
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

    # Final Score (P4-01: unified scoring for prioritization)
    final_score: float | None = Field(
        default=None,
        ge=0.0,
        le=1.5,  # Max with engine weight 1.2
        description="Unified final score for prioritization (0.0-1.5)",
    )
    score_detail: dict[str, Any] | None = Field(
        default=None,
        description="Detailed breakdown of final_score calculation",
    )

    # Exploitability (P4-02: for adjudication override)
    exploitability: str | None = Field(
        default=None,
        description="Exploitability assessment (exploitable/likely/possible/unlikely/not_exploitable)",
    )

    # Final Status (P4-02: adjudication result)
    final_status: str | None = Field(
        default=None,
        description="Final adjudication status based on exploitability override",
    )

    # Logical Vulnerability ID (P4-03: for consistency checking)
    logical_vuln_id: str | None = Field(
        default=None,
        description="Logical vulnerability ID for deduplication across engines",
    )

    # P4-04: Semantic deduplication fields
    related_engines: list[str] = Field(
        default_factory=list,
        description="List of engines that detected this vulnerability (for cross-engine dedup)",
    )
    duplicate_count: int = Field(
        default=0,
        ge=0,
        description="Number of duplicate findings merged into this one",
    )
    merged_findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Details of findings merged into this one (engine, rule_id, code snippet, line)",
    )
    ast_hash: str | None = Field(
        default=None,
        description="Semantic hash for AST-level deduplication",
    )

    # P4-05: Unified report status
    report_status: str | None = Field(
        default=None,
        description="Unified report status for external output (exploitable/conditional/informational/suppressed)",
    )

    # P6-03: Evidence strength (anti-hallucination integration)
    evidence_strength: EvidenceStrength | None = Field(
        default=None,
        description="Evidence strength based on anti-hallucination rules",
    )
    evidence_details: dict[str, Any] | None = Field(
        default=None,
        description="Detailed evidence strength calculation breakdown",
    )
    hallucination_check: HallucinationCheckResult | None = Field(
        default=None,
        description="Anti-hallucination validation result",
    )

    # P6-04: Status subtypes for fine-grained classification
    conditional_subtype: ConditionalSubtype | None = Field(
        default=None,
        description="P6-04a: Conditional status subtype (strong/weak)",
    )
    informational_subtype: InformationalSubtype | None = Field(
        default=None,
        description="P6-04b: Informational status subtype",
    )

    # P6-04c: Taint analysis report (integrated from code-audit)
    taint_analysis: dict[str, Any] | None = Field(
        default=None,
        description="P6-04c: Taint analysis report (Source/Propagation/Sink/Sanitizer)",
    )

    # P6-04d: Confidence score from verification methodology
    confidence_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="P6-04d: Confidence score (0-100) from verification methodology",
    )
    confidence_factors: list[tuple[str, int]] | None = Field(
        default=None,
        description="P6-04d: Factors contributing to confidence score",
    )

    # P6-07: Directory classification for non-production code downgrading
    directory_class: str | None = Field(
        default=None,
        description="P6-07: Directory classification (production_code/test_code/sample_code/fixture_code/challenge_code)",
    )
    score_multiplier: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="P6-07: Score multiplier based on directory class (1.0 for production, lower for non-production)",
    )

    # P9-01: CPG attack path information
    cpg_path: dict[str, Any] | None = Field(
        default=None,
        description="P9-01: Attack path information from CPG analysis (entry_point, sink, path, confidence, sanitizers, reaches_sink)",
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

    # Metadata for engine-specific information (rule gating, finding budget, etc.)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Engine-specific metadata (rule gating, finding budget, etc.)",
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
            "# Scan Report",
            "",
            f"**Source:** {self.source_path}",
            f"**Engine:** {self.engine}",
            f"**Status:** {'Success' if self.success else 'Failed'}",
            f"**Duration:** {self.duration_seconds:.2f}s" if self.duration_seconds else "",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
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
                "**Description:**",
                f"{finding.description}",
                "",
            ])

        return "\n".join(lines)
