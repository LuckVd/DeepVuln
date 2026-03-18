"""
P6-04c: Taint Analysis Report Module

Integrated from code-audit/references/core/taint_analysis.md.
Provides standardized taint analysis report format for vulnerability findings.

Taint Analysis Flow:
    Source ──→ Propagation ──→ Sanitizer? ──→ Sink
    (污点源)    (传播路径)      (净化检查)     (汇聚点)
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    """Types of taint sources (user-controllable inputs)."""

    HTTP_PARAM = "http_param"
    HTTP_HEADER = "http_header"
    COOKIE = "cookie"
    FILE_UPLOAD = "file_upload"
    DATABASE = "database"
    ENVIRONMENT = "environment"
    COMMAND_LINE = "command_line"
    INTERNAL = "internal"


class Controllability(str, Enum):
    """Level of control an attacker has over the tainted data."""

    FULL = "full"              # Completely controllable by attacker
    PARTIAL = "partial"        # Partially controllable (some restrictions)
    CONDITIONAL = "conditional"  # Requires specific conditions
    INDIRECT = "indirect"      # Indirectly controllable (via other data)
    NONE = "none"              # Not controllable by attacker


class SinkType(str, Enum):
    """Types of dangerous sinks."""

    SQL_EXEC = "sql_exec"
    COMMAND_EXEC = "command_exec"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    TEMPLATE_RENDER = "template_render"
    DESERIALIZE = "deserialize"
    NETWORK_REQUEST = "network_request"
    LOG_OUTPUT = "log_output"


class SanitizerType(str, Enum):
    """Types of sanitization measures."""

    INPUT_VALIDATION = "input_validation"
    OUTPUT_ENCODING = "output_encoding"
    PARAMETERIZED_QUERY = "parameterized_query"
    ALLOWLIST = "allowlist"
    TYPE_CONVERSION = "type_conversion"


class TaintSource(BaseModel):
    """
    P6-04c: Taint source information.

    Represents where untrusted data enters the system.
    """

    location: str = Field(
        ...,
        description="Source location (file:line)",
    )
    source_type: SourceType = Field(
        ...,
        description="Type of taint source",
    )
    code_snippet: str | None = Field(
        default=None,
        description="Code snippet where taint enters",
    )
    variable_name: str | None = Field(
        default=None,
        description="Variable that receives tainted data",
    )
    controllability: Controllability = Field(
        default=Controllability.FULL,
        description="Attacker control level over the source",
    )
    entry_point: str | None = Field(
        default=None,
        description="Entry point (e.g., URL endpoint, API method)",
    )
    auth_required: bool = Field(
        default=False,
        description="Whether authentication is required",
    )


class PropagationStep(BaseModel):
    """
    Single step in the taint propagation path.
    """

    location: str = Field(..., description="Step location (file:line)")
    code_snippet: str | None = Field(default=None, description="Code at this step")
    operation: str = Field(..., description="Operation type (assignment/call/return/concat)")
    from_var: str | None = Field(default=None, description="Source variable")
    to_var: str | None = Field(default=None, description="Target variable")
    function_call: str | None = Field(default=None, description="Function called if applicable")
    preserves_taint: bool = Field(default=True, description="Whether taint is preserved")


class TaintPropagation(BaseModel):
    """
    P6-04c: Taint propagation path.

    Tracks how tainted data flows from source to sink.
    """

    steps: list[PropagationStep] = Field(
        default_factory=list,
        description="List of propagation steps",
    )
    total_span_lines: int = Field(
        default=0,
        description="Total lines of code spanned",
    )
    intermediate_vars: list[str] = Field(
        default_factory=list,
        description="Intermediate variable names",
    )
    cross_function_calls: list[str] = Field(
        default_factory=list,
        description="Function calls traversed",
    )
    cross_file_transitions: list[tuple[str, str]] = Field(
        default_factory=list,
        description="File transitions (from_file, to_file)",
    )

    def add_step(self, step: PropagationStep) -> None:
        """Add a propagation step."""
        self.steps.append(step)

    def get_summary(self) -> str:
        """Get a one-line summary of the propagation."""
        return f"{len(self.steps)} steps, {len(self.cross_function_calls)} function calls"


class TaintSink(BaseModel):
    """
    P6-04c: Sink (dangerous operation) information.

    Represents where tainted data is used in a dangerous operation.
    """

    location: str = Field(..., description="Sink location (file:line)")
    sink_type: SinkType = Field(..., description="Type of dangerous sink")
    code_snippet: str | None = Field(default=None, description="Code at the sink")
    function_name: str | None = Field(default=None, description="Dangerous function called")
    argument_position: int | None = Field(default=None, description="Which argument is tainted")
    impact: str | None = Field(default=None, description="Potential impact if exploited")

    # Slot type classification (from taint_analysis.md)
    slot_type: str | None = Field(
        default=None,
        description="Slot type (SQL-val/SQL-ident/CMD-argument/FILE-path/etc.)",
    )


class SanitizerCheck(BaseModel):
    """
    P6-04c: Sanitization effectiveness check.

    Evaluates whether sanitization measures are effective.
    """

    location: str | None = Field(default=None, description="Where sanitization occurs")
    sanitizer_type: SanitizerType | None = Field(
        default=None,
        description="Type of sanitization",
    )
    code_snippet: str | None = Field(default=None, description="Sanitization code")
    effective: bool = Field(
        default=False,
        description="Whether sanitization is effective",
    )
    bypass_methods: list[str] = Field(
        default_factory=list,
        description="Known bypass methods if not effective",
    )

    # Detailed checks
    input_validation_type: str | None = Field(
        default=None,
        description="Type of input validation (none/allowlist/blocklist/regex)",
    )
    encoding_type: str | None = Field(
        default=None,
        description="Type of encoding (none/html/url/sql)",
    )
    type_conversion: str | None = Field(
        default=None,
        description="Type conversion applied (none/int/length)",
    )


class TaintAnalysisReport(BaseModel):
    """
    P6-04c: Complete taint analysis report.

    Standardized report format for taint-based vulnerability analysis.
    Integrates with code-audit taint_analysis.md template.
    """

    # Identity
    vuln_id: str = Field(..., description="Vulnerability identifier")
    vuln_type: str = Field(..., description="Vulnerability type (SQL injection, XSS, etc.)")
    severity: str = Field(..., description="Severity level")
    cwe: str | None = Field(default=None, description="CWE identifier")

    # Taint analysis components
    source: TaintSource = Field(..., description="Taint source")
    propagation: TaintPropagation = Field(..., description="Propagation path")
    sink: TaintSink = Field(..., description="Dangerous sink")
    sanitizer: SanitizerCheck | None = Field(
        default=None,
        description="Sanitization check (if any)",
    )

    # Analysis conclusions
    exploitability_assessment: Controllability = Field(
        ...,
        description="Overall exploitability assessment",
    )
    attack_vector: str | None = Field(
        default=None,
        description="Example attack vector/payload",
    )
    poc_steps: list[str] | None = Field(
        default=None,
        description="Proof-of-concept steps",
    )

    # Fix recommendations
    fix_suggestion: str | None = Field(
        default=None,
        description="Suggested fix",
    )
    fix_code: str | None = Field(
        default=None,
        description="Example fix code",
    )

    # References
    references: list[str] = Field(
        default_factory=list,
        description="Reference URLs",
    )

    def to_markdown(self) -> str:
        """
        Generate Markdown format report.

        Follows the template from code-audit taint_analysis.md.
        """
        lines = [
            f"## [{self.severity.upper()}] {self.vuln_type} - {self.sink.location}",
            "",
            "### 基本信息",
            "| 属性 | 值 |",
            "|------|-----|",
            f"| 漏洞类型 | {self.vuln_type} |",
            f"| 严重程度 | {self.severity} |",
        ]
        if self.cwe:
            lines.append(f"| CWE编号 | {self.cwe} |")

        # Source section
        lines.extend([
            "",
            "---",
            "",
            "### Source (污点源)",
            "",
            f"**位置**: `{self.source.location}`",
            "",
            f"**类型**: {self.source.source_type.value}",
            "",
        ])
        if self.source.code_snippet:
            lines.extend([
                "**代码**:",
                f"```",
                self.source.code_snippet,
                "```",
                "",
            ])
        lines.append(f"**可控性**: {self.source.controllability.value}")

        # Propagation section
        lines.extend([
            "",
            "---",
            "",
            "### Taint Propagation (污点传播路径)",
            "",
            "```",
        ])
        for i, step in enumerate(self.propagation.steps, 1):
            lines.append(f"[步骤{i}] {step.location}")
            if step.code_snippet:
                lines.append(f"        代码: {step.code_snippet}")
            lines.append(f"        操作: {step.operation}")
            if i < len(self.propagation.steps):
                lines.append("        ↓")
        lines.extend([
            "```",
            "",
            f"**传播链摘要**: {self.propagation.get_summary()}",
        ])

        # Sink section
        lines.extend([
            "",
            "---",
            "",
            "### Sink (汇聚点)",
            "",
            f"**位置**: `{self.sink.location}`",
            "",
            f"**类型**: {self.sink.sink_type.value}",
            "",
        ])
        if self.sink.code_snippet:
            lines.extend([
                "**代码**:",
                "```",
                self.sink.code_snippet,
                "```",
                "",
            ])
        if self.sink.impact:
            lines.append(f"**危害**: {self.sink.impact}")

        # Sanitizer section
        if self.sanitizer:
            lines.extend([
                "",
                "---",
                "",
                "### Sanitizer (净化检查)",
                "",
                f"**有效性**: {'✓ 有效' if self.sanitizer.effective else '✗ 无效'}",
                "",
            ])
            if self.sanitizer.bypass_methods:
                lines.extend([
                    "**绕过方法**:",
                    *[f"- {m}" for m in self.sanitizer.bypass_methods],
                    "",
                ])

        # Attack vector
        if self.attack_vector:
            lines.extend([
                "---",
                "",
                "### Attack Vector (攻击向量)",
                "```",
                self.attack_vector,
                "```",
                "",
            ])

        # Fix suggestion
        if self.fix_suggestion:
            lines.extend([
                "---",
                "",
                "### Fix Suggestion (修复建议)",
                self.fix_suggestion,
                "",
            ])
            if self.fix_code:
                lines.extend([
                    "```",
                    self.fix_code,
                    "```",
                    "",
                ])

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage in Finding.taint_analysis."""
        return {
            "vuln_id": self.vuln_id,
            "vuln_type": self.vuln_type,
            "source": self.source.model_dump(),
            "propagation": {
                "steps": [s.model_dump() for s in self.propagation.steps],
                "total_span_lines": self.propagation.total_span_lines,
                "cross_function_calls": self.propagation.cross_function_calls,
            },
            "sink": self.sink.model_dump(),
            "sanitizer": self.sanitizer.model_dump() if self.sanitizer else None,
            "exploitability_assessment": self.exploitability_assessment.value,
            "attack_vector": self.attack_vector,
        }


def build_taint_report_from_finding(
    finding: Any,
    dataflow_path: list[dict[str, Any]] | None = None,
    sanitizer_info: dict[str, Any] | None = None,
) -> TaintAnalysisReport | None:
    """
    Build a TaintAnalysisReport from a Finding and additional context.

    Args:
        finding: Finding object with location, metadata, etc.
        dataflow_path: Optional dataflow path from analysis
        sanitizer_info: Optional sanitizer check information

    Returns:
        TaintAnalysisReport or None if insufficient data
    """
    if not hasattr(finding, "location"):
        return None

    # Build source from metadata or default
    source_info = getattr(finding, "metadata", {}).get("source_info", {})
    source = TaintSource(
        location=source_info.get("location", f"{finding.location.file}:?"),
        source_type=SourceType(source_info.get("type", "http_param")),
        controllability=Controllability(
            source_info.get("controllability", "full")
        ),
        code_snippet=source_info.get("code_snippet"),
        entry_point=source_info.get("entry_point"),
    )

    # Build propagation from dataflow path
    propagation = TaintPropagation()
    if dataflow_path:
        for step_data in dataflow_path:
            step = PropagationStep(
                location=step_data.get("location", "unknown"),
                code_snippet=step_data.get("code"),
                operation=step_data.get("operation", "unknown"),
                from_var=step_data.get("from_var"),
                to_var=step_data.get("to_var"),
            )
            propagation.add_step(step)

    # Build sink from finding location
    sink_type = SinkType.SQL_EXEC  # Default, should be inferred from rule
    if hasattr(finding, "rule_id") and finding.rule_id:
        if "xss" in finding.rule_id.lower():
            sink_type = SinkType.TEMPLATE_RENDER
        elif "rce" in finding.rule_id.lower() or "command" in finding.rule_id.lower():
            sink_type = SinkType.COMMAND_EXEC
        elif "path" in finding.rule_id.lower() or "traversal" in finding.rule_id.lower():
            sink_type = SinkType.FILE_READ

    sink = TaintSink(
        location=finding.location.to_display(),
        sink_type=sink_type,
        code_snippet=finding.location.snippet,
        impact=finding.description if hasattr(finding, "description") else None,
    )

    # Build sanitizer check
    sanitizer = None
    if sanitizer_info:
        sanitizer = SanitizerCheck(
            location=sanitizer_info.get("location"),
            sanitizer_type=SanitizerType(
                sanitizer_info.get("type", "input_validation")
            ) if sanitizer_info.get("type") else None,
            effective=sanitizer_info.get("effective", False),
            bypass_methods=sanitizer_info.get("bypass_methods", []),
        )

    return TaintAnalysisReport(
        vuln_id=finding.id,
        vuln_type=finding.title if hasattr(finding, "title") else "Unknown",
        severity=finding.severity.value if hasattr(finding, "severity") else "medium",
        cwe=finding.cwe if hasattr(finding, "cwe") else None,
        source=source,
        propagation=propagation,
        sink=sink,
        sanitizer=sanitizer,
        exploitability_assessment=Controllability.FULL,
        fix_suggestion=finding.fix_suggestion if hasattr(finding, "fix_suggestion") else None,
    )


__all__ = [
    "SourceType",
    "Controllability",
    "SinkType",
    "SanitizerType",
    "TaintSource",
    "PropagationStep",
    "TaintPropagation",
    "TaintSink",
    "SanitizerCheck",
    "TaintAnalysisReport",
    "build_taint_report_from_finding",
]
