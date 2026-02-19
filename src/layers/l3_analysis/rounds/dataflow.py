"""
Dataflow Models

Data structures for tracking taint propagation and data flow analysis.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from src.layers.l3_analysis.models import CodeLocation


class SourceType(str, Enum):
    """Type of taint source."""

    HTTP_PARAM = "http_param"           # HTTP request parameter
    HTTP_HEADER = "http_header"         # HTTP header
    HTTP_BODY = "http_body"             # HTTP request body
    HTTP_COOKIE = "http_cookie"         # HTTP cookie
    FILE_INPUT = "file_input"           # File upload/input
    DATABASE = "database"               # Database query result
    ENV_VAR = "env_var"                 # Environment variable
    COMMAND_ARG = "command_arg"         # Command line argument
    RPC_PARAM = "rpc_param"             # RPC parameter
    MESSAGE_QUEUE = "message_queue"     # MQ message
    USER_INPUT = "user_input"           # Generic user input
    EXTERNAL_API = "external_api"       # External API response
    DESERIALIZATION = "deserialization"  # Deserialized object


class SinkType(str, Enum):
    """Type of sensitive sink."""

    SQL_QUERY = "sql_query"             # SQL query execution
    COMMAND_EXEC = "command_exec"       # Command execution
    FILE_WRITE = "file_write"           # File write operation
    FILE_READ = "file_read"             # File read (for path traversal)
    HTTP_REDIRECT = "http_redirect"     # HTTP redirect
    HTTP_RESPONSE = "http_response"     # HTTP response (XSS)
    LDAP_QUERY = "ldap_query"           # LDAP query
    XPATH_QUERY = "xpath_query"         # XPath query
    LOG_OUTPUT = "log_output"           # Log output (injection)
    TEMPLATE_RENDER = "template_render"  # Template rendering (SSTI)
    SERIALIZATION = "serialization"     # Serialization (unsafe)
    CRYPTO_OPERATION = "crypto_op"      # Cryptographic operation
    AUTH_CHECK = "auth_check"           # Authentication check
    ACCESS_CONTROL = "access_control"   # Access control decision


class SanitizerType(str, Enum):
    """Type of sanitizer/purification function."""

    SQL_ESCAPE = "sql_escape"           # SQL escaping
    HTML_ENCODE = "html_encode"         # HTML encoding
    URL_ENCODE = "url_encode"           # URL encoding
    COMMAND_ESCAPE = "cmd_escape"       # Command escaping
    PATH_VALIDATE = "path_validate"     # Path validation
    INPUT_VALIDATE = "input_validate"   # Input validation
    TYPE_CAST = "type_cast"             # Type casting
    WHITELIST = "whitelist"             # Whitelist filtering
    PREPARED_STMT = "prepared_stmt"     # Prepared statement
    PARAMETERIZED = "parameterized"     # Parameterized query


class TaintSource(BaseModel):
    """
    Represents a source of tainted (untrusted) data.

    A taint source is where user-controlled or external data enters
    the application.
    """

    # Identity
    id: str = Field(..., description="Unique source identifier")

    # Location
    location: CodeLocation = Field(..., description="Code location of the source")

    # Classification
    source_type: SourceType = Field(..., description="Type of taint source")
    user_controlled: bool = Field(
        default=True,
        description="Whether the data is user-controlled",
    )

    # Context
    variable_name: str | None = Field(
        default=None,
        description="Name of the variable receiving the input",
    )
    parameter_name: str | None = Field(
        default=None,
        description="HTTP/RPC parameter name if applicable",
    )
    data_format: str | None = Field(
        default=None,
        description="Format of the data (json, xml, form, etc.)",
    )

    # Risk assessment
    risk_level: str = Field(
        default="medium",
        description="Inherent risk level of this source type",
    )
    notes: str | None = Field(default=None, description="Additional notes")

    def to_prompt_context(self) -> str:
        """Generate context string for LLM prompt."""
        parts = [
            f"Source Type: {self.source_type.value}",
            f"Location: {self.location.to_display()}",
        ]
        if self.variable_name:
            parts.append(f"Variable: {self.variable_name}")
        if self.parameter_name:
            parts.append(f"Parameter: {self.parameter_name}")
        if self.user_controlled:
            parts.append("User Controlled: Yes")
        return "\n".join(parts)


class TaintSink(BaseModel):
    """
    Represents a sensitive sink where tainted data could cause harm.

    A sink is a function or operation that could be exploited if
    it receives tainted (untrusted) data.
    """

    # Identity
    id: str = Field(..., description="Unique sink identifier")

    # Location
    location: CodeLocation = Field(..., description="Code location of the sink")

    # Classification
    sink_type: SinkType = Field(..., description="Type of sensitive sink")
    dangerous_if_tainted: bool = Field(
        default=True,
        description="Whether this sink is dangerous with tainted input",
    )

    # Context
    function_name: str | None = Field(
        default=None,
        description="Function/method name at the sink",
    )
    argument_position: int | None = Field(
        default=None,
        description="Position of the vulnerable argument",
    )
    expected_type: str | None = Field(
        default=None,
        description="Expected data type at this sink",
    )

    # Vulnerability info
    vulnerability_class: list[str] = Field(
        default_factory=list,
        description="Classes of vulnerabilities possible (SQLi, XSS, etc.)",
    )
    cwe_ids: list[str] = Field(
        default_factory=list,
        description="Related CWE identifiers",
    )

    # Risk assessment
    risk_level: str = Field(
        default="high",
        description="Risk level if tainted data reaches this sink",
    )
    notes: str | None = Field(default=None, description="Additional notes")

    def to_prompt_context(self) -> str:
        """Generate context string for LLM prompt."""
        parts = [
            f"Sink Type: {self.sink_type.value}",
            f"Location: {self.location.to_display()}",
        ]
        if self.function_name:
            parts.append(f"Function: {self.function_name}")
        if self.vulnerability_class:
            parts.append(f"Vulnerability Classes: {', '.join(self.vulnerability_class)}")
        if self.dangerous_if_tainted:
            parts.append("Dangerous with Tainted Input: Yes")
        return "\n".join(parts)


class Sanitizer(BaseModel):
    """
    Represents a sanitizer that can cleanse tainted data.
    """

    # Identity
    id: str = Field(..., description="Unique sanitizer identifier")

    # Location
    location: CodeLocation = Field(..., description="Code location of the sanitizer")

    # Classification
    sanitizer_type: SanitizerType = Field(
        ...,
        description="Type of sanitization applied",
    )

    # Effectiveness
    effective: bool = Field(
        default=True,
        description="Whether this sanitizer is effective",
    )
    effectiveness_reason: str | None = Field(
        default=None,
        description="Reason for effectiveness assessment",
    )

    # Context
    function_name: str | None = Field(
        default=None,
        description="Sanitizer function name",
    )
    input_variable: str | None = Field(
        default=None,
        description="Variable being sanitized",
    )
    output_variable: str | None = Field(
        default=None,
        description="Variable receiving sanitized output",
    )


class PathNode(BaseModel):
    """
    A single node in the data flow path.
    """

    # Location
    location: CodeLocation = Field(..., description="Code location")

    # Node info
    node_type: str = Field(
        ...,
        description="Type of node (source, sink, sanitizer, propagation)",
    )
    variable_name: str | None = Field(
        default=None,
        description="Variable at this node",
    )
    expression: str | None = Field(
        default=None,
        description="Expression at this node",
    )

    # For function calls
    function_name: str | None = Field(
        default=None,
        description="Function being called (if applicable)",
    )
    is_interprocedural: bool = Field(
        default=False,
        description="Whether this involves a call to another function",
    )

    # Additional context
    notes: str | None = Field(default=None, description="Additional notes")


class DataFlowPath(BaseModel):
    """
    A complete data flow path from source to sink.

    Represents how tainted data propagates through the application
    from a source to a sensitive sink.
    """

    # Identity
    id: str = Field(..., description="Unique path identifier")
    candidate_id: str | None = Field(
        default=None,
        description="ID of the related vulnerability candidate",
    )

    # Source and Sink
    source: TaintSource = Field(..., description="The taint source")
    sink: TaintSink = Field(..., description="The sensitive sink")

    # Path
    path_nodes: list[PathNode] = Field(
        default_factory=list,
        description="Nodes along the data flow path",
    )
    path_length: int = Field(default=0, description="Number of nodes in the path")

    # Sanitizers
    sanitizers: list[Sanitizer] = Field(
        default_factory=list,
        description="Sanitizers found along the path",
    )
    has_effective_sanitizer: bool = Field(
        default=False,
        description="Whether an effective sanitizer exists",
    )

    # Completeness
    is_complete: bool = Field(
        default=False,
        description="Whether the path is complete (source reaches sink)",
    )
    is_interprocedural: bool = Field(
        default=False,
        description="Whether the path crosses function boundaries",
    )
    gaps: list[str] = Field(
        default_factory=list,
        description="Description of any gaps in the path",
    )

    # Confidence
    path_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in the path accuracy",
    )
    exploitation_likelihood: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Likelihood of exploitation",
    )

    # Analysis metadata
    analyzer: str = Field(
        default="unknown",
        description="Engine that found this path (codeql, agent, etc.)",
    )
    analysis_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this path was analyzed",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )

    def add_node(self, node: PathNode) -> None:
        """Add a node to the path."""
        self.path_nodes.append(node)
        self.path_length = len(self.path_nodes)
        if node.is_interprocedural:
            self.is_interprocedural = True

    def add_sanitizer(self, sanitizer: Sanitizer) -> None:
        """Add a sanitizer to the path."""
        self.sanitizers.append(sanitizer)
        if sanitizer.effective:
            self.has_effective_sanitizer = True

    def get_summary(self) -> str:
        """Get a one-line summary of the path."""
        source_loc = self.source.location.to_display()
        sink_loc = self.sink.location.to_display()
        sanitized = " (sanitized)" if self.has_effective_sanitizer else ""
        return f"{self.source.source_type.value} → {self.sink.sink_type.value}{sanitized}"

    def to_prompt_context(self) -> str:
        """Generate detailed context for LLM prompt."""
        lines = [
            "## Data Flow Path Analysis",
            "",
            "### Source",
            self.source.to_prompt_context(),
            "",
            "### Sink",
            self.sink.to_prompt_context(),
            "",
            f"### Path ({self.path_length} nodes)",
        ]

        for i, node in enumerate(self.path_nodes, 1):
            lines.append(f"  {i}. {node.location.to_display()}")
            if node.function_name:
                lines.append(f"     Function: {node.function_name}")
            if node.variable_name:
                lines.append(f"     Variable: {node.variable_name}")

        if self.sanitizers:
            lines.append("")
            lines.append("### Sanitizers")
            for san in self.sanitizers:
                status = "✓ Effective" if san.effective else "✗ Ineffective"
                lines.append(f"  - {san.sanitizer_type.value} at {san.location.to_display()} [{status}]")

        lines.append("")
        lines.append("### Assessment")
        lines.append(f"  Complete Path: {'Yes' if self.is_complete else 'No'}")
        lines.append(f"  Path Confidence: {self.path_confidence:.0%}")
        lines.append(f"  Exploitation Likelihood: {self.exploitation_likelihood:.0%}")

        return "\n".join(lines)


class DeepAnalysisResult(BaseModel):
    """
    Result of deep analysis on a vulnerability candidate.

    Contains detailed findings from data flow analysis and
    Agent deep audit.
    """

    # Identity
    id: str = Field(..., description="Unique result identifier")
    candidate_id: str = Field(..., description="ID of the analyzed candidate")

    # Data flow paths
    dataflow_paths: list[DataFlowPath] = Field(
        default_factory=list,
        description="Data flow paths found",
    )
    complete_paths: int = Field(default=0, description="Number of complete paths")
    sanitized_paths: int = Field(default=0, description="Number of sanitized paths")

    # Analysis results
    confirmed_vulnerability: bool = Field(
        default=False,
        description="Whether vulnerability is confirmed",
    )
    false_positive: bool = Field(
        default=False,
        description="Whether this is a false positive",
    )
    needs_manual_review: bool = Field(
        default=True,
        description="Whether manual review is needed",
    )

    # Confidence update
    original_confidence: str = Field(
        default="medium",
        description="Original confidence level",
    )
    updated_confidence: str = Field(
        default="medium",
        description="Updated confidence after deep analysis",
    )
    confidence_reason: str | None = Field(
        default=None,
        description="Reason for confidence change",
    )

    # Evidence
    code_evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Code evidence collected",
    )
    exploitability_notes: str | None = Field(
        default=None,
        description="Notes on exploitability",
    )

    # Engine results
    codeql_findings: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw CodeQL findings",
    )
    agent_findings: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw Agent findings",
    )

    # Timing
    analysis_started: datetime | None = Field(default=None)
    analysis_completed: datetime | None = Field(default=None)
    duration_seconds: float | None = Field(default=None)

    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict)

    def add_dataflow_path(self, path: DataFlowPath) -> None:
        """Add a data flow path."""
        self.dataflow_paths.append(path)
        self.complete_paths = sum(1 for p in self.dataflow_paths if p.is_complete)
        self.sanitized_paths = sum(1 for p in self.dataflow_paths if p.has_effective_sanitizer)

    def add_code_evidence(self, evidence_type: str, data: dict[str, Any]) -> None:
        """Add code evidence."""
        self.code_evidence.append({
            "type": evidence_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": data,
        })

    def update_confidence(
        self,
        new_confidence: str,
        reason: str,
    ) -> None:
        """Update confidence level."""
        self.updated_confidence = new_confidence
        self.confidence_reason = reason

    def mark_confirmed(self, reason: str) -> None:
        """Mark as confirmed vulnerability."""
        self.confirmed_vulnerability = True
        self.false_positive = False
        self.needs_manual_review = False
        self.update_confidence("high", reason)

    def mark_false_positive(self, reason: str) -> None:
        """Mark as false positive."""
        self.confirmed_vulnerability = False
        self.false_positive = True
        self.needs_manual_review = False
        self.update_confidence("low", reason)

    def get_summary(self) -> str:
        """Get result summary."""
        status = "Confirmed" if self.confirmed_vulnerability else (
            "False Positive" if self.false_positive else "Needs Review"
        )
        paths_info = f"{self.complete_paths}/{len(self.dataflow_paths)} complete paths"
        return f"[{status}] {paths_info} (confidence: {self.updated_confidence})"

    def to_prompt_context(self) -> str:
        """Generate context for LLM prompt."""
        lines = [
            "## Deep Analysis Result",
            "",
            f"Candidate ID: {self.candidate_id}",
            f"Status: {self.get_summary()}",
            "",
            f"Confidence: {self.original_confidence} → {self.updated_confidence}",
        ]

        if self.confidence_reason:
            lines.append(f"Reason: {self.confidence_reason}")

        if self.dataflow_paths:
            lines.append("")
            lines.append("### Data Flow Paths")
            for path in self.dataflow_paths:
                lines.append(f"  - {path.get_summary()}")

        if self.exploitability_notes:
            lines.append("")
            lines.append("### Exploitability Notes")
            lines.append(self.exploitability_notes)

        return "\n".join(lines)
