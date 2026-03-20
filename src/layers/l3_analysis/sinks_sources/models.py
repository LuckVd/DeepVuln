"""
P6-05: Sink and Source Data Models

Defines the structure for taint sources and dangerous sinks
based on code-audit sinks_sources.md reference.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SinkCategory(str, Enum):
    """
    Categories of dangerous sinks.

    Based on code-audit sinks_sources.md classification.
    """

    RCE = "rce"
    """Remote Code Execution - Critical severity"""

    UNSERIALIZE = "unserialize"
    """Deserialization vulnerabilities - Critical severity"""

    SQLI = "sqli"
    """SQL Injection - Critical severity"""

    SSRF = "ssrf"
    """Server-Side Request Forgery - High severity"""

    XXE = "xxe"
    """XML External Entity - High severity"""

    PATH_TRAVERSAL = "path_traversal"
    """Path Traversal / Local File Inclusion - High severity"""

    LDAP = "ldap"
    """LDAP Injection - High severity"""

    XSS = "xss"
    """Cross-Site Scripting - Medium severity"""

    REDIRECT = "redirect"
    """Open Redirect - Medium severity"""

    SSTI = "ssti"
    """Server-Side Template Injection - High severity"""


class SourceCategory(str, Enum):
    """
    Categories of taint sources (user-controllable inputs).

    Based on code-audit sinks_sources.md classification.
    """

    HTTP_PARAM = "http_param"
    """HTTP GET/POST parameters - High risk"""

    HTTP_HEADER = "http_header"
    """HTTP headers (Host, Referer, User-Agent, X-*) - High risk"""

    COOKIE = "cookie"
    """HTTP cookies - High risk"""

    FILE_UPLOAD = "file_upload"
    """Uploaded file name/content - Critical risk"""

    WEBSOCKET = "websocket"
    """WebSocket messages - High risk"""

    DATABASE = "database"
    """Database query results (second-order injection) - Medium risk"""

    FILE_READ = "file_read"
    """File content (config files, logs) - Medium risk"""

    ENVIRONMENT = "environment"
    """Environment variables - Low risk"""

    COMMAND_LINE = "command_line"
    """CLI arguments - Medium risk"""

    INTERNAL = "internal"
    """Internal function calls - Low risk"""


class SeverityMapping:
    """Maps sink categories to severity levels."""

    MAPPING: dict[SinkCategory, str] = {
        SinkCategory.RCE: "critical",
        SinkCategory.UNSERIALIZE: "critical",
        SinkCategory.SQLI: "critical",
        SinkCategory.SSRF: "high",
        SinkCategory.XXE: "high",
        SinkCategory.PATH_TRAVERSAL: "high",
        SinkCategory.LDAP: "high",
        SinkCategory.SSTI: "high",
        SinkCategory.XSS: "medium",
        SinkCategory.REDIRECT: "medium",
    }

    @classmethod
    def get_severity(cls, category: SinkCategory) -> str:
        """Get severity level for a sink category."""
        return cls.MAPPING.get(category, "medium")


class SinkDefinition(BaseModel):
    """
    Definition of a dangerous sink function.

    A sink is a function that executes dangerous operations
    with potentially tainted data.
    """

    # Identity
    name: str = Field(..., description="Sink function name pattern")
    category: SinkCategory = Field(..., description="Sink category")
    language: str = Field(..., description="Programming language")

    # Pattern matching
    function_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns to match the sink function",
    )
    class_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns to match the containing class",
    )

    # Classification
    severity: str = Field(
        default="medium",
        description="Severity level (critical/high/medium/low)",
    )
    cwe: str = Field(..., description="CWE identifier (e.g., 'CWE-89')")
    owasp: str | None = Field(
        default=None,
        description="OWASP category (e.g., 'A03:2021')",
    )

    # Documentation
    description: str = Field(..., description="Description of the vulnerability")
    impact: str | None = Field(
        default=None,
        description="Potential impact if exploited",
    )

    # Mitigation
    effective_sanitizers: list[str] = Field(
        default_factory=list,
        description="Functions/methods that effectively sanitize this sink",
    )
    safe_alternatives: list[str] = Field(
        default_factory=list,
        description="Safe alternative functions to use",
    )

    # Detection hints
    confidence: str = Field(
        default="medium",
        description="Default confidence for pattern matches",
    )
    requires_dataflow: bool = Field(
        default=False,
        description="Whether dataflow analysis is required for accurate detection",
    )

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )

    def model_post_init(self, __context: Any) -> None:
        """Auto-fill severity from category if not specified."""
        if self.severity == "medium":
            self.severity = SeverityMapping.get_severity(self.category)


class SourceDefinition(BaseModel):
    """
    Definition of a taint source function.

    A source is a function that introduces user-controllable data
    into the application.
    """

    # Identity
    name: str = Field(..., description="Source function name pattern")
    category: SourceCategory = Field(..., description="Source category")
    language: str = Field(..., description="Programming language")

    # Pattern matching
    function_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns to match the source function",
    )
    annotation_patterns: list[str] = Field(
        default_factory=list,
        description="Annotation patterns that mark sources (e.g., @RequestParam)",
    )
    variable_patterns: list[str] = Field(
        default_factory=list,
        description="Variable patterns for implicit sources (e.g., $_GET)",
    )

    # Classification
    risk_level: str = Field(
        default="high",
        description="Risk level (critical/high/medium/low)",
    )
    controllability: str = Field(
        default="full",
        description="Attacker control level (full/partial/conditional/none)",
    )

    # Documentation
    description: str = Field(..., description="Description of the source")
    example: str | None = Field(
        default=None,
        description="Example code showing the source",
    )

    # Entry point info
    is_entry_point: bool = Field(
        default=True,
        description="Whether this source marks an entry point",
    )
    requires_auth: bool = Field(
        default=False,
        description="Whether authentication is typically required",
    )

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )


class SinkLibrary(BaseModel):
    """
    Collection of sink definitions for a specific language.
    """

    language: str = Field(..., description="Programming language")
    sinks: list[SinkDefinition] = Field(
        default_factory=list,
        description="List of sink definitions",
    )

    def get_by_category(self, category: SinkCategory) -> list[SinkDefinition]:
        """Get all sinks of a specific category."""
        return [s for s in self.sinks if s.category == category]

    def get_patterns(self) -> list[str]:
        """Get all function patterns for regex matching."""
        patterns = []
        for sink in self.sinks:
            patterns.extend(sink.function_patterns)
        return patterns


class SourceLibrary(BaseModel):
    """
    Collection of source definitions for a specific language.
    """

    language: str = Field(..., description="Programming language")
    sources: list[SourceDefinition] = Field(
        default_factory=list,
        description="List of source definitions",
    )

    def get_by_category(self, category: SourceCategory) -> list[SourceDefinition]:
        """Get all sources of a specific category."""
        return [s for s in self.sources if s.category == category]

    def get_patterns(self) -> list[str]:
        """Get all function patterns for regex matching."""
        patterns = []
        for source in self.sources:
            patterns.extend(source.function_patterns)
            patterns.extend(source.annotation_patterns)
            patterns.extend(source.variable_patterns)
        return patterns


__all__ = [
    "SinkCategory",
    "SourceCategory",
    "SeverityMapping",
    "SinkDefinition",
    "SourceDefinition",
    "SinkLibrary",
    "SourceLibrary",
]
