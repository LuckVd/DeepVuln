"""Data models for build configuration security analysis."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SecurityRisk(str, Enum):
    """Security risk levels for findings."""

    CRITICAL = "critical"  # Hardcoded secrets, sensitive data exposure
    HIGH = "high"  # Insecure configuration, exposed signing configs
    MEDIUM = "medium"  # Missing security hardening
    LOW = "low"  # Information disclosure, best practices
    INFO = "info"  # Informational only


class FindingCategory(str, Enum):
    """Categories for security findings."""

    SECRETS = "secrets"  # Hardcoded secrets, API keys
    MAVEN_CONFIG = "maven_config"  # Maven configuration issues
    GRADLE_CONFIG = "gradle_config"  # Gradle configuration issues
    PYTHON_CONFIG = "python_config"  # Python build configuration
    DOCKERFILE = "dockerfile"  # Dockerfile security issues
    CI_CD = "ci_cd"  # CI/CD pipeline security
    DEPENDENCY = "dependency"  # Dependency-related issues
    GENERAL = "general"  # General configuration issues


class SecurityFinding(BaseModel):
    """Represents a security finding in build configuration."""

    category: FindingCategory
    risk_level: SecurityRisk
    title: str = Field(..., description="Short title of the finding")
    description: str = Field(..., description="Detailed description")
    file_path: str = Field(..., description="Path to the file containing the finding")
    line_start: int | None = Field(default=None, description="Starting line number")
    line_end: int | None = Field(default=None, description="Ending line number")
    evidence: str | None = Field(default=None, description="Code snippet or value")
    recommendation: str = Field(..., description="How to fix the issue")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    cwe: str | None = Field(default=None, description="CWE identifier if applicable")

    def __hash__(self) -> int:
        return hash((self.category, self.title, self.file_path, self.line_start))


class MavenPluginInfo(BaseModel):
    """Information about a Maven plugin."""

    group_id: str
    artifact_id: str
    version: str | None = None
    configuration: dict[str, Any] = Field(default_factory=dict)
    executions: list[dict[str, Any]] = Field(default_factory=list)
    source_file: str | None = None
    line_number: int | None = None


class MavenProfileInfo(BaseModel):
    """Information about a Maven profile."""

    id: str
    activation: dict[str, Any] | None = None
    properties: dict[str, str] = Field(default_factory=dict)
    plugins: list[MavenPluginInfo] = Field(default_factory=list)
    dependencies: list[dict[str, Any]] = Field(default_factory=list)
    source_file: str | None = None


class MavenModuleInfo(BaseModel):
    """Information about a Maven module in multi-module project."""

    name: str
    path: str
    parent: str | None = None
    properties: dict[str, str] = Field(default_factory=dict)
    source_file: str | None = None


class GradleSigningConfig(BaseModel):
    """Information about Gradle signing configuration."""

    name: str
    store_file: str | None = None
    store_password: str | None = None
    key_alias: str | None = None
    key_password: str | None = None
    has_hardcoded_passwords: bool = False
    source_file: str | None = None
    line_number: int | None = None


class GradleBuildType(BaseModel):
    """Information about Gradle build type."""

    name: str
    is_debuggable: bool = False
    minify_enabled: bool = False
    shrink_resources: bool = False
    proguard_files: list[str] = Field(default_factory=list)
    source_file: str | None = None


class DockerfileIssue(BaseModel):
    """Information about Dockerfile security issue."""

    instruction: str
    line_number: int
    issue_type: str
    details: str
    source_file: str | None = None


class CICDSecret(BaseModel):
    """Information about secrets found in CI/CD configuration."""

    name: str
    value: str | None = None
    is_encrypted: bool = False
    is_masked: bool = False
    location: str  # e.g., "env.ENV_NAME" or "secrets.SECRET_NAME"
    source_file: str | None = None
    line_number: int | None = None


class BuildConfigReport(BaseModel):
    """Complete report of build configuration security analysis."""

    source_path: str = Field(..., description="Analyzed source path")
    findings: list[SecurityFinding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict, description="Count by risk level")
    scanned_files: list[str] = Field(default_factory=list)
    scan_errors: list[str] = Field(default_factory=list)

    # Detailed breakdown
    maven_plugins: list[MavenPluginInfo] = Field(default_factory=list)
    maven_profiles: list[MavenProfileInfo] = Field(default_factory=list)
    maven_modules: list[MavenModuleInfo] = Field(default_factory=list)
    gradle_signing_configs: list[GradleSigningConfig] = Field(default_factory=list)
    gradle_build_types: list[GradleBuildType] = Field(default_factory=list)

    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a security finding to the report."""
        self.findings.append(finding)

        # Update summary
        risk_key = finding.risk_level.value
        self.summary[risk_key] = self.summary.get(risk_key, 0) + 1

    def get_critical_findings(self) -> list[SecurityFinding]:
        """Get all critical findings."""
        return [f for f in self.findings if f.risk_level == SecurityRisk.CRITICAL]

    def get_findings_by_category(self, category: FindingCategory) -> list[SecurityFinding]:
        """Get findings filtered by category."""
        return [f for f in self.findings if f.category == category]

    def get_total_risk_score(self) -> int:
        """Calculate total risk score (weighted sum)."""
        weights = {
            SecurityRisk.CRITICAL: 100,
            SecurityRisk.HIGH: 50,
            SecurityRisk.MEDIUM: 20,
            SecurityRisk.LOW: 5,
            SecurityRisk.INFO: 1,
        }
        return sum(weights.get(f.risk_level, 0) for f in self.findings)
