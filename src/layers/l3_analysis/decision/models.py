"""
Data models for CodeQL language decision.

This module defines the data structures used for LLM-driven CodeQL language selection,
including language structure, build difficulty, attack surface summaries, and decision results.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class BuildDifficultyLevel(str, Enum):
    """Build difficulty levels for CodeQL database creation."""

    EASY = "easy"          # Python, JS/TS - no build required
    MEDIUM = "medium"      # Java, Go - standard build systems
    HARD = "hard"          # C/C++ - complex build systems
    UNKNOWN = "unknown"    # Cannot determine


class LanguageStructure(BaseModel):
    """Language structure information for decision input."""

    name: str = Field(..., description="Language name (e.g., 'java', 'python')")
    file_count: int = Field(default=0, ge=0, description="Total number of source files")
    line_count: int = Field(default=0, ge=0, description="Total lines of code")
    percentage: float = Field(default=0.0, ge=0.0, le=100.0, description="Percentage of total LOC")
    role: str = Field(default="secondary", description="Role: 'primary' or 'secondary'")


class BuildDifficulty(BaseModel):
    """Build difficulty assessment for a language."""

    level: BuildDifficultyLevel = Field(
        default=BuildDifficultyLevel.UNKNOWN,
        description="Difficulty level",
    )
    estimated_time_seconds: int = Field(
        default=0,
        ge=0,
        description="Estimated time for CodeQL database creation (seconds)",
    )
    has_build_config: bool = Field(
        default=False,
        description="Whether build configuration files exist",
    )
    blockers: list[str] = Field(
        default_factory=list,
        description="List of blocking factors",
    )
    build_signals: list[str] = Field(
        default_factory=list,
        description="Detected build system signals (e.g., 'pom.xml', 'go.mod')",
    )


class AttackSurfaceSummary(BaseModel):
    """Summary of attack surface analysis for decision input."""

    entry_points_by_language: dict[str, int] = Field(
        default_factory=dict,
        description="Entry point count per language",
    )
    sensitive_data_flows: list[str] = Field(
        default_factory=list,
        description="Identified sensitive data flow patterns",
    )
    external_dependencies: list[str] = Field(
        default_factory=list,
        description="External dependency identifiers",
    )
    total_endpoints: int = Field(default=0, ge=0, description="Total HTTP/Web endpoints")


class SemgrepSummary(BaseModel):
    """Summary of Semgrep scan results for decision input."""

    findings_by_language: dict[str, dict[str, int]] = Field(
        default_factory=dict,
        description="Finding counts by language and severity. "
        "Format: {'java': {'critical': 0, 'high': 3, 'medium': 8, 'low': 2}}",
    )
    total_findings: int = Field(default=0, ge=0, description="Total findings across all languages")


class ModuleSummary(BaseModel):
    """Summary of a module/subproject for monorepo awareness."""

    name: str = Field(..., description="Module name")
    path: str = Field(..., description="Module path relative to repo root")
    primary_language: str = Field(..., description="Primary language of this module")
    languages: list[str] = Field(default_factory=list, description="All languages in this module")
    build_signals: list[str] = Field(
        default_factory=list,
        description="Build system signals detected in this module",
    )
    loc_estimate: int = Field(default=0, ge=0, description="Estimated lines of code")


class DecisionConstraints(BaseModel):
    """Constraints for language decision."""

    max_languages: int = Field(default=3, ge=1, le=10, description="Maximum languages to scan")
    max_time_budget_seconds: int = Field(
        default=1800,  # 30 minutes
        ge=300,
        le=7200,
        description="Maximum total time budget in seconds",
    )
    min_confidence: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Minimum confidence threshold for LLM decision",
    )
    llm_timeout_seconds: int = Field(
        default=30,
        ge=10,
        le=120,
        description="Timeout for LLM decision call",
    )
    fallback_strategy: str = Field(
        default="hybrid",
        description="Fallback strategy: 'primary-language', 'attack-surface', or 'hybrid'",
    )


class LanguageDecisionInput(BaseModel):
    """Complete input for LLM language decision."""

    languages: list[LanguageStructure] = Field(
        default_factory=list,
        description="Language structure information",
    )
    modules: list[ModuleSummary] = Field(
        default_factory=list,
        description="Module/subproject summaries",
    )
    attack_surface: AttackSurfaceSummary = Field(
        default_factory=AttackSurfaceSummary,
        description="Attack surface summary",
    )
    semgrep_result: SemgrepSummary | None = Field(
        default=None,
        description="Semgrep scan results (optional)",
    )
    build_difficulties: dict[str, BuildDifficulty] = Field(
        default_factory=dict,
        description="Build difficulty per language",
    )
    constraints: DecisionConstraints = Field(
        default_factory=DecisionConstraints,
        description="Decision constraints",
    )
    project_path: str = Field(default="", description="Path to the project being analyzed")

    def get_codeql_supported_languages(self) -> list[str]:
        """Get list of CodeQL-supported languages present in the project."""
        codeql_supported = {
            "python", "javascript", "typescript", "java", "go",
            "csharp", "cpp", "ruby", "swift", "kotlin", "scala",
        }
        return [lang.name.lower() for lang in self.languages if lang.name.lower() in codeql_supported]


class LanguageRecommendation(BaseModel):
    """Recommendation for a single language."""

    language: str = Field(..., description="Language name")
    priority_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Priority score (0.0-1.0)",
    )
    reasoning: str = Field(default="", description="Reasoning for this recommendation")
    estimated_time_seconds: int = Field(default=0, ge=0, description="Estimated scan time")


class SkippedLanguage(BaseModel):
    """Information about a skipped language."""

    language: str = Field(..., description="Language name")
    reason: str = Field(default="", description="Reason for skipping")


class LanguageDecision(BaseModel):
    """LLM decision result for CodeQL language selection."""

    recommended_languages: list[str] = Field(
        default_factory=list,
        description="List of recommended languages in priority order",
    )
    recommendations: list[LanguageRecommendation] = Field(
        default_factory=list,
        description="Detailed recommendations per language",
    )
    skipped_languages: list[str] = Field(
        default_factory=list,
        description="Languages that were skipped",
    )
    skip_reasons: dict[str, str] = Field(
        default_factory=dict,
        description="Reasons for skipping each language",
    )
    estimated_total_time: str = Field(
        default="",
        description="Human-readable estimated total time",
    )
    estimated_total_seconds: int = Field(
        default=0,
        ge=0,
        description="Estimated total time in seconds",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence level of this decision",
    )
    time_budget_applied: bool = Field(
        default=False,
        description="Whether time budget constraint was applied",
    )
    decision_source: str = Field(
        default="llm",
        description="Source of decision: 'llm', 'baseline', or 'fallback'",
    )
    reasoning_summary: str = Field(
        default="",
        description="Overall reasoning for the decision",
    )

    def get_priority_score(self, language: str) -> float:
        """Get priority score for a specific language."""
        for rec in self.recommendations:
            if rec.language.lower() == language.lower():
                return rec.priority_score
        return 0.0

    def get_reasoning(self, language: str) -> str:
        """Get reasoning for a specific language."""
        for rec in self.recommendations:
            if rec.language.lower() == language.lower():
                return rec.reasoning
        return self.skip_reasons.get(language, "")


class DecisionError(BaseModel):
    """Error information for failed decisions."""

    error_type: str = Field(..., description="Type of error")
    message: str = Field(..., description="Error message")
    fallback_used: bool = Field(default=False, description="Whether fallback was applied")
    fallback_decision: LanguageDecision | None = Field(
        default=None,
        description="Fallback decision if applied",
    )
