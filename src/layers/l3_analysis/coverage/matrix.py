"""
P6-08: Coverage Matrix Data Models

Implements the language x engine x dimension x status matrix
for tracking audit coverage.

Matrix Structure:
    Language → Engine → Dimension → CoverageStatus

Usage:
    matrix = CoverageMatrix()
    matrix.set_coverage(Language.PYTHON, "semgrep", 1, CoverageStatus.COVERED)
    status = matrix.get_coverage(Language.PYTHON, "semgrep", 1)
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# =============================================================================
# Constants
# =============================================================================

# Core 10 languages supported by DeepVuln
CORE_LANGUAGES = [
    "python",
    "javascript",
    "typescript",
    "java",
    "go",
    "php",
    "ruby",
    "csharp",
    "cpp",
    "rust",
]

# Analysis engines
ALL_ENGINES = ["semgrep", "codeql", "agent"]

# Security dimensions (D1-D10)
ALL_DIMENSIONS = list(range(1, 11))  # 1-10


# =============================================================================
# Enums
# =============================================================================


class CoverageStatus(str, Enum):
    """
    Coverage status for a dimension.

    Based on code-audit coverage_matrix.md standards.
    """

    NOT_COVERED = "not_covered"
    """Dimension was not audited by any agent."""

    SHALLOW = "shallow"
    """Partial coverage - needs deeper analysis."""

    COVERED = "covered"
    """Full coverage per dimension-specific criteria."""

    NOT_APPLICABLE = "not_applicable"
    """Dimension not relevant to this project/language."""


class DimensionType(str, Enum):
    """
    Dimension type determines coverage evaluation method.

    Based on code-audit coverage_matrix.md audit strategy classification.
    """

    SINK_DRIVEN = "sink_driven"
    """
    Sink-driven dimensions (D1, D4, D5, D6).

    Coverage criteria:
    - Covered: All core sink categories searched + dataflow traced + sink fanout ≥ 30%
    - Shallow: Searched but sink categories missing / no tracing / fanout < 30%
    - Not covered: Dimension not searched by any agent
    """

    CONTROL_DRIVEN = "control_driven"
    """
    Control-driven dimensions (D3, D9).

    Coverage criteria:
    - Covered: Endpoint audit rate ≥ 50% (deep) / ≥ 30% (standard) + CRUD consistency checked
    - Shallow: Only Grep patterns, no systematic endpoint enumeration
    - Not covered: No control-driven audit performed
    """

    CONFIG_DRIVEN = "config_driven"
    """
    Config-driven dimensions (D2, D7, D8, D10).

    Coverage criteria:
    - Covered: Core config items checked + versions/algorithms compared to baseline
    - Shallow: Only partial config checked / no deep verification
    - Not covered: Dimension not checked by any agent
    """


# Mapping from dimension number to type
DIMENSION_TYPE_MAP: dict[int, DimensionType] = {
    1: DimensionType.SINK_DRIVEN,      # D1: Injection
    2: DimensionType.CONFIG_DRIVEN,    # D2: Authentication
    3: DimensionType.CONTROL_DRIVEN,   # D3: Authorization
    4: DimensionType.SINK_DRIVEN,      # D4: Deserialization
    5: DimensionType.SINK_DRIVEN,      # D5: File Operations
    6: DimensionType.SINK_DRIVEN,      # D6: SSRF
    7: DimensionType.CONFIG_DRIVEN,    # D7: Cryptography
    8: DimensionType.CONFIG_DRIVEN,    # D8: Configuration
    9: DimensionType.CONTROL_DRIVEN,   # D9: Business Logic
    10: DimensionType.CONFIG_DRIVEN,   # D10: Supply Chain
}


def get_dimension_type(dimension: int) -> DimensionType:
    """Get the type of a security dimension."""
    return DIMENSION_TYPE_MAP.get(dimension, DimensionType.CONFIG_DRIVEN)


# =============================================================================
# Models
# =============================================================================


class DimensionCoverage(BaseModel):
    """
    Coverage status for a single dimension.

    Tracks the coverage status and metrics specific to each dimension type.
    """

    dimension: int = Field(
        ...,
        ge=1,
        le=10,
        description="Security dimension number (D1-D10)",
    )
    status: CoverageStatus = Field(
        default=CoverageStatus.NOT_COVERED,
        description="Coverage status for this dimension",
    )

    # Metrics for Sink-driven dimensions
    sink_categories_searched: list[str] = Field(
        default_factory=list,
        description="Sink categories that were searched",
    )
    sink_categories_total: int = Field(
        default=0,
        description="Total sink categories applicable",
    )
    dataflow_traced: bool = Field(
        default=False,
        description="Whether dataflow analysis was performed",
    )
    sink_fanout_rate: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Sink fanout rate (sinks analyzed / total sinks)",
    )

    # Metrics for Control-driven dimensions
    endpoints_total: int = Field(
        default=0,
        description="Total endpoints identified",
    )
    endpoints_audited: int = Field(
        default=0,
        description="Endpoints that were audited",
    )
    crud_consistency_checked: bool = Field(
        default=False,
        description="Whether CRUD permission consistency was checked",
    )
    resource_types_checked: int = Field(
        default=0,
        description="Number of resource types with CRUD consistency checked",
    )

    # Metrics for Config-driven dimensions
    config_items_total: int = Field(
        default=0,
        description="Total config items to check",
    )
    config_items_checked: int = Field(
        default=0,
        description="Config items that were checked",
    )
    baseline_compared: bool = Field(
        default=False,
        description="Whether results were compared to security baseline",
    )

    # General metrics
    findings_count: int = Field(
        default=0,
        description="Number of findings in this dimension",
    )
    notes: str | None = Field(
        default=None,
        description="Additional notes about coverage",
    )

    @property
    def dimension_type(self) -> DimensionType:
        """Get the type of this dimension."""
        return get_dimension_type(self.dimension)

    @property
    def endpoint_coverage_rate(self) -> float:
        """Calculate endpoint coverage rate for control-driven dimensions."""
        if self.endpoints_total == 0:
            return 0.0
        return self.endpoints_audited / self.endpoints_total

    @property
    def config_coverage_rate(self) -> float:
        """Calculate config coverage rate for config-driven dimensions."""
        if self.config_items_total == 0:
            return 0.0
        return self.config_items_checked / self.config_items_total


class LanguageEngineCoverage(BaseModel):
    """
    Coverage for a single language and engine combination.

    Contains coverage status for all D1-D10 dimensions.
    """

    language: str = Field(
        ...,
        description="Programming language",
    )
    engine: str = Field(
        ...,
        description="Analysis engine (semgrep/codeql/agent)",
    )
    dimensions: dict[int, DimensionCoverage] = Field(
        default_factory=dict,
        description="Coverage for each dimension (D1-D10)",
    )
    enabled: bool = Field(
        default=True,
        description="Whether this language/engine combo is enabled",
    )

    def get_dimension(self, dimension: int) -> DimensionCoverage:
        """Get coverage for a specific dimension, creating if needed."""
        if dimension not in self.dimensions:
            self.dimensions[dimension] = DimensionCoverage(dimension=dimension)
        return self.dimensions[dimension]

    def set_dimension(self, coverage: DimensionCoverage) -> None:
        """Set coverage for a dimension."""
        self.dimensions[coverage.dimension] = coverage

    def get_covered_count(self) -> int:
        """Get count of covered dimensions."""
        return sum(
            1 for d in self.dimensions.values()
            if d.status == CoverageStatus.COVERED
        )

    def get_shallow_count(self) -> int:
        """Get count of shallow-covered dimensions."""
        return sum(
            1 for d in self.dimensions.values()
            if d.status == CoverageStatus.SHALLOW
        )

    def get_not_covered_count(self) -> int:
        """Get count of not-covered dimensions."""
        return sum(
            1 for d in self.dimensions.values()
            if d.status == CoverageStatus.NOT_COVERED
        )


class CoverageMatrix(BaseModel):
    """
    Full coverage matrix for all languages and engines.

    Structure: language → engine → dimension → status

    Usage:
        matrix = CoverageMatrix()
        matrix.set_coverage("python", "semgrep", 1, CoverageStatus.COVERED)
        status = matrix.get_coverage("python", "semgrep", 1)
    """

    languages: list[str] = Field(
        default_factory=lambda: CORE_LANGUAGES.copy(),
        description="Languages tracked in this matrix",
    )
    engines: list[str] = Field(
        default_factory=lambda: ALL_ENGINES.copy(),
        description="Engines tracked in this matrix",
    )
    matrix: dict[str, LanguageEngineCoverage] = Field(
        default_factory=dict,
        description="Coverage data keyed by '{language}_{engine}'",
    )

    def _get_key(self, language: str, engine: str) -> str:
        """Generate matrix key for language+engine."""
        return f"{language}_{engine}"

    def get_coverage(
        self,
        language: str,
        engine: str,
        dimension: int,
    ) -> DimensionCoverage:
        """Get coverage for a specific language/engine/dimension."""
        key = self._get_key(language, engine)
        if key not in self.matrix:
            self.matrix[key] = LanguageEngineCoverage(
                language=language,
                engine=engine,
            )
        return self.matrix[key].get_dimension(dimension)

    def set_coverage(
        self,
        language: str,
        engine: str,
        dimension: int,
        status: CoverageStatus,
        **kwargs: Any,
    ) -> None:
        """Set coverage status for a dimension."""
        key = self._get_key(language, engine)
        if key not in self.matrix:
            self.matrix[key] = LanguageEngineCoverage(
                language=language,
                engine=engine,
            )

        existing = self.matrix[key].get_dimension(dimension)
        existing.status = status

        # Update any additional fields
        for field_name, value in kwargs.items():
            if hasattr(existing, field_name):
                setattr(existing, field_name, value)

        self.matrix[key].set_dimension(existing)

    def set_dimension_coverage(
        self,
        language: str,
        engine: str,
        coverage: DimensionCoverage,
    ) -> None:
        """Set full dimension coverage object."""
        key = self._get_key(language, engine)
        if key not in self.matrix:
            self.matrix[key] = LanguageEngineCoverage(
                language=language,
                engine=engine,
            )
        self.matrix[key].set_dimension(coverage)

    def get_language_coverage(
        self,
        language: str,
    ) -> dict[str, LanguageEngineCoverage]:
        """Get all engine coverage for a language."""
        return {
            k: v for k, v in self.matrix.items()
            if v.language == language
        }

    def get_dimension_status_across_engines(
        self,
        language: str,
        dimension: int,
    ) -> dict[str, CoverageStatus]:
        """Get a dimension's status across all engines for a language."""
        result = {}
        for engine in self.engines:
            key = self._get_key(language, engine)
            if key in self.matrix:
                result[engine] = self.matrix[key].get_dimension(dimension).status
            else:
                result[engine] = CoverageStatus.NOT_COVERED
        return result

    def get_overall_coverage_rate(self) -> float:
        """
        Calculate overall coverage rate.

        Returns the percentage of covered dimensions across all
        language/engine combinations.
        """
        total = 0
        covered = 0

        for lang in self.languages:
            for engine in self.engines:
                for dim in ALL_DIMENSIONS:
                    total += 1
                    status = self.get_coverage(lang, engine, dim).status
                    if status == CoverageStatus.COVERED:
                        covered += 1

        return covered / total if total > 0 else 0.0

    def get_dimension_coverage_summary(self) -> dict[int, dict[str, int]]:
        """
        Get coverage summary per dimension.

        Returns dict mapping dimension number to status counts.
        """
        summary: dict[int, dict[str, int]] = {
            d: {"covered": 0, "shallow": 0, "not_covered": 0, "na": 0}
            for d in ALL_DIMENSIONS
        }

        for key, lec in self.matrix.items():
            for dim, coverage in lec.dimensions.items():
                if coverage.status == CoverageStatus.COVERED:
                    summary[dim]["covered"] += 1
                elif coverage.status == CoverageStatus.SHALLOW:
                    summary[dim]["shallow"] += 1
                elif coverage.status == CoverageStatus.NOT_COVERED:
                    summary[dim]["not_covered"] += 1
                else:
                    summary[dim]["na"] += 1

        return summary

    def is_audit_complete(self) -> bool:
        """
        Check if audit coverage meets minimum requirements.

        Based on code-audit coverage_matrix.md termination criteria:
        - Coverage matrix ≥ 8/10 dimensions covered
        - D1-D3 (core triangle) all covered
        """
        # Check D1-D3 coverage
        for dim in [1, 2, 3]:
            dim_covered = False
            for key, lec in self.matrix.items():
                if dim in lec.dimensions:
                    if lec.dimensions[dim].status == CoverageStatus.COVERED:
                        dim_covered = True
                        break
            if not dim_covered:
                return False

        # Check overall dimension coverage
        summary = self.get_dimension_coverage_summary()
        covered_count = sum(
            1 for d in ALL_DIMENSIONS
            if summary[d]["covered"] > 0
        )

        return covered_count >= 8

    def to_summary_dict(self) -> dict[str, Any]:
        """Generate a summary dict for reporting."""
        return {
            "languages": self.languages,
            "engines": self.engines,
            "overall_coverage_rate": self.get_overall_coverage_rate(),
            "dimension_summary": self.get_dimension_coverage_summary(),
            "audit_complete": self.is_audit_complete(),
            "matrix_entries": len(self.matrix),
        }


__all__ = [
    # Constants
    "CORE_LANGUAGES",
    "ALL_ENGINES",
    "ALL_DIMENSIONS",
    "DIMENSION_TYPE_MAP",
    # Enums
    "CoverageStatus",
    "DimensionType",
    # Functions
    "get_dimension_type",
    # Models
    "DimensionCoverage",
    "LanguageEngineCoverage",
    "CoverageMatrix",
]
