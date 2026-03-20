"""
P6-08: Coverage Evaluator

Implements coverage evaluation logic for each dimension type
based on code-audit coverage_matrix.md standards.

Dimension Types:
- Sink-driven (D1, D4, D5, D6): Coverage = sink coverage + dataflow + fanout
- Control-driven (D3, D9): Coverage = endpoint audit rate + CRUD consistency
- Config-driven (D2, D7, D8, D10): Coverage = config items checked + baseline
"""

from src.layers.l3_analysis.coverage.matrix import (
    CoverageStatus,
    DimensionCoverage,
    DimensionType,
    get_dimension_type,
)


class CoverageEvaluator:
    """
    Evaluates coverage status based on dimension-specific criteria.

    Based on code-audit coverage_matrix.md coverage standards.
    """

    # Minimum sink fanout rate for Sink-driven coverage
    MIN_SINK_FANOUT_RATE = 0.30  # 30%

    # Minimum endpoint audit rates for Control-driven coverage
    MIN_ENDPOINT_RATE_DEEP = 0.50  # 50% for deep mode
    MIN_ENDPOINT_RATE_STANDARD = 0.30  # 30% for standard mode

    # Minimum resource types for CRUD consistency check
    MIN_RESOURCE_TYPES_CHECKED = 3

    @classmethod
    def evaluate(
        cls,
        coverage: DimensionCoverage,
        audit_mode: str = "standard",
    ) -> CoverageStatus:
        """
        Evaluate coverage status for a dimension.

        Args:
            coverage: DimensionCoverage with metrics populated
            audit_mode: "quick", "standard", or "deep"

        Returns:
            Evaluated CoverageStatus
        """
        dimension_type = coverage.dimension_type

        if dimension_type == DimensionType.SINK_DRIVEN:
            return cls.evaluate_sink_driven(coverage)
        elif dimension_type == DimensionType.CONTROL_DRIVEN:
            return cls.evaluate_control_driven(coverage, audit_mode)
        elif dimension_type == DimensionType.CONFIG_DRIVEN:
            return cls.evaluate_config_driven(coverage)

        return CoverageStatus.NOT_COVERED

    @classmethod
    def evaluate_sink_driven(cls, coverage: DimensionCoverage) -> CoverageStatus:
        """
        Evaluate Sink-driven dimension coverage (D1, D4, D5, D6).

        Coverage criteria:
        - Covered: All core sink categories searched + dataflow traced + fanout ≥ 30%
        - Shallow: Searched but incomplete / no tracing / fanout < 30%
        - Not covered: Dimension not searched
        """
        # Not covered if no sinks were searched
        if not coverage.sink_categories_searched:
            return CoverageStatus.NOT_COVERED

        # Check if all sink categories were covered
        all_categories_covered = (
            coverage.sink_categories_total > 0
            and len(coverage.sink_categories_searched) >= coverage.sink_categories_total
        )

        # Check dataflow tracing
        has_dataflow = coverage.dataflow_traced

        # Check sink fanout rate
        has_sufficient_fanout = coverage.sink_fanout_rate >= cls.MIN_SINK_FANOUT_RATE

        # Full coverage requires all three
        if all_categories_covered and has_dataflow and has_sufficient_fanout:
            return CoverageStatus.COVERED

        # Shallow coverage if anything was searched
        if coverage.sink_categories_searched:
            return CoverageStatus.SHALLOW

        return CoverageStatus.NOT_COVERED

    @classmethod
    def evaluate_control_driven(
        cls,
        coverage: DimensionCoverage,
        audit_mode: str = "standard",
    ) -> CoverageStatus:
        """
        Evaluate Control-driven dimension coverage (D3, D9).

        Coverage criteria:
        - Covered: Endpoint audit rate ≥ 50% (deep) / ≥ 30% (standard)
                   + CRUD consistency checked for ≥ 3 resource types
        - Shallow: Only Grep patterns, no systematic endpoint enumeration
        - Not covered: No control-driven audit performed
        """
        # Not covered if no endpoints identified
        if coverage.endpoints_total == 0:
            return CoverageStatus.NOT_COVERED

        # Calculate endpoint coverage rate
        endpoint_rate = coverage.endpoint_coverage_rate

        # Determine minimum rate based on audit mode
        min_rate = (
            cls.MIN_ENDPOINT_RATE_DEEP
            if audit_mode == "deep"
            else cls.MIN_ENDPOINT_RATE_STANDARD
        )

        # Check if sufficient endpoints were audited
        has_sufficient_endpoints = endpoint_rate >= min_rate

        # Check CRUD consistency
        has_crud_check = (
            coverage.crud_consistency_checked
            and coverage.resource_types_checked >= cls.MIN_RESOURCE_TYPES_CHECKED
        )

        # Full coverage requires both
        if has_sufficient_endpoints and has_crud_check:
            return CoverageStatus.COVERED

        # Shallow if any endpoints were audited
        if coverage.endpoints_audited > 0:
            return CoverageStatus.SHALLOW

        return CoverageStatus.NOT_COVERED

    @classmethod
    def evaluate_config_driven(cls, coverage: DimensionCoverage) -> CoverageStatus:
        """
        Evaluate Config-driven dimension coverage (D2, D7, D8, D10).

        Coverage criteria:
        - Covered: Core config items checked + baseline compared
        - Shallow: Only partial config checked / no deep verification
        - Not covered: Dimension not checked
        """
        # Not covered if no config items to check
        if coverage.config_items_total == 0:
            return CoverageStatus.NOT_COVERED

        # Check if all config items were checked
        all_checked = (
            coverage.config_items_checked >= coverage.config_items_total
        )

        # Check baseline comparison
        has_baseline = coverage.baseline_compared

        # Full coverage requires both
        if all_checked and has_baseline:
            return CoverageStatus.COVERED

        # Shallow if any config items were checked
        if coverage.config_items_checked > 0:
            return CoverageStatus.SHALLOW

        return CoverageStatus.NOT_COVERED


# Convenience functions for direct use


def evaluate_sink_driven_coverage(coverage: DimensionCoverage) -> CoverageStatus:
    """Evaluate coverage for a Sink-driven dimension."""
    return CoverageEvaluator.evaluate_sink_driven(coverage)


def evaluate_control_driven_coverage(
    coverage: DimensionCoverage,
    audit_mode: str = "standard",
) -> CoverageStatus:
    """Evaluate coverage for a Control-driven dimension."""
    return CoverageEvaluator.evaluate_control_driven(coverage, audit_mode)


def evaluate_config_driven_coverage(coverage: DimensionCoverage) -> CoverageStatus:
    """Evaluate coverage for a Config-driven dimension."""
    return CoverageEvaluator.evaluate_config_driven(coverage)


__all__ = [
    "CoverageEvaluator",
    "evaluate_sink_driven_coverage",
    "evaluate_control_driven_coverage",
    "evaluate_config_driven_coverage",
]
