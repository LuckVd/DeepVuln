"""
P6-08: Coverage Matrix Tests

Tests for the coverage matrix data structures and evaluation logic.
"""

import pytest

from src.layers.l3_analysis.coverage.matrix import (
    CoverageStatus,
    DimensionType,
    DimensionCoverage,
    LanguageEngineCoverage,
    CoverageMatrix,
    CORE_LANGUAGES,
    ALL_ENGINES,
    ALL_DIMENSIONS,
    get_dimension_type,
    DIMENSION_TYPE_MAP,
)
from src.layers.l3_analysis.coverage.evaluator import (
    CoverageEvaluator,
    evaluate_sink_driven_coverage,
    evaluate_control_driven_coverage,
    evaluate_config_driven_coverage,
)


class TestConstants:
    """Test module constants."""

    def test_core_languages_count(self):
        """Verify we have 10 core languages."""
        assert len(CORE_LANGUAGES) == 10

    def test_core_languages_content(self):
        """Verify core languages include expected values."""
        assert "python" in CORE_LANGUAGES
        assert "java" in CORE_LANGUAGES
        assert "go" in CORE_LANGUAGES
        assert "javascript" in CORE_LANGUAGES
        assert "typescript" in CORE_LANGUAGES

    def test_all_engines_count(self):
        """Verify we have 3 engines."""
        assert len(ALL_ENGINES) == 3

    def test_all_engines_content(self):
        """Verify engines include expected values."""
        assert "semgrep" in ALL_ENGINES
        assert "codeql" in ALL_ENGINES
        assert "agent" in ALL_ENGINES

    def test_all_dimensions_count(self):
        """Verify we have 10 dimensions."""
        assert len(ALL_DIMENSIONS) == 10

    def test_all_dimensions_range(self):
        """Verify dimensions are 1-10."""
        assert ALL_DIMENSIONS == list(range(1, 11))


class TestCoverageStatusEnum:
    """Test CoverageStatus enum."""

    def test_not_covered_exists(self):
        """Verify NOT_COVERED status exists."""
        assert CoverageStatus.NOT_COVERED.value == "not_covered"

    def test_shallow_exists(self):
        """Verify SHALLOW status exists."""
        assert CoverageStatus.SHALLOW.value == "shallow"

    def test_covered_exists(self):
        """Verify COVERED status exists."""
        assert CoverageStatus.COVERED.value == "covered"

    def test_not_applicable_exists(self):
        """Verify NOT_APPLICABLE status exists."""
        assert CoverageStatus.NOT_APPLICABLE.value == "not_applicable"


class TestDimensionTypeEnum:
    """Test DimensionType enum."""

    def test_sink_driven_exists(self):
        """Verify SINK_DRIVEN type exists."""
        assert DimensionType.SINK_DRIVEN.value == "sink_driven"

    def test_control_driven_exists(self):
        """Verify CONTROL_DRIVEN type exists."""
        assert DimensionType.CONTROL_DRIVEN.value == "control_driven"

    def test_config_driven_exists(self):
        """Verify CONFIG_DRIVEN type exists."""
        assert DimensionType.CONFIG_DRIVEN.value == "config_driven"

    def test_dimension_type_map_sink_driven(self):
        """Verify D1, D4, D5, D6 are Sink-driven."""
        assert DIMENSION_TYPE_MAP[1] == DimensionType.SINK_DRIVEN
        assert DIMENSION_TYPE_MAP[4] == DimensionType.SINK_DRIVEN
        assert DIMENSION_TYPE_MAP[5] == DimensionType.SINK_DRIVEN
        assert DIMENSION_TYPE_MAP[6] == DimensionType.SINK_DRIVEN

    def test_dimension_type_map_control_driven(self):
        """Verify D3, D9 are Control-driven."""
        assert DIMENSION_TYPE_MAP[3] == DimensionType.CONTROL_DRIVEN
        assert DIMENSION_TYPE_MAP[9] == DimensionType.CONTROL_DRIVEN

    def test_dimension_type_map_config_driven(self):
        """Verify D2, D7, D8, D10 are Config-driven."""
        assert DIMENSION_TYPE_MAP[2] == DimensionType.CONFIG_DRIVEN
        assert DIMENSION_TYPE_MAP[7] == DimensionType.CONFIG_DRIVEN
        assert DIMENSION_TYPE_MAP[8] == DimensionType.CONFIG_DRIVEN
        assert DIMENSION_TYPE_MAP[10] == DimensionType.CONFIG_DRIVEN


class TestGetDimensionType:
    """Test get_dimension_type function."""

    def test_get_sink_driven_dimensions(self):
        """Test getting type for Sink-driven dimensions."""
        for dim in [1, 4, 5, 6]:
            assert get_dimension_type(dim) == DimensionType.SINK_DRIVEN

    def test_get_control_driven_dimensions(self):
        """Test getting type for Control-driven dimensions."""
        for dim in [3, 9]:
            assert get_dimension_type(dim) == DimensionType.CONTROL_DRIVEN

    def test_get_config_driven_dimensions(self):
        """Test getting type for Config-driven dimensions."""
        for dim in [2, 7, 8, 10]:
            assert get_dimension_type(dim) == DimensionType.CONFIG_DRIVEN


class TestDimensionCoverage:
    """Test DimensionCoverage model."""

    def test_create_dimension_coverage(self):
        """Test creating a basic DimensionCoverage."""
        coverage = DimensionCoverage(dimension=1)
        assert coverage.dimension == 1
        assert coverage.status == CoverageStatus.NOT_COVERED

    def test_dimension_type_property(self):
        """Test dimension_type property."""
        coverage = DimensionCoverage(dimension=1)
        assert coverage.dimension_type == DimensionType.SINK_DRIVEN

        coverage = DimensionCoverage(dimension=3)
        assert coverage.dimension_type == DimensionType.CONTROL_DRIVEN

    def test_endpoint_coverage_rate(self):
        """Test endpoint_coverage_rate calculation."""
        coverage = DimensionCoverage(
            dimension=3,
            endpoints_total=100,
            endpoints_audited=50,
        )
        assert coverage.endpoint_coverage_rate == 0.5

    def test_endpoint_coverage_rate_zero_total(self):
        """Test endpoint_coverage_rate with zero total."""
        coverage = DimensionCoverage(dimension=3)
        assert coverage.endpoint_coverage_rate == 0.0

    def test_config_coverage_rate(self):
        """Test config_coverage_rate calculation."""
        coverage = DimensionCoverage(
            dimension=2,
            config_items_total=10,
            config_items_checked=8,
        )
        assert coverage.config_coverage_rate == 0.8


class TestLanguageEngineCoverage:
    """Test LanguageEngineCoverage model."""

    def test_create_language_engine_coverage(self):
        """Test creating a basic LanguageEngineCoverage."""
        lec = LanguageEngineCoverage(language="python", engine="semgrep")
        assert lec.language == "python"
        assert lec.engine == "semgrep"
        assert lec.dimensions == {}
        assert lec.enabled is True

    def test_get_dimension_creates_if_missing(self):
        """Test get_dimension creates entry if missing."""
        lec = LanguageEngineCoverage(language="python", engine="semgrep")
        coverage = lec.get_dimension(1)
        assert coverage.dimension == 1
        assert 1 in lec.dimensions

    def test_set_dimension(self):
        """Test setting a dimension coverage."""
        lec = LanguageEngineCoverage(language="python", engine="semgrep")
        coverage = DimensionCoverage(dimension=1, status=CoverageStatus.COVERED)
        lec.set_dimension(coverage)
        assert lec.dimensions[1].status == CoverageStatus.COVERED

    def test_get_covered_count(self):
        """Test counting covered dimensions."""
        lec = LanguageEngineCoverage(language="python", engine="semgrep")
        lec.set_dimension(DimensionCoverage(dimension=1, status=CoverageStatus.COVERED))
        lec.set_dimension(DimensionCoverage(dimension=2, status=CoverageStatus.COVERED))
        lec.set_dimension(DimensionCoverage(dimension=3, status=CoverageStatus.SHALLOW))
        assert lec.get_covered_count() == 2


class TestCoverageMatrix:
    """Test CoverageMatrix model."""

    def test_create_coverage_matrix(self):
        """Test creating a basic CoverageMatrix."""
        matrix = CoverageMatrix()
        assert matrix.languages == CORE_LANGUAGES
        assert matrix.engines == ALL_ENGINES

    def test_get_coverage_creates_if_missing(self):
        """Test get_coverage creates entry if missing."""
        matrix = CoverageMatrix()
        coverage = matrix.get_coverage("python", "semgrep", 1)
        assert coverage.dimension == 1

    def test_set_coverage(self):
        """Test setting coverage status."""
        matrix = CoverageMatrix()
        matrix.set_coverage("python", "semgrep", 1, CoverageStatus.COVERED)
        status = matrix.get_coverage("python", "semgrep", 1).status
        assert status == CoverageStatus.COVERED

    def test_set_coverage_with_kwargs(self):
        """Test setting coverage with additional kwargs."""
        matrix = CoverageMatrix()
        matrix.set_coverage(
            "python", "semgrep", 1,
            CoverageStatus.COVERED,
            sink_categories_searched=["exec", "system"],
            sink_categories_total=3,
            dataflow_traced=True,
            sink_fanout_rate=0.5,
        )
        coverage = matrix.get_coverage("python", "semgrep", 1)
        assert coverage.status == CoverageStatus.COVERED
        assert coverage.sink_categories_searched == ["exec", "system"]
        assert coverage.sink_fanout_rate == 0.5

    def test_get_dimension_status_across_engines(self):
        """Test getting dimension status across engines."""
        matrix = CoverageMatrix()
        matrix.set_coverage("python", "semgrep", 1, CoverageStatus.COVERED)
        matrix.set_coverage("python", "codeql", 1, CoverageStatus.SHALLOW)

        statuses = matrix.get_dimension_status_across_engines("python", 1)
        assert statuses["semgrep"] == CoverageStatus.COVERED
        assert statuses["codeql"] == CoverageStatus.SHALLOW
        assert statuses["agent"] == CoverageStatus.NOT_COVERED

    def test_get_overall_coverage_rate(self):
        """Test overall coverage rate calculation."""
        matrix = CoverageMatrix()
        # Set one dimension as covered
        matrix.set_coverage("python", "semgrep", 1, CoverageStatus.COVERED)
        rate = matrix.get_overall_coverage_rate()
        assert rate > 0.0

    def test_get_dimension_coverage_summary(self):
        """Test dimension coverage summary."""
        matrix = CoverageMatrix()
        matrix.set_coverage("python", "semgrep", 1, CoverageStatus.COVERED)
        matrix.set_coverage("python", "semgrep", 2, CoverageStatus.SHALLOW)

        summary = matrix.get_dimension_coverage_summary()
        assert 1 in summary
        assert summary[1]["covered"] >= 1
        assert summary[2]["shallow"] >= 1


class TestCoverageEvaluatorSinkDriven:
    """Test CoverageEvaluator for Sink-driven dimensions."""

    def test_not_covered_when_no_sinks_searched(self):
        """Test NOT_COVERED when no sinks searched."""
        coverage = DimensionCoverage(dimension=1)
        result = CoverageEvaluator.evaluate_sink_driven(coverage)
        assert result == CoverageStatus.NOT_COVERED

    def test_shallow_when_partial_search(self):
        """Test SHALLOW when partial search without dataflow."""
        coverage = DimensionCoverage(
            dimension=1,
            sink_categories_searched=["exec"],
            sink_categories_total=3,
            dataflow_traced=False,
            sink_fanout_rate=0.1,
        )
        result = CoverageEvaluator.evaluate_sink_driven(coverage)
        assert result == CoverageStatus.SHALLOW

    def test_covered_when_full_coverage(self):
        """Test COVERED when all criteria met."""
        coverage = DimensionCoverage(
            dimension=1,
            sink_categories_searched=["exec", "system", "popen"],
            sink_categories_total=3,
            dataflow_traced=True,
            sink_fanout_rate=0.5,
        )
        result = CoverageEvaluator.evaluate_sink_driven(coverage)
        assert result == CoverageStatus.COVERED

    def test_shallow_when_low_fanout(self):
        """Test SHALLOW when fanout rate is below threshold."""
        coverage = DimensionCoverage(
            dimension=1,
            sink_categories_searched=["exec", "system", "popen"],
            sink_categories_total=3,
            dataflow_traced=True,
            sink_fanout_rate=0.2,  # Below 30%
        )
        result = CoverageEvaluator.evaluate_sink_driven(coverage)
        assert result == CoverageStatus.SHALLOW


class TestCoverageEvaluatorControlDriven:
    """Test CoverageEvaluator for Control-driven dimensions."""

    def test_not_covered_when_no_endpoints(self):
        """Test NOT_COVERED when no endpoints identified."""
        coverage = DimensionCoverage(dimension=3)
        result = CoverageEvaluator.evaluate_control_driven(coverage, "standard")
        assert result == CoverageStatus.NOT_COVERED

    def test_shallow_when_low_endpoint_rate(self):
        """Test SHALLOW when endpoint rate is low."""
        coverage = DimensionCoverage(
            dimension=3,
            endpoints_total=100,
            endpoints_audited=20,
            crud_consistency_checked=False,
            resource_types_checked=0,
        )
        result = CoverageEvaluator.evaluate_control_driven(coverage, "standard")
        assert result == CoverageStatus.SHALLOW

    def test_covered_in_standard_mode(self):
        """Test COVERED in standard mode with 30% endpoints."""
        coverage = DimensionCoverage(
            dimension=3,
            endpoints_total=100,
            endpoints_audited=35,  # 35% > 30%
            crud_consistency_checked=True,
            resource_types_checked=3,
        )
        result = CoverageEvaluator.evaluate_control_driven(coverage, "standard")
        assert result == CoverageStatus.COVERED

    def test_not_covered_in_deep_mode_insufficient_endpoints(self):
        """Test not COVERED in deep mode with < 50% endpoints."""
        coverage = DimensionCoverage(
            dimension=3,
            endpoints_total=100,
            endpoints_audited=40,  # 40% < 50%
            crud_consistency_checked=True,
            resource_types_checked=3,
        )
        result = CoverageEvaluator.evaluate_control_driven(coverage, "deep")
        assert result == CoverageStatus.SHALLOW

    def test_covered_in_deep_mode(self):
        """Test COVERED in deep mode with 50% endpoints."""
        coverage = DimensionCoverage(
            dimension=3,
            endpoints_total=100,
            endpoints_audited=55,  # 55% > 50%
            crud_consistency_checked=True,
            resource_types_checked=4,
        )
        result = CoverageEvaluator.evaluate_control_driven(coverage, "deep")
        assert result == CoverageStatus.COVERED


class TestCoverageEvaluatorConfigDriven:
    """Test CoverageEvaluator for Config-driven dimensions."""

    def test_not_covered_when_no_config_items(self):
        """Test NOT_COVERED when no config items to check."""
        coverage = DimensionCoverage(dimension=2)
        result = CoverageEvaluator.evaluate_config_driven(coverage)
        assert result == CoverageStatus.NOT_COVERED

    def test_shallow_when_partial_config(self):
        """Test SHALLOW when partial config checked."""
        coverage = DimensionCoverage(
            dimension=2,
            config_items_total=10,
            config_items_checked=5,
            baseline_compared=False,
        )
        result = CoverageEvaluator.evaluate_config_driven(coverage)
        assert result == CoverageStatus.SHALLOW

    def test_shallow_when_all_checked_no_baseline(self):
        """Test SHALLOW when all checked but no baseline comparison."""
        coverage = DimensionCoverage(
            dimension=2,
            config_items_total=10,
            config_items_checked=10,
            baseline_compared=False,
        )
        result = CoverageEvaluator.evaluate_config_driven(coverage)
        assert result == CoverageStatus.SHALLOW

    def test_covered_when_all_criteria_met(self):
        """Test COVERED when all criteria met."""
        coverage = DimensionCoverage(
            dimension=2,
            config_items_total=10,
            config_items_checked=10,
            baseline_compared=True,
        )
        result = CoverageEvaluator.evaluate_config_driven(coverage)
        assert result == CoverageStatus.COVERED


class TestCoverageEvaluatorEvaluate:
    """Test CoverageEvaluator.evaluate method."""

    def test_evaluate_sink_driven_dimension(self):
        """Test evaluate routes correctly for Sink-driven."""
        coverage = DimensionCoverage(
            dimension=1,
            sink_categories_searched=["exec", "system"],
            sink_categories_total=2,
            dataflow_traced=True,
            sink_fanout_rate=0.5,
        )
        result = CoverageEvaluator.evaluate(coverage)
        assert result == CoverageStatus.COVERED

    def test_evaluate_control_driven_dimension(self):
        """Test evaluate routes correctly for Control-driven."""
        coverage = DimensionCoverage(
            dimension=3,
            endpoints_total=10,
            endpoints_audited=5,
            crud_consistency_checked=True,
            resource_types_checked=3,
        )
        result = CoverageEvaluator.evaluate(coverage, "standard")
        assert result == CoverageStatus.COVERED

    def test_evaluate_config_driven_dimension(self):
        """Test evaluate routes correctly for Config-driven."""
        coverage = DimensionCoverage(
            dimension=2,
            config_items_total=5,
            config_items_checked=5,
            baseline_compared=True,
        )
        result = CoverageEvaluator.evaluate(coverage)
        assert result == CoverageStatus.COVERED


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_evaluate_sink_driven_coverage(self):
        """Test evaluate_sink_driven_coverage function."""
        coverage = DimensionCoverage(
            dimension=1,
            sink_categories_searched=["exec"],
            sink_categories_total=1,
            dataflow_traced=True,
            sink_fanout_rate=0.5,
        )
        result = evaluate_sink_driven_coverage(coverage)
        assert result == CoverageStatus.COVERED

    def test_evaluate_control_driven_coverage(self):
        """Test evaluate_control_driven_coverage function."""
        coverage = DimensionCoverage(
            dimension=3,
            endpoints_total=10,
            endpoints_audited=5,
            crud_consistency_checked=True,
            resource_types_checked=3,
        )
        result = evaluate_control_driven_coverage(coverage, "standard")
        assert result == CoverageStatus.COVERED

    def test_evaluate_config_driven_coverage(self):
        """Test evaluate_config_driven_coverage function."""
        coverage = DimensionCoverage(
            dimension=2,
            config_items_total=5,
            config_items_checked=5,
            baseline_compared=True,
        )
        result = evaluate_config_driven_coverage(coverage)
        assert result == CoverageStatus.COVERED
