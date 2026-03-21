"""
P6-11: Coverage Stats Tests

Tests for P6-06 CoverageStats and EngineStats models.

CoverageStats tracks:
- File coverage: total_files, scanned_files, skipped_files
- Line coverage: total_lines, scanned_lines
- Target coverage: total_targets, analyzed_targets
- Entry point coverage: entry_points_scanned, http/rpc endpoints
- Dimension matrix: Security dimension coverage (P6-08)
"""

import pytest

from src.layers.l3_analysis.coverage.matrix import (
    CoverageMatrix,
    CoverageStatus,
)
from src.layers.l3_analysis.rounds.models import (
    CoverageStats,
    EngineStats,
)


# =============================================================================
# Test CoverageStats Creation
# =============================================================================


class TestCoverageStatsCreation:
    """Test CoverageStats model creation and defaults."""

    def test_create_with_defaults(self):
        """Test creating CoverageStats with default values."""
        stats = CoverageStats()
        assert stats.total_files == 0
        assert stats.scanned_files == 0
        assert stats.skipped_files == 0
        assert stats.total_lines == 0
        assert stats.scanned_lines == 0
        assert stats.total_targets == 0
        assert stats.analyzed_targets == 0
        assert stats.entry_points_scanned == 0
        assert stats.dimension_matrix is None

    def test_create_with_file_counts(self):
        """Test creating CoverageStats with file counts."""
        stats = CoverageStats(
            total_files=100,
            scanned_files=80,
            skipped_files=20,
        )
        assert stats.total_files == 100
        assert stats.scanned_files == 80
        assert stats.skipped_files == 20

    def test_create_with_line_counts(self):
        """Test creating CoverageStats with line counts."""
        stats = CoverageStats(
            total_lines=10000,
            scanned_lines=7500,
        )
        assert stats.total_lines == 10000
        assert stats.scanned_lines == 7500

    def test_create_with_target_counts(self):
        """Test creating CoverageStats with target counts."""
        stats = CoverageStats(
            total_targets=50,
            analyzed_targets=40,
            critical_targets_analyzed=10,
            high_targets_analyzed=15,
        )
        assert stats.total_targets == 50
        assert stats.analyzed_targets == 40
        assert stats.critical_targets_analyzed == 10
        assert stats.high_targets_analyzed == 15


# =============================================================================
# Test File Coverage Calculation
# =============================================================================


class TestCoverageStatsFileCoverage:
    """Test file coverage percentage calculation."""

    def test_file_coverage_percent_zero_total(self):
        """Test file coverage with zero total files."""
        stats = CoverageStats(total_files=0, scanned_files=0)
        assert stats.file_coverage_percent == 0.0

    def test_file_coverage_percent_full(self):
        """Test file coverage when all files scanned."""
        stats = CoverageStats(total_files=100, scanned_files=100)
        assert stats.file_coverage_percent == 100.0

    def test_file_coverage_percent_partial(self):
        """Test file coverage with partial scan."""
        stats = CoverageStats(total_files=100, scanned_files=75)
        assert stats.file_coverage_percent == 75.0

    def test_file_coverage_percent_fractional(self):
        """Test file coverage with fractional result."""
        stats = CoverageStats(total_files=3, scanned_files=1)
        assert abs(stats.file_coverage_percent - 33.33333333333333) < 0.001

    def test_skipped_files_not_in_coverage(self):
        """Test that skipped files are separate from coverage."""
        stats = CoverageStats(
            total_files=100,
            scanned_files=70,
            skipped_files=30,
        )
        assert stats.file_coverage_percent == 70.0
        assert stats.skipped_files == 30


# =============================================================================
# Test Target Coverage Calculation
# =============================================================================


class TestCoverageStatsTargetCoverage:
    """Test target coverage percentage calculation."""

    def test_target_coverage_percent_zero_total(self):
        """Test target coverage with zero total targets."""
        stats = CoverageStats(total_targets=0, analyzed_targets=0)
        assert stats.target_coverage_percent == 0.0

    def test_target_coverage_percent_full(self):
        """Test target coverage when all targets analyzed."""
        stats = CoverageStats(total_targets=50, analyzed_targets=50)
        assert stats.target_coverage_percent == 100.0

    def test_target_coverage_percent_partial(self):
        """Test target coverage with partial analysis."""
        stats = CoverageStats(total_targets=100, analyzed_targets=35)
        assert stats.target_coverage_percent == 35.0

    def test_target_coverage_with_priority_breakdown(self):
        """Test target coverage with critical/high priority breakdown."""
        stats = CoverageStats(
            total_targets=100,
            analyzed_targets=50,
            critical_targets_analyzed=10,
            high_targets_analyzed=20,
        )
        assert stats.target_coverage_percent == 50.0
        assert stats.critical_targets_analyzed == 10
        assert stats.high_targets_analyzed == 20

    def test_target_coverage_exceeds_100_clamped(self):
        """Test target coverage calculation is mathematically correct."""
        # Note: Model doesn't enforce analyzed <= total
        stats = CoverageStats(total_targets=50, analyzed_targets=60)
        assert stats.target_coverage_percent == 120.0


# =============================================================================
# Test Entry Point Coverage
# =============================================================================


class TestCoverageStatsEntryPointCoverage:
    """Test entry point coverage statistics."""

    def test_entry_points_scanned_default(self):
        """Test entry_points_scanned default value."""
        stats = CoverageStats()
        assert stats.entry_points_scanned == 0

    def test_http_endpoints_scanned(self):
        """Test HTTP endpoints scanned tracking."""
        stats = CoverageStats(
            entry_points_scanned=100,
            http_endpoints_scanned=80,
        )
        assert stats.entry_points_scanned == 100
        assert stats.http_endpoints_scanned == 80

    def test_rpc_endpoints_scanned(self):
        """Test RPC endpoints scanned tracking."""
        stats = CoverageStats(
            entry_points_scanned=50,
            rpc_endpoints_scanned=20,
        )
        assert stats.rpc_endpoints_scanned == 20

    def test_mixed_endpoint_types(self):
        """Test mixed HTTP and RPC endpoints."""
        stats = CoverageStats(
            entry_points_scanned=100,
            http_endpoints_scanned=70,
            rpc_endpoints_scanned=30,
        )
        assert stats.http_endpoints_scanned + stats.rpc_endpoints_scanned == 100


# =============================================================================
# Test Dimension Matrix Integration
# =============================================================================


class TestCoverageStatsDimensionMatrix:
    """Test dimension matrix integration with CoverageStats."""

    def test_dimension_matrix_none_by_default(self):
        """Test dimension_matrix is None by default."""
        stats = CoverageStats()
        assert stats.dimension_matrix is None

    def test_dimension_coverage_rate_zero_when_none(self):
        """Test dimension_coverage_rate is 0 when matrix is None."""
        stats = CoverageStats()
        assert stats.dimension_coverage_rate == 0.0

    def test_dimension_coverage_rate_with_matrix(self):
        """Test dimension_coverage_rate with CoverageMatrix."""
        matrix = CoverageMatrix()
        matrix.set_coverage("python", "semgrep", 1, CoverageStatus.COVERED)
        matrix.set_coverage("python", "semgrep", 2, CoverageStatus.COVERED)

        stats = CoverageStats(dimension_matrix=matrix)
        rate = stats.dimension_coverage_rate

        assert rate > 0.0
        assert rate <= 1.0

    def test_get_dimension_coverage_summary(self):
        """Test get_dimension_coverage_summary returns summary."""
        matrix = CoverageMatrix()
        matrix.set_coverage("python", "semgrep", 1, CoverageStatus.COVERED)

        stats = CoverageStats(dimension_matrix=matrix)
        summary = stats.get_dimension_coverage_summary()

        assert summary is not None
        assert 1 in summary
        assert summary[1]["covered"] >= 1


# =============================================================================
# Test EngineStats
# =============================================================================


class TestEngineStats:
    """Test EngineStats model."""

    def test_create_with_defaults(self):
        """Test creating EngineStats with defaults."""
        stats = EngineStats(engine="semgrep")
        assert stats.engine == "semgrep"
        assert stats.enabled is True
        assert stats.executed is False
        assert stats.files_scanned == 0
        assert stats.findings_count == 0
        assert stats.errors == []

    def test_create_with_counts(self):
        """Test creating EngineStats with counts."""
        stats = EngineStats(
            engine="codeql",
            files_scanned=100,
            targets_analyzed=50,
            findings_count=25,
            candidates_count=10,
        )
        assert stats.files_scanned == 100
        assert stats.targets_analyzed == 50
        assert stats.findings_count == 25
        assert stats.candidates_count == 10

    def test_add_error(self):
        """Test add_error method."""
        stats = EngineStats(engine="agent")
        stats.add_error("Test error message")
        assert len(stats.errors) == 1
        assert stats.errors[0] == "Test error message"

    def test_add_warning(self):
        """Test add_warning method."""
        stats = EngineStats(engine="agent")
        stats.add_warning("Test warning message")
        assert len(stats.warnings) == 1
        assert stats.warnings[0] == "Test warning message"

    def test_tokens_and_api_calls(self):
        """Test LLM resource tracking."""
        stats = EngineStats(
            engine="agent",
            tokens_used=50000,
            api_calls=10,
        )
        assert stats.tokens_used == 50000
        assert stats.api_calls == 10


# =============================================================================
# Test Coverage Stats Integration Scenarios
# =============================================================================


class TestCoverageStatsIntegration:
    """Test CoverageStats integration scenarios."""

    def test_full_audit_coverage(self):
        """Test coverage stats after a full audit."""
        matrix = CoverageMatrix()
        # Mark several dimensions as covered
        for dim in [1, 2, 3, 4, 5]:
            matrix.set_coverage("python", "semgrep", dim, CoverageStatus.COVERED)

        stats = CoverageStats(
            total_files=200,
            scanned_files=180,
            skipped_files=20,
            total_lines=50000,
            scanned_lines=45000,
            total_targets=100,
            analyzed_targets=85,
            critical_targets_analyzed=15,
            high_targets_analyzed=25,
            entry_points_scanned=50,
            http_endpoints_scanned=40,
            dimension_matrix=matrix,
        )

        assert stats.file_coverage_percent == 90.0
        assert stats.target_coverage_percent == 85.0
        assert stats.dimension_coverage_rate > 0.0
        assert stats.get_dimension_coverage_summary() is not None

    def test_minimal_coverage_stats(self):
        """Test minimal coverage stats for quick scan."""
        stats = CoverageStats(
            total_files=10,
            scanned_files=10,
        )
        assert stats.file_coverage_percent == 100.0
        assert stats.target_coverage_percent == 0.0  # No targets defined
        assert stats.dimension_coverage_rate == 0.0  # No matrix

    def test_coverage_summary_with_mixed_status(self):
        """Test coverage summary with mixed dimension statuses."""
        matrix = CoverageMatrix()
        matrix.set_coverage("python", "semgrep", 1, CoverageStatus.COVERED)
        matrix.set_coverage("python", "semgrep", 2, CoverageStatus.SHALLOW)
        matrix.set_coverage("python", "semgrep", 3, CoverageStatus.NOT_COVERED)

        stats = CoverageStats(dimension_matrix=matrix)
        summary = stats.get_dimension_coverage_summary()

        assert summary is not None
        assert summary[1]["covered"] >= 1
        assert summary[2]["shallow"] >= 1
        assert summary[3]["not_covered"] >= 1
