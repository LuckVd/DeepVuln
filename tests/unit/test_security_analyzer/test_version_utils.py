"""Unit tests for version comparison utilities."""

import pytest

from src.layers.l1_intelligence.security_analyzer.version_utils import (
    VersionRange,
    compare_versions,
    extract_version_from_go_range,
    is_version_vulnerable,
    normalize_version,
    parse_version_range,
)


class TestNormalizeVersion:
    """Tests for normalize_version function."""

    def test_normalize_simple_version(self) -> None:
        """Test normalizing simple version."""
        assert normalize_version("1.0.0") == "1.0.0"
        assert normalize_version("2.1.3") == "2.1.3"

    def test_normalize_with_v_prefix(self) -> None:
        """Test normalizing version with v prefix."""
        assert normalize_version("v1.0.0") == "1.0.0"
        assert normalize_version("V2.0.0") == "2.0.0"

    def test_normalize_two_part_version(self) -> None:
        """Test normalizing two-part version."""
        assert normalize_version("1.0") == "1.0.0"
        assert normalize_version("2.5") == "2.5.0"

    def test_normalize_single_part_version(self) -> None:
        """Test normalizing single-part version."""
        assert normalize_version("1") == "1.0.0"

    def test_normalize_with_prerelease(self) -> None:
        """Test normalizing version with pre-release."""
        assert normalize_version("1.0.0-alpha") == "1.0.0"
        assert normalize_version("2.0.0-beta.1") == "2.0.0"

    def test_normalize_with_build_metadata(self) -> None:
        """Test normalizing version with build metadata."""
        assert normalize_version("1.0.0+build.1") == "1.0.0"

    def test_normalize_wildcard(self) -> None:
        """Test normalizing wildcard."""
        assert normalize_version("*") == "0.0.0"
        assert normalize_version("") == "0.0.0"

    def test_normalize_with_operators(self) -> None:
        """Test normalizing version with operators."""
        assert normalize_version(">=1.0.0") == "1.0.0"
        assert normalize_version("^2.0.0") == "2.0.0"


class TestCompareVersions:
    """Tests for compare_versions function."""

    def test_equal_versions(self) -> None:
        """Test comparing equal versions."""
        assert compare_versions("1.0.0", "1.0.0") == 0
        assert compare_versions("2.5.3", "2.5.3") == 0

    def test_less_than(self) -> None:
        """Test comparing less than versions."""
        assert compare_versions("1.0.0", "2.0.0") == -1
        assert compare_versions("1.0.0", "1.1.0") == -1
        assert compare_versions("1.0.0", "1.0.1") == -1

    def test_greater_than(self) -> None:
        """Test comparing greater than versions."""
        assert compare_versions("2.0.0", "1.0.0") == 1
        assert compare_versions("1.1.0", "1.0.0") == 1
        assert compare_versions("1.0.1", "1.0.0") == 1

    def test_compare_different_lengths(self) -> None:
        """Test comparing versions with different lengths."""
        assert compare_versions("1.0", "1.0.0") == 0
        assert compare_versions("1.0.0.1", "1.0.0") == 1


class TestVersionRange:
    """Tests for VersionRange class."""

    def test_contains_exact_version(self) -> None:
        """Test contains with exact version."""
        range_ = VersionRange(min_version="1.0.0", max_version="1.0.0",
                              min_inclusive=True, max_inclusive=True)
        assert range_.contains("1.0.0")
        assert not range_.contains("1.0.1")
        assert not range_.contains("0.9.0")

    def test_contains_range(self) -> None:
        """Test contains with version range."""
        range_ = VersionRange(min_version="1.0.0", max_version="2.0.0",
                              min_inclusive=True, max_inclusive=False)
        assert range_.contains("1.0.0")
        assert range_.contains("1.5.0")
        assert not range_.contains("2.0.0")
        assert not range_.contains("2.1.0")

    def test_contains_min_only(self) -> None:
        """Test contains with min version only."""
        range_ = VersionRange(min_version="1.0.0", min_inclusive=True)
        assert range_.contains("1.0.0")
        assert range_.contains("10.0.0")
        assert not range_.contains("0.9.0")

    def test_contains_max_only(self) -> None:
        """Test contains with max version only."""
        range_ = VersionRange(max_version="2.0.0", max_inclusive=True)
        assert range_.contains("1.0.0")
        assert range_.contains("2.0.0")
        assert not range_.contains("2.0.1")


class TestParseVersionRange:
    """Tests for parse_version_range function."""

    def test_parse_exact_version(self) -> None:
        """Test parsing exact version."""
        range_ = parse_version_range("1.0.0")
        assert range_ is not None
        assert range_.contains("1.0.0")
        assert not range_.contains("1.0.1")

    def test_parse_exact_version_with_v(self) -> None:
        """Test parsing exact version with v prefix."""
        range_ = parse_version_range("v1.0.0")
        assert range_ is not None
        assert range_.contains("1.0.0")

    def test_parse_dash_range(self) -> None:
        """Test parsing dash-separated range."""
        range_ = parse_version_range("1.0.0 - 1.5.0")
        assert range_ is not None
        assert range_.contains("1.0.0")
        assert range_.contains("1.2.0")
        assert range_.contains("1.5.0")
        assert not range_.contains("0.9.0")
        assert not range_.contains("1.5.1")

    def test_parse_greater_equal(self) -> None:
        """Test parsing >= constraint."""
        range_ = parse_version_range(">=1.0.0")
        assert range_ is not None
        assert range_.contains("1.0.0")
        assert range_.contains("2.0.0")
        assert not range_.contains("0.9.0")

    def test_parse_less_than(self) -> None:
        """Test parsing < constraint."""
        range_ = parse_version_range("<2.0.0")
        assert range_ is not None
        assert range_.contains("1.0.0")
        assert not range_.contains("2.0.0")
        assert not range_.contains("2.1.0")

    def test_parse_comma_separated(self) -> None:
        """Test parsing comma-separated constraints."""
        range_ = parse_version_range(">=1.0.0, <2.0.0")
        assert range_ is not None
        assert range_.contains("1.0.0")
        assert range_.contains("1.5.0")
        assert not range_.contains("2.0.0")
        assert not range_.contains("0.9.0")


class TestIsVersionVulnerable:
    """Tests for is_version_vulnerable function."""

    def test_vulnerable_in_range(self) -> None:
        """Test version is vulnerable when in range."""
        assert is_version_vulnerable("1.5.0", [">=1.0.0, <2.0.0"])

    def test_not_vulnerable_out_of_range(self) -> None:
        """Test version is not vulnerable when out of range."""
        assert not is_version_vulnerable("2.5.0", [">=1.0.0, <2.0.0"])
        assert not is_version_vulnerable("0.5.0", [">=1.0.0, <2.0.0"])

    def test_patched_version(self) -> None:
        """Test patched version is not vulnerable."""
        assert not is_version_vulnerable("2.5.0", [">=1.0.0"], patched_versions=["2.0.0"])

    def test_not_patched_yet(self) -> None:
        """Test version before patch is vulnerable."""
        assert is_version_vulnerable("1.5.0", [">=1.0.0"], patched_versions=["2.0.0"])

    def test_empty_ranges(self) -> None:
        """Test with empty ranges."""
        assert not is_version_vulnerable("1.0.0", [])


class TestExtractVersionFromGoRange:
    """Tests for extract_version_from_go_range function."""

    def test_extract_basic_range(self) -> None:
        """Test extracting basic Go range."""
        min_v, max_v = extract_version_from_go_range(">=1.0.0 <1.1.0")
        assert min_v == "1.0.0"
        assert max_v == "1.1.0"

    def test_extract_min_only(self) -> None:
        """Test extracting min only."""
        min_v, max_v = extract_version_from_go_range(">=1.2.0")
        assert min_v == "1.2.0"
        assert max_v is None

    def test_extract_with_v_prefix(self) -> None:
        """Test extracting with v prefix."""
        min_v, max_v = extract_version_from_go_range(">=v1.0.0 <v1.1.0")
        assert min_v == "1.0.0"
        assert max_v == "1.1.0"
