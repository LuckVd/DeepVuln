"""
Unit tests for Tool Resolver.

Tests tool discovery, version detection, compatibility checking,
and readiness report generation.
"""

import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.layers.l3_analysis.build.tool_resolver import (
    CompatibilityChecker,
    CompatibilityResult,
    CompatibilityStatus,
    ProvisionPolicy,
    ReadinessReport,
    ToolConfig,
    ToolInfo,
    ToolResolver,
    ToolSource,
    ToolType,
    TOOL_CONFIGS,
    check_tool_compatibility,
    generate_readiness_report,
    parse_version,
    resolve_tool,
    version_matches,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_tools_dir(tmp_path):
    """Create a temporary tools directory."""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    return tools_dir


@pytest.fixture
def mock_env():
    """Create a mock environment without PATH tools."""
    return {"PATH": ""}


# =============================================================================
# Version Parsing Tests
# =============================================================================


class TestParseVersion:
    """Tests for version parsing."""

    def test_parse_simple_version(self):
        """Test parsing simple version like '11'."""
        result = parse_version("11")
        assert result == (11,)

    def test_parse_semver_version(self):
        """Test parsing semantic version like '11.0.1'."""
        result = parse_version("11.0.1")
        assert result == (11, 0, 1)

    def test_parse_two_part_version(self):
        """Test parsing two-part version like '1.8'."""
        result = parse_version("1.8")
        assert result == (1, 8)

    def test_parse_version_with_v_prefix(self):
        """Test parsing version with 'v' prefix."""
        result = parse_version("v18.17.0")
        assert result == (18, 17, 0)

    def test_parse_invalid_version(self):
        """Test parsing invalid version returns None."""
        result = parse_version("invalid")
        assert result is None

    def test_parse_empty_version(self):
        """Test parsing empty string returns None."""
        result = parse_version("")
        assert result is None


class TestVersionMatches:
    """Tests for version matching."""

    def test_exact_match(self):
        """Test exact version match."""
        assert version_matches("11", "11") is True
        assert version_matches("11.0", "11.0") is True
        assert version_matches("11.0.1", "11.0.1") is True

    def test_exact_match_major_only(self):
        """Test major version match when only major specified."""
        assert version_matches("11.0.1", "11") is True
        assert version_matches("17.0.2", "17") is True

    def test_exact_mismatch(self):
        """Test version mismatch."""
        assert version_matches("11", "17") is False
        assert version_matches("11.0.1", "11.0.2") is False

    def test_gte_match(self):
        """Test >= version constraint."""
        assert version_matches("17", ">=11") is True
        assert version_matches("11", ">=11") is True
        assert version_matches("10", ">=11") is False

    def test_gt_match(self):
        """Test > version constraint."""
        assert version_matches("17", ">11") is True
        assert version_matches("11", ">11") is False
        assert version_matches("11.0.1", ">11.0") is True

    def test_range_match(self):
        """Test version range constraint."""
        assert version_matches("14", "11-17") is True
        assert version_matches("11", "11-17") is True
        assert version_matches("17", "11-17") is True
        assert version_matches("10", "11-17") is False
        assert version_matches("18", "11-17") is False

    def test_no_actual_version(self):
        """Test when actual version is None."""
        assert version_matches(None, "11") is False

    def test_no_actual_version_string(self):
        """Test when actual version is empty string."""
        assert version_matches("", "11") is False


# =============================================================================
# ToolInfo Tests
# =============================================================================


class TestToolInfo:
    """Tests for ToolInfo dataclass."""

    def test_create_tool_info(self):
        """Test creating ToolInfo."""
        info = ToolInfo(
            tool_type=ToolType.JAVA,
            path=Path("/usr/bin/java"),
            version="17.0.1",
            source=ToolSource.SYSTEM_PATH,
        )

        assert info.tool_type == ToolType.JAVA
        assert info.version == "17.0.1"
        assert info.source == ToolSource.SYSTEM_PATH

    def test_tool_info_to_dict(self):
        """Test ToolInfo serialization."""
        info = ToolInfo(
            tool_type=ToolType.GO,
            path=Path("/usr/local/go/bin/go"),
            version="1.21",
            source=ToolSource.MANAGED_PATH,
        )

        result = info.to_dict()

        assert result["tool_type"] == "go"
        assert result["version"] == "1.21"
        assert result["source"] == "managed_path"


# =============================================================================
# CompatibilityResult Tests
# =============================================================================


class TestCompatibilityResult:
    """Tests for CompatibilityResult dataclass."""

    def test_compatible_result(self):
        """Test compatible result."""
        tool = ToolInfo(
            tool_type=ToolType.JAVA,
            path=Path("/usr/bin/java"),
            version="17",
        )
        result = CompatibilityResult(
            tool_type=ToolType.JAVA,
            status=CompatibilityStatus.OK,
            tool=tool,
            actual_version="17",
        )

        assert result.compatible is True
        assert result.status == CompatibilityStatus.OK

    def test_incompatible_result(self):
        """Test incompatible result."""
        result = CompatibilityResult(
            tool_type=ToolType.JAVA,
            status=CompatibilityStatus.VERSION_MISMATCH,
            required_version="17",
            actual_version="11",
            message="Version mismatch",
        )

        assert result.compatible is False
        assert result.status == CompatibilityStatus.VERSION_MISMATCH

    def test_not_found_result(self):
        """Test not found result."""
        result = CompatibilityResult(
            tool_type=ToolType.GRADLE,
            status=CompatibilityStatus.NOT_FOUND,
            message="Tool not found",
        )

        assert result.compatible is False
        assert result.status == CompatibilityStatus.NOT_FOUND


# =============================================================================
# ReadinessReport Tests
# =============================================================================


class TestReadinessReport:
    """Tests for ReadinessReport dataclass."""

    def test_empty_report(self):
        """Test empty report."""
        report = ReadinessReport(policy=ProvisionPolicy.REUSE_ONLY)

        assert report.is_ready is True
        assert report.has_warnings is False

    def test_report_with_ready_tools(self):
        """Test report with ready tools."""
        tool = ToolInfo(
            tool_type=ToolType.JAVA,
            path=Path("/usr/bin/java"),
            version="17",
        )
        report = ReadinessReport(
            ready_tools=[tool],
            policy=ProvisionPolicy.REUSE_ONLY,
        )

        assert report.is_ready is True
        assert report.has_warnings is False

    def test_report_with_warnings(self):
        """Test report with warnings."""
        result = CompatibilityResult(
            tool_type=ToolType.GRADLE,
            status=CompatibilityStatus.NOT_FOUND,
        )
        report = ReadinessReport(
            incompatible_tools=[result],
            policy=ProvisionPolicy.REUSE_ONLY,
        )

        assert report.is_ready is True  # Non-strict policy
        assert report.has_warnings is True

    def test_strict_policy_with_warnings(self):
        """Test strict policy with warnings."""
        result = CompatibilityResult(
            tool_type=ToolType.GRADLE,
            status=CompatibilityStatus.NOT_FOUND,
        )
        report = ReadinessReport(
            incompatible_tools=[result],
            policy=ProvisionPolicy.STRICT,
        )

        assert report.is_ready is False  # Strict policy fails
        assert report.has_warnings is True

    def test_report_to_dict(self):
        """Test report serialization."""
        tool = ToolInfo(
            tool_type=ToolType.JAVA,
            path=Path("/usr/bin/java"),
            version="17",
        )
        report = ReadinessReport(
            ready_tools=[tool],
            policy=ProvisionPolicy.STRICT,
        )

        result = report.to_dict()

        assert result["policy"] == "strict"
        assert len(result["ready_tools"]) == 1


# =============================================================================
# ToolResolver Tests
# =============================================================================


class TestToolResolver:
    """Tests for ToolResolver."""

    def test_resolver_initialization(self):
        """Test resolver initialization."""
        resolver = ToolResolver()

        assert resolver.managed_paths is not None
        assert resolver.cache_dir is not None

    def test_resolver_with_custom_paths(self, tmp_path):
        """Test resolver with custom paths."""
        custom_managed = [tmp_path / "tools"]
        custom_cache = tmp_path / "cache"

        resolver = ToolResolver(
            managed_paths=custom_managed,
            cache_dir=custom_cache,
        )

        assert resolver.managed_paths == custom_managed
        assert resolver.cache_dir == custom_cache

    def test_resolve_from_system_path(self):
        """Test resolving tool from system PATH."""
        resolver = ToolResolver()

        # Python should always be available in PATH
        tool = resolver.resolve(ToolType.PYTHON)

        # May or may not find python depending on environment
        # Just verify the method runs without error
        if tool:
            assert tool.tool_type == ToolType.PYTHON
            assert tool.source == ToolSource.SYSTEM_PATH

    def test_resolve_nonexistent_tool(self, mock_env):
        """Test resolving tool that doesn't exist."""
        resolver = ToolResolver(env=mock_env)

        tool = resolver.resolve(ToolType.YARN)

        assert tool is None

    def test_resolve_all_tools(self):
        """Test resolving multiple tools."""
        resolver = ToolResolver()

        results = resolver.resolve_all([ToolType.PYTHON, ToolType.NODE])

        assert ToolType.PYTHON in results
        assert ToolType.NODE in results


# =============================================================================
# CompatibilityChecker Tests
# =============================================================================


class TestCompatibilityChecker:
    """Tests for CompatibilityChecker."""

    def test_checker_initialization(self):
        """Test checker initialization."""
        checker = CompatibilityChecker()
        assert checker.resolver is not None

    def test_check_tool_no_requirement(self):
        """Test checking tool without version requirement."""
        checker = CompatibilityChecker()

        result = checker.check(ToolType.PYTHON)

        # Python should be available
        if result.status == CompatibilityStatus.OK:
            assert result.tool is not None

    def test_check_tool_not_found(self, mock_env):
        """Test checking tool that doesn't exist."""
        resolver = ToolResolver(env=mock_env)
        checker = CompatibilityChecker(resolver)

        result = checker.check(ToolType.YARN)

        assert result.status == CompatibilityStatus.NOT_FOUND
        assert result.tool is None

    def test_check_all_tools(self):
        """Test checking multiple tools."""
        checker = CompatibilityChecker()

        requirements = {
            ToolType.PYTHON: None,
            ToolType.NODE: None,
        }

        results = checker.check_all(requirements)

        assert len(results) == 2


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_resolve_tool_function(self):
        """Test resolve_tool convenience function."""
        tool = resolve_tool(ToolType.PYTHON)

        # May or may not find python
        if tool:
            assert isinstance(tool, ToolInfo)

    def test_check_tool_compatibility_function(self):
        """Test check_tool_compatibility convenience function."""
        result = check_tool_compatibility(ToolType.PYTHON)

        assert isinstance(result, CompatibilityResult)

    def test_generate_readiness_report_function(self):
        """Test generate_readiness_report convenience function."""
        requirements = {
            ToolType.PYTHON: None,
            ToolType.NODE: ">=16",
        }

        report = generate_readiness_report(requirements)

        assert isinstance(report, ReadinessReport)
        assert report.policy == ProvisionPolicy.REUSE_ONLY


# =============================================================================
# Tool Config Tests
# =============================================================================


class TestToolConfigs:
    """Tests for tool configurations."""

    def test_java_config(self):
        """Test Java tool configuration."""
        config = TOOL_CONFIGS[ToolType.JAVA]

        assert config.tool_type == ToolType.JAVA
        assert config.version_command == ["java", "-version"]
        assert config.stderr_version is True

    def test_go_config(self):
        """Test Go tool configuration."""
        config = TOOL_CONFIGS[ToolType.GO]

        assert config.tool_type == ToolType.GO
        assert config.version_command == ["go", "version"]
        assert config.stderr_version is False

    def test_node_config(self):
        """Test Node tool configuration."""
        config = TOOL_CONFIGS[ToolType.NODE]

        assert config.tool_type == ToolType.NODE
        assert "node" in config.executable_names

    def test_python_config(self):
        """Test Python tool configuration."""
        config = TOOL_CONFIGS[ToolType.PYTHON]

        assert config.tool_type == ToolType.PYTHON
        # Python has multiple executable names
        assert "python" in config.executable_names or "python3" in config.executable_names


# =============================================================================
# ProvisionPolicy Tests
# =============================================================================


class TestProvisionPolicy:
    """Tests for ProvisionPolicy enum."""

    def test_strict_policy(self):
        """Test STRICT policy value."""
        assert ProvisionPolicy.STRICT.value == "strict"

    def test_reuse_only_policy(self):
        """Test REUSE_ONLY policy value."""
        assert ProvisionPolicy.REUSE_ONLY.value == "reuse_only"

    def test_managed_cache_policy(self):
        """Test MANAGED_CACHE policy value."""
        assert ProvisionPolicy.MANAGED_CACHE.value == "managed_cache"


# =============================================================================
# ToolSource Tests
# =============================================================================


class TestToolSource:
    """Tests for ToolSource enum."""

    def test_system_path_source(self):
        """Test SYSTEM_PATH source value."""
        assert ToolSource.SYSTEM_PATH.value == "system_path"

    def test_local_cache_source(self):
        """Test LOCAL_CACHE source value."""
        assert ToolSource.LOCAL_CACHE.value == "local_cache"

    def test_managed_path_source(self):
        """Test MANAGED_PATH source value."""
        assert ToolSource.MANAGED_PATH.value == "managed_path"


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for tool resolver."""

    def test_full_workflow(self):
        """Test full tool resolution workflow."""
        # Create requirements
        requirements = {
            ToolType.PYTHON: ">=3.8",
            ToolType.NODE: None,  # Any version
        }

        # Generate report
        report = generate_readiness_report(
            requirements,
            policy=ProvisionPolicy.REUSE_ONLY,
        )

        # Verify report structure
        assert isinstance(report, ReadinessReport)
        assert report.policy == ProvisionPolicy.REUSE_ONLY

    def test_readiness_report_with_missing_tools(self, mock_env):
        """Test report when tools are missing."""
        resolver = ToolResolver(env=mock_env)
        requirements = {
            ToolType.YARN: None,
            ToolType.PNPM: None,
        }

        report = generate_readiness_report(
            requirements,
            policy=ProvisionPolicy.STRICT,
            resolver=resolver,
        )

        assert report.is_ready is False
        assert len(report.missing_tools) > 0
