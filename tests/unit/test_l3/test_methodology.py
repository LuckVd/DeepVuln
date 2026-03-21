"""
P6-06b: Business Logic Methodology Tests
P6-07d: WooYun Case Library Tests

Tests for the methodology module that provides detection patterns
for business logic vulnerabilities (D9 dimension).
"""

from pathlib import Path

import pytest

from src.layers.l3_analysis.methodology import (
    METHODOLOGY_DIR,
    METHODOLOGY_FILES,
    WOOWYUN_DIR,
    WOOWYUN_FILES,
    WOOWYUN_STATS,
    get_methodology_path,
    list_available_methodologies,
    get_wooyun_path,
    list_available_wooyun_types,
    get_wooyun_stats,
)
from src.layers.l3_analysis.sinks_sources import BusinessLogicCategory


class TestMethodologyDirectory:
    """Test methodology directory structure."""

    def test_methodology_directory_exists(self):
        """Verify methodology directory exists."""
        assert METHODOLOGY_DIR.exists()
        assert METHODOLOGY_DIR.is_dir()

    def test_methodology_directory_location(self):
        """Verify methodology directory is under l3_analysis."""
        assert "l3_analysis" in str(METHODOLOGY_DIR)
        assert "methodology" in str(METHODOLOGY_DIR)


class TestMethodologyFiles:
    """Test methodology file availability."""

    def test_methodology_files_defined(self):
        """Verify METHODOLOGY_FILES has expected keys."""
        expected_keys = {"general", "python", "java", "go"}
        assert expected_keys.issubset(METHODOLOGY_FILES.keys())

    def test_general_methodology_exists(self):
        """Verify general business_logic.md exists."""
        path = METHODOLOGY_FILES["general"]
        assert path.exists(), f"General methodology not found: {path}"
        assert path.suffix == ".md"

    def test_python_methodology_exists(self):
        """Verify Python-specific methodology exists."""
        path = METHODOLOGY_FILES["python"]
        assert path.exists(), f"Python methodology not found: {path}"

    def test_java_methodology_exists(self):
        """Verify Java-specific methodology exists."""
        path = METHODOLOGY_FILES["java"]
        assert path.exists(), f"Java methodology not found: {path}"

    def test_go_methodology_exists(self):
        """Verify Go-specific methodology exists."""
        path = METHODOLOGY_FILES["go"]
        assert path.exists(), f"Go methodology not found: {path}"


class TestGetMethodologyPath:
    """Test get_methodology_path function."""

    def test_get_general_methodology(self):
        """Test getting general methodology path."""
        path = get_methodology_path()
        assert path is not None
        assert path.exists()
        assert path.name == "business_logic.md"

    def test_get_python_methodology(self):
        """Test getting Python methodology path."""
        path = get_methodology_path("python")
        assert path is not None
        assert path.exists()
        assert "python" in path.name

    def test_get_java_methodology(self):
        """Test getting Java methodology path."""
        path = get_methodology_path("java")
        assert path is not None
        assert path.exists()
        assert "java" in path.name

    def test_get_go_methodology(self):
        """Test getting Go methodology path."""
        path = get_methodology_path("go")
        assert path is not None
        assert path.exists()
        assert "go" in path.name

    def test_get_invalid_methodology(self):
        """Test getting invalid methodology returns None."""
        path = get_methodology_path("invalid_language")
        assert path is None


class TestListAvailableMethodologies:
    """Test list_available_methodologies function."""

    def test_list_returns_list(self):
        """Test that function returns a list."""
        result = list_available_methodologies()
        assert isinstance(result, list)

    def test_list_includes_general(self):
        """Test that general methodology is included."""
        result = list_available_methodologies()
        assert "general" in result

    def test_list_includes_languages(self):
        """Test that language methodologies are included."""
        result = list_available_methodologies()
        assert "python" in result
        assert "java" in result
        assert "go" in result


class TestMethodologyContent:
    """Test methodology document content."""

    def test_general_methodology_has_d9_sections(self):
        """Verify general methodology has D9 subtypes."""
        path = METHODOLOGY_FILES["general"]
        content = path.read_text()

        # Check for D9 subtypes (case-insensitive, supporting both English and Chinese)
        content_lower = content.lower()
        assert "idor" in content_lower
        assert "mass assignment" in content_lower or "mass_assignment" in content_lower
        assert "状态机" in content or "state_machine" in content_lower or "state machine" in content_lower
        assert "race condition" in content_lower or "race_condition" in content_lower or "竞态" in content

    def test_python_methodology_has_framework_sections(self):
        """Verify Python methodology has framework-specific content."""
        path = METHODOLOGY_FILES["python"]
        content = path.read_text()

        # Check for Python frameworks
        assert "Django" in content
        assert "Flask" in content
        assert "FastAPI" in content

    def test_java_methodology_has_spring_content(self):
        """Verify Java methodology has Spring-specific content."""
        path = METHODOLOGY_FILES["java"]
        content = path.read_text()

        # Check for Spring framework
        assert "Spring" in content

    def test_go_methodology_has_framework_sections(self):
        """Verify Go methodology has framework-specific content."""
        path = METHODOLOGY_FILES["go"]
        content = path.read_text()

        # Check for Go frameworks
        assert "Gin" in content
        assert "Echo" in content


class TestBusinessLogicCategory:
    """Test BusinessLogicCategory enum."""

    def test_category_idor_exists(self):
        """Verify IDOR category exists."""
        assert BusinessLogicCategory.IDOR.value == "idor"

    def test_category_mass_assignment_exists(self):
        """Verify Mass Assignment category exists."""
        assert BusinessLogicCategory.MASS_ASSIGNMENT.value == "mass_assignment"

    def test_category_state_machine_exists(self):
        """Verify State Machine category exists."""
        assert BusinessLogicCategory.STATE_MACHINE.value == "state_machine"

    def test_category_race_condition_exists(self):
        """Verify Race Condition category exists."""
        assert BusinessLogicCategory.RACE_CONDITION.value == "race_condition"

    def test_category_data_export_exists(self):
        """Verify Data Export category exists."""
        assert BusinessLogicCategory.DATA_EXPORT.value == "data_export"

    def test_category_multi_tenant_exists(self):
        """Verify Multi-tenant category exists."""
        assert BusinessLogicCategory.MULTI_TENANT.value == "multi_tenant"

    def test_all_categories_count(self):
        """Verify we have expected number of categories."""
        categories = list(BusinessLogicCategory)
        assert len(categories) == 6


# =============================================================================
# P6-07d: WooYun Case Library Tests
# =============================================================================


class TestWooYunDirectory:
    """Test WooYun case library directory structure."""

    def test_wooyun_directory_exists(self):
        """Verify WooYun directory exists."""
        assert WOOWYUN_DIR.exists()
        assert WOOWYUN_DIR.is_dir()

    def test_wooyun_directory_location(self):
        """Verify WooYun directory is under methodology."""
        assert "methodology" in str(WOOWYUN_DIR)
        assert "wooyun" in str(WOOWYUN_DIR)


class TestWooYunFiles:
    """Test WooYun file availability."""

    def test_wooyun_files_defined(self):
        """Verify WOOWYUN_FILES has expected keys."""
        expected_keys = {
            "index",
            "sql_injection",
            "xss",
            "command_execution",
            "logic_flaws",
            "file_upload",
            "unauthorized_access",
            "info_disclosure",
            "file_traversal",
        }
        assert expected_keys.issubset(WOOWYUN_FILES.keys())

    def test_wooyun_index_exists(self):
        """Verify WooYun INDEX.md exists."""
        path = WOOWYUN_FILES["index"]
        assert path.exists(), f"WooYun index not found: {path}"

    def test_sql_injection_file_exists(self):
        """Verify SQL injection methodology exists."""
        path = WOOWYUN_FILES["sql_injection"]
        assert path.exists(), f"SQL injection file not found: {path}"

    def test_xss_file_exists(self):
        """Verify XSS methodology exists."""
        path = WOOWYUN_FILES["xss"]
        assert path.exists(), f"XSS file not found: {path}"

    def test_command_execution_file_exists(self):
        """Verify command execution methodology exists."""
        path = WOOWYUN_FILES["command_execution"]
        assert path.exists(), f"Command execution file not found: {path}"

    def test_logic_flaws_file_exists(self):
        """Verify logic flaws methodology exists."""
        path = WOOWYUN_FILES["logic_flaws"]
        assert path.exists(), f"Logic flaws file not found: {path}"

    def test_file_upload_file_exists(self):
        """Verify file upload methodology exists."""
        path = WOOWYUN_FILES["file_upload"]
        assert path.exists(), f"File upload file not found: {path}"

    def test_unauthorized_access_file_exists(self):
        """Verify unauthorized access methodology exists."""
        path = WOOWYUN_FILES["unauthorized_access"]
        assert path.exists(), f"Unauthorized access file not found: {path}"

    def test_info_disclosure_file_exists(self):
        """Verify info disclosure methodology exists."""
        path = WOOWYUN_FILES["info_disclosure"]
        assert path.exists(), f"Info disclosure file not found: {path}"

    def test_file_traversal_file_exists(self):
        """Verify file traversal methodology exists."""
        path = WOOWYUN_FILES["file_traversal"]
        assert path.exists(), f"File traversal file not found: {path}"


class TestGetWooYunPath:
    """Test get_wooyun_path function."""

    def test_get_wooyun_index(self):
        """Test getting WooYun index path."""
        path = get_wooyun_path()
        assert path is not None
        assert path.exists()
        assert path.name == "INDEX.md"

    def test_get_sql_injection_path(self):
        """Test getting SQL injection path."""
        path = get_wooyun_path("sql_injection")
        assert path is not None
        assert path.exists()
        assert "sql-injection" in path.name

    def test_get_xss_path(self):
        """Test getting XSS path."""
        path = get_wooyun_path("xss")
        assert path is not None
        assert path.exists()

    def test_get_invalid_type(self):
        """Test getting invalid type returns None."""
        path = get_wooyun_path("invalid_type")
        assert path is None


class TestListAvailableWooYunTypes:
    """Test list_available_wooyun_types function."""

    def test_list_returns_list(self):
        """Test that function returns a list."""
        result = list_available_wooyun_types()
        assert isinstance(result, list)

    def test_list_includes_index(self):
        """Test that index is included."""
        result = list_available_wooyun_types()
        assert "index" in result

    def test_list_includes_vuln_types(self):
        """Test that vulnerability types are included."""
        result = list_available_wooyun_types()
        assert "sql_injection" in result
        assert "xss" in result
        assert "command_execution" in result


class TestWooYunStats:
    """Test WooYun statistics."""

    def test_stats_is_dict(self):
        """Test that stats is a dictionary."""
        stats = get_wooyun_stats()
        assert isinstance(stats, dict)

    def test_stats_has_total(self):
        """Test that stats has total count."""
        stats = get_wooyun_stats()
        assert "total" in stats
        assert stats["total"] == 88636

    def test_stats_sql_injection_count(self):
        """Test SQL injection case count."""
        stats = get_wooyun_stats()
        assert stats["sql_injection"] == 27732

    def test_stats_all_types_present(self):
        """Test all vulnerability types have stats."""
        stats = get_wooyun_stats()
        expected_types = [
            "sql_injection",
            "xss",
            "command_execution",
            "logic_flaws",
            "file_upload",
            "unauthorized_access",
            "info_disclosure",
            "file_traversal",
        ]
        for vuln_type in expected_types:
            assert vuln_type in stats
            assert stats[vuln_type] > 0


class TestWooYunContent:
    """Test WooYun document content."""

    def test_index_has_statistics(self):
        """Verify index has vulnerability statistics."""
        path = WOOWYUN_FILES["index"]
        content = path.read_text()
        assert "88,636" in content or "88636" in content

    def test_index_has_vuln_types(self):
        """Verify index lists all vulnerability types."""
        path = WOOWYUN_FILES["index"]
        content = path.read_text()
        assert "SQL注入" in content or "SQL" in content
        assert "XSS" in content
        assert "命令执行" in content or "command" in content.lower()

    def test_sql_injection_has_methodology(self):
        """Verify SQL injection has methodology content."""
        path = WOOWYUN_FILES["sql_injection"]
        content = path.read_text()
        # Check for key methodology elements
        assert "注入" in content or "injection" in content.lower()
        assert "绕过" in content or "bypass" in content.lower()
