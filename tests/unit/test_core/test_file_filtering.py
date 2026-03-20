"""
Unit tests for directory classification (P6-07).

Tests for DirectoryClass enum, classify_directory(), and get_score_multiplier().
"""

import pytest
from pathlib import Path

from src.core.file_filtering import (
    DirectoryClass,
    classify_directory,
    get_score_multiplier,
    SCORE_MULTIPLIERS,
    DIRECTORY_CLASSIFICATION_RULES,
    FILENAME_CLASSIFICATION_RULES,
)


class TestDirectoryClass:
    """Test DirectoryClass enum."""

    def test_enum_values(self):
        """Test all enum values are correct."""
        assert DirectoryClass.PRODUCTION.value == "production_code"
        assert DirectoryClass.TEST.value == "test_code"
        assert DirectoryClass.SAMPLE.value == "sample_code"
        assert DirectoryClass.FIXTURE.value == "fixture_code"
        assert DirectoryClass.CHALLENGE.value == "challenge_code"

    def test_enum_count(self):
        """Test we have exactly 5 directory classes."""
        assert len(DirectoryClass) == 5

    def test_enum_is_string(self):
        """Test enum values are strings."""
        assert isinstance(DirectoryClass.PRODUCTION.value, str)


class TestClassifyDirectory:
    """Test classify_directory function."""

    # --- Test directories ---

    def test_classify_test_directory(self):
        """Test test directories are classified as TEST."""
        assert classify_directory("tests/test_main.py") == DirectoryClass.TEST
        assert classify_directory("test/unit/test_x.py") == DirectoryClass.TEST
        assert classify_directory("__tests__/component.test.js") == DirectoryClass.TEST
        assert classify_directory("spec/models/user_spec.rb") == DirectoryClass.TEST
        assert classify_directory("specs/api.spec.ts") == DirectoryClass.TEST
        assert classify_directory("integration/test_api.py") == DirectoryClass.TEST
        assert classify_directory("e2e/test_login.py") == DirectoryClass.TEST
        assert classify_directory("unit/test_utils.py") == DirectoryClass.TEST

    def test_classify_fixture_directory(self):
        """Test fixture directories are classified as FIXTURE."""
        assert classify_directory("tests/fixtures/data.json") == DirectoryClass.FIXTURE
        assert classify_directory("testdata/input.xml") == DirectoryClass.FIXTURE
        assert classify_directory("test_data/users.json") == DirectoryClass.FIXTURE
        assert classify_directory("mocks/user_mock.py") == DirectoryClass.FIXTURE
        assert classify_directory("stubs/api_stub.py") == DirectoryClass.FIXTURE
        assert classify_directory("fake/fake_service.py") == DirectoryClass.FIXTURE
        assert classify_directory("factories/user_factory.py") == DirectoryClass.FIXTURE

    def test_classify_sample_directory(self):
        """Test sample directories are classified as SAMPLE."""
        assert classify_directory("examples/demo.py") == DirectoryClass.SAMPLE
        assert classify_directory("samples/basic_usage.js") == DirectoryClass.SAMPLE
        assert classify_directory("demo/app.py") == DirectoryClass.SAMPLE
        assert classify_directory("tutorials/getting_started.py") == DirectoryClass.SAMPLE

    def test_classify_challenge_directory(self):
        """Test challenge directories are classified as CHALLENGE."""
        assert classify_directory("challenges/sql_injection.py") == DirectoryClass.CHALLENGE
        assert classify_directory("juice-shop/server.js") == DirectoryClass.CHALLENGE
        assert classify_directory("ctf/web_challenge.py") == DirectoryClass.CHALLENGE
        assert classify_directory("dvwa/vulnerabilities/sqli.php") == DirectoryClass.CHALLENGE
        assert classify_directory("webgoat/lessons/xss.java") == DirectoryClass.CHALLENGE
        assert classify_directory("vulnerable/app.py") == DirectoryClass.CHALLENGE
        assert classify_directory("vuln-apps/demo.py") == DirectoryClass.CHALLENGE

    def test_classify_production_directory(self):
        """Test production directories are classified as PRODUCTION."""
        assert classify_directory("src/main.py") == DirectoryClass.PRODUCTION
        assert classify_directory("lib/utils.js") == DirectoryClass.PRODUCTION
        assert classify_directory("app/handlers/user.go") == DirectoryClass.PRODUCTION
        assert classify_directory("api/controllers/user_controller.py") == DirectoryClass.PRODUCTION
        assert classify_directory("internal/service/auth.go") == DirectoryClass.PRODUCTION
        assert classify_directory("pkg/crypto/hash.go") == DirectoryClass.PRODUCTION

    # --- Test file patterns ---

    def test_classify_test_file_pattern_python(self):
        """Test Python test file patterns."""
        assert classify_directory("src/main_test.py") == DirectoryClass.TEST
        assert classify_directory("utils/test_helper.py") == DirectoryClass.TEST
        assert classify_directory("api/handler_spec.py") == DirectoryClass.TEST

    def test_classify_test_file_pattern_javascript(self):
        """Test JavaScript/TypeScript test file patterns."""
        assert classify_directory("utils/helper.test.js") == DirectoryClass.TEST
        assert classify_directory("components/Button.spec.tsx") == DirectoryClass.TEST
        assert classify_directory("services/api_test.js") == DirectoryClass.TEST

    def test_classify_test_file_pattern_go(self):
        """Test Go test file patterns."""
        assert classify_directory("pkg/handler/handler_test.go") == DirectoryClass.TEST
        assert classify_directory("internal/service/user_test.go") == DirectoryClass.TEST

    def test_classify_test_file_pattern_java(self):
        """Test Java test file patterns."""
        assert classify_directory("src/UserTest.java") == DirectoryClass.TEST
        assert classify_directory("src/CalculatorTests.java") == DirectoryClass.TEST

    def test_classify_fixture_file_pattern(self):
        """Test fixture file patterns."""
        assert classify_directory("data/fixture_users.json") == DirectoryClass.FIXTURE
        assert classify_directory("data/users.fixture.json") == DirectoryClass.FIXTURE
        assert classify_directory("mocks/user_mock.py") == DirectoryClass.FIXTURE
        assert classify_directory("stubs/service.stub.py") == DirectoryClass.FIXTURE

    # --- Test priority ---

    def test_priority_challenge_over_test(self):
        """Test Challenge has higher priority than Test."""
        # juice-shop is challenge, but contains 'tests' path
        assert classify_directory("juice-shop/tests/test_x.py") == DirectoryClass.CHALLENGE
        assert classify_directory("dvwa/test/test_unit.py") == DirectoryClass.CHALLENGE

    def test_priority_fixture_over_test(self):
        """Test Fixture has higher priority than Test."""
        # fixtures is fixture, under tests directory
        assert classify_directory("tests/fixtures/data.json") == DirectoryClass.FIXTURE
        assert classify_directory("test/mocks/user.py") == DirectoryClass.FIXTURE

    def test_priority_sample_over_test(self):
        """Test Sample has higher priority than Test."""
        assert classify_directory("examples/test_demo.py") == DirectoryClass.SAMPLE
        assert classify_directory("demo/test_example.py") == DirectoryClass.SAMPLE

    # --- Test custom rules ---

    def test_custom_rules_challenge(self):
        """Test custom rules for challenge classification."""
        custom = {"challenge_code": ["my-vuln-app", "security-demo"]}
        assert classify_directory("my-vuln-app/exploit.py", custom_rules=custom) == DirectoryClass.CHALLENGE
        assert classify_directory("security-demo/xss.py", custom_rules=custom) == DirectoryClass.CHALLENGE

    def test_custom_rules_test(self):
        """Test custom rules for test classification."""
        custom = {"test_code": ["__tests__", "__spec__"]}
        assert classify_directory("__tests__/main.js", custom_rules=custom) == DirectoryClass.TEST
        assert classify_directory("__spec__/api.rb", custom_rules=custom) == DirectoryClass.TEST

    def test_custom_rules_override_default(self):
        """Test custom rules override default classification."""
        # By default, src/ is production
        assert classify_directory("src/main.py") == DirectoryClass.PRODUCTION
        # But with custom rule, it can be overridden
        custom = {"test_code": ["src"]}
        assert classify_directory("src/main.py", custom_rules=custom) == DirectoryClass.TEST

    def test_custom_rules_invalid_class_ignored(self):
        """Test invalid class names in custom rules are ignored."""
        custom = {"invalid_class": ["src"]}
        # Should fall back to default classification
        assert classify_directory("src/main.py", custom_rules=custom) == DirectoryClass.PRODUCTION

    # --- Test edge cases ---

    def test_windows_path(self):
        """Test Windows-style paths are handled."""
        # The function normalizes backslashes
        assert classify_directory("tests\\test_main.py") == DirectoryClass.TEST
        assert classify_directory("src\\main.py") == DirectoryClass.PRODUCTION

    def test_path_object(self):
        """Test Path objects are accepted."""
        assert classify_directory(Path("tests/test_main.py")) == DirectoryClass.TEST
        assert classify_directory(Path("src/main.py")) == DirectoryClass.PRODUCTION

    def test_nested_directories(self):
        """Test deeply nested directories."""
        assert classify_directory("a/b/c/tests/unit/test.py") == DirectoryClass.TEST
        assert classify_directory("a/b/c/examples/demo/demo.py") == DirectoryClass.SAMPLE
        assert classify_directory("a/b/c/juice-shop/app.js") == DirectoryClass.CHALLENGE

    def test_empty_path(self):
        """Test empty or minimal path."""
        assert classify_directory("") == DirectoryClass.PRODUCTION
        assert classify_directory("file.py") == DirectoryClass.PRODUCTION

    def test_case_insensitive(self):
        """Test classification is case-insensitive."""
        assert classify_directory("TESTS/test.py") == DirectoryClass.TEST
        assert classify_directory("Tests/test.py") == DirectoryClass.TEST
        assert classify_directory("EXAMPLES/demo.py") == DirectoryClass.SAMPLE
        assert classify_directory("JUICE-SHOP/app.js") == DirectoryClass.CHALLENGE


class TestGetScoreMultiplier:
    """Test get_score_multiplier function."""

    def test_production_multiplier(self):
        """Test production has no multiplier."""
        assert get_score_multiplier(DirectoryClass.PRODUCTION) == 1.0

    def test_test_multiplier(self):
        """Test test has 0.3 multiplier."""
        assert get_score_multiplier(DirectoryClass.TEST) == 0.3

    def test_fixture_multiplier(self):
        """Test fixture has 0.2 multiplier."""
        assert get_score_multiplier(DirectoryClass.FIXTURE) == 0.2

    def test_sample_multiplier(self):
        """Test sample has 0.1 multiplier."""
        assert get_score_multiplier(DirectoryClass.SAMPLE) == 0.1

    def test_challenge_multiplier(self):
        """Test challenge has 0.1 multiplier."""
        assert get_score_multiplier(DirectoryClass.CHALLENGE) == 0.1

    def test_all_multipliers_in_valid_range(self):
        """Test all default multipliers are in valid range."""
        for dir_class in DirectoryClass:
            multiplier = get_score_multiplier(dir_class)
            assert 0.0 <= multiplier <= 1.0, f"Multiplier for {dir_class} out of range"

    def test_custom_multipliers_override(self):
        """Test custom multipliers override defaults."""
        custom = {"test_code": 0.5, "challenge_code": 0.0}
        assert get_score_multiplier(DirectoryClass.TEST, custom_multipliers=custom) == 0.5
        assert get_score_multiplier(DirectoryClass.CHALLENGE, custom_multipliers=custom) == 0.0

    def test_custom_multipliers_partial(self):
        """Test partial custom multipliers don't affect other classes."""
        custom = {"test_code": 0.5}
        # Test has custom multiplier
        assert get_score_multiplier(DirectoryClass.TEST, custom_multipliers=custom) == 0.5
        # Other classes use defaults
        assert get_score_multiplier(DirectoryClass.PRODUCTION, custom_multipliers=custom) == 1.0
        assert get_score_multiplier(DirectoryClass.SAMPLE, custom_multipliers=custom) == 0.1

    def test_custom_multipliers_clamped_high(self):
        """Test custom multipliers above 1.0 are clamped."""
        custom = {"test_code": 2.0}
        assert get_score_multiplier(DirectoryClass.TEST, custom_multipliers=custom) == 1.0

    def test_custom_multipliers_clamped_low(self):
        """Test custom multipliers below 0.0 are clamped."""
        custom = {"test_code": -0.5}
        assert get_score_multiplier(DirectoryClass.TEST, custom_multipliers=custom) == 0.0


class TestScoreMultipliersConstant:
    """Test SCORE_MULTIPLIERS constant."""

    def test_all_classes_have_multipliers(self):
        """Test all DirectoryClass values have a multiplier defined."""
        for dir_class in DirectoryClass:
            assert dir_class in SCORE_MULTIPLIERS, f"Missing multiplier for {dir_class}"

    def test_production_is_highest(self):
        """Test production has the highest multiplier."""
        for dir_class, multiplier in SCORE_MULTIPLIERS.items():
            if dir_class != DirectoryClass.PRODUCTION:
                assert SCORE_MULTIPLIERS[DirectoryClass.PRODUCTION] >= multiplier


class TestClassificationRules:
    """Test classification rule constants."""

    def test_directory_rules_not_empty(self):
        """Test directory classification rules are defined."""
        assert len(DIRECTORY_CLASSIFICATION_RULES) > 0

    def test_directory_rules_ordered_by_priority(self):
        """Test directory rules are ordered (challenge first, test last)."""
        # First rule should be challenge
        _, first_class = DIRECTORY_CLASSIFICATION_RULES[0]
        assert first_class == DirectoryClass.CHALLENGE
        # Last rule should be test
        _, last_class = DIRECTORY_CLASSIFICATION_RULES[-1]
        assert last_class == DirectoryClass.TEST

    def test_filename_rules_not_empty(self):
        """Test filename classification rules are defined."""
        assert len(FILENAME_CLASSIFICATION_RULES) > 0

    def test_filename_rules_are_regex(self):
        """Test filename rules are valid regex patterns."""
        import re
        for pattern, _ in FILENAME_CLASSIFICATION_RULES:
            # Should not raise
            re.compile(pattern)
