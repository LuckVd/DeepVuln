"""Unit tests for Rule AST Validator module."""

import pytest

from src.core.rule_ast_validator import (
    RuleASTValidator,
    RuleValidationStatus,
    RuleValidationResult,
    ASTValidationSummary,
    validate_rule,
    validate_rules,
    METAVARIABLE_PATTERN,
)


class TestMetavariablePattern:
    """Test the metavariable regex pattern."""

    def test_simple_metavariable(self):
        """Test simple metavariable like $X."""
        assert METAVARIABLE_PATTERN.search("$X")
        assert METAVARIABLE_PATTERN.search("pattern: $X")

    def test_underscore_metavariable(self):
        """Test metavariable with underscore like $VAR_NAME."""
        assert METAVARIABLE_PATTERN.search("$VAR_NAME")
        assert METAVARIABLE_PATTERN.search("$MY_VAR")

    def test_numeric_suffix_metavariable(self):
        """Test metavariable with numeric suffix like $X123."""
        assert METAVARIABLE_PATTERN.search("$X123")
        assert METAVARIABLE_PATTERN.search("$VAR1")

    def test_no_lowercase_start(self):
        """Metavariables must start with uppercase."""
        # Lowercase should not match
        assert not METAVARIABLE_PATTERN.search("$x")
        assert not METAVARIABLE_PATTERN.search("$var")

    def test_in_code_context(self):
        """Test metavariable in code context."""
        pattern = "eval($USER_INPUT)"
        match = METAVARIABLE_PATTERN.search(pattern)
        assert match is not None
        assert match.group() == "$USER_INPUT"


class TestRuleValidationStatus:
    """Test the RuleValidationStatus enum."""

    def test_valid_status(self):
        """Test VALID status value."""
        assert RuleValidationStatus.VALID.value == "valid"

    def test_literal_only_status(self):
        """Test LITERAL_ONLY status value."""
        assert RuleValidationStatus.LITERAL_ONLY.value == "literal_only"

    def test_invalid_structure_status(self):
        """Test INVALID_STRUCTURE status value."""
        assert RuleValidationStatus.INVALID_STRUCTURE.value == "invalid_structure"


class TestRuleValidationResult:
    """Test the RuleValidationResult dataclass."""

    def test_create_valid_result(self):
        """Test creating a valid result."""
        result = RuleValidationResult(
            rule_id="test.rule.valid",
            status=RuleValidationStatus.VALID,
            reason="Rule has AST semantic matching",
            pattern_count=2,
            has_metavariable=True,
            has_structure=True,
        )
        assert result.rule_id == "test.rule.valid"
        assert result.status == RuleValidationStatus.VALID
        assert result.has_metavariable is True

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = RuleValidationResult(
            rule_id="test.rule",
            status=RuleValidationStatus.LITERAL_ONLY,
            reason="Literal string only",
            pattern_count=1,
            has_metavariable=False,
            has_structure=False,
        )
        d = result.to_dict()
        assert d["rule_id"] == "test.rule"
        assert d["status"] == "literal_only"
        assert d["has_metavariable"] is False


class TestASTValidationSummary:
    """Test the ASTValidationSummary dataclass."""

    def test_empty_summary(self):
        """Test creating empty summary."""
        summary = ASTValidationSummary()
        assert summary.validated_count == 0
        assert summary.rejected_count == 0
        assert summary.disabled_literal_rules == []
        assert summary.rejection_rate == "0.0%"

    def test_summary_with_data(self):
        """Test summary with data."""
        summary = ASTValidationSummary(
            validated_count=100,
            rejected_count=20,
            disabled_literal_rules=["rule1", "rule2"],
            rejection_rate="16.7%",
        )
        assert summary.validated_count == 100
        assert summary.rejected_count == 20
        assert len(summary.disabled_literal_rules) == 2

    def test_to_dict(self):
        """Test converting summary to dictionary."""
        summary = ASTValidationSummary(
            validated_count=80,
            rejected_count=20,
            disabled_literal_rules=["rule1", "rule2", "rule3"],
            rejection_rate="20.0%",
        )
        d = summary.to_dict()
        assert d["validated_count"] == 80
        assert d["rejected_count"] == 20
        assert len(d["disabled_literal_rules"]) == 3
        assert d["rejection_rate"] == "20.0%"


class TestRuleASTValidator:
    """Test the RuleASTValidator class."""

    @pytest.fixture
    def validator(self):
        """Create a validator instance."""
        return RuleASTValidator()

    def test_validate_rule_with_metavariable(self, validator):
        """Test rule with metavariable is VALID."""
        rule = {
            "id": "test.rule.with_metavar",
            "pattern": "eval($USER_INPUT)",
        }
        result = validator.validate_rule(rule)
        assert result.status == RuleValidationStatus.VALID
        assert result.has_metavariable is True

    def test_validate_rule_with_pattern_either(self, validator):
        """Test rule with pattern-either is VALID."""
        rule = {
            "id": "test.rule.pattern_either",
            "pattern-either": [
                {"pattern": "dangerous_call1()"},
                {"pattern": "dangerous_call2()"},
            ],
        }
        result = validator.validate_rule(rule)
        assert result.status == RuleValidationStatus.VALID

    def test_validate_rule_with_patterns(self, validator):
        """Test rule with patterns is VALID."""
        rule = {
            "id": "test.rule.patterns",
            "patterns": [
                {"pattern": "eval(...)"},
                {"pattern-not": "eval(safe)"},
            ],
        }
        result = validator.validate_rule(rule)
        assert result.status == RuleValidationStatus.VALID

    def test_validate_rule_with_pattern_inside(self, validator):
        """Test rule with pattern-inside is VALID."""
        rule = {
            "id": "test.rule.pattern_inside",
            "patterns": [
                {"pattern-inside": "function $FUNC(...) {...}"},
                {"pattern": "dangerous_call()"},
            ],
        }
        result = validator.validate_rule(rule)
        assert result.status == RuleValidationStatus.VALID

    def test_validate_rule_with_function_call(self, validator):
        """Test rule with function call structure is VALID."""
        rule = {
            "id": "test.rule.func_call",
            "pattern": "dangerous_func($VAR)",
        }
        result = validator.validate_rule(rule)
        assert result.status == RuleValidationStatus.VALID
        assert result.has_structure is True

    def test_validate_literal_only_rule(self, validator):
        """Test literal-only rule is LITERAL_ONLY."""
        rule = {
            "id": "test.rule.literal",
            "pattern": "eval(",  # Just a string, no structure
        }
        result = validator.validate_rule(rule)
        # This should be LITERAL_ONLY because:
        # - No metavariables
        # - No pattern-either/patterns
        # - No AST structure features
        assert result.status == RuleValidationStatus.LITERAL_ONLY

    def test_validate_literal_string_rule(self, validator):
        """Test pure string matching rule is LITERAL_ONLY."""
        rule = {
            "id": "test.rule.string_only",
            "pattern": "password",  # Pure string match
        }
        result = validator.validate_rule(rule)
        assert result.status == RuleValidationStatus.LITERAL_ONLY
        assert result.has_metavariable is False
        assert result.has_structure is False

    def test_validate_rule_missing_id(self, validator):
        """Test rule without id is INVALID_STRUCTURE."""
        rule = {
            "pattern": "something",
        }
        result = validator.validate_rule(rule)
        assert result.status == RuleValidationStatus.INVALID_STRUCTURE

    def test_validate_rule_with_assignment(self, validator):
        """Test rule with assignment is VALID."""
        rule = {
            "id": "test.rule.assignment",
            "pattern": "$VAR = dangerous_value",
        }
        result = validator.validate_rule(rule)
        assert result.status == RuleValidationStatus.VALID

    def test_validate_rule_with_class_definition(self, validator):
        """Test rule with class definition is VALID."""
        rule = {
            "id": "test.rule.class",
            "pattern": "class $CLASS:",
        }
        result = validator.validate_rule(rule)
        assert result.status == RuleValidationStatus.VALID

    def test_validate_rule_with_method_call(self, validator):
        """Test rule with method call is VALID."""
        rule = {
            "id": "test.rule.method",
            "pattern": "$OBJ.dangerousMethod(...)",
        }
        result = validator.validate_rule(rule)
        assert result.status == RuleValidationStatus.VALID


class TestValidateRules:
    """Test the validate_rules function."""

    def test_validate_rules_mixed(self):
        """Test validating a mix of valid and invalid rules."""
        rules = [
            {
                "id": "valid.rule.metavar",
                "pattern": "eval($X)",
            },
            {
                "id": "literal.rule.string",
                "pattern": "password",
            },
            {
                "id": "valid.rule.patterns",
                "patterns": [
                    {"pattern": "dangerous()"},
                ],
            },
        ]
        valid_rules, summary = validate_rules(rules)

        assert len(valid_rules) == 2  # Two valid rules
        assert summary.validated_count == 2
        assert summary.rejected_count == 1
        assert "literal.rule.string" in summary.disabled_literal_rules

    def test_validate_rules_all_valid(self):
        """Test validating all valid rules."""
        rules = [
            {"id": "rule1", "pattern": "eval($X)"},
            {"id": "rule2", "pattern": "$OBJ.method()"},
        ]
        valid_rules, summary = validate_rules(rules)

        assert len(valid_rules) == 2
        assert summary.rejected_count == 0
        assert summary.rejection_rate == "0.0%"

    def test_validate_rules_all_literal(self):
        """Test validating all literal rules."""
        rules = [
            {"id": "rule1", "pattern": "password"},
            {"id": "rule2", "pattern": "secret"},
        ]
        valid_rules, summary = validate_rules(rules)

        assert len(valid_rules) == 0
        assert summary.validated_count == 0
        assert summary.rejected_count == 2
        assert summary.rejection_rate == "100.0%"

    def test_validate_rules_empty(self):
        """Test validating empty rule list."""
        valid_rules, summary = validate_rules([])

        assert len(valid_rules) == 0
        assert summary.validated_count == 0
        assert summary.rejected_count == 0


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_validate_rule_function(self):
        """Test the validate_rule convenience function."""
        rule = {"id": "test", "pattern": "eval($X)"}
        result = validate_rule(rule)

        assert isinstance(result, RuleValidationResult)
        assert result.status == RuleValidationStatus.VALID

    def test_validate_rules_function(self):
        """Test the validate_rules convenience function."""
        rules = [
            {"id": "rule1", "pattern": "eval($X)"},
            {"id": "rule2", "pattern": "password"},
        ]
        valid_rules, summary = validate_rules(rules)

        assert isinstance(summary, ASTValidationSummary)
        assert len(valid_rules) == 1


class TestPatternHasStructure:
    """Test the _pattern_has_structure method."""

    @pytest.fixture
    def validator(self):
        """Create a validator instance."""
        return RuleASTValidator()

    def test_pattern_with_metavariable(self, validator):
        """Test pattern with metavariable has structure."""
        assert validator._pattern_has_structure("eval($X)") is True

    def test_pattern_with_function_call(self, validator):
        """Test pattern with function call has structure."""
        assert validator._pattern_has_structure("some_func()") is True

    def test_pattern_pure_string(self, validator):
        """Test pure string pattern has no structure."""
        assert validator._pattern_has_structure("password") is False

    def test_pattern_with_method_call(self, validator):
        """Test pattern with method call has structure."""
        assert validator._pattern_has_structure("obj.method()") is True
