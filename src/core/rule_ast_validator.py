"""
Rule AST Validator - Validates Semgrep rules for semantic matching.

This module enforces that only rules with AST-level semantic matching
are executed, rejecting literal-only rules that cause false positive
explosions.

Core principle: Precision over recall. Eliminate literal rules that
match strings in comments, documentation, and other non-code contexts.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.core.logger.logger import get_logger


class RuleValidationStatus(str, Enum):
    """Status of rule validation."""

    VALID = "valid"
    """Rule has AST semantic matching capabilities."""

    LITERAL_ONLY = "literal_only"
    """Rule only performs literal string matching, no AST structure."""

    INVALID_STRUCTURE = "invalid_structure"
    """Rule has invalid structure that cannot be validated."""


@dataclass
class RuleValidationResult:
    """Result of validating a single rule."""

    rule_id: str
    """Unique identifier of the rule."""

    status: RuleValidationStatus
    """Validation status of the rule."""

    reason: str
    """Human-readable reason for the status."""

    pattern_count: int = 0
    """Number of patterns found in the rule."""

    has_metavariable: bool = False
    """Whether the rule uses metavariables like $X."""

    has_structure: bool = False
    """Whether the rule has AST structure features."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for metadata storage."""
        return {
            "rule_id": self.rule_id,
            "status": self.status.value,
            "reason": self.reason,
            "pattern_count": self.pattern_count,
            "has_metavariable": self.has_metavariable,
            "has_structure": self.has_structure,
        }


@dataclass
class ASTValidationSummary:
    """Summary of AST validation across all rules."""

    validated_count: int = 0
    """Number of rules that passed validation."""

    rejected_count: int = 0
    """Number of rules rejected (LITERAL_ONLY + INVALID_STRUCTURE)."""

    disabled_literal_rules: list[str] = field(default_factory=list)
    """List of rule IDs that were rejected."""

    rejection_rate: str = "0.0%"
    """Percentage of rules rejected."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for metadata storage."""
        return {
            "validated_count": self.validated_count,
            "rejected_count": self.rejected_count,
            "disabled_literal_rules": self.disabled_literal_rules,
            "rejection_rate": self.rejection_rate,
        }


# Metavariable pattern: $X, $VAR, $FUNCTION_NAME, etc.
METAVARIABLE_PATTERN = re.compile(r'\$[A-Z_][A-Z0-9_]*')

# AST structure keywords that indicate semantic matching
AST_STRUCTURE_KEYWORDS = [
    # Function/method calls
    r'\$[A-Z_]+\s*\(',  # $FUNC(
    r'\.\s*\$[A-Z_]+\s*\(',  # .method(
    r'\.\s*\w+\s*\(',  # .method(

    # Assignments
    r'\$[A-Z_]+\s*=',  # $X =
    r'\w+\s*=\s*\$[A-Z_]+',  # var = $X
    r'\w+\s*=\s*[^"$\'\s]',  # var = something (not string literal)

    # Function definitions
    r'\bfunction\s+\$[A-Z_]+',
    r'\bdef\s+\$[A-Z_]+',
    r'\basync\s+function',
    r'\basync\s+def',

    # Class definitions
    r'\bclass\s+\$[A-Z_]+',
    r'\bclass\s+\w+\s*:',

    # Control flow
    r'\bif\s*\(',
    r'\bwhile\s*\(',
    r'\bfor\s*\(',
    r'\bswitch\s*\(',
    r'\btry\s*\{',
    r'\btry\s*:',

    # Import/require
    r'\bimport\s+\$[A-Z_]+',
    r'\bfrom\s+\$[A-Z_]+\s+import',
    r'\brequire\s*\(',
    r'\brequire\s+\$[A-Z_]+',

    # Property access
    r'\$[A-Z_]+\s*\.\s*\$?[A-Z_]*',  # $OBJ.property or $OBJ.$PROP

    # Operators (in patterns, not just strings)
    r'==\s*\$[A-Z_]+',
    r'!=\s*\$[A-Z_]+',
    r'>=\s*\$[A-Z_]+',
    r'<=\s*\$[A-Z_]+',

    # Return statements
    r'\breturn\s+\$[A-Z_]+',

    # New/instantiation
    r'\bnew\s+\$[A-Z_]+',
    r'\bnew\s+\w+',

    # Await
    r'\bawait\s+\$[A-Z_]+',

    # Throw/raise
    r'\bthrow\s+\$[A-Z_]+',
    r'\braise\s+\$[A-Z_]+',
]

# Compile patterns for performance
AST_STRUCTURE_COMPILED = [re.compile(p) for p in AST_STRUCTURE_KEYWORDS]


class RuleASTValidator:
    """
    Validator for Semgrep rules to enforce AST semantic matching.

    This validator rejects rules that only perform literal string matching,
    which are the primary source of false positives in security scanning.

    Rules are VALID if they use any of:
    - Metavariables ($X, $VAR, etc.)
    - pattern-either (multiple patterns)
    - patterns: (compound logic)
    - pattern-inside: (context constraints)
    - pattern-regex with structure
    - AST structure keywords

    Rules are LITERAL_ONLY if they only have:
    - Single pattern: "some_string" with no metavariables
    - No compound logic
    - No context constraints
    - No AST structure features
    """

    def __init__(self) -> None:
        """Initialize the validator."""
        self.logger = get_logger(__name__)

    def validate_rule(self, rule: dict[str, Any]) -> RuleValidationResult:
        """
        Validate a single Semgrep rule.

        Args:
            rule: Parsed Semgrep rule dictionary.

        Returns:
            RuleValidationResult with validation status and details.
        """
        rule_id = rule.get("id", "unknown")

        try:
            # Check for valid rule structure
            if "id" not in rule:
                return RuleValidationResult(
                    rule_id=rule_id,
                    status=RuleValidationStatus.INVALID_STRUCTURE,
                    reason="Rule missing 'id' field",
                )

            # Count patterns and check features
            pattern_count = 0
            has_metavariable = False
            has_structure = False
            has_pattern_either = False
            has_patterns = False
            has_pattern_inside = False
            has_pattern_regex = False

            # Check all pattern-related fields
            rule_str = str(rule)

            # Check for metavariables
            if METAVARIABLE_PATTERN.search(rule_str):
                has_metavariable = True

            # Check for AST structure keywords
            for pattern in AST_STRUCTURE_COMPILED:
                if pattern.search(rule_str):
                    has_structure = True
                    break

            # Count and categorize patterns
            if "pattern" in rule:
                pattern_count += 1
                pattern_value = rule["pattern"]
                if isinstance(pattern_value, str):
                    # Check if the pattern has structure
                    if self._pattern_has_structure(pattern_value):
                        has_structure = True

            if "pattern-either" in rule:
                has_pattern_either = True
                pattern_count += len(rule.get("pattern-either", []))

            if "patterns" in rule:
                has_patterns = True
                patterns_list = rule.get("patterns", [])
                pattern_count += len(patterns_list)

                # Check nested patterns
                for p in patterns_list:
                    if "pattern-inside" in p:
                        has_pattern_inside = True
                    if "pattern-regex" in p:
                        has_pattern_regex = True

            if "pattern-regex" in rule:
                has_pattern_regex = True
                pattern_count += 1

            if "pattern-inside" in rule:
                has_pattern_inside = True
                pattern_count += 1

            # Determine validity
            # VALID if any of these conditions are met:
            is_valid = (
                has_metavariable or
                has_pattern_either or
                has_patterns or
                has_pattern_inside or
                (has_pattern_regex and has_structure) or
                has_structure
            )

            if is_valid:
                return RuleValidationResult(
                    rule_id=rule_id,
                    status=RuleValidationStatus.VALID,
                    reason="Rule has AST semantic matching capabilities",
                    pattern_count=pattern_count,
                    has_metavariable=has_metavariable,
                    has_structure=has_structure,
                )
            else:
                return RuleValidationResult(
                    rule_id=rule_id,
                    status=RuleValidationStatus.LITERAL_ONLY,
                    reason="Rule only performs literal string matching",
                    pattern_count=pattern_count,
                    has_metavariable=has_metavariable,
                    has_structure=has_structure,
                )

        except Exception as e:
            return RuleValidationResult(
                rule_id=rule_id,
                status=RuleValidationStatus.INVALID_STRUCTURE,
                reason=f"Validation error: {e}",
            )

    def _pattern_has_structure(self, pattern: str) -> bool:
        """
        Check if a pattern string has AST structure features.

        Args:
            pattern: Pattern string to check.

        Returns:
            True if pattern has structure features.
        """
        # Check for metavariables
        if METAVARIABLE_PATTERN.search(pattern):
            return True

        # Check for AST structure keywords
        for compiled_pattern in AST_STRUCTURE_COMPILED:
            if compiled_pattern.search(pattern):
                return True

        # Check for common code structures
        # Function calls (not just strings)
        if re.search(r'\w+\s*\([^)]*\)', pattern):
            # But not if it's just a string literal check
            if not re.match(r'^["\'].*["\']$', pattern.strip()):
                return True

        return False

    def validate_rules(
        self,
        rules: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], ASTValidationSummary]:
        """
        Validate a list of rules and filter out literal-only rules.

        Args:
            rules: List of Semgrep rule dictionaries.

        Returns:
            Tuple of (valid_rules, validation_summary).
        """
        valid_rules = []
        disabled_rules = []

        for rule in rules:
            result = self.validate_rule(rule)

            if result.status == RuleValidationStatus.VALID:
                valid_rules.append(rule)
            else:
                disabled_rules.append(result.rule_id)
                self.logger.debug(
                    f"Rejected rule '{result.rule_id}': {result.reason}"
                )

        # Calculate summary
        total = len(rules)
        rejected = len(disabled_rules)
        validated = len(valid_rules)

        if total > 0:
            rejection_rate = f"{(rejected / total) * 100:.1f}%"
        else:
            rejection_rate = "0.0%"

        summary = ASTValidationSummary(
            validated_count=validated,
            rejected_count=rejected,
            disabled_literal_rules=disabled_rules,
            rejection_rate=rejection_rate,
        )

        if rejected > 0:
            self.logger.info(
                f"AST validation: {validated} valid, {rejected} rejected "
                f"({rejection_rate} rejection rate)"
            )

        return valid_rules, summary

    def get_validation_status(
        self,
        rule: dict[str, Any],
    ) -> RuleValidationStatus:
        """
        Get the validation status of a rule.

        Args:
            rule: Semgrep rule dictionary.

        Returns:
            RuleValidationStatus enum value.
        """
        result = self.validate_rule(rule)
        return result.status


# Module-level convenience functions
def validate_rule(rule: dict[str, Any]) -> RuleValidationResult:
    """
    Validate a single Semgrep rule.

    Args:
        rule: Semgrep rule dictionary.

    Returns:
        RuleValidationResult with validation status.
    """
    validator = RuleASTValidator()
    return validator.validate_rule(rule)


def validate_rules(
    rules: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], ASTValidationSummary]:
    """
    Validate a list of rules and filter out literal-only rules.

    Args:
        rules: List of Semgrep rule dictionaries.

    Returns:
        Tuple of (valid_rules, validation_summary).
    """
    validator = RuleASTValidator()
    return validator.validate_rules(rules)
