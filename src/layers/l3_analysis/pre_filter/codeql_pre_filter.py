"""
CodeQL Pre-Filter - P8-08d Component

This module implements pre-filtering for CodeQL scans to reduce false positives.

Strategies:
1. Rule confidence adjustment - Lower default confidence for high-FP rules
2. Response type detection - Distinguish JSON vs HTML for XSS
3. Project type awareness - Adjust rules based on project characteristics

Integration Point:
    Called in CodeQL engine before and after scan.
"""

import logging
import re
from dataclasses import dataclass
from typing import Any

from src.layers.l3_analysis.models import Finding, SeverityLevel


@dataclass
class RuleAdjustment:
    """Adjustment to apply to a CodeQL rule."""
    confidence_penalty: float = 0.0
    """Amount to reduce confidence by (0-1)."""

    requires_response_check: bool = False
    """Whether to check response type for XSS rules."""

    min_confidence: float = 0.0
    """Minimum confidence threshold."""


class CodeQLPreFilter:
    """
    CodeQL pre-filter for reducing false positives.

    This filter operates in two phases:
    1. Pre-scan: Adjust rule configurations based on project type
    2. Post-scan: Filter individual findings based on context
    """

    # Default rule adjustments by pattern
    RULE_ADJUSTMENTS: dict[str, RuleAdjustment] = {
        # XSS rules - high FP rate
        "javascript/xss": RuleAdjustment(
            confidence_penalty=0.2,
            requires_response_check=True,
            min_confidence=0.3,
        ),
        "*/xss*": RuleAdjustment(
            confidence_penalty=0.2,
            requires_response_check=True,
            min_confidence=0.3,
        ),
        # Generic rules - may need adjustment
        "*/generic*": RuleAdjustment(
            confidence_penalty=0.1,
            min_confidence=0.4,
        ),
    }

    # Patterns that indicate JSON response (no XSS)
    JSON_RESPONSE_PATTERNS = [
        r"response\.json\(",
        r"res\.json\(",
        r"json\(",
        r"return\s*\{",
        r"content-type:\s*application/json",
        r"@responsebody",
        r"responseentity",
    ]

    # Patterns that indicate HTML rendering (possible XSS)
    HTML_RENDERING_PATTERNS = [
        r"innerHTML",
        r"outerHTML",
        r"insertAdjacentHTML",
        r"document\.write",
        r"render\s*\(",
        r"response\.write\(",
        r"<html",
        r"{{",
        r"\${",
    ]

    def __init__(self, strict_mode: bool = False):
        """
        Initialize the CodeQL pre-filter.

        Args:
            strict_mode: If True, be more aggressive in filtering.
        """
        self.strict_mode = strict_mode
        self.logger = logging.getLogger(__name__)

    def get_adjusted_rules(
        self,
        project_type: str | None = None,
        language: str | None = None,
    ) -> dict[str, RuleAdjustment]:
        """
        Get rule adjustments based on project characteristics.

        Args:
            project_type: Type of project (e.g., "api", "web-app").
            language: Primary programming language.

        Returns:
            Dictionary mapping rule patterns to adjustments.
        """
        adjustments = {}

        # Base adjustments
        for pattern, rule_adj in self.RULE_ADJUSTMENTS.items():
            adjustments[pattern] = rule_adj

        # Project-specific adjustments
        if project_type:
            if "api" in project_type.lower():
                # API projects: More aggressive XSS filtering
                adjustments["*/xss*"] = RuleAdjustment(
                    confidence_penalty=0.3,
                    requires_response_check=True,
                    min_confidence=0.2,
                )

        # Language-specific adjustments
        if language:
            if language == "javascript" or language == "typescript":
                # JS/TS: Higher FP rate for XSS
                adjustments["javascript/xss"] = RuleAdjustment(
                    confidence_penalty=0.25,
                    requires_response_check=True,
                    min_confidence=0.25,
                )

        return adjustments

    def should_accept_finding(
        self,
        finding: Finding,
        adjustments: dict[str, RuleAdjustment] | None = None,
    ) -> tuple[bool, str]:
        """
        Determine if a CodeQL finding should be accepted.

        Args:
            finding: The CodeQL finding to evaluate.
            adjustments: Rule adjustments to apply.

        Returns:
            (accept, reason) tuple.
        """
        if adjustments is None:
            adjustments = self.RULE_ADJUSTMENTS

        rule_id = finding.rule_id or ""

        # Check for matching adjustment
        for pattern, rule_adj in adjustments.items():
            if self._rule_matches_pattern(rule_id, pattern):
                # Apply confidence penalty
                adjusted_confidence = max(
                    0.0,
                    (finding.confidence or 0.5) - rule_adj.confidence_penalty
                )

                # Check minimum confidence
                if adjusted_confidence < rule_adj.min_confidence:
                    return False, f"Below minimum confidence ({adjusted_confidence:.2f} < {rule_adj.min_confidence})"

                # Check response type for XSS
                if rule_adj.requires_response_check and "xss" in rule_id.lower():
                    if not self._confirms_html_response(finding):
                        return False, "XSS finding but no HTML response - likely false positive"

        return True, "Accept"

    def _rule_matches_pattern(self, rule_id: str, pattern: str) -> bool:
        """
        Check if a rule ID matches a pattern.

        Supports:
        - Exact match: "javascript/xss"
        - Wildcard: "*/xss*" matches "javascript/xss", "python/xss"
        """
        if pattern == rule_id:
            return True

        # Handle wildcards
        if "*" in pattern:
            # Convert pattern to regex
            # Escape special regex characters except *
            escaped = re.escape(pattern).replace(r"\*", ".*")
            return bool(re.match(escaped, rule_id))

        return False

    def _confirms_html_response(self, finding: Finding) -> bool:
        """
        Check if a finding confirms HTML rendering (for XSS).

        Returns True if the code snippet shows HTML rendering.
        Returns False if it shows JSON response or no rendering.

        Args:
            finding: The finding to check.

        Returns:
            True if HTML response is confirmed.
        """
        code = (finding.location.snippet or "").lower()

        # Check for HTML rendering patterns
        has_html = any(
            re.search(pattern, code, re.IGNORECASE)
            for pattern in self.HTML_RENDERING_PATTERNS
        )

        # Check for JSON response patterns
        has_json = any(
            re.search(pattern, code, re.IGNORECASE)
            for pattern in self.JSON_RESPONSE_PATTERNS
        )

        # HTML without JSON = likely XSS
        return has_html and not has_json

    def adjust_finding_confidence(
        self,
        finding: Finding,
        adjustments: dict[str, RuleAdjustment] | None = None,
    ) -> Finding:
        """
        Adjust finding confidence based on rules.

        Args:
            finding: The finding to adjust.
            adjustments: Rule adjustments to apply.

        Returns:
            Adjusted finding (new instance).
        """
        if adjustments is None:
            adjustments = self.RULE_ADJUSTMENTS

        rule_id = finding.rule_id or ""
        adjustment = None

        # Find matching adjustment
        for pattern, rule_adj in adjustments.items():
            if self._rule_matches_pattern(rule_id, pattern):
                adjustment = rule_adj
                break

        if adjustment:
            new_confidence = max(
                0.0,
                (finding.confidence or 0.5) - adjustment.confidence_penalty
            )

            # Create new Finding with adjusted confidence
            new_metadata = dict(finding.metadata) if finding.metadata else {}
            new_metadata["codeql_adjusted"] = True
            new_metadata["original_confidence"] = finding.confidence
            new_metadata["adjustment_penalty"] = adjustment.confidence_penalty

            return Finding(
                id=finding.id,
                rule_id=finding.rule_id,
                type=finding.type,
                severity=finding.severity,
                confidence=new_confidence,
                title=finding.title,
                description=finding.description,
                fix_suggestion=finding.fix_suggestion,
                location=finding.location,
                source=finding.source,
                cwe=finding.cwe,
                owasp=finding.owasp,
                metadata=new_metadata,
                final_score=None,  # Will be recalculated
            )

        return finding


# Convenience function
def should_accept_codeql_finding(
    finding: Finding,
    project_type: str | None = None,
    strict_mode: bool = False,
) -> tuple[bool, str]:
    """
    Convenience function for CodeQL finding acceptance.

    Args:
        finding: The CodeQL finding to evaluate.
        project_type: Type of project.
        strict_mode: Whether to use strict filtering.

    Returns:
        (accept, reason) tuple.
    """
    pre_filter = CodeQLPreFilter(strict_mode=strict_mode)
    adjustments = pre_filter.get_adjusted_rules(project_type)
    return pre_filter.should_accept_finding(finding, adjustments)
"""
    P8-08d: CodeQL Pre-Filter - reduces CodeQL false positives

    Components:
    - CodeQLPreFilter: Main pre-filter class
    - RuleAdjustment: Rule configuration dataclass
    - should_accept_codeql_finding: Convenience function

    Integration:
        Called in CodeQL engine before and after scan.
"""
