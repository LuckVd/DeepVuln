"""
Transform Analyzer for AST-based sanitizer detection.

This module provides functionality to detect sanitizers by analyzing
AST transformations (string replacement operations, encoding calls) and dangerous
characters coverage ratio to determine if a function is an effective sanitizer.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.call_graph.models import TransformScore

from src.layers.l3_analysis.codeql.sanitizer_detector import (
    SanitizerEffectiveness,
    SanitizerMatch,
)

from src.layers.l3_analysis.models import CodeLocation

logger = get_logger(__name__)


# Dangerous character patterns by vulnerability type
# Using raw strings to avoid escape sequence issues
DANGEROUS_CHARS: dict[str, list[str]] = {
    "xss": ["<", ">", "&", '"', "'", "/", " ", "=", r"\n"],
    "sqli": ["'", '"', ";", "--", "/*", "*/", "=", "OR", "AND"],
    "cmdi": ["|", ";", "&", "$", "`", "(", ")", r"\n", r"\r"],
    "path_traversal": ["/", "\\", "..", "~", "\x00"],
    "ldap": ["(", ")", "\\", "*", "\x00"],
}


@dataclass
class TransformAnalysisResult:
    """Result of transform analysis for a function."""

    function_id: str = ""
    function_name: str = ""
    has_replace_ops: bool = False
    has_encode_calls: bool = False
    dangerous_char_coverage: float = 0.0
    is_sanitizer: bool = False
    confidence: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


class TransformAnalyzer:
    """
    Analyzes function AST for sanitizer-like transform patterns.

    Detects sanitizers by:
    1. String replacement operations (str.replace, re.sub)
    2. Encoding/decoding function calls (html.escape, encodeURIComponent)
    3. Coverage of dangerous characters
    """

    def __init__(self, vuln_type: str = "xss"):
        """
        Initialize the analyzer.

        Args:
            vuln_type: Vulnerability type for dangerous character patterns
        """
        self.vuln_type = vuln_type
        self.dangerous_chars = DANGEROUS_CHARS.get(vuln_type, DANGEROUS_CHARS["xss"])

    def analyze_function(self, function_node: Any, source_code: str) -> TransformScore:
        """
        Analyze a function AST node for sanitizer patterns.

        Args:
            function_node: AST FunctionDef node
            source_code: Full source code string

        Returns:
            TransformScore with analysis results
        """
        # Initialize result
        score = TransformScore()

        # Check for replace operations
        score.has_replace_ops = self._has_replace_operations(function_node)

        # Check for encode calls
        score.has_encode_calls = self._has_encode_calls(function_node)

        # Calculate dangerous character coverage
        score.dangerous_char_coverage = self._calculate_char_coverage(
            function_node, source_code
        )

        # Determine if sanitizer based on combined factors
        score.is_sanitizer = self._is_sanitizer(score)
        score.confidence = self._calculate_confidence(score)

        # Store additional details
        score.details = {
            "vuln_type": self.vuln_type,
            "dangerous_chars": self.dangerous_chars,
        }

        return score

    def _has_replace_operations(self, function_node: Any) -> bool:
        """Check if function contains string replace operations."""
        # This is a placeholder - actual implementation would walk the AST
        # looking for str.replace, re.sub, etc.
        return False

    def _has_encode_calls(self, function_node: Any) -> bool:
        """Check if function contains encoding/escaping function calls."""
        # This is a placeholder - actual implementation would walk the AST
        # looking for html.escape, encodeURIComponent, etc.
        return False

    def _calculate_char_coverage(
        self, function_node: Any, source_code: str
    ) -> float:
        """
        Calculate coverage of dangerous characters in replace patterns.

        Returns:
            Coverage ratio (0.0 to 1.0)
        """
        # This is a placeholder - actual implementation would:
        # 1. Extract string literals from replace/sub calls
        # 2. Check which dangerous characters they cover
        # 3. Return coverage ratio
        return 0.0

    def _is_sanitizer(self, score: TransformScore) -> bool:
        """
        Determine if function is a sanitizer based on heuristics.

        Args:
            score: TransformScore with analysis results

        Returns:
            True if function appears to be a sanitizer
        """
        # Heuristic: need at least 2 of 3 indicators
        indicators = [
            score.has_replace_ops,
            score.has_encode_calls,
            score.dangerous_char_coverage > 0.5,
        ]
        return sum(indicators) >= 2

    def _calculate_confidence(self, score: TransformScore) -> float:
        """
        Calculate confidence score for sanitizer detection.

        Returns:
            Confidence value (0.0 to 1.0)
        """
        # Weighted combination of factors
        weights = {
            "replace": 0.4,
            "encode": 0.3,
            "coverage": 0.3,
        }

        confidence = 0.0
        if score.has_replace_ops:
            confidence += weights["replace"]
        if score.has_encode_calls:
            confidence += weights["encode"]
        confidence += weights["coverage"] * score.dangerous_char_coverage

        return min(confidence, 1.0)
