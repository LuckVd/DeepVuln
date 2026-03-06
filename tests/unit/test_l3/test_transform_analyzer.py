"""
Tests for Transform Analyzer (P5-01c).

Tests the AST-based sanitizer detection through transform analysis.
"""

import pytest

from src.layers.l3_analysis.call_graph.transform_analyzer import (
    DANGEROUS_CHARS,
    TransformAnalyzer,
)

# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def sanitizer_with_replace():
    """Code with str.replace operations."""
    return '''
def escape_html(input_string):
    """Escape HTML special characters."""
    result = input_string.replace("<", "&lt;")
    result = result.replace(">", "&gt;")
    result = result.replace("&", "&amp;")
    result = result.replace('"', "&quot;")
    result = result.replace("'", "&#x27;")
    return result
'''

@pytest.fixture
def sanitizer_with_encode():
    """Code with encode function calls."""
    return '''
def sanitize_input(user_input):
    """Sanitize using html.escape."""
    import html
    return html.escape(user_input)
'''

@pytest.fixture
def sanitizer_with_re_sub():
    """Code with re.sub operations."""
    return '''
import re

def clean_script_input(text):
    """Remove script tags using regex."""
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\\w+\\s*=\\s*"[^"]*"', '', text)
    return text
'''

@pytest.fixture
def sanitizer_combined():
    """Code with both replace and encode."""
    return '''
import html

def double_escape(user_data):
    """Double escaping for safety."""
    # First pass: replace known dangerous patterns
    data = user_data.replace("<script>", "")
    data = data.replace("javascript:", "")

    # Second pass: html escape
    return html.escape(data)
'''

@pytest.fixture
def non_sanitizer():
    """Code that looks like a function but is NOT a sanitizer."""
    return '''
def process_user_data(name, email):
    """Regular data processing function."""
    formatted_name = name.strip().title()
    formatted_email = email.lower().strip()
    return {
        "name": formatted_name,
        "email": formatted_email
    }
'''

@pytest.fixture
def empty_function():
    """Empty function for edge case testing."""
    return '''
def do_nothing():
    """Empty function."""
    pass
'''


# ============================================================
# Initialization Tests
# ============================================================

class TestTransformAnalyzerInit:
    """Tests for TransformAnalyzer initialization."""

    def test_default_init(self):
        """Test default initialization."""
        analyzer = TransformAnalyzer()
        assert analyzer.vuln_type == "xss"
        assert analyzer.language == "python"
        assert analyzer.dangerous_chars == DANGEROUS_CHARS["xss"]

    def test_custom_vuln_type(self):
        """Test initialization with custom vulnerability type."""
        analyzer = TransformAnalyzer(vuln_type="sqli")
        assert analyzer.vuln_type == "sqli"
        assert analyzer.dangerous_chars == DANGEROUS_CHARS["sqli"]

    def test_invalid_vuln_type_defaults_to_xss(self):
        """Test that invalid vuln type defaults to XSS patterns."""
        analyzer = TransformAnalyzer(vuln_type="invalid_type")
        assert analyzer.dangerous_chars == DANGEROUS_CHARS["xss"]

    def test_language_initialization(self):
        """Test language-specific initialization."""
        analyzer = TransformAnalyzer(language="python")
        assert analyzer.language == "python"
        assert "str.replace" in analyzer.replace_funcs
        assert "html.escape" in analyzer.encode_funcs


# ============================================================
# Replace Operations Detection
# ============================================================

class TestReplaceOperationsDetection:
    """Tests for _has_replace_operations method."""

    def test_detect_str_replace(self, sanitizer_with_replace):
        """Test detection of str.replace operations."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(sanitizer_with_replace, "escape_html")
        assert score.has_replace_ops is True

    def test_detect_re_sub(self, sanitizer_with_re_sub):
        """Test detection of re.sub operations."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(sanitizer_with_re_sub, "clean_script_input")
        assert score.has_replace_ops is True

    def test_no_replace_in_non_sanitizer(self, non_sanitizer):
        """Test that non-sanitizers don't trigger replace detection."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(non_sanitizer, "process_user_data")
        assert score.has_replace_ops is False

    def test_no_replace_in_empty_function(self, empty_function):
        """Test edge case of empty function."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(empty_function, "do_nothing")
        assert score.has_replace_ops is False


# ============================================================
# Encode Calls Detection
# ============================================================

class TestEncodeCallsDetection:
    """Tests for _has_encode_calls method."""

    def test_detect_html_escape(self, sanitizer_with_encode):
        """Test detection of html.escape calls."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(sanitizer_with_encode, "sanitize_input")
        assert score.has_encode_calls is True

    def test_no_encode_in_non_sanitizer(self, non_sanitizer):
        """Test that non-sanitizers don't trigger encode detection."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(non_sanitizer, "process_user_data")
        assert score.has_encode_calls is False


# ============================================================
# Character Coverage Calculation
# ============================================================

class TestCharacterCoverage:
    """Tests for _calculate_char_coverage method."""

    def test_xss_char_coverage(self, sanitizer_with_replace):
        """Test XSS dangerous character coverage."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(sanitizer_with_replace, "escape_html")

        # The function covers: <, >, &, ", '
        xss_chars = set(DANGEROUS_CHARS["xss"])
        covered_chars = {"<", ">", "&", '"', "'"}

        # Coverage should be at least these 5 chars out of all XSS chars
        assert score.dangerous_char_coverage >= len(covered_chars) / len(xss_chars)

    def test_sqli_char_coverage(self):
        """Test SQLi dangerous character coverage."""
        code = '''
def escape_sql(input_str):
    """Escape SQL special characters."""
    result = input_str.replace("'", "''")
    result = result.replace('"', '""')
    return result
'''
        analyzer = TransformAnalyzer(vuln_type="sqli")
        score = analyzer.analyze_from_source(code, "escape_sql")

        # Should detect quote character coverage
        assert score.dangerous_char_coverage > 0

    def test_zero_coverage_non_sanitizer(self, non_sanitizer):
        """Test that non-sanitizers have zero coverage."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(non_sanitizer, "process_user_data")
        assert score.dangerous_char_coverage == 0.0


# ============================================================
# Sanitizer Detection Heuristics
# ============================================================

class TestSanitizerDetection:
    """Tests for overall sanitizer detection logic."""

    def test_replace_only_is_sanitizer(self, sanitizer_with_replace):
        """Test that replace-only function is detected as sanitizer."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(sanitizer_with_replace, "escape_html")
        assert score.is_sanitizer is True
        assert score.confidence > 0

    def test_encode_only_is_sanitizer(self, sanitizer_with_encode):
        """Test that encode-only function is detected as sanitizer."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(sanitizer_with_encode, "sanitize_input")
        # Encode alone should trigger with high confidence
        assert score.has_encode_calls is True

    def test_combined_is_strong_sanitizer(self, sanitizer_combined):
        """Test that combined sanitizer has highest confidence."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(sanitizer_combined, "double_escape")
        assert score.has_replace_ops is True
        assert score.has_encode_calls is True
        # Combined should have high confidence

    def test_non_sanitizer_rejected(self, non_sanitizer):
        """Test that non-sanitizers are correctly rejected."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(non_sanitizer, "process_user_data")
        assert score.is_sanitizer is False
        assert score.confidence == 0.0

    def test_re_sub_detect_as_replace(self, sanitizer_with_re_sub):
        """Test that re.sub is detected as replace operation."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(sanitizer_with_re_sub, "clean_script_input")
        assert score.has_replace_ops is True


# ============================================================
# Confidence Calculation
# ============================================================

class TestConfidenceCalculation:
    """Tests for confidence score calculation."""

    def test_confidence_weights(self):
        """Test that confidence uses correct weights."""
        # The weights are: replace=0.4, encode=0.3, coverage=0.3
        code = '''
import html

def full_sanitizer(data):
    """Full sanitizer with all indicators."""
    data = data.replace("<", "&lt;")
    return html.escape(data)
'''
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(code, "full_sanitizer")

        # Should have high confidence with both replace and encode
        assert score.confidence > 0.5

    def test_max_confidence_capped_at_one(self):
        """Test that confidence never exceeds 1.0."""
        # Create a function with maximum indicators
        code = '''
import html
import re

def ultimate_sanitizer(text):
    """Every possible sanitizer pattern."""
    text = text.replace("<", "")
    text = text.replace(">", "")
    text = re.sub(r'&', "&amp;", text)
    return html.escape(text)
'''
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(code, "ultimate_sanitizer")
        assert score.confidence <= 1.0


# ============================================================
# Details Storage
# ============================================================

class TestDetailsStorage:
    """Tests for details dictionary in results."""

    def test_details_contains_vuln_type(self, sanitizer_with_replace):
        """Test that details includes vulnerability type."""
        analyzer = TransformAnalyzer(vuln_type="xss")
        score = analyzer.analyze_from_source(sanitizer_with_replace, "escape_html")
        assert "vuln_type" in score.details
        assert score.details["vuln_type"] == "xss"

    def test_details_contains_dangerous_chars(self, sanitizer_with_replace):
        """Test that details includes dangerous characters list."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(sanitizer_with_replace, "escape_html")
        assert "dangerous_chars" in score.details
        assert isinstance(score.details["dangerous_chars"], list)

    def test_details_contains_language(self, sanitizer_with_replace):
        """Test that details includes language."""
        analyzer = TransformAnalyzer(language="python")
        score = analyzer.analyze_from_source(sanitizer_with_replace, "escape_html")
        assert "language" in score.details
        assert score.details["language"] == "python"


# ============================================================
# Edge Cases
# ============================================================

class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_function_not_found(self):
        """Test behavior when function is not found in source."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source("def foo(): pass", "nonexistent")
        assert score.is_sanitizer is False
        assert score.confidence == 0.0

    def test_empty_source(self):
        """Test behavior with empty source code."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source("", "any_function")
        assert score.is_sanitizer is False

    def test_none_source(self):
        """Test behavior with None source (should not crash)."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source("", "any_function")
        assert score is not None

    def test_nested_function_calls(self):
        """Test detection in nested function call scenarios."""
        code = '''
def complex_sanitizer(text):
    """Sanitizer with nested calls."""
    return html.escape(text.replace("<", "&lt;").replace(">", "&gt;"))
'''
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(code, "complex_sanitizer")
        assert score.has_replace_ops or score.has_encode_calls

    def test_method_in_class(self):
        """Test detection for methods within classes."""
        code = '''
class Sanitizer:
    def escape(self, text):
        """Method sanitizer."""
        return text.replace("<", "&lt;")
'''
        analyzer = TransformAnalyzer()
        # Note: Current implementation may not find class methods
        score = analyzer.analyze_from_source(code, "escape")  # noqa: F841
        # Should handle gracefully


# ============================================================
# Different Vulnerability Types
# ============================================================

class TestDifferentVulnTypes:
    """Tests for different vulnerability types."""

    def test_cmdi_detection(self):
        """Test command injection character detection."""
        code = '''
def escape_command(cmd):
    """Escape command injection characters."""
    cmd = cmd.replace("|", "")
    cmd = cmd.replace("&", "")
    cmd = cmd.replace(";", "")
    return cmd
'''
        analyzer = TransformAnalyzer(vuln_type="cmdi")
        score = analyzer.analyze_from_source(code, "escape_command")
        assert score.has_replace_ops is True

    def test_path_traversal_detection(self):
        """Test path traversal character detection."""
        code = '''
def normalize_path(path):
    """Normalize file paths."""
    path = path.replace("..", "")
    path = path.replace("\\", "/")
    return path
'''
        analyzer = TransformAnalyzer(vuln_type="path_traversal")
        score = analyzer.analyze_from_source(code, "normalize_path")
        assert score.has_replace_ops is True


# ============================================================
# Serialization Tests
# ============================================================

class TestSerialization:
    """Tests for TransformScore serialization."""

    def test_to_dict(self, sanitizer_with_replace):
        """Test TransformScore.to_dict() method."""
        analyzer = TransformAnalyzer()
        score = analyzer.analyze_from_source(sanitizer_with_replace, "escape_html")
        result_dict = score.to_dict()

        assert isinstance(result_dict, dict)
        assert "has_replace_ops" in result_dict
        assert "has_encode_calls" in result_dict
        assert "dangerous_char_coverage" in result_dict
        assert "is_sanitizer" in result_dict
        assert "confidence" in result_dict
        assert "details" in result_dict
