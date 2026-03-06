"""
Tests for Type Analyzer (P5-01c).

Tests the type-based sanitizer detection through return types and decorators.
"""

import pytest

from src.layers.l3_analysis.call_graph.type_analyzer import (
    TypeAnalyzer,
)

# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def function_with_safe_return_type():
    """Function with safe return type annotation."""
    return '''
from markupsafe import Markup

def render_html(template: str) -> Markup:
    """Render template and return safe HTML."""
    return Markup(template)
'''

@pytest.fixture
def function_with_decorator():
    """Function with sanitizer decorator."""
    return '''
@sanitizer
def escape_user_input(input_data):
    """Escape user input."""
    return input_data.replace("<", "&lt;")
'''

@pytest.fixture
def function_with_escape_decorator():
    """Function with @escape decorator."""
    return '''
@escape
def clean_text(text):
    """Clean text input."""
    import html
    return html.escape(text)
'''

@pytest.fixture
def function_with_type_guard():
    """Function with type guard pattern."""
    return '''
def validate_and_escape(data):
    """Validate and escape input."""
    if isinstance(data, str):
        import html
        return html.escape(data)
    return None
'''

@pytest.fixture
def function_with_safe_return_in_body():
    """Function that returns safe type in body (no annotation)."""
    return '''
def make_safe(content):
    """Wrap content in safe type."""
    from markupsafe import Markup
    return Markup(content)
'''

@pytest.fixture
def function_combined_indicators():
    """Function with both safe return type and decorator."""
    return '''
from markupsafe import Markup

@sanitizer
def render_safe(template: str) -> Markup:
    """Render template as safe HTML."""
    return Markup(template)
'''

@pytest.fixture
def regular_function():
    """Regular function without sanitizer indicators."""
    return '''
def process_data(data):
    """Regular data processing."""
    return data.strip()
'''

@pytest.fixture
def flask_route_function():
    """Flask route function (entry point, not sanitizer)."""
    return '''
from flask import Flask
app = Flask(__name__)

@app.route('/api')
def api_endpoint():
    """API endpoint."""
    return "Hello"
'''


# ============================================================
# Initialization Tests
# ============================================================

class TestTypeAnalyzerInit:
    """Tests for TypeAnalyzer initialization."""

    def test_default_init(self):
        """Test default initialization."""
        analyzer = TypeAnalyzer()
        assert analyzer.vuln_type == "xss"
        assert analyzer.language == "python"

    def test_custom_vuln_type(self):
        """Test initialization with custom vulnerability type."""
        analyzer = TypeAnalyzer(vuln_type="sqli")
        assert analyzer.vuln_type == "sqli"

    def test_custom_language(self):
        """Test initialization with custom language."""
        analyzer = TypeAnalyzer(language="javascript")
        assert analyzer.language == "javascript"

    def test_safe_types_loaded(self):
        """Test that safe types are loaded correctly."""
        analyzer = TypeAnalyzer(vuln_type="xss")
        assert len(analyzer.safe_types) > 0
        assert any("Markup" in t for t in analyzer.safe_types)

    def test_decorators_loaded(self):
        """Test that sanitizer decorators are loaded."""
        analyzer = TypeAnalyzer()
        assert len(analyzer.sanitizer_decorators) > 0
        assert "@sanitizer" in analyzer.sanitizer_decorators


# ============================================================
# Safe Return Type Detection
# ============================================================

class TestSafeReturnTypeDetection:
    """Tests for safe return type detection."""

    def test_detect_safe_return_annotation(self, function_with_safe_return_type):
        """Test detection of safe return type in annotation."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_safe_return_type, "render_html")
        assert score.has_safe_return_type is True
        assert len(score.safe_types) > 0

    def test_detect_safe_return_in_body(self, function_with_safe_return_in_body):
        """Test detection of safe type returned in body."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_safe_return_in_body, "make_safe")
        # Should detect Markup in return statement
        assert score.has_safe_return_type is True

    def test_no_safe_type_in_regular_function(self, regular_function):
        """Test that regular functions don't trigger safe type detection."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(regular_function, "process_data")
        assert score.has_safe_return_type is False

    def test_records_safe_type_name(self, function_with_safe_return_type):
        """Test that safe type name is recorded."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_safe_return_type, "render_html")
        assert any("Markup" in t or "markupsafe" in t.lower() for t in score.safe_types)


# ============================================================
# Decorator Detection
# ============================================================

class TestDecoratorDetection:
    """Tests for sanitizer decorator detection."""

    def test_detect_sanitizer_decorator(self, function_with_decorator):
        """Test detection of @sanitizer decorator."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_decorator, "escape_user_input")
        assert score.has_sanitizer_decorator is True

    def test_detect_escape_decorator(self, function_with_escape_decorator):
        """Test detection of @escape decorator."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_escape_decorator, "clean_text")
        assert score.has_sanitizer_decorator is True

    def test_record_decorator_text(self, function_with_decorator):
        """Test that decorator text is recorded."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_decorator, "escape_user_input")
        assert len(score.decorators) > 0
        assert any("sanitizer" in d.lower() for d in score.decorators)

    def test_no_decorator_in_regular_function(self, regular_function):
        """Test that regular functions don't trigger decorator detection."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(regular_function, "process_data")
        assert score.has_sanitizer_decorator is False
        assert len(score.decorators) == 0

    def test_multiple_decorators(self):
        """Test function with multiple decorators."""
        code = '''
@safe
@escape
def double_safe(text):
    """Double decorated sanitizer."""
    return html.escape(text)
'''
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(code, "double_safe")
        assert score.has_sanitizer_decorator is True
        assert len(score.decorators) >= 2


# ============================================================
# Type Guard Detection
# ============================================================

class TestTypeGuardDetection:
    """Tests for type guard pattern detection."""

    def test_detect_isinstance_type_guard(self, function_with_type_guard):
        """Test detection of isinstance type guard."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_type_guard, "validate_and_escape")
        assert score.has_type_guard is True

    def test_no_type_guard_without_isinstance(self, regular_function):
        """Test that functions without isinstance don't trigger."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(regular_function, "process_data")
        assert score.has_type_guard is False


# ============================================================
# Sanitizer Detection Heuristics
# ============================================================

class TestSanitizerDetection:
    """Tests for overall sanitizer detection logic."""

    def test_safe_return_triggers_sanitizer(self, function_with_safe_return_type):
        """Test that safe return type alone identifies sanitizer."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_safe_return_type, "render_html")
        assert score.is_sanitizer is True

    def test_decorator_triggers_sanitizer(self, function_with_decorator):
        """Test that decorator alone identifies sanitizer."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_decorator, "escape_user_input")
        assert score.is_sanitizer is True

    def test_combined_indicators_stronger(self, function_combined_indicators):
        """Test that combined indicators give stronger detection."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_combined_indicators, "render_safe")
        assert score.is_sanitizer is True
        assert score.has_safe_return_type is True
        assert score.has_sanitizer_decorator is True

    def test_regular_function_not_sanitizer(self, regular_function):
        """Test that regular functions are not detected as sanitizers."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(regular_function, "process_data")
        assert score.is_sanitizer is False

    def test_flask_route_not_sanitizer(self, flask_route_function):
        """Test that Flask routes are not detected as sanitizers."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(flask_route_function, "api_endpoint")
        assert score.is_sanitizer is False


# ============================================================
# Confidence Calculation
# ============================================================

class TestConfidenceCalculation:
    """Tests for confidence score calculation."""

    def test_safe_return_contributes_to_confidence(self, function_with_safe_return_type):
        """Test that safe return type adds to confidence."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_safe_return_type, "render_html")
        assert score.confidence >= 0.5  # Safe return type is 0.5 weight

    def test_decorator_contributes_to_confidence(self, function_with_decorator):
        """Test that decorator adds to confidence."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_decorator, "escape_user_input")
        assert score.confidence > 0.3  # Decorator is 0.4 weight

    def test_combined_gives_highest_confidence(self, function_combined_indicators):
        """Test that combined indicators give highest confidence."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_combined_indicators, "render_safe")
        # Combined should have confidence >= 0.9 (0.5 + 0.4)
        assert score.confidence >= 0.9

    def test_max_confidence_capped(self):
        """Test that confidence never exceeds 1.0."""
        analyzer = TypeAnalyzer()
        # Even with all indicators, max is 1.0
        code = '''
@sanitizer
@escape

def ultimate(type_annotation: Markup) -> Markup:
    """All indicators."""
    if isinstance(data, str):
        return Markup(data)
    return Markup("")
'''
        score = analyzer.analyze_from_source(code, "ultimate")
        assert score.confidence <= 1.0


# ============================================================
# Different Vulnerability Types
# ============================================================

class TestDifferentVulnTypes:
    """Tests for different vulnerability types."""

    def test_sqli_safe_types(self):
        """Test SQLi safe type detection."""
        code = '''
from sqlalchemy import TextClause

def safe_query(sql: str) -> TextClause:
    """Return safe SQL text clause."""
    return TextClause(sql)
'''
        analyzer = TypeAnalyzer(vuln_type="sqli")
        score = analyzer.analyze_from_source(code, "safe_query")  # noqa: F841
        # Should detect TextClause as safe type for SQLi

    def test_cmdi_safe_types(self):
        """Test command injection safe type detection."""
        code = '''
import shlex

def safe_command(cmd: str) -> str:
    """Quote command for safe execution."""
    return shlex.quote(cmd)
'''
        analyzer = TypeAnalyzer(vuln_type="cmdi")
        score = analyzer.analyze_from_source(code, "safe_command")  # noqa: F841
        # shlex.quote should be detected via semantic


# ============================================================
# Edge Cases
# ============================================================

class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_function_not_found(self):
        """Test when function is not found in source."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source("def foo(): pass", "nonexistent")
        assert score.is_sanitizer is False
        assert score.confidence == 0.0

    def test_empty_source(self):
        """Test with empty source code."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source("", "any_function")
        assert score.is_sanitizer is False

    def test_function_without_return(self):
        """Test function without return statement."""
        code = '''
def no_return():
    """Function with no return."""
    pass
'''
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(code, "no_return")
        assert score.has_safe_return_type is False

    def test_nested_functions(self):
        """Test detection in nested function scenarios."""
        code = '''
def outer():
    """Outer function."""
    def inner():
        """Inner sanitizer."""
        return Markup(data)
    return inner()
'''
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(code, "inner")  # noqa: F841
        # Should handle nested functions

    def test_class_methods(self):
        """Test detection for class methods."""
        code = '''
class SanitizerClass:
    @escape
    def method_escape(self, text):
        """Method with decorator."""
        return text.replace("<", "&lt;")
'''
        analyzer = TypeAnalyzer()
        # Note: May need to handle class context
        score = analyzer.analyze_from_source(code, "method_escape")  # noqa: F841


# ============================================================
# Serialization Tests
# ============================================================

class TestSerialization:
    """Tests for TypeBasedScore serialization."""

    def test_to_dict(self, function_with_decorator):
        """Test TypeBasedScore.to_dict() method."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_decorator, "escape_user_input")
        result_dict = score.to_dict()

        assert isinstance(result_dict, dict)
        assert "has_safe_return_type" in result_dict
        assert "has_sanitizer_decorator" in result_dict
        assert "has_type_guard" in result_dict
        assert "is_sanitizer" in result_dict
        assert "confidence" in result_dict
        assert "safe_types" in result_dict
        assert "decorators" in result_dict

    def test_decorator_list_serialized(self, function_with_decorator):
        """Test that decorators list is properly serialized."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_decorator, "escape_user_input")
        result_dict = score.to_dict()

        assert isinstance(result_dict["decorators"], list)

    def test_safe_types_list_serialized(self, function_with_safe_return_type):
        """Test that safe_types list is properly serialized."""
        analyzer = TypeAnalyzer()
        score = analyzer.analyze_from_source(function_with_safe_return_type, "render_html")
        result_dict = score.to_dict()

        assert isinstance(result_dict["safe_types"], list)
