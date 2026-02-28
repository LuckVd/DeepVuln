"""Unit tests for fault-tolerant JSON parser."""

import pytest

from src.core.utils import (
    JSONParseError,
    extract_first_json_object,
    extract_json_from_markdown,
    fix_incomplete_json,
    fix_json_comments,
    fix_single_quotes,
    fix_trailing_commas,
    robust_json_loads,
    safe_json_loads,
)


class TestExtractJsonFromMarkdown:
    """Tests for extract_json_from_markdown function."""

    def test_json_code_block(self):
        """Extract JSON from ```json code block."""
        text = '''Here is the response:
```json
{"key": "value"}
```
That's it.'''
        result = extract_json_from_markdown(text)
        assert result == '{"key": "value"}'

    def test_generic_code_block(self):
        """Extract JSON from generic ``` code block."""
        text = '''```
{"key": "value"}
```'''
        result = extract_json_from_markdown(text)
        assert result == '{"key": "value"}'

    def test_array_in_code_block(self):
        """Extract JSON array from code block."""
        text = '''```json
[1, 2, 3]
```'''
        result = extract_json_from_markdown(text)
        assert result == "[1, 2, 3]"

    def test_no_code_block(self):
        """Return None when no code block found."""
        text = "Just plain text without code blocks"
        result = extract_json_from_markdown(text)
        assert result is None

    def test_code_block_without_json(self):
        """Return None when code block doesn't contain JSON."""
        text = '''```python
print("hello")
```'''
        result = extract_json_from_markdown(text)
        assert result is None


class TestFixTrailingCommas:
    """Tests for fix_trailing_commas function."""

    def test_object_trailing_comma(self):
        """Remove trailing comma in object."""
        json_str = '{"a": 1,}'
        result = fix_trailing_commas(json_str)
        assert result == '{"a": 1}'

    def test_array_trailing_comma(self):
        """Remove trailing comma in array."""
        json_str = '[1, 2, 3,]'
        result = fix_trailing_commas(json_str)
        assert result == '[1, 2, 3]'

    def test_nested_trailing_commas(self):
        """Remove trailing commas in nested structures."""
        json_str = '{"arr": [1, 2,], "obj": {"x": 1,},}'
        result = fix_trailing_commas(json_str)
        assert result == '{"arr": [1, 2], "obj": {"x": 1}}'

    def test_no_trailing_comma(self):
        """Leave valid JSON unchanged."""
        json_str = '{"a": 1, "b": 2}'
        result = fix_trailing_commas(json_str)
        assert result == '{"a": 1, "b": 2}'


class TestFixJsonComments:
    """Tests for fix_json_comments function."""

    def test_single_line_comment(self):
        """Remove single-line comments."""
        json_str = '''{
    "key": "value", // this is a comment
    "num": 42
}'''
        result = fix_json_comments(json_str)
        assert "//" not in result
        assert "this is a comment" not in result

    def test_multi_line_comment(self):
        """Remove multi-line comments."""
        json_str = '''{
    /* This is a
       multi-line comment */
    "key": "value"
}'''
        result = fix_json_comments(json_str)
        assert "/*" not in result
        assert "multi-line comment" not in result

    def test_comment_in_string(self):
        """Don't remove // inside strings."""
        json_str = '{"url": "https://example.com"}'
        result = fix_json_comments(json_str)
        assert "https://example.com" in result

    def test_no_comments(self):
        """Leave JSON without comments unchanged."""
        json_str = '{"key": "value"}'
        result = fix_json_comments(json_str)
        assert result == '{"key": "value"}'


class TestFixSingleQuotes:
    """Tests for fix_single_quotes function."""

    def test_single_quotes_to_double(self):
        """Convert single quotes to double quotes."""
        json_str = "{'key': 'value'}"
        result = fix_single_quotes(json_str)
        assert result == '{"key": "value"}'

    def test_mixed_quotes(self):
        """Handle mixed single and double quotes."""
        json_str = '''{'key': "value"}'''
        result = fix_single_quotes(json_str)
        assert result == '{"key": "value"}'

    def test_nested_single_quotes(self):
        """Handle nested objects with single quotes."""
        json_str = "{'outer': {'inner': 'value'}}"
        result = fix_single_quotes(json_str)
        assert result == '{"outer": {"inner": "value"}}'

    def test_escaped_quotes(self):
        """Handle escaped quotes inside strings."""
        json_str = r"{'key': 'it\\'s fine'}"
        result = fix_single_quotes(json_str)
        # Should convert outer quotes but handle escaped quotes
        assert '"' in result


class TestExtractFirstJsonObject:
    """Tests for extract_first_json_object function."""

    def test_extract_object(self):
        """Extract first JSON object from text."""
        text = 'Some text {"key": "value"} more text'
        result = extract_first_json_object(text)
        assert result == '{"key": "value"}'

    def test_extract_nested_object(self):
        """Extract nested JSON object."""
        text = '{"outer": {"inner": "value"}}'
        result = extract_first_json_object(text)
        assert result == '{"outer": {"inner": "value"}}'

    def test_extract_array(self):
        """Extract JSON array."""
        text = 'Prefix [1, 2, 3] suffix'
        result = extract_first_json_object(text)
        assert result == '[1, 2, 3]'

    def test_no_json_found(self):
        """Return None when no JSON found."""
        text = "No JSON here"
        result = extract_first_json_object(text)
        assert result is None

    def test_json_with_string_containing_braces(self):
        """Handle JSON with braces inside strings."""
        text = '{"code": "if (x) { y() }"}'
        result = extract_first_json_object(text)
        assert result == '{"code": "if (x) { y() }"}'


class TestFixIncompleteJson:
    """Tests for fix_incomplete_json function."""

    def test_missing_closing_brace(self):
        """Add missing closing brace."""
        json_str = '{"key": "value"'
        result = fix_incomplete_json(json_str)
        assert result == '{"key": "value"}'

    def test_missing_closing_bracket(self):
        """Add missing closing bracket."""
        json_str = '[1, 2, 3'
        result = fix_incomplete_json(json_str)
        assert result == '[1, 2, 3]'

    def test_missing_multiple_closing(self):
        """Add multiple missing closing brackets."""
        json_str = '{"arr": [1, 2'
        result = fix_incomplete_json(json_str)
        assert result == '{"arr": [1, 2]}'

    def test_trailing_comma_removal(self):
        """Remove trailing comma before closing."""
        json_str = '{"key": "value",'
        result = fix_incomplete_json(json_str)
        assert result == '{"key": "value"}'


class TestRobustJsonLoads:
    """Tests for robust_json_loads function."""

    def test_valid_json(self):
        """Parse valid JSON directly."""
        text = '{"key": "value"}'
        result = robust_json_loads(text)
        assert result == {"key": "value"}

    def test_markdown_wrapped(self):
        """Parse JSON wrapped in markdown."""
        text = '''```json
{"key": "value"}
```'''
        result = robust_json_loads(text)
        assert result == {"key": "value"}

    def test_with_trailing_comma(self):
        """Parse JSON with trailing comma."""
        text = '{"key": "value",}'
        result = robust_json_loads(text)
        assert result == {"key": "value"}

    def test_with_comments(self):
        """Parse JSON with comments."""
        text = '''{
    "key": "value", // comment
    "num": 42
}'''
        result = robust_json_loads(text)
        assert result == {"key": "value", "num": 42}

    def test_with_single_quotes(self):
        """Parse JSON with single quotes."""
        text = "{'key': 'value'}"
        result = robust_json_loads(text)
        assert result == {"key": "value"}

    def test_incomplete_json(self):
        """Parse incomplete JSON."""
        text = '{"key": "value"'
        result = robust_json_loads(text)
        assert result == {"key": "value"}

    def test_invalid_raises_error(self):
        """Raise JSONParseError for completely invalid text."""
        text = "This is not JSON at all"
        with pytest.raises(JSONParseError):
            robust_json_loads(text)

    def test_parse_array(self):
        """Parse JSON array."""
        text = '[1, 2, 3]'
        result = robust_json_loads(text)
        assert result == [1, 2, 3]


class TestSafeJsonLoads:
    """Tests for safe_json_loads function."""

    def test_valid_json(self):
        """Parse valid JSON."""
        text = '{"key": "value"}'
        result = safe_json_loads(text)
        assert result == {"key": "value"}

    def test_invalid_returns_default(self):
        """Return default value for invalid JSON."""
        text = "not json"
        result = safe_json_loads(text, default={"default": True})
        assert result == {"default": True}

    def test_default_none(self):
        """Return None by default for invalid JSON."""
        text = "not json"
        result = safe_json_loads(text)
        assert result is None


class TestGLM5Scenarios:
    """Test cases for GLM-5 specific JSON format issues."""

    def test_markdown_with_trailing_comma(self):
        """Handle markdown code block with trailing commas."""
        text = '''```json
{"entry_points": [{"file": "test.py"},],}
```'''
        result = robust_json_loads(text)
        assert "entry_points" in result
        assert result["entry_points"][0]["file"] == "test.py"

    def test_with_comments(self):
        """Handle JSON with comments."""
        text = '''{
    "findings": [
        // SQL injection finding
        {"type": "sql_injection"}
    ]
}'''
        result = robust_json_loads(text)
        assert result["findings"][0]["type"] == "sql_injection"

    def test_single_quotes(self):
        """Handle single quotes."""
        text = "{'entry_points': [{'type': 'http'}]}"
        result = robust_json_loads(text)
        assert "entry_points" in result
        assert result["entry_points"][0]["type"] == "http"

    def test_complex_nested_with_issues(self):
        """Handle complex nested JSON with multiple issues."""
        text = '''```json
{
    "files_analyzed": 3,
    "entry_points": [
        {
            "file": "api/handler.py",
            "type": "http",
            "method": "GET",
            "path": "/api/users",
            "handler": "get_users",
            "line": 42,
            "auth_required": true,
        },  // trailing comma + comment
    ],  // more trailing
    "framework_detected": "flask",
    "confidence": 0.85,
}
```'''
        result = robust_json_loads(text)
        assert result["files_analyzed"] == 3
        assert len(result["entry_points"]) == 1
        assert result["entry_points"][0]["handler"] == "get_users"

    def test_truncated_response(self):
        """Handle truncated JSON response (missing outer closing braces)."""
        text = '''{
    "entry_points": [
        {"file": "a.py", "type": "http"},
        {"file": "b.py", "type": "http"}'''
        result = robust_json_loads(text)
        assert "entry_points" in result
        # Should have recovered the data by adding missing closing brackets
        assert len(result["entry_points"]) == 2

    def test_deeply_truncated_response(self):
        """Handle deeply truncated JSON - this may fail gracefully."""
        text = '{"entry_points": [{"file": "a.py"'
        # This should either parse partially or raise an error
        # We just verify it doesn't crash
        try:
            result = robust_json_loads(text)
            # If it succeeds, verify structure
            assert "entry_points" in result
        except JSONParseError:
            # It's acceptable to fail on heavily truncated JSON
            pass

    def test_text_before_json(self):
        """Handle extra text before JSON."""
        text = '''Based on my analysis, here are the findings:

{"findings": [{"type": "xss", "severity": "high"}]}

Let me know if you need more details.'''
        result = robust_json_loads(text)
        assert result["findings"][0]["type"] == "xss"

    def test_empty_json_object(self):
        """Handle empty JSON object."""
        text = '{"entry_points": []}'
        result = robust_json_loads(text)
        assert result == {"entry_points": []}
