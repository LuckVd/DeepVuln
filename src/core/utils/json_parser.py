"""
Fault-tolerant JSON parser for LLM responses.

Handles common JSON formatting issues from LLM outputs:
- Markdown code blocks (```json ... ```)
- Trailing commas (JavaScript style)
- Comments (// and /* */)
- Single quotes instead of double quotes
- Incomplete/truncated JSON
"""

import json
import re
from typing import Any


class JSONParseError(Exception):
    """Raised when JSON parsing fails after all recovery attempts."""

    def __init__(
        self,
        message: str,
        original_error: Exception | None = None,
        raw_response: str | None = None,
    ):
        super().__init__(message)
        self.original_error = original_error
        self.raw_response = raw_response


def extract_json_from_markdown(text: str) -> str | None:
    """Extract JSON from Markdown code blocks.

    Handles:
    - ```json ... ```
    - ``` ... ```

    Args:
        text: Text potentially containing markdown code blocks.

    Returns:
        Extracted JSON string or None if no code block found.
    """
    # Try ```json ... ``` first
    json_block_match = re.search(
        r"```json\s*([\s\S]*?)```",
        text,
        re.IGNORECASE
    )
    if json_block_match:
        return json_block_match.group(1).strip()

    # Try generic ``` ... ``` (must contain { or [)
    code_block_match = re.search(
        r"```\s*([\s\S]*?)```",
        text
    )
    if code_block_match:
        content = code_block_match.group(1).strip()
        # Only return if it looks like JSON
        if content.startswith("{") or content.startswith("["):
            return content

    return None


def fix_trailing_commas(json_str: str) -> str:
    """Remove trailing commas from JSON.

    Converts JavaScript-style trailing commas to valid JSON:
    - {"a": 1,} -> {"a": 1}
    - [1, 2,] -> [1, 2]

    Args:
        json_str: JSON string with potential trailing commas.

    Returns:
        JSON string with trailing commas removed.
    """
    # Remove trailing commas before } or ]
    # This handles: {"a": 1,} and [1, 2,]
    result = re.sub(r",(\s*[}\]])", r"\1", json_str)
    return result


def fix_json_comments(json_str: str) -> str:
    """Remove JavaScript-style comments from JSON.

    Handles:
    - Single-line comments: // comment
    - Multi-line comments: /* comment */

    Args:
        json_str: JSON string with potential comments.

    Returns:
        JSON string with comments removed.
    """
    # Remove single-line comments (// ...)
    # Be careful not to remove // inside strings
    result = []
    i = 0
    in_string = False
    escape_next = False

    while i < len(json_str):
        char = json_str[i]

        if escape_next:
            result.append(char)
            escape_next = False
            i += 1
            continue

        if char == "\\" and in_string:
            result.append(char)
            escape_next = True
            i += 1
            continue

        if char == '"':
            in_string = not in_string
            result.append(char)
            i += 1
            continue

        if in_string:
            result.append(char)
            i += 1
            continue

        # Check for single-line comment
        if char == "/" and i + 1 < len(json_str) and json_str[i + 1] == "/":
            # Skip until end of line
            while i < len(json_str) and json_str[i] != "\n":
                i += 1
            continue

        # Check for multi-line comment
        if char == "/" and i + 1 < len(json_str) and json_str[i + 1] == "*":
            i += 2
            # Skip until */
            while i < len(json_str) - 1:
                if json_str[i] == "*" and json_str[i + 1] == "/":
                    i += 2
                    break
                i += 1
            continue

        result.append(char)
        i += 1

    return "".join(result)


def fix_single_quotes(json_str: str) -> str:
    """Convert single quotes to double quotes for JSON compatibility.

    Handles:
    - {'key': 'value'} -> {"key": "value"}
    - Handles escaped quotes within strings

    Args:
        json_str: JSON string with potential single quotes.

    Returns:
        JSON string with double quotes.
    """
    # This is a simplified approach - replace single quotes with double quotes
    # when they appear to be JSON string delimiters
    result = []
    i = 0
    in_single_quote = False
    in_double_quote = False
    escape_next = False

    while i < len(json_str):
        char = json_str[i]

        if escape_next:
            result.append(char)
            escape_next = False
            i += 1
            continue

        if char == "\\":
            result.append(char)
            escape_next = True
            i += 1
            continue

        if char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            result.append(char)
            i += 1
            continue

        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            result.append('"')  # Replace with double quote
            i += 1
            continue

        result.append(char)
        i += 1

    return "".join(result)


def extract_first_json_object(text: str) -> str | None:
    """Extract the first complete JSON object using bracket counting.

    This handles cases where the LLM includes extra text before/after the JSON.

    Args:
        text: Text potentially containing a JSON object.

    Returns:
        Extracted JSON object string or None if not found.
    """
    start = text.find("{")
    if start == -1:
        # Try array
        start = text.find("[")
        if start == -1:
            return None
        open_char = "["
        close_char = "]"
    else:
        open_char = "{"
        close_char = "}"

    depth = 0
    in_string = False
    escape_next = False

    for i, char in enumerate(text[start:], start):
        if escape_next:
            escape_next = False
            continue

        if char == "\\" and in_string:
            escape_next = True
            continue

        if char == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]

    return None


def fix_incomplete_json(json_str: str) -> str:
    """Attempt to fix incomplete JSON by adding missing closing brackets.

    This handles truncated JSON responses from LLMs.

    Args:
        json_str: Potentially incomplete JSON string.

    Returns:
        Attempted fixed JSON string.
    """
    # Count unclosed brackets
    open_braces = 0
    open_brackets = 0
    in_string = False
    escape_next = False

    for char in json_str:
        if escape_next:
            escape_next = False
            continue

        if char == "\\" and in_string:
            escape_next = True
            continue

        if char == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == "{":
            open_braces += 1
        elif char == "}":
            open_braces -= 1
        elif char == "[":
            open_brackets += 1
        elif char == "]":
            open_brackets -= 1

    # Build closing brackets
    closing = ""

    # Close arrays first, then objects
    for _ in range(max(0, open_brackets)):
        closing += "]"

    for _ in range(max(0, open_braces)):
        closing += "}"

    # Also remove trailing incomplete values
    # e.g., {"key": "value", -> {"key": "value"}
    result = json_str.rstrip()

    # Remove trailing comma if present
    if result.endswith(","):
        result = result[:-1]

    return result + closing


def fix_chinese_punctuation(json_str: str) -> str:
    """Replace Chinese punctuation with ASCII equivalents in JSON.

    GLM-5 and other Chinese LLMs may output JSON with Chinese punctuation.

    Handles:
    - Chinese colon (：) -> ASCII colon (:)
    - Chinese comma (，) -> ASCII comma (,)
    - Chinese quotes ("") -> ASCII quotes ("")
    - Chinese brackets (【】) -> ASCII brackets ([])

    Args:
        json_str: JSON string with potential Chinese punctuation.

    Returns:
        JSON string with ASCII punctuation.
    """
    # Replace Chinese punctuation
    replacements = {
        "：": ":",  # Chinese colon
        "，": ",",  # Chinese comma
        """: '"',  # Chinese left quote
        """: '"',  # Chinese right quote
        "【": "[",  # Chinese left bracket
        "】": "]",  # Chinese right bracket
        "「": '"',  # Chinese corner bracket
        "」": '"',  # Chinese corner bracket
        "『": '"',  # Chinese double corner bracket
        "』": '"',  # Chinese double corner bracket
    }

    result = json_str
    for ch_char, ascii_char in replacements.items():
        result = result.replace(ch_char, ascii_char)

    return result


def remove_text_before_json(text: str) -> str:
    """Remove explanatory text before JSON in LLM responses.

    GLM-5 and other LLMs often add introductory text like:
    - "这是分析结果："
    - "以下是JSON格式的输出："
    - "Based on my analysis:"

    Args:
        text: Text that may contain JSON with leading text.

    Returns:
        Text with leading explanatory text removed.
    """
    # Common patterns of introductory text
    patterns = [
        # Chinese patterns
        r"^[\s\S]*?(?=这是.*?[：:]\s*[\{\[])",
        r"^[\s\S]*?(?=以下是.*?[：:]\s*[\{\[])",
        r"^[\s\S]*?(?=分析结果.*?[：:]\s*[\{\[])",
        r"^[\s\S]*?(?=结果.*?[：:]\s*[\{\[])",
        # English patterns
        r"^[\s\S]*?(?=Here\s*(?:is|are)\s*(?:the\s*)?[a-zA-Z\s]*[：:]\s*[\{\[])",
        r"^[\s\S]*?(?=Based\s+on\s+(?:my\s+)?(?:the\s+)?analysis[：:]\s*[\{\[])",
        r"^[\s\S]*?(?=The\s+(?:following\s+)?(?:is\s+)?(?:the\s+)?result[s]?[：:]\s*[\{\[])",
        # Generic: find first { or [
        r"^[\s\S]*?(?=[\{\[])",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            result = text[match.end():]
            # Verify the result starts with { or [
            if result.strip().startswith(("{", "[")):
                return result

    # Fallback: just find first { or [
    first_brace = text.find("{")
    first_bracket = text.find("[")

    if first_brace == -1 and first_bracket == -1:
        return text

    if first_brace == -1:
        return text[first_bracket:]
    if first_bracket == -1:
        return text[first_brace:]

    return text[min(first_brace, first_bracket):]


def fix_unquoted_keys(json_str: str) -> str:
    """Attempt to fix unquoted keys in JSON.

    Some LLMs may output {key: "value"} instead of {"key": "value"}.

    Args:
        json_str: JSON string with potentially unquoted keys.

    Returns:
        JSON string with quoted keys.
    """
    # Pattern to match unquoted keys: identifier followed by colon
    # This is a simple heuristic and may not work in all cases
    pattern = r'(\{|\,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:'

    def add_quotes(match):
        prefix = match.group(1)
        key = match.group(2)
        return f'{prefix}"{key}":'

    return re.sub(pattern, add_quotes, json_str)


def fix_newlines_in_strings(json_str: str) -> str:
    """Escape unescaped newlines in JSON string values.

    Some LLMs may include literal newlines in string values.

    Args:
        json_str: JSON string with potentially unescaped newlines.

    Returns:
        JSON string with escaped newlines.
    """
    result = []
    i = 0
    in_string = False
    escape_next = False

    while i < len(json_str):
        char = json_str[i]

        if escape_next:
            result.append(char)
            escape_next = False
            i += 1
            continue

        if char == "\\" and in_string:
            result.append(char)
            escape_next = True
            i += 1
            continue

        if char == '"':
            in_string = not in_string
            result.append(char)
            i += 1
            continue

        if in_string and char == "\n":
            result.append("\\n")
            i += 1
            continue

        if in_string and char == "\r":
            result.append("\\r")
            i += 1
            continue

        if in_string and char == "\t":
            result.append("\\t")
            i += 1
            continue

        result.append(char)
        i += 1

    return "".join(result)


def robust_json_loads(
    text: str,
    fix_comments: bool = True,
    fix_trailing: bool = True,
    fix_quotes: bool = True,
    fix_incomplete: bool = True,
    fix_chinese: bool = True,
    fix_unquoted: bool = True,
) -> dict | list:
    """Parse JSON with fault tolerance for common LLM output issues.

    Strategy:
    1. Try direct json.loads()
    2. Extract from Markdown code blocks
    3. Remove explanatory text before JSON
    4. Extract first JSON object using bracket counting
    5. Fix Chinese punctuation (GLM-5)
    6. Remove comments
    7. Fix trailing commas
    8. Fix single quotes
    9. Fix unquoted keys
    10. Fix newlines in strings
    11. Try to fix incomplete JSON

    Args:
        text: Text containing JSON (possibly malformed).
        fix_comments: Whether to remove comments.
        fix_trailing: Whether to fix trailing commas.
        fix_quotes: Whether to fix single quotes.
        fix_incomplete: Whether to try fixing incomplete JSON.
        fix_chinese: Whether to fix Chinese punctuation.
        fix_unquoted: Whether to try fixing unquoted keys.

    Returns:
        Parsed JSON data (dict or list).

    Raises:
        JSONParseError: If all parsing attempts fail.
    """
    original_error = None
    json_str = text.strip()

    # Strategy 1: Try direct parse
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        original_error = e

    # Strategy 2: Extract from Markdown
    extracted = extract_json_from_markdown(json_str)
    if extracted:
        try:
            return json.loads(extracted)
        except json.JSONDecodeError:
            json_str = extracted

    # Strategy 3: Remove explanatory text before JSON (common in GLM-5)
    json_str = remove_text_before_json(json_str)
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        original_error = e

    # Strategy 4: Extract first JSON object
    extracted = extract_first_json_object(json_str)
    if extracted:
        try:
            return json.loads(extracted)
        except json.JSONDecodeError:
            json_str = extracted

    # Strategy 5: Fix Chinese punctuation (GLM-5 specific)
    if fix_chinese:
        json_str = fix_chinese_punctuation(json_str)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

    # Strategy 6: Remove comments
    if fix_comments:
        json_str = fix_json_comments(json_str)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

    # Strategy 7: Fix trailing commas
    if fix_trailing:
        json_str = fix_trailing_commas(json_str)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

    # Strategy 8: Fix single quotes
    if fix_quotes:
        json_str = fix_single_quotes(json_str)
        # Also need to re-fix trailing commas after quote conversion
        if fix_trailing:
            json_str = fix_trailing_commas(json_str)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

    # Strategy 9: Fix unquoted keys
    if fix_unquoted:
        json_str = fix_unquoted_keys(json_str)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

    # Strategy 10: Fix newlines in strings
    json_str = fix_newlines_in_strings(json_str)
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        pass

    # Strategy 11: Fix incomplete JSON
    if fix_incomplete:
        json_str = fix_incomplete_json(json_str)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            original_error = e

    # All strategies failed
    raise JSONParseError(
        message=f"Failed to parse JSON after all recovery attempts: {original_error}",
        original_error=original_error,
        raw_response=text[:500] if len(text) > 500 else text,
    )


def safe_json_loads(
    text: str,
    default: Any = None,
    **options,
) -> Any:
    """Safely parse JSON, returning default value on failure.

    This is a convenience wrapper around robust_json_loads that
    never raises an exception.

    Args:
        text: Text containing JSON.
        default: Value to return on parsing failure.
        **options: Additional options passed to robust_json_loads.

    Returns:
        Parsed JSON data or default value on failure.
    """
    try:
        return robust_json_loads(text, **options)
    except (JSONParseError, json.JSONDecodeError):
        return default
