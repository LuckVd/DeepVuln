"""
Core utilities module for DeepVuln.
"""

from src.core.utils.json_parser import (
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

__all__ = [
    "JSONParseError",
    "extract_json_from_markdown",
    "fix_trailing_commas",
    "fix_json_comments",
    "fix_single_quotes",
    "extract_first_json_object",
    "fix_incomplete_json",
    "robust_json_loads",
    "safe_json_loads",
]
