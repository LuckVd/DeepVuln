"""
Transform Analyzer for AST-based sanitizer detection.

This module provides functionality to detect sanitizers by analyzing
AST transformations (string replacement operations, encoding calls) and dangerous
characters coverage ratio to determine if a function is an effective sanitizer.
"""

from dataclasses import dataclass, field
from typing import Any

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.call_graph.models import TransformScore

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


# Common sanitizer function names by category
REPLACE_FUNCTIONS = {
    "python": [
        "str.replace",
        "replace",
        "re.sub",
        "re.subn",
        "string.replace",
    ],
    "javascript": [
        "String.prototype.replace",
        "String.prototype.replaceAll",
        "replace",
        "replaceAll",
    ],
    "java": [
        "String.replace",
        "String.replaceAll",
        "replace",
        "replaceAll",
    ],
    "go": [
        "strings.Replace",
        "strings.ReplaceAll",
        "strings.Replacer",
    ],
}

ENCODE_FUNCTIONS = {
    "python": [
        "html.escape",
        "html.unescape",
        "urllib.parse.quote",
        "urllib.parse.quote_plus",
        "urllib.parse.quote_from_bytes",
        "cgi.escape",
        "xml.sax.saxutils.escape",
        "json.dumps",
    ],
    "javascript": [
        "encodeURIComponent",
        "encodeURI",
        "escape",
        "JSON.stringify",
        "DOMPurify.sanitize",
    ],
    "java": [
        "StringEscapeUtils.escapeHtml4",
        "StringEscapeUtils.escapeEcmaScript",
        "URLEncoder.encode",
        "StringEscapeUtils.escapeSql",
    ],
    "go": [
        "url.QueryEscape",
        "html.EscapeString",
        "json.HTMLEscape",
        "sqlquote",
    ],
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

    def __init__(self, vuln_type: str = "xss", language: str = "python"):
        """
        Initialize the analyzer.

        Args:
            vuln_type: Vulnerability type for dangerous character patterns
            language: Programming language for function detection
        """
        self.vuln_type = vuln_type
        self.language = language
        self.dangerous_chars = DANGEROUS_CHARS.get(vuln_type, DANGEROUS_CHARS["xss"])
        self.replace_funcs = REPLACE_FUNCTIONS.get(language, REPLACE_FUNCTIONS["python"])
        self.encode_funcs = ENCODE_FUNCTIONS.get(language, ENCODE_FUNCTIONS["python"])

        # Initialize parser for the language
        self._parser: Parser | None = None
        self._language: Language | None = None
        self._init_parser()

    def _init_parser(self) -> None:
        """Initialize tree-sitter parser for Python."""
        try:
            if self.language == "python":
                self._language = Language(tspython.language())
                self._parser = Parser(self._language)
        except Exception as e:
            logger.warning(f"Failed to initialize parser: {e}")

    def analyze_function(self, function_node: Any, source_code: str) -> TransformScore:
        """
        Analyze a function AST node for sanitizer patterns.

        Args:
            function_node: AST FunctionDef node (tree-sitter node)
            source_code: Full source code string

        Returns:
            TransformScore with analysis results
        """
        # Initialize result
        score = TransformScore()

        # Check for replace operations
        score.has_replace_ops = self._has_replace_operations(function_node, source_code)

        # Check for encode calls
        score.has_encode_calls = self._has_encode_calls(function_node, source_code)

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
            "language": self.language,
        }

        return score

    def analyze_from_source(
        self, source_code: str, function_name: str
    ) -> TransformScore:
        """
        Analyze a function from source code by finding it in AST.

        Args:
            source_code: Source code content
            function_name: Name of the function to analyze

        Returns:
            TransformScore with analysis results
        """
        if not self._parser:
            return TransformScore()

        try:
            tree = self._parser.parse(source_code.encode("utf-8"))
            root = tree.root_node

            # Find the function in AST
            func_node = self._find_function(root, function_name, source_code)
            if not func_node:
                logger.debug(f"Function {function_name} not found in source")
                return TransformScore()

            return self.analyze_function(func_node, source_code)

        except Exception as e:
            logger.warning(f"Failed to analyze function {function_name}: {e}")
            return TransformScore()

    def _find_function(self, root: Any, function_name: str, source_code: str = "") -> Any | None:
        """Find a function definition node by name."""
        return self._find_function_in_node(root, function_name, source_code)

    def _find_function_in_node(self, node: Any, function_name: str, source_code: str = "") -> Any | None:
        """Recursively search for function definition."""
        if node.type == "function_definition":
            # Get function name
            for child in node.children:
                if child.type == "identifier":
                    func_name = self._get_text(child, source_code)
                    if func_name == function_name:
                        return node
                    break

        # Recurse into children
        for child in node.children:
            result = self._find_function_in_node(child, function_name, source_code)
            if result:
                return result

        return None

    def _has_replace_operations(self, function_node: Any, source_code: str = "") -> bool:
        """
        Check if function contains string replace operations.

        Detects:
        - str.replace calls
        - re.sub calls
        - string.replace calls
        """
        if not function_node:
            return False

        # Find the function body (block)
        func_body = None
        for child in function_node.children:
            if child.type == "block":
                func_body = child
                break

        if not func_body:
            return False

        # Search for call expressions
        return self._has_replace_in_node(func_body, source_code)

    def _has_replace_in_node(self, node: Any, source_code: str) -> bool:
        """Recursively check if node contains replace function calls."""
        if node.type == "call":
            func_name = self._extract_call_name(node, source_code)
            if func_name and any(
                f in func_name or func_name.endswith(f)
                for f in self.replace_funcs
            ):
                return True

        # Recurse into children
        for child in node.children:
            if self._has_replace_in_node(child, source_code):
                return True

        return False

    def _has_encode_calls(self, function_node: Any, source_code: str = "") -> bool:
        """
        Check if function contains encoding/escaping function calls.

        Detects:
        - html.escape
        - urllib.parse.quote
        - cgi.escape
        - etc.
        """
        if not function_node:
            return False

        # Find the function body
        func_body = None
        for child in function_node.children:
            if child.type == "block":
                func_body = child
                break

        if not func_body:
            return False

        # Search for encode function calls
        return self._has_encode_in_node(func_body, source_code)

    def _has_encode_in_node(self, node: Any, source_code: str) -> bool:
        """Recursively check if node contains encode function calls."""
        if node.type == "call":
            func_name = self._extract_call_name(node, source_code)
            if func_name and any(
                f in func_name or func_name.endswith(f)
                for f in self.encode_funcs
            ):
                return True

        # Recurse into children
        for child in node.children:
            if self._has_encode_in_node(child, source_code):
                return True

        return False

    def _extract_call_name(self, call_node: Any, source_code: str) -> str | None:
        """
        Extract the full function name from a call node.

        Handles:
        - Direct calls: func()
        - Attribute calls: module.func()
        - Method calls: obj.func()
        """
        if not call_node or call_node.type != "call":
            return None

        for child in call_node.children:
            if child.type == "identifier":
                return self._get_text(child, source_code)
            elif child.type == "attribute":
                # Extract attribute chain (e.g., html.escape)
                return self._extract_attribute_name(child, source_code)
            elif child.type == "call":
                # Nested call
                return self._extract_call_name(child, source_code)

        return None

    def _extract_attribute_name(self, attr_node: Any, source_code: str) -> str | None:
        """Extract attribute chain from an attribute node."""
        if not attr_node or attr_node.type != "attribute":
            return None

        parts = []

        # An attribute has: obj.attr
        # We need to traverse to get the full chain
        for child in attr_node.children:
            if child.type == "identifier":
                parts.append(self._get_text(child, source_code))
            elif child.type == "attribute":
                # Nested attribute
                attr = self._extract_attribute_name(child, source_code)
                if attr:
                    parts.insert(0, attr)

        return ".".join(parts) if parts else None

    def _calculate_char_coverage(
        self, function_node: Any, source_code: str
    ) -> float:
        """
        Calculate coverage of dangerous characters in replace patterns.

        Extracts string literals from replace/sub calls and checks
        which dangerous characters they would remove.

        Returns:
            Coverage ratio (0.0 to 1.0)
        """
        if not function_node:
            return 0.0

        # Find the function body
        func_body = None
        for child in function_node.children:
            if child.type == "block":
                func_body = child
                break

        if not func_body:
            return 0.0

        # Collect all string literals from replace calls
        covered_chars = set()

        self._extract_chars_from_replace_calls(
            func_body, source_code, covered_chars
        )

        if not self.dangerous_chars:
            return 0.0

        # Calculate coverage ratio
        coverage = len(covered_chars) / len(self.dangerous_chars)
        return min(coverage, 1.0)

    def _extract_chars_from_replace_calls(
        self, node: Any, source_code: str, covered_chars: set[str]
    ) -> None:
        """Extract dangerous characters from replace call string literals."""
        if node.type == "call":
            func_name = self._extract_call_name(node, source_code)
            if func_name and any(
                f in func_name or func_name.endswith(f)
                for f in self.replace_funcs
            ):
                # This is a replace call, extract string arguments
                self._extract_string_literals(node, source_code, covered_chars)

        # Recurse into children
        for child in node.children:
            self._extract_chars_from_replace_calls(child, source_code, covered_chars)

    def _extract_string_literals(
        self, call_node: Any, source_code: str, covered_chars: set[str]
    ) -> None:
        """Extract string literals from function call arguments."""
        # Look for argument list
        for child in call_node.children:
            if child.type == "argument_list":
                # Check each argument
                for arg in child.children:
                    if arg.type == "string":
                        # Extract the string content
                        literal = self._get_string_literal_content(arg, source_code)
                        if literal:
                            # Check which dangerous chars are covered
                            for char in self.dangerous_chars:
                                if char in literal:
                                    covered_chars.add(char)

    def _get_string_literal_content(self, string_node: Any, source_code: str) -> str | None:
        """
        Extract the actual content from a string literal node.

        Handles:
        - Single-quoted strings: 'text'
        - Double-quoted strings: "text"
        - Triple-quoted strings: '''text''', \"\"\"text\"\"\"
        - Raw strings: r'text'
        - Escape sequences
        """
        if not string_node or string_node.type != "string":
            return None

        # Get the raw text
        try:
            start = string_node.start_byte
            end = string_node.end_byte
            raw_text = source_code[start:end]
        except (AttributeError, IndexError):
            return None

        # Remove quotes and evaluate escape sequences
        try:
            # Python's eval handles all string formats
            content = eval(raw_text)
            return content
        except Exception:
            # Fallback: strip quotes manually
            if raw_text.startswith('"""') or raw_text.startswith("'''"):
                return raw_text[3:-3]
            elif raw_text.startswith('"') or raw_text.startswith("'"):
                return raw_text[1:-1]
            return raw_text

    def _get_text(self, node: Any, content: str) -> str:
        """Get text content of a tree-sitter node."""
        if not node:
            return ""
        try:
            return content[node.start_byte : node.end_byte]
        except (AttributeError, IndexError):
            return ""

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
