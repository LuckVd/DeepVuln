"""
Type Analyzer for type-based sanitizer detection.

This module provides functionality to detect sanitizers by analyzing
type annotations, return types, and decorators.
"""

from dataclasses import dataclass, field
from typing import Any

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.call_graph.models import TypeBasedScore

logger = get_logger(__name__)


# Known safe return types by vulnerability type
SAFE_RETURN_TYPES = {
    "xss": [
        # Python
        "markupsafe.Markup",
        "markupsafe.Escape",
        "django.utils.safestring.SafeText",
        "django.utils.safestring.SafeString",
        "django.utils.safestring.mark_safe",
        "flask.Markup",
        "Markup",  # Short name for markupsafe.Markup
        "Escape",  # Short name for markupsafe.Escape
        "SafeText",  # Short name
        "SafeString",  # Short name
        # JavaScript
        "SafeHtml",
        "TrustedHTML",
        # Java
        "org.owasp.html.HtmlSanitizer",
        "org.owasp.html.PolicyFactory",
    ],
    "sqli": [
        # Python
        "sqlalchemy.sql.expression.TextClause",
        "sqlalchemy.sql.expression.BindParameter",
        "TextClause",  # Short name
        # Java
        "java.sql.PreparedStatement",
    ],
    "cmdi": [
        # Python
        "subprocess.list2cmdline",
        "shlex.quote",
    ],
    "path_traversal": [
        # Python
        "pathlib.PurePath",
        "pathlib.Path",
        "PurePath",  # Short name
        "Path",  # Short name
    ],
}


# Known sanitizer decorator patterns
SANITIZER_DECORATORS = {
    "python": [
        "@sanitizer",
        "@escape",
        "@safe",
        "@xss_safe",
        "@sql_safe",
        "@html_safe",
    ],
    "javascript": [
        "@Sanitize",
        "@Escape",
        "@Safe",
    ],
    "java": [
        "@Sanitize",
        "@SafeHtml",
        "@SafeSql",
    ],
    "go": [
        "//sanitizer",
        "//escape",
    ],
}


# Type guard patterns (functions that validate/sanitize types)
TYPE_GUARD_PATTERNS = {
    "python": [
        "isinstance(",
        "hasattr(",
        "validate(",
        "sanitize(",
        "escape(",
        "clean(",
    ],
    "javascript": [
        "typeof",
        "instanceof",
        "validate",
        "sanitize",
        "escape",
    ],
    "java": [
        "instanceof",
        "validate",
        "sanitize",
        "escape",
    ],
}


@dataclass
class TypeAnalysisResult:
    """Result of type-based sanitizer detection."""

    function_id: str = ""
    function_name: str = ""
    has_safe_return_type: bool = False
    has_sanitizer_decorator: bool = False
    has_type_guard: bool = False
    is_sanitizer: bool = False
    confidence: float = 0.0
    safe_types: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)


class TypeAnalyzer:
    """
    Analyzes function type signatures for sanitizer patterns.

    Detects sanitizers by:
    1. Safe return types (SafeHtml, SafeSql, Markup)
    2. Sanitizer decorators (@sanitizer, @escape, @safe)
    3. Type guard patterns (validation functions)
    """

    def __init__(self, vuln_type: str = "xss", language: str = "python"):
        """
        Initialize the analyzer.

        Args:
            vuln_type: Vulnerability type for safe type patterns
            language: Programming language for pattern matching
        """
        self.vuln_type = vuln_type
        self.language = language
        self.safe_types = SAFE_RETURN_TYPES.get(vuln_type, [])
        self.sanitizer_decorators = SANITIZER_DECORATORS.get(language, [])
        self.type_guard_patterns = TYPE_GUARD_PATTERNS.get(language, [])

        # Initialize parser
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

    def analyze_function(self, function_node: Any, source_code: str) -> TypeBasedScore:
        """
        Analyze a function AST node for type-based sanitizer patterns.

        Args:
            function_node: AST FunctionDef node (tree-sitter node)
            source_code: Full source code string

        Returns:
            TypeBasedScore with analysis results
        """
        # Initialize result
        score = TypeBasedScore()

        # Check for safe return type
        safe_type = self._has_safe_return_type(function_node, source_code)
        score.has_safe_return_type = safe_type[0]
        if safe_type[1]:
            score.safe_types.append(safe_type[1])

        # Check for sanitizer decorators
        decorators = self._get_sanitizer_decorators(function_node, source_code)
        score.has_sanitizer_decorator = len(decorators) > 0
        score.decorators = decorators

        # Check for type guard patterns
        score.has_type_guard = self._has_type_guard(function_node, source_code)

        # Determine if sanitizer based on combined factors
        score.is_sanitizer = self._is_sanitizer(score)
        score.confidence = self._calculate_confidence(score)

        return score

    def analyze_from_source(
        self, source_code: str, function_name: str
    ) -> TypeBasedScore:
        """
        Analyze a function from source code by finding it in AST.

        Args:
            source_code: Source code content
            function_name: Name of the function to analyze

        Returns:
            TypeBasedScore with analysis results
        """
        if not self._parser:
            return TypeBasedScore()

        try:
            tree = self._parser.parse(source_code.encode("utf-8"))
            root = tree.root_node

            # Find the function in AST
            func_node = self._find_function(root, function_name, source_code)
            if not func_node:
                logger.debug(f"Function {function_name} not found in source")
                return TypeBasedScore()

            return self.analyze_function(func_node, source_code)

        except Exception as e:
            logger.warning(f"Failed to analyze function {function_name}: {e}")
            return TypeBasedScore()

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

    def _has_safe_return_type(
        self, function_node: Any, source_code: str
    ) -> tuple[bool, str | None]:
        """
        Check if function has a safe return type.

        Detects:
        - Function annotations with safe types
        - Return statements that wrap with safe constructors

        Returns:
            Tuple of (has_safe_type, type_name)
        """
        if not function_node:
            return False, None

        # Check return type annotation
        for child in function_node.children:
            if child.type == "type":
                # This is a return type annotation
                type_text = self._get_text(child, source_code)
                for safe_type in self.safe_types:
                    if safe_type.lower() in type_text.lower():
                        return True, safe_type

            elif child.type == "block":
                # Check return statements in function body
                return self._check_return_statements(child, source_code)

        return False, None

    def _check_return_statements(
        self, block_node: Any, source_code: str
    ) -> tuple[bool, str | None]:
        """Check return statements for safe type constructors."""
        for child in block_node.children:
            if child.type == "return_statement":
                # Check what's being returned
                for ret_child in child.children:
                    if ret_child.type == "call":
                        # Check if this is a safe type constructor
                        func_name = self._extract_call_name(ret_child, source_code)
                        for safe_type in self.safe_types:
                            if func_name and safe_type in func_name:
                                return True, safe_type

            # Recurse into nested blocks
            elif child.type == "block" or child.type == "if_statement":
                result = self._check_return_statements(child, source_code)
                if result[0]:
                    return result

        return False, None

    def _get_sanitizer_decorators(
        self, function_node: Any, source_code: str
    ) -> list[str]:
        """
        Get all sanitizer decorators on a function.

        Returns:
            List of decorator names
        """
        decorators = []

        if not function_node:
            return decorators

        # Check if function is decorated
        parent = function_node.parent
        if parent and parent.type == "decorated_definition":
            for child in parent.children:
                if child.type == "decorator":
                    decorator_text = self._get_text(child, source_code)
                    # Check if this matches any known sanitizer decorator
                    for pattern in self.sanitizer_decorators:
                        if pattern.lower() in decorator_text.lower():
                            decorators.append(decorator_text)
                            break

        return decorators

    def _has_type_guard(self, function_node: Any, source_code: str = "") -> bool:
        """
        Check if function contains type guard patterns.

        Type guards are validation/sanitization function calls that
        check or sanitize input before use.

        Returns:
            True if type guard patterns are found
        """
        if not function_node:
            return False

        # Find function body
        func_body = None
        for child in function_node.children:
            if child.type == "block":
                func_body = child
                break

        if not func_body:
            return False

        # Search for type guard patterns
        return self._has_type_guard_in_node(func_body, source_code)

    def _has_type_guard_in_node(self, node: Any, source_code: str) -> bool:
        """Recursively check if node contains type guard patterns."""
        if node.type == "call":
            func_name = self._extract_call_name(node, source_code)
            if func_name:
                for pattern in self.type_guard_patterns:
                    if pattern in func_name:
                        return True

        # Check if statements with isinstance
        if node.type == "if_statement":
            condition = self._get_condition_text(node, source_code)
            if condition and "isinstance" in condition:
                return True

        # Recurse into children
        for child in node.children:
            if self._has_type_guard_in_node(child, source_code):
                return True

        return False

    def _get_condition_text(self, if_node: Any, source_code: str = "") -> str | None:
        """Extract condition text from if statement."""
        if not if_node or if_node.type != "if_statement":
            return None

        for child in if_node.children:
            if child.type == "parenthesized_expression" or child.type == "expression_statement":
                return self._get_text(child, source_code)
            elif child.type == "condition":
                return self._get_text(child, source_code)
            elif child.type == "call":
                # In Python AST, the condition can be a call directly
                return self._get_text(child, source_code)

        return None

    def _extract_call_name(self, call_node: Any, source_code: str = "") -> str | None:
        """
        Extract the full function name from a call node.
        """
        if not call_node or call_node.type != "call":
            return None

        for child in call_node.children:
            if child.type == "identifier":
                return self._get_text(child, source_code)
            elif child.type == "attribute":
                attr_name = self._extract_attribute_name(child, source_code)
                if attr_name:
                    return attr_name

        return None

    def _extract_attribute_name(self, attr_node: Any, source_code: str = "") -> str | None:
        """Extract attribute chain from an attribute node."""
        if not attr_node or attr_node.type != "attribute":
            return None

        parts = []

        for child in attr_node.children:
            if child.type == "identifier":
                parts.append(self._get_text(child, source_code))
            elif child.type == "attribute":
                attr = self._extract_attribute_name(child, source_code)
                if attr:
                    parts.insert(0, attr)

        return ".".join(parts) if parts else None

    def _get_text(self, node: Any, content: str) -> str:
        """Get text content of a tree-sitter node."""
        if not node:
            return ""
        try:
            return content[node.start_byte : node.end_byte]
        except (AttributeError, IndexError):
            return ""

    def _is_sanitizer(self, score: TypeBasedScore) -> bool:
        """
        Determine if function is a sanitizer based on heuristics.

        Args:
            score: TypeBasedScore with analysis results

        Returns:
            True if function appears to be a sanitizer
        """
        # Strong indicators
        if score.has_safe_return_type and score.has_sanitizer_decorator:
            return True

        # Single strong indicator
        if score.has_safe_return_type or score.has_sanitizer_decorator:
            return True

        # Weaker indicator
        if score.has_type_guard and score.has_safe_return_type:
            return True

        return False

    def _calculate_confidence(self, score: TypeBasedScore) -> float:
        """
        Calculate confidence score for sanitizer detection.

        Returns:
            Confidence value (0.0 to 1.0)
        """
        confidence = 0.0

        # Strong indicators
        if score.has_safe_return_type:
            confidence += 0.5
        if score.has_sanitizer_decorator:
            confidence += 0.4
        if score.has_type_guard:
            confidence += 0.1

        return min(confidence, 1.0)
