"""
Sanitizer Detector - Identify and evaluate sanitizers in data flow paths.

This module provides functionality to detect sanitization functions and
evaluate their effectiveness in blocking taint propagation.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.models import CodeLocation

logger = get_logger(__name__)


class SanitizerEffectiveness(str, Enum):
    """Effectiveness level of a sanitizer."""
    FULL = "full"  # Completely blocks the vulnerability
    PARTIAL = "partial"  # Reduces but doesn't eliminate risk
    INEFFECTIVE = "ineffective"  # Known to be bypassable
    UNKNOWN = "unknown"  # Effectiveness unclear


@dataclass
class SanitizerMatch:
    """A detected sanitizer in the code."""

    # Identification
    name: str
    category: str  # html_encode, sql_escape, etc.

    # Location
    location: CodeLocation
    function_name: str | None = None
    library: str | None = None

    # Effectiveness
    effectiveness: SanitizerEffectiveness = SanitizerEffectiveness.UNKNOWN
    bypass_conditions: list[str] = field(default_factory=list)
    notes: str | None = None

    # Context
    input_variable: str | None = None
    output_variable: str | None = None
    is_wrapped: bool = False  # Is the sanitizer properly wrapping the input?

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "category": self.category,
            "location": {
                "file": self.location.file,
                "line": self.location.line,
            },
            "function_name": self.function_name,
            "library": self.library,
            "effectiveness": self.effectiveness.value,
            "bypass_conditions": self.bypass_conditions,
            "notes": self.notes,
            "input_variable": self.input_variable,
            "output_variable": self.output_variable,
            "is_wrapped": self.is_wrapped,
        }


# Sanitizer patterns by category and language
SANITIZER_PATTERNS: dict[str, dict[str, list[dict[str, Any]]]] = {
    "python": {
        "html_encode": [
            {
                "patterns": [
                    r"bleach\.clean\s*\(",
                    r"markupsafe\.escape\s*\(",
                    r"html\.escape\s*\(",
                    r"cgi\.escape\s*\(",
                    r"django\.utils\.html\.escape\s*\(",
                    r"flask\.escape\s*\(",
                ],
                "effectiveness": SanitizerEffectiveness.FULL,
                "libraries": ["bleach", "markupsafe", "html", "cgi", "django", "flask"],
            },
        ],
        "sql_escape": [
            {
                "patterns": [
                    r"mysql\.escape_string\s*\(",
                    r"psycopg2\.extras\.quote_ident\s*\(",
                    r"sqlite3\.escape\s*\(",
                ],
                "effectiveness": SanitizerEffectiveness.PARTIAL,
                "bypass": ["Encoding issues", "Context mismatch"],
                "libraries": ["mysql", "psycopg2", "sqlite3"],
            },
        ],
        "prepared_stmt": [
            {
                "patterns": [
                    r"\.execute\s*\([^)]*%s",
                    r"\.execute\s*\([^)]*\?",
                    r"\.execute\s*\([^)]*:param",
                    r"cursor\.execute\s*\([^,]+,\s*\[",
                    r"session\.execute\s*\([^,]+,\s*\{",
                ],
                "effectiveness": SanitizerEffectiveness.FULL,
                "libraries": ["sqlite3", "psycopg2", "mysql", "sqlalchemy"],
            },
        ],
        "command_escape": [
            {
                "patterns": [
                    r"shlex\.quote\s*\(",
                    r"pipes\.quote\s*\(",
                    r"subprocess\.list2cmdline\s*\(",
                ],
                "effectiveness": SanitizerEffectiveness.FULL,
                "libraries": ["shlex", "pipes", "subprocess"],
            },
        ],
        "path_validate": [
            {
                "patterns": [
                    r"os\.path\.realpath\s*\(",
                    r"os\.path\.abspath\s*\(",
                    r"os\.path\.basename\s*\(",
                    r"pathlib\.Path\s*\([^)]*\)\.resolve\s*\(",
                    r"\.startswith\s*\(['\"]\/",
                ],
                "effectiveness": SanitizerEffectiveness.PARTIAL,
                "bypass": ["Null bytes", "Symlink following"],
                "libraries": ["os", "pathlib"],
            },
        ],
        "input_validate": [
            {
                "patterns": [
                    r"\.isdigit\s*\(\)",
                    r"\.isalnum\s*\(\)",
                    r"\.isalpha\s*\(\)",
                    r"re\.match\s*\([^)]+\)",
                    r"re\.search\s*\([^)]+\)",
                    r"re\.fullmatch\s*\([^)]+\)",
                ],
                "effectiveness": SanitizerEffectiveness.PARTIAL,
                "bypass": ["Regex bypass", "Unicode issues"],
                "libraries": ["re"],
            },
        ],
        "type_cast": [
            {
                "patterns": [
                    r"int\s*\(",
                    r"float\s*\(",
                    r"str\s*\(",
                    r"bool\s*\(",
                ],
                "effectiveness": SanitizerEffectiveness.FULL,
                "libraries": ["builtins"],
            },
        ],
    },
    "java": {
        "html_encode": [
            {
                "patterns": [
                    r"StringEscapeUtils\.escapeHtml",
                    r"Encoder\.htmlEncode",
                    r"ESAPI\.encoder\(\)\.encodeForHTML",
                    r"HtmlUtils\.htmlEscape",
                ],
                "effectiveness": SanitizerEffectiveness.FULL,
                "libraries": ["apache-commons", "owasp-esapi", "spring"],
            },
        ],
        "prepared_stmt": [
            {
                "patterns": [
                    r"PreparedStatement",
                    r"NamedParameterJdbcTemplate",
                    r"\.setString\s*\(",
                    r"\.setInt\s*\(",
                    r"\.setObject\s*\(",
                ],
                "effectiveness": SanitizerEffectiveness.FULL,
                "libraries": ["java.sql", "spring-jdbc"],
            },
        ],
        "command_escape": [
            {
                "patterns": [
                    r"FilenameUtils\.getName",
                    r"Strings\.escapeBash",
                ],
                "effectiveness": SanitizerEffectiveness.PARTIAL,
                "libraries": ["apache-commons"],
            },
        ],
    },
    "javascript": {
        "html_encode": [
            {
                "patterns": [
                    r"DOMPurify\.sanitize",
                    r"escapeHtml",
                    r"he\.encode",
                    r"xss\(.*?\)",
                    r"sanitizeHtml",
                ],
                "effectiveness": SanitizerEffectiveness.FULL,
                "libraries": ["dompurify", "he", "xss", "sanitize-html"],
            },
        ],
        "sql_escape": [
            {
                "patterns": [
                    r"mysql\.escape\s*\(",
                    r"pg\.escapeLiteral",
                    r"sequelize\.escape",
                ],
                "effectiveness": SanitizerEffectiveness.PARTIAL,
                "libraries": ["mysql", "pg", "sequelize"],
            },
        ],
        "prepared_stmt": [
            {
                "patterns": [
                    r"\.query\s*\([^,]+,\s*\[",
                    r"\.execute\s*\([^,]+,\s*\[",
                    r"\$1|\$2|\$3",  # PostgreSQL parameterized
                    r"\?|\?\?",  # MySQL parameterized
                ],
                "effectiveness": SanitizerEffectiveness.FULL,
                "libraries": ["pg", "mysql", "sequelize"],
            },
        ],
        "input_validate": [
            {
                "patterns": [
                    r"validator\.is[A-Z]",
                    r"joi\.validate",
                    r"yup\.validate",
                    r"/\^.+\$/.test\(",
                ],
                "effectiveness": SanitizerEffectiveness.PARTIAL,
                "libraries": ["validator", "joi", "yup"],
            },
        ],
    },
    "go": {
        "html_encode": [
            {
                "patterns": [
                    r"html\.EscapeString",
                    r"template\.HTMLEscapeString",
                ],
                "effectiveness": SanitizerEffectiveness.FULL,
                "libraries": ["html", "html/template"],
            },
        ],
        "prepared_stmt": [
            {
                "patterns": [
                    r"\$1|\$2|\$3",  # Parameterized query placeholders
                    r"\.Query\s*\([^,]+,",
                    r"\.Exec\s*\([^,]+,",
                ],
                "effectiveness": SanitizerEffectiveness.FULL,
                "libraries": ["database/sql"],
            },
        ],
        "command_escape": [
            {
                "patterns": [
                    r"exec\.Command",
                    r"filepath\.Base",
                    r"filepath\.Clean",
                ],
                "effectiveness": SanitizerEffectiveness.PARTIAL,
                "libraries": ["os/exec", "path/filepath"],
            },
        ],
    },
}

# Known ineffective sanitizers
INEFFECTIVE_SANITIZERS: dict[str, list[str]] = {
    "python": [
        r"replace\s*\(\s*['\"]<['\"]\s*,",  # Only removes < (incomplete)
        r"replace\s*\(\s*['\"]>'\"]\s*,",  # Only removes > (incomplete)
        r"replace\s*\(\s*['\"]['\"]\s*,",  # Only removes quotes (incomplete)
    ],
    "javascript": [
        r"\.replace\s*\(\s*/<[^>]*>/g",  # Strips tags but not attributes
        r"unescape\s*\(",  # Actually decodes, not sanitizes
        r"eval\s*\(",  # Dangerous function
    ],
    "java": [
        r"String\.replace\s*\(",  # Single character replacement (incomplete)
    ],
}


class SanitizerDetector:
    """
    Detects and evaluates sanitizers in code.

    Analyzes code snippets and data flow paths to identify sanitization
    functions and assess their effectiveness.
    """

    def __init__(self, language: str = "python"):
        """
        Initialize the sanitizer detector.

        Args:
            language: Target programming language.
        """
        self.language = language.lower()
        self._patterns = SANITIZER_PATTERNS.get(self.language, {})
        self._ineffective = INEFFECTIVE_SANITIZERS.get(self.language, [])

    def detect_in_snippet(
        self,
        snippet: str,
        location: CodeLocation | None = None,
    ) -> list[SanitizerMatch]:
        """
        Detect sanitizers in a code snippet.

        Args:
            snippet: Code snippet to analyze.
            location: Optional code location for the snippet.

        Returns:
            List of detected sanitizers.
        """
        sanitizers = []
        loc = location or CodeLocation(file="", line=1)

        # Check for each sanitizer category
        for category, pattern_groups in self._patterns.items():
            for group in pattern_groups:
                for pattern in group.get("patterns", []):
                    matches = re.finditer(pattern, snippet, re.IGNORECASE)
                    for match in matches:
                        # Determine effectiveness
                        effectiveness = group.get(
                            "effectiveness",
                            SanitizerEffectiveness.UNKNOWN
                        )

                        # Check if it's actually ineffective
                        for ineffective_pattern in self._ineffective:
                            if re.search(ineffective_pattern, snippet, re.IGNORECASE):
                                effectiveness = SanitizerEffectiveness.INEFFECTIVE
                                break

                        sanitizer = SanitizerMatch(
                            name=f"{category}_sanitizer",
                            category=category,
                            location=CodeLocation(
                                file=loc.file,
                                line=loc.line,
                                column=match.start() + 1 if loc.column is None else loc.column + match.start(),
                                snippet=snippet[match.start():match.end()],
                            ),
                            function_name=self._extract_function_name(snippet, match),
                            library=self._identify_library(group.get("libraries", [])),
                            effectiveness=effectiveness,
                            bypass_conditions=group.get("bypass", []),
                            is_wrapped=self._check_wrapped(snippet, match),
                        )
                        sanitizers.append(sanitizer)

        # Deduplicate similar sanitizers
        return self._deduplicate(sanitizers)

    def detect_in_path(
        self,
        path_nodes: list[dict[str, Any]],
    ) -> list[SanitizerMatch]:
        """
        Detect sanitizers along a data flow path.

        Args:
            path_nodes: List of path node dictionaries.

        Returns:
            List of detected sanitizers.
        """
        all_sanitizers = []

        for i, node in enumerate(path_nodes):
            snippet = node.get("snippet", "") or node.get("expression", "")
            if not snippet:
                continue

            location = CodeLocation(
                file=node.get("file_path", ""),
                line=node.get("line", 1),
                column=node.get("column"),
                snippet=snippet,
            )

            sanitizers = self.detect_in_snippet(snippet, location)

            # Mark position in path
            for san in sanitizers:
                san.notes = f"Found at path position {i}"

            all_sanitizers.extend(sanitizers)

        return all_sanitizers

    def evaluate_effectiveness(
        self,
        sanitizers: list[SanitizerMatch],
        vulnerability_type: str,
    ) -> tuple[bool, str]:
        """
        Evaluate overall effectiveness of sanitizers against a vulnerability.

        Args:
            sanitizers: List of detected sanitizers.
            vulnerability_type: Type of vulnerability (sql_injection, xss, etc.).

        Returns:
            Tuple of (is_effective, reason).
        """
        if not sanitizers:
            return False, "No sanitizers found"

        # Map vulnerability types to relevant sanitizer categories
        relevant_categories = self._get_relevant_categories(vulnerability_type)

        # Find relevant sanitizers
        relevant_sanitizers = [
            s for s in sanitizers
            if s.category in relevant_categories
        ]

        if not relevant_sanitizers:
            return False, f"No sanitizers relevant to {vulnerability_type}"

        # Check for fully effective sanitizers
        fully_effective = [
            s for s in relevant_sanitizers
            if s.effectiveness == SanitizerEffectiveness.FULL
        ]

        if fully_effective:
            names = [s.function_name or s.category for s in fully_effective]
            return True, f"Effective sanitizers: {', '.join(names)}"

        # Check for partially effective
        partially_effective = [
            s for s in relevant_sanitizers
            if s.effectiveness == SanitizerEffectiveness.PARTIAL
        ]

        if partially_effective:
            bypasses = []
            for s in partially_effective:
                bypasses.extend(s.bypass_conditions)
            bypass_str = ", ".join(set(bypasses)) if bypasses else "possible bypasses"
            return False, f"Partial protection - potential bypasses: {bypass_str}"

        # All ineffective or unknown
        ineffective = [
            s for s in relevant_sanitizers
            if s.effectiveness == SanitizerEffectiveness.INEFFECTIVE
        ]

        if ineffective:
            names = [s.function_name or s.category for s in ineffective]
            return False, f"Ineffective sanitizers: {', '.join(names)}"

        return False, "Sanitizer effectiveness unknown"

    def _get_relevant_categories(self, vuln_type: str) -> list[str]:
        """Get sanitizer categories relevant to a vulnerability type."""
        mapping = {
            "sql_injection": ["prepared_stmt", "sql_escape", "input_validate", "type_cast"],
            "xss": ["html_encode", "input_validate"],
            "command_injection": ["command_escape", "input_validate", "type_cast"],
            "path_traversal": ["path_validate", "input_validate"],
            "ldap_injection": ["input_validate", "type_cast"],
            "xpath_injection": ["input_validate", "type_cast"],
            "ssrf": ["input_validate", "whitelist"],
        }
        return mapping.get(vuln_type.lower(), ["input_validate"])

    def _extract_function_name(self, snippet: str, match: re.Match) -> str | None:
        """Extract function name from matched pattern."""
        matched_text = match.group(0)

        # Try to extract function name
        func_match = re.match(r"(\w+(?:\.\w+)*)\s*\(", matched_text)
        if func_match:
            return func_match.group(1)

        return None

    def _identify_library(self, libraries: list[str]) -> str | None:
        """Identify which library is likely being used."""
        if libraries:
            return libraries[0]  # Return first as most likely
        return None

    def _check_wrapped(self, snippet: str, match: re.Match) -> bool:
        """Check if the sanitizer is properly wrapping the input."""
        # Look for patterns like sanitize(input) or escape(user_input)
        matched_text = match.group(0)

        # Check if there's something inside the parentheses
        paren_match = re.search(r"\(([^)]+)\)", matched_text)
        if paren_match and paren_match.group(1).strip():
            return True

        return False

    def _deduplicate(self, sanitizers: list[SanitizerMatch]) -> list[SanitizerMatch]:
        """Remove duplicate sanitizer detections."""
        seen = set()
        result = []

        for san in sanitizers:
            key = (san.category, san.location.file, san.location.line)
            if key not in seen:
                seen.add(key)
                result.append(san)

        return result

    def get_statistics(self, sanitizers: list[SanitizerMatch]) -> dict[str, Any]:
        """Get statistics about detected sanitizers."""
        if not sanitizers:
            return {
                "total": 0,
                "by_category": {},
                "by_effectiveness": {},
                "fully_effective_count": 0,
            }

        by_category: dict[str, int] = {}
        by_effectiveness: dict[str, int] = {}

        for san in sanitizers:
            by_category[san.category] = by_category.get(san.category, 0) + 1
            eff = san.effectiveness.value
            by_effectiveness[eff] = by_effectiveness.get(eff, 0) + 1

        fully_effective = sum(
            1 for s in sanitizers
            if s.effectiveness == SanitizerEffectiveness.FULL
        )

        return {
            "total": len(sanitizers),
            "by_category": by_category,
            "by_effectiveness": by_effectiveness,
            "fully_effective_count": fully_effective,
        }
