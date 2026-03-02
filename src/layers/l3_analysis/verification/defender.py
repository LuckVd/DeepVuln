"""
Defender Verifier - Checks for sanitizers and defense mechanisms.

This role analyzes vulnerability candidates from a defender's perspective,
identifying security controls that may prevent exploitation.
"""

import json
import logging
import re
from typing import Any

from ..llm.client import LLMClient, LLMError
from ..prompts.adversarial import DEFENDER_SYSTEM_PROMPT, get_defender_user_prompt
from ..prompts.security_audit import VULNERABILITY_PATTERNS
from .models import ArgumentStrength, VerificationArgument

logger = logging.getLogger(__name__)


class DefenderVerifier:
    """
    Defender role in adversarial verification.

    Attempts to prove that a vulnerability is NOT exploitable by:
    - Identifying sanitization functions
    - Finding validation checks
    - Discovering framework-level protections
    - Analyzing exploitation barriers
    """

    # Common sanitizer patterns by language
    SANITIZER_PATTERNS = {
        "python": {
            "sql": [
                r"%s",  # Parameterized query placeholder
                r"\?",
                r":\w+",  # Named parameters
                r"bindparam",
                r"bindParam",
                r"PreparedStatement",
                r"cursor\.execute\s*\([^,]+\s*,",  # Parameterized execute
            ],
            "xss": [
                r"escape\s*\(",
                r"html_escape",
                r"markupsafe",
                r"bleach\.clean",
                r"DOMPurify",
                r"sanitize\s*\(",
                r"{{\s*\w+\s*}}",  # Auto-escaped template
            ],
            "command": [
                r"shlex\.quote",
                r"shell\s*=\s*False",
                r"subprocess\.run\s*\([^)]*shell\s*=\s*False",
            ],
            "path": [
                r"os\.path\.basename",
                r"os\.path\.realpath",
                r"os\.path\.abspath",
                r"Path\s*\([^)]*\)\.resolve",
                r"filepath\.Clean",
            ],
        },
        "javascript": {
            "sql": [
                r"\$\d+",  # Parameterized query
                r"\?\s*,",  # Question mark placeholder
                r"sequelize\.query\s*\([^,]+,\s*\{",
                r"knex\(.*\)\.where\s*\(",
                r"pg-promise",
            ],
            "xss": [
                r"DOMPurify\.sanitize",
                r"escapeHtml",
                r"textContent\s*=",
                r"innerText\s*=",
                r"xss\(.*\)",
                r"sanitize-html",
            ],
            "command": [
                r"escapeShellArg",
                r"shell_escape",
                r"spawn\s*\([^)]*,\s*\[",  # spawn with array args
            ],
            "path": [
                r"path\.basename",
                r"path\.normalize",
                r"path\.resolve",
            ],
        },
        "java": {
            "sql": [
                r"PreparedStatement",
                r"setString\s*\(",
                r"setInt\s*\(",
                r"setParameter",
                r"NamedParameterJdbcTemplate",
            ],
            "xss": [
                r"StringEscapeUtils\.escapeHtml",
                r"HtmlUtils\.htmlEscape",
                r"ESAPI\.encoder",
                r"c:out",  # JSTL auto-escape
            ],
            "command": [],
            "path": [
                r"Paths\.get\s*\([^)]*\)\.normalize",
                r"FilenameUtils\.getName",
                r"getCanonicalPath",
            ],
        },
        "go": {
            "sql": [
                r"sql\.Named",
                r"\$\d+",
                r"\?",
                r"db\.Query\s*\([^,]+,",
                r"db\.Exec\s*\([^,]+,",
            ],
            "xss": [
                r"html\.EscapeString",
                r"template\.HTMLEscapeString",
            ],
            "command": [
                r"exec\.Command\s*\([^)]*\)\.Run",  # Command with separate args
            ],
            "path": [
                r"filepath\.Base",
                r"filepath\.Clean",
                r"filepath\.EvalSymlinks",
            ],
        },
    }

    def __init__(
        self,
        llm_client: LLMClient,
        max_context_length: int = 4000,
        use_static_analysis: bool = True,
    ):
        """
        Initialize the defender verifier.

        Args:
            llm_client: LLM client for generating arguments.
            max_context_length: Maximum code context length.
            use_static_analysis: Whether to use static pattern matching.
        """
        self.llm_client = llm_client
        self.max_context_length = max_context_length
        self.use_static_analysis = use_static_analysis

    async def analyze(
        self,
        finding: dict[str, Any],
        code_context: str,
        related_code: str | None = None,
        attacker_argument: dict[str, Any] | None = None,
    ) -> VerificationArgument:
        """
        Analyze a vulnerability from a defender's perspective.

        Args:
            finding: The vulnerability finding to analyze.
            code_context: The vulnerable code snippet.
            related_code: Additional context code.
            attacker_argument: The attacker's argument to counter.

        Returns:
            VerificationArgument with defender's analysis.
        """
        # Truncate code if needed
        if len(code_context) > self.max_context_length:
            code_context = code_context[: self.max_context_length] + "\n... (truncated)"

        # First, do static analysis for quick defense detection
        static_defenses = {}
        if self.use_static_analysis:
            static_defenses = self._static_defense_analysis(
                code=code_context,
                vuln_type=finding.get("type", ""),
                language=finding.get("language", ""),
            )

        # Build prompt
        user_prompt = get_defender_user_prompt(
            finding=finding,
            code_context=code_context,
            related_code=related_code,
            attacker_argument=attacker_argument,
        )

        try:
            # Call LLM
            response = await self.llm_client.complete_with_context(
                system_prompt=DEFENDER_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )

            # Parse response
            content = response.content.strip()

            # Try to extract JSON from markdown code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            result = json.loads(content)

            # Map strength string to enum
            strength_str = result.get("strength", "moderate").lower()
            strength_map = {
                "weak": ArgumentStrength.WEAK,
                "moderate": ArgumentStrength.MODERATE,
                "strong": ArgumentStrength.STRONG,
                "definitive": ArgumentStrength.DEFINITIVE,
            }
            strength = strength_map.get(strength_str, ArgumentStrength.MODERATE)

            # Merge static analysis results with LLM results
            sanitizers = list(set(
                result.get("sanitizers_found", []) + static_defenses.get("sanitizers", [])
            ))
            validations = list(set(
                result.get("validation_checks", []) + static_defenses.get("validations", [])
            ))
            framework_protections = list(set(
                result.get("framework_protections", []) + static_defenses.get("framework", [])
            ))

            # Adjust confidence based on static findings
            confidence = float(result.get("confidence", 0.5))
            if sanitizers:
                confidence = min(1.0, confidence + 0.1 * len(sanitizers[:3]))
            if validations:
                confidence = min(1.0, confidence + 0.05 * len(validations[:3]))

            return VerificationArgument(
                role="defender",
                claim=result.get("claim", "This vulnerability is not exploitable"),
                evidence=result.get("evidence", []),
                reasoning=result.get("reasoning", ""),
                strength=strength,
                confidence=confidence,
                counter_arguments=result.get("counter_arguments", []),
                sanitizers_found=sanitizers,
                validation_checks=validations,
                framework_protections=framework_protections,
            )

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse defender response as JSON: {e}")
            # Fall back to static analysis results
            return VerificationArgument(
                role="defender",
                claim="Static analysis found potential defenses",
                evidence=static_defenses.get("evidence", []),
                reasoning="LLM response parsing failed, using static analysis results",
                strength=ArgumentStrength.MODERATE if static_defenses.get("sanitizers") else ArgumentStrength.WEAK,
                confidence=0.3 if static_defenses.get("sanitizers") else 0.1,
                counter_arguments=[],
                sanitizers_found=static_defenses.get("sanitizers", []),
                validation_checks=static_defenses.get("validations", []),
                framework_protections=static_defenses.get("framework", []),
            )

        except LLMError as e:
            logger.error(f"LLM error in defender analysis: {e}")
            return VerificationArgument(
                role="defender",
                claim="Analysis failed due to LLM error",
                evidence=[],
                reasoning=str(e),
                strength=ArgumentStrength.WEAK,
                confidence=0.0,
                counter_arguments=[],
            )

    def _static_defense_analysis(
        self,
        code: str,
        vuln_type: str,
        language: str = "",
    ) -> dict[str, Any]:
        """
        Perform static analysis to find defense mechanisms.

        Args:
            code: Code to analyze.
            vuln_type: Type of vulnerability.
            language: Programming language.

        Returns:
            Dictionary with found defenses.
        """
        result = {
            "sanitizers": [],
            "validations": [],
            "framework": [],
            "evidence": [],
        }

        # Map vuln_type to sanitizer category
        type_mapping = {
            "sql_injection": "sql",
            "xss": "xss",
            "command_injection": "command",
            "path_traversal": "path",
        }
        category = type_mapping.get(vuln_type)

        if not category:
            return result

        # Check language-specific patterns
        lang_patterns = self.SANITIZER_PATTERNS.get(language, {})
        if not lang_patterns:
            # Try to find patterns from any language
            for lang_patterns in self.SANITIZER_PATTERNS.values():
                patterns = lang_patterns.get(category, [])
                for pattern in patterns:
                    if re.search(pattern, code):
                        result["sanitizers"].append(f"detected: {pattern[:30]}")
            return result

        patterns = lang_patterns.get(category, [])
        for pattern in patterns:
            if re.search(pattern, code):
                result["sanitizers"].append(pattern[:50])
                result["evidence"].append(f"Found sanitizer pattern: {pattern[:30]}")

        # Check for common validation patterns
        validation_patterns = [
            (r"if\s+.*\s*(?:is|in|==|!=|>|<)", "conditional validation"),
            (r"validate\s*\(", "validate function"),
            (r"check\s*\(", "check function"),
            (r"assert\s+", "assertion"),
            (r"raise\s+\w*Error", "error raising"),
            (r"try\s*:", "try-except block"),
            (r"try\s*\{", "try-catch block"),
            (r"@validate", "validation decorator"),
            (r"whitelist", "whitelist check"),
            (r"allowlist", "allowlist check"),
        ]

        for pattern, name in validation_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                result["validations"].append(name)

        # Check for framework protections
        framework_patterns = [
            (r"@csrf", "CSRF protection"),
            (r"@login_required", "authentication required"),
            (r"@permission", "permission check"),
            (r"csrf_token", "CSRF token"),
            (r"Content-Security-Policy", "CSP header"),
            (r"X-Frame-Options", "frame protection"),
            (r"X-Content-Type-Options", "MIME sniffing protection"),
        ]

        for pattern, name in framework_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                result["framework"].append(name)
                result["evidence"].append(f"Framework protection: {name}")

        return result

    def get_quick_assessment(self, finding: dict[str, Any], code: str) -> dict[str, Any]:
        """
        Get a quick heuristic assessment without LLM.

        Args:
            finding: The vulnerability finding.
            code: The code to analyze.

        Returns:
            Quick assessment with detected defenses.
        """
        static = self._static_defense_analysis(
            code=code,
            vuln_type=finding.get("type", ""),
            language=finding.get("language", ""),
        )

        # Calculate initial defense confidence
        confidence = 0.1  # Base (low confidence without LLM)
        if static["sanitizers"]:
            confidence += 0.2 * min(len(static["sanitizers"]), 3)
        if static["validations"]:
            confidence += 0.1 * min(len(static["validations"]), 3)
        if static["framework"]:
            confidence += 0.15 * min(len(static["framework"]), 2)

        return {
            "defense_confidence": min(confidence, 0.9),
            "sanitizers_found": static["sanitizers"],
            "validations_found": static["validations"],
            "framework_protections": static["framework"],
            "has_defenses": bool(static["sanitizers"] or static["validations"] or static["framework"]),
        }
