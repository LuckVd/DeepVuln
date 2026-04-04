"""
Streaming Validator - P8-08c Component

This module implements real-time validation of findings as they are produced
by the Agent, before they enter the result list.

This is the SECOND line of defense in the P8-08 architecture:
- Each finding is validated immediately after parsing
- Obvious false positives are filtered out
- Confidence is calibrated based on evidence
- Category is adjusted when appropriate

Integration Point:
    Called in OpenCodeAgent._parse_llm_response() for each finding.
"""

import logging
import re
from dataclasses import dataclass
from typing import Any

from src.layers.l3_analysis.models import Finding, SeverityLevel


@dataclass
class ValidationResult:
    """Result of finding validation."""
    accept: bool
    """Whether the finding should be accepted."""

    adjusted_finding: Finding | None
    """The finding, possibly adjusted (confidence, category, etc.)."""

    reason: str
    """Human-readable reason for the decision."""


class StreamingValidator:
    """
    Real-time finding validator.

    This validator operates as findings are produced, filtering out
    obvious false positives and calibrating confidence before findings
    enter the processing pipeline.

    Core Principle: Validate early, validate often, save resources.
    """

    # Dangerous call patterns (with actual execution)
    EXECUTION_PATTERNS = [
        r"\.execute\(", r"\.evaluate\(", r"\.exec\(", r"\.run\(",
        r"processbuilder\(", r"runtime\.exec\(",
        r"file\(", r"open\(", r"readfile\(", r"writefile\(",
        r"eval\(", r"exec\(", r"compile\(", r"unpickle\(",
        r"\.start\(", r"\.launch\(", r"\.invoke\(",
    ]

    # Construction-only patterns (no actual execution)
    CONSTRUCTION_ONLY_PATTERNS = [
        r"newinstance\(", r"getclass\(", r"forname\(",
        r"getregistry\(", r"initialdircontext\(",
        r"processbuilder",  # Match class name without requiring (
    ]

    # Safe response patterns (indicates no XSS)
    SAFE_RESPONSE_PATTERNS = [
        r"response\.json\(", r"json\(", r"return \{",
        r"content-type: application/json",
        r"@responsebody", r"responseentity",
        r"res\.json\(", r"res\.sendjson\(",
    ]

    # Config file indicators
    CONFIG_PATTERNS = [
        "dockerfile", "dockerfile.",
        ".conf", ".yaml", ".yml", ".json", ".properties",
        ".toml", ".ini", ".cfg",
    ]

    def __init__(self, strict_mode: bool = False):
        """
        Initialize the streaming validator.

        Args:
            strict_mode: If True, be more aggressive in filtering.
                        If False, be more lenient (safer).
        """
        self.strict_mode = strict_mode
        self.logger = logging.getLogger(__name__)

        # Compile regex patterns for performance
        self._execution_regex = re.compile(
            "|".join(self.EXECUTION_PATTERNS),
            re.IGNORECASE
        )
        self._construction_regex = re.compile(
            "|".join(self.CONSTRUCTION_ONLY_PATTERNS),
            re.IGNORECASE
        )

    def validate_finding(self, finding: Finding) -> ValidationResult:
        """
        Validate a single finding.

        Args:
            finding: The finding to validate.

        Returns:
            ValidationResult with decision and adjusted finding.
        """
        # 1. Check for XSS with JSON response (false positive) - HIGH PRIORITY
        if finding.rule_id and "xss" in finding.rule_id.lower():
            code = (finding.location.snippet or "").lower()
            json_indicators = [
                "res.json", "response.json", "sendjson",
                "content-type: application/json",
                "@responsebody", "responseentity",
            ]
            if any(indicator in code for indicator in json_indicators):
                # Downgrade significantly for XSS + JSON
                finding = self._downgrade_finding(
                    finding,
                    new_confidence=0.2,
                    note="XSS with JSON response - likely false positive"
                )
                return ValidationResult(
                    accept=True,
                    adjusted_finding=finding,
                    reason="Downgraded: XSS with JSON response"
                )

        # 2. Check execution evidence
        execution_check = self._check_execution_evidence(finding)
        if not execution_check["has_evidence"]:
            if finding.confidence > 0.5:
                # Downgrade to suspicious
                finding = self._downgrade_finding(
                    finding,
                    new_confidence=max(0.3, finding.confidence - 0.3),
                    note="No execution evidence - downgraded"
                )
                return ValidationResult(
                    accept=True,
                    adjusted_finding=finding,
                    reason="Downgraded to suspicious due to lack of execution evidence"
                )
            else:
                # Already low confidence, drop
                return ValidationResult(
                    accept=False,
                    adjusted_finding=finding,
                    reason="No execution evidence - dropped"
                )

        # 2. Check confidence calibration
        if finding.confidence > 0.8:
            if not self._has_strong_evidence(finding):
                finding = self._downgrade_finding(
                    finding,
                    new_confidence=0.7,
                    note="Insufficient evidence for high confidence"
                )
                return ValidationResult(
                    accept=True,
                    adjusted_finding=finding,
                    reason="Downgraded confidence due to insufficient evidence"
                )

        # 3. Check for config issues
        if self._is_config_issue(finding):
            finding.metadata["category"] = "CONFIG"
            finding.severity = SeverityLevel.INFO
            return ValidationResult(
                accept=True,
                adjusted_finding=finding,
                reason="Marked as config issue"
            )

        # 4. All checks passed
        return ValidationResult(
            accept=True,
            adjusted_finding=finding,
            reason="Passed validation"
        )

    def _check_execution_evidence(self, finding: Finding) -> dict[str, Any]:
        """
        Check if finding has execution evidence.

        Returns dict with:
            has_evidence: bool
            reason: str
        """
        code = (finding.location.snippet or "").lower()

        # Check for dangerous calls (with actual execution)
        has_execution = bool(self._execution_regex.search(code))

        # Check if it's only construction (no execution)
        is_construction_only = bool(self._construction_regex.search(code))

        # Special check: ProcessBuilder without start() is construction only
        if "processbuilder" in code and ".start" not in code:
            is_construction_only = True
            has_execution = False

        if is_construction_only and not has_execution:
            return {
                "has_evidence": False,
                "reason": "Only construction, no execution"
            }

        # Check for return-only patterns
        if "return" in code and ("\"" in code or "'" in code):
            # Further check if there's dangerous operation
            if not has_execution:
                return {
                    "has_evidence": False,
                    "reason": "Only returns string, no dangerous operation"
                }

        # Check for XSS with JSON response (false positive)
        if finding.rule_id and "xss" in finding.rule_id.lower():
            # Check for JSON response patterns (case-insensitive)
            json_indicators = [
                "res.json", "response.json", "json(", "sendjson",
                "content-type: application/json",
                "@responsebody", "responseentity",
            ]
            if any(indicator in code for indicator in json_indicators):
                return {
                    "has_evidence": False,
                    "reason": "XSS finding but JSON response - likely false positive"
                }

        return {
            "has_evidence": has_execution or not is_construction_only,
            "reason": "Has execution evidence" if has_execution else "No clear execution evidence"
        }

    def _has_strong_evidence(self, finding: Finding) -> bool:
        """
        Check if finding has strong evidence for high confidence.

        Strong evidence includes:
        - Working PoC
        - Clear data flow
        - Multiple lines of vulnerable code
        - Exploitation conditions documented
        """
        # Check for PoC
        if finding.metadata.get("poc"):
            return True

        # Check for clear data flow
        if finding.metadata.get("dataflow"):
            return True

        # Check for code snippet (indicates evidence)
        snippet = finding.location.snippet or ""
        if len(snippet) > 100:  # Substantial code snippet
            return True

        # Check for exploitation conditions
        desc = finding.description or ""
        if "exploitation" in desc.lower() or "attack" in desc.lower():
            return True

        return False

    def _is_config_issue(self, finding: Finding) -> bool:
        """Check if finding is a configuration issue."""
        # Dockerfile issues
        file_lower = finding.location.file.lower()
        if "dockerfile" in file_lower:
            return True

        # Check file extension
        for ext in self.CONFIG_PATTERNS:
            if file_lower.endswith(ext):
                return True

        # Check title/description for config keywords
        title = (finding.title or "").lower()
        desc = (finding.description or "").lower()
        text = title + " " + desc

        config_keywords = [
            "docker", "container", "image",
            "missing user", "root user",
            "exposed port", "open port",
        ]

        return any(keyword in text for keyword in config_keywords)

    def _downgrade_finding(
        self,
        finding: Finding,
        new_confidence: float,
        note: str
    ) -> Finding:
        """
        Downgrade a finding's confidence and add metadata note.

        Returns a modified Finding (immutable dataclass pattern).
        """
        # Create a copy of metadata
        new_metadata = dict(finding.metadata) if finding.metadata else {}
        new_metadata["validation_note"] = note
        new_metadata["category"] = "suspicious"

        # Create new Finding with updated fields
        return Finding(
            id=finding.id,
            rule_id=finding.rule_id,
            type=finding.type,
            severity=finding.severity,
            confidence=new_confidence,
            title=finding.title,
            description=finding.description,
            fix_suggestion=finding.fix_suggestion,
            location=finding.location,
            source=finding.source,
            cwe=finding.cwe,
            owasp=finding.owasp,
            metadata=new_metadata,
            final_score=self._recalculate_score(new_confidence, finding),
        )

    def _recalculate_score(self, new_confidence: float, finding: Finding) -> float | None:
        """
        Recalculate final_score based on new confidence.

        Simple heuristic: scale the original score by the confidence ratio.
        Returns None to use default scoring calculation.
        """
        # Don't set final_score - let the default scoring system handle it
        # This avoids exceeding the max allowed value
        return None


# Convenience function
def validate_finding(
    finding: Finding,
    strict_mode: bool = False,
) -> tuple[bool, Finding | None, str]:
    """
    Convenience function for finding validation.

    Args:
        finding: The finding to validate.
        strict_mode: Whether to use strict validation.

    Returns:
        (accept, adjusted_finding, reason) tuple.
    """
    validator = StreamingValidator(strict_mode=strict_mode)
    result = validator.validate_finding(finding)

    return result.accept, result.adjusted_finding, result.reason
"""
    P8-08c: Streaming Validator - validates findings in real-time

    Components:
    - StreamingValidator: Main validator class
    - ValidationResult: Data class for validation results
    - validate_finding: Convenience function

    Integration:
        Called in OpenCodeAgent._parse_llm_response() for each finding.
"""
