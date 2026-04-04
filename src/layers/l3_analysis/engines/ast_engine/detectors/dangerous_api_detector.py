"""Dangerous API Detector - Detects dangerous function calls."""

import re
from pathlib import Path
from typing import Any

from src.layers.l3_analysis.engines.ast_engine.detectors.base_detector import BaseDetector
from src.layers.l3_analysis.models import Finding, SeverityLevel


class DangerousAPIDetector(BaseDetector):
    """
    Detector for dangerous API usage.

    Detects:
    - eval(), exec() - code execution
    - os.system(), subprocess.call(shell=True) - command injection
    """

    def detector_type(self) -> str:
        return "dangerous_api"

    def _get_default_rules_dir(self) -> Path:
        return Path("rules/ast_query/dangerous_api")

    async def _post_validate(
        self,
        findings: list[Finding],
        code: str,
        language: str,
        file_path: str,
    ) -> list[Finding]:
        """
        Simple validation: detect constant literal arguments.

        Examples:
        - eval("hello") -> constant, lower confidence
        - eval(user_input) -> variable, keep high confidence
        """
        for finding in findings:
            snippet = finding.location.snippet or ""

            if self._is_constant_literal(snippet):
                finding.confidence = 0.3
                finding.metadata["validation"] = "constant_literal"
                finding.metadata["safe_pattern"] = True
                finding.severity = SeverityLevel.LOW
            else:
                finding.confidence = 0.85
                finding.metadata["validation"] = "variable_argument"

        return findings

    def _is_constant_literal(self, snippet: str) -> bool:
        """
        Check if the argument is a constant literal.

        Patterns:
        - eval("xxx") -> True
        - eval('xxx') -> True
        - eval(x) -> False
        - eval(func()) -> False
        """
        # Match function calls with string literals only
        # eval("...") or eval('...')
        pattern = r'(?:eval|exec)\s*\(\s*["\'][^"\']*["\']\s*\)'
        return bool(re.search(pattern, snippet))
