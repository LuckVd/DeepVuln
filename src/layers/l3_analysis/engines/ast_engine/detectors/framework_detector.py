"""Framework Detector - AST-based detector for framework-specific vulnerabilities."""

from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.ast_engine.detectors.base_detector import (
    BaseDetector,
    _get_rules_base_dir,
)
from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    SeverityLevel,
)


class FrameworkDetector(BaseDetector):
    """
    Detector for framework-specific vulnerabilities.

    Loads rules from rules/ast_query/framework/ directory,
    covering Flask, Django, FastAPI, Express, and common
    framework security patterns.
    """

    def detector_type(self) -> str:
        return "framework"

    def _get_default_rules_dir(self) -> Path:
        """Return the default rules directory for framework rules."""
        return _get_rules_base_dir() / "framework"

    async def detect(
        self,
        code: str,
        language: str,
        file_path: str,
    ) -> list[Finding]:
        """
        Run detection and return findings.

        Args:
            code: Source code to analyze.
            language: Programming language.
            file_path: Path to the source file.

        Returns:
            List of findings.
        """
        findings = await self._execute_queries(code, language, file_path)

        # Add additional framework-specific validation
        findings = await self._validate_framework_context(
            findings, code, language, file_path
        )

        return findings

    async def _validate_framework_context(
        self,
        findings: list[Finding],
        code: str,
        language: str,
        file_path: str,
    ) -> list[Finding]:
        """
        Add framework-specific validation logic.

        This can check for:
        - Missing security decorators in Flask
        - Missing CSRF tokens in Django forms
        - Missing validation decorators in FastAPI
        """
        validated = []

        for finding in findings:
            # Keep all findings by default
            validated.append(finding)

            # Add framework-specific recommendations
            if finding.metadata.get("detector") == "framework":
                if "django" in file_path.lower() and "extra_raw_sql" in finding.rule_id:
                    # Add note about using QuerySet instead
                    if finding.fix_suggestion:
                        finding.fix_suggestion += (
                            "\n\nNote: Consider using Django ORM QuerySet "
                            "with parameterized queries instead of raw SQL."
                        )

        return validated


# Register the detector - but we don't auto-instantiate it
# It will be loaded by the engine registry when needed
