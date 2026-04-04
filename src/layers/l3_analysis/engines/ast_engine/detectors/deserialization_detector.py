"""Deserialization Detector - Detects unsafe deserialization."""

from pathlib import Path
from typing import Any

from src.layers.l3_analysis.engines.ast_engine.detectors.base_detector import BaseDetector
from src.layers.l3_analysis.models import Finding


class DeserializationDetector(BaseDetector):
    """
    Detector for unsafe deserialization.

    Detects:
    - pickle.load(), pickle.loads() - Python arbitrary code execution
    - yaml.load() (without Loader) - unsafe YAML loading
    - marshal.load() - unsafe marshalling
    """

    def detector_type(self) -> str:
        return "deserialization"

    def _get_default_rules_dir(self) -> Path:
        return Path("rules/ast_query/deserialization")

    async def _post_validate(
        self,
        findings: list[Finding],
        code: str,
        language: str,
        file_path: str,
    ) -> list[Finding]:
        """
        No additional validation for P8-03.

        Future: could check if data source is trusted file vs user input.
        """
        # Keep default confidence for now
        for finding in findings:
            finding.metadata["validation"] = "basic_pattern_only"

        return findings
