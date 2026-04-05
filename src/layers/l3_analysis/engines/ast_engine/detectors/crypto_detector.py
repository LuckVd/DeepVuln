"""Crypto Misuse Detector - Detects weak cryptography usage."""

from pathlib import Path
from typing import Any

from src.layers.l3_analysis.engines.ast_engine.detectors.base_detector import (
    BaseDetector,
    _get_rules_base_dir,
)
from src.layers.l3_analysis.models import Finding, SeverityLevel


class CryptoMisuseDetector(BaseDetector):
    """
    Detector for weak cryptography usage.

    Detects:
    - hashlib.md5(), hashlib.sha1() - weak hash
    - Crypto.Cipher.ARC4, DES.MODE_ECB - weak cipher
    """

    def detector_type(self) -> str:
        return "crypto_misuse"

    def _get_default_rules_dir(self) -> Path:
        return _get_rules_base_dir() / "crypto"

    async def _post_validate(
        self,
        findings: list[Finding],
        code: str,
        language: str,
        file_path: str,
    ) -> list[Finding]:
        """
        Simple validation: filter test code.

        If the finding is in a test file, lower severity.
        """
        for finding in findings:
            # Check if in test directory
            if self._is_test_file(file_path):
                finding.metadata["in_test_code"] = True
                finding.severity = SeverityLevel.INFO
                finding.metadata["note"] = "weak_crypto_in_test"

        return findings

    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is in a test directory."""
        path_parts = file_path.replace("\\", "/").split("/")
        return any("test" in part.lower() for part in path_parts)
