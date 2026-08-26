"""Regression tests for AST rule id collisions across languages.

Audit finding A1 (2026-08-25): python_eval.yaml and javascript_eval.yaml both
declare ``id: dangerous_eval``; the detector used to key its rule dict by id
alone, so one language's file silently overwrote the other and Python
eval/exec detection was lost.
"""

import pytest

from src.layers.l3_analysis.engines.ast_engine.detectors.crypto_detector import (
    CryptoMisuseDetector,
)
from src.layers.l3_analysis.engines.ast_engine.detectors.dangerous_api_detector import (
    DangerousAPIDetector,
)


class TestRuleIdCollision:
    """Rules sharing an id across languages must all stay loaded."""

    def test_rules_keyed_per_language(self) -> None:
        """Each (id, language) pair survives loading."""
        detector = DangerousAPIDetector()
        keys = set(detector._rules.keys())
        assert "dangerous_eval:python" in keys
        assert "dangerous_eval:javascript" in keys
        assert "dangerous_exec:python" in keys

    def test_crypto_md5_keyed_per_language(self) -> None:
        """weak_crypto_md5 exists for both python and javascript."""
        detector = CryptoMisuseDetector()
        keys = set(detector._rules.keys())
        assert "weak_crypto_md5:python" in keys
        assert "weak_crypto_md5:javascript" in keys

    @pytest.mark.asyncio
    async def test_python_eval_detected_not_shadowed(self) -> None:
        """Python eval() must be detected even though a JS rule shares the id."""
        detector = DangerousAPIDetector()
        code = "result = eval(user_input)\n"
        findings = await detector.detect(code, "python", "app.py")
        assert len(findings) >= 1
        assert findings[0].rule_id == "dangerous_eval"

    @pytest.mark.asyncio
    async def test_javascript_eval_still_detected(self) -> None:
        """The JS eval rule keeps working alongside the python one."""
        detector = DangerousAPIDetector()
        code = "const result = eval(userInput);\n"
        findings = await detector.detect(code, "javascript", "app.js")
        assert len(findings) >= 1
        assert findings[0].rule_id == "dangerous_eval"

    def test_finding_rule_id_unchanged_by_keying(self) -> None:
        """The dict key carries the language suffix; rule['id'] stays clean."""
        detector = DangerousAPIDetector()
        for rule in detector._rules.values():
            assert ":" not in rule["id"]
