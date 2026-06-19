"""Tests for LogicVulnerabilityDetector (E5: AI 补漏逻辑漏洞).

The detector is an AI-supplement pass: it feeds only entry-point-reachable
source regions to the LLM (limited scope, anti-FP) and converts grounded
responses into ``Finding(source="logic_vuln")``. These tests pin:
- no attack surface / no LLM → no-op (never calls the LLM);
- region selection is entry-point-scoped and de-duplicated per file;
- responses are converted to findings with source=logic_vuln,
  evidence_strength=SPECULATIVE, and confidence capped at MAX_CONFIDENCE;
- findings lacking the three-element hard evidence are dropped.
"""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from src.core.models.attack_surface import (
    AttackSurfaceReport,
    EntryPoint,
    EntryPointType,
)
from src.layers.l3_analysis.engines.logic_vuln_detector import (
    LogicVulnerabilityDetector,
)
from src.layers.l3_analysis.models import EvidenceStrength, Finding


class FakeLLMClient:
    """Minimal async LLM client stub matching LLMClientProtocol."""

    def __init__(self, content: str) -> None:
        self._content = content
        self.call_count = 0

    async def complete_with_context(
        self,
        system_prompt: str,
        user_prompt: str,
        context: Any = None,
        **kwargs: Any,
    ) -> SimpleNamespace:
        self.call_count += 1
        return SimpleNamespace(
            content=self._content,
            usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15),
        )


def _entry(file: str, handler: str, line: int = 1) -> EntryPoint:
    return EntryPoint(
        type=EntryPointType.HTTP,
        path=f"/api/{handler}",
        handler=handler,
        file=file,
        line=line,
    )


def _write_app(path: Path, name: str, body: str) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / name
    f.write_text(body, encoding="utf-8")
    return f


def _raw_finding(**overrides: Any) -> dict:
    base = {
        "title": "Missing authorization",
        "category": "missing_authorization",
        "severity": "high",
        "confidence": 0.8,
        "file": "app.py",
        "line": 5,
        "function": "get_user",
        "missing_check": "No ownership check",
        "entry_point": "GET /api/users -> get_user",
        "attack_path": "Swap id param to read another user",
        "description": "IDOR.",
        "cwe": "CWE-862",
    }
    base.update(overrides)
    return base


def _detector(
    tmp_path: Path, llm_content: str, entries: list[EntryPoint], **kw: Any
) -> tuple[LogicVulnerabilityDetector, FakeLLMClient]:
    report = AttackSurfaceReport(source_path=str(tmp_path), entry_points=entries)
    llm = FakeLLMClient(llm_content)
    return LogicVulnerabilityDetector(tmp_path, llm, report, **kw), llm


@pytest.mark.asyncio
class TestLogicVulnDetector:
    async def test_no_attack_surface_returns_empty_without_llm_call(
        self, tmp_path: Path
    ) -> None:
        llm = FakeLLMClient(json.dumps({"findings": [_raw_finding()]}))
        det = LogicVulnerabilityDetector(tmp_path, llm, attack_surface_report=None)
        assert await det.discover() == []
        assert llm.call_count == 0

    async def test_no_llm_client_returns_empty(self, tmp_path: Path) -> None:
        report = AttackSurfaceReport(
            source_path=str(tmp_path), entry_points=[_entry("app.py", "get_user")]
        )
        det = LogicVulnerabilityDetector(tmp_path, None, attack_surface_report=report)
        assert await det.discover() == []

    async def test_select_regions_is_entry_scoped_and_deduped_per_file(
        self, tmp_path: Path
    ) -> None:
        _write_app(tmp_path, "app.py", "def get_user(): ...\ndef delete_user(): ...\n")
        _write_app(tmp_path, "util.py", "def helper(): ...")  # NOT an entry point
        det, _ = _detector(
            tmp_path,
            "",
            [_entry("app.py", "get_user"), _entry("app.py", "delete_user")],
        )
        regions = det.select_entry_regions()
        # Two entry points in the same file collapse to one region.
        assert len(regions) == 1
        assert regions[0]["file"] == "app.py"
        assert "get_user" in regions[0]["code"]
        assert "delete_user" in regions[0]["code"]
        assert {h["handler"] for h in regions[0]["handlers"]} == {"get_user", "delete_user"}

    async def test_unreadable_entry_file_skipped(self, tmp_path: Path) -> None:
        det, _ = _detector(tmp_path, "", [_entry("missing.py", "ghost")])
        assert det.select_entry_regions() == []

    async def test_discover_converts_to_findings(self, tmp_path: Path) -> None:
        _write_app(tmp_path, "app.py", "def get_user(): return db.get(id)\n")
        det, llm = _detector(
            tmp_path,
            json.dumps({"findings": [_raw_finding()]}),
            [_entry("app.py", "get_user")],
        )
        findings = await det.discover()

        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, Finding)
        assert f.source == "logic_vuln"
        assert f.evidence_strength == EvidenceStrength.SPECULATIVE
        assert f.location.file == "app.py"
        assert f.cwe == "CWE-862"
        assert llm.call_count == 1

    async def test_confidence_capped(self, tmp_path: Path) -> None:
        _write_app(tmp_path, "app.py", "def get_user(): ...\n")
        det, _ = _detector(
            tmp_path,
            json.dumps({"findings": [_raw_finding(confidence=0.95)]}),
            [_entry("app.py", "get_user")],
        )
        findings = await det.discover()
        cap = LogicVulnerabilityDetector.MAX_CONFIDENCE
        assert findings[0].confidence == pytest.approx(cap)
        assert cap <= 0.6
        assert findings[0].confidence <= 0.6

    async def test_drops_findings_missing_evidence(self, tmp_path: Path) -> None:
        _write_app(tmp_path, "app.py", "def get_user(): ...\n")
        payload = json.dumps(
            {"findings": [_raw_finding(attack_path=""), _raw_finding(title="Good")]}
        )
        det, _ = _detector(tmp_path, payload, [_entry("app.py", "get_user")])
        findings = await det.discover()
        assert len(findings) == 1
        assert findings[0].title == "Good"

    async def test_respects_max_entry_points_cap(self, tmp_path: Path) -> None:
        for i in range(10):
            _write_app(tmp_path, f"f{i}.py", f"def h{i}(): ...\n")
        entries = [_entry(f"f{i}.py", f"h{i}") for i in range(10)]
        det, _ = _detector(tmp_path, "", entries, max_entry_points=3)
        regions = det.select_entry_regions()
        assert len(regions) <= 3
