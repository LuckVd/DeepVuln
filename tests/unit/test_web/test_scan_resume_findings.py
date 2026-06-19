"""D3: 断点续扫 findings 持久化与恢复（单元测试）.

On resume, completed phases (engine_execution) are skipped, so the findings
they produced must be restored from the checkpoint — otherwise downstream
(exploitability/adjudication) have nothing to work on. These tests pin the
serialize/restore helpers, the WebCheckpointSink payload injection, and the
checkpoint-driven state restore.
"""

from unittest.mock import MagicMock

import pytest

from src.layers.l3_analysis.models import (
    CodeLocation,
    EvidenceStrength,
    Finding,
    FindingType,
    ScanResult,
    SeverityLevel,
)
from src.web.models.scan import PhaseName
from src.web.services.checkpoint_service import CheckpointData
from src.web.services.scan_orchestrator import ScanOrchestrator
from src.web.services.scan_pipeline_adapters import WebCheckpointSink


def _orch() -> ScanOrchestrator:
    """Lightweight orchestrator (no DB / no LLM) for unit tests."""
    return ScanOrchestrator(
        scan_id=1, source_path="/tmp", scan_config={}, progress_callback=MagicMock()
    )


def _finding(**overrides) -> Finding:
    base = dict(
        id="finding-1",
        rule_id="rule-x",
        type=FindingType.VULNERABILITY,
        severity=SeverityLevel.HIGH,
        confidence=0.8,
        title="SQL injection",
        description="desc",
        location=CodeLocation(file="app.py", line=12, function="get_user"),
        source="semgrep",
        cwe="CWE-89",
        evidence_strength=EvidenceStrength.MEDIUM,
    )
    base.update(overrides)
    return Finding(**base)


def _scan_results() -> dict[str, ScanResult]:
    semgrep = ScanResult(
        source_path="/tmp",
        engine="semgrep",
        findings=[_finding(), _finding(id="finding-2", severity=SeverityLevel.LOW)],
        total_findings=2,
    )
    agent = ScanResult(
        source_path="/tmp",
        engine="agent",
        findings=[_finding(id="finding-3", source="agent")],
        total_findings=1,
    )
    return {"semgrep": semgrep, "agent": agent}


class TestSerializeRestoreRoundTrip:
    def test_roundtrip_preserves_engines_and_counts(self) -> None:
        orch = _orch()
        orch.scan_results = _scan_results()
        serialized = orch._serialize_scan_results()

        orch2 = _orch()
        orch2._restore_scan_results(serialized)

        assert set(orch2.scan_results.keys()) == {"semgrep", "agent"}
        assert orch2.scan_results["semgrep"].total_findings == 2
        assert orch2.scan_results["agent"].total_findings == 1
        assert len(orch2.scan_results["semgrep"].findings) == 2

    def test_roundtrip_preserves_finding_fields(self) -> None:
        orch = _orch()
        orch.scan_results = {"semgrep": ScanResult(source_path="/tmp", engine="semgrep", findings=[_finding(evidence_strength=EvidenceStrength.SPECULATIVE)])}
        orch._restore_scan_results(orch._serialize_scan_results())
        f = orch.scan_results["semgrep"].findings[0]
        assert f.severity == SeverityLevel.HIGH
        assert f.source == "semgrep"
        assert f.cwe == "CWE-89"
        assert f.location.file == "app.py"
        assert f.location.line == 12
        assert f.location.function == "get_user"
        assert f.evidence_strength == EvidenceStrength.SPECULATIVE
        assert f.confidence == pytest.approx(0.8)

    def test_roundtrip_preserves_logic_vuln_source(self) -> None:
        orch = _orch()
        orch.scan_results = {
            "logic_vuln": ScanResult(
                source_path="/tmp",
                engine="logic_vuln",
                findings=[_finding(source="logic_vuln", rule_id="logic-vuln:idor")],
            )
        }
        orch._restore_scan_results(orch._serialize_scan_results())
        f = orch.scan_results["logic_vuln"].findings[0]
        assert f.source == "logic_vuln"
        assert f.rule_id == "logic-vuln:idor"

    def test_empty_scan_results_roundtrip(self) -> None:
        orch = _orch()
        assert orch._serialize_scan_results() == []
        orch._restore_scan_results([])
        assert orch.scan_results == {}

    def test_serialized_is_json_compatible(self) -> None:
        """Serialized output must survive json.dumps/loads (DB JSON column + file backup)."""
        import json

        orch = _orch()
        orch.scan_results = _scan_results()
        serialized = orch._serialize_scan_results()
        # Must round-trip through JSON without error.
        roundtripped = json.loads(json.dumps(serialized))
        orch2 = _orch()
        orch2._restore_scan_results(roundtripped)
        assert len(orch2.scan_results["semgrep"].findings) == 2

    def test_restore_handles_garbage_gracefully(self) -> None:
        """Malformed checkpoint data must not crash the resume path."""
        orch = _orch()
        orch._restore_scan_results(None)  # type: ignore[arg-type]
        assert orch.scan_results == {}
        orch._restore_scan_results([{"not": "a scan result"}])
        assert orch.scan_results == {}


class TestWebCheckpointSinkSave:
    @pytest.mark.asyncio
    async def test_save_injects_resume_data_with_findings(self) -> None:
        orch = _orch()
        orch.scan_results = _scan_results()
        captured: dict = {}

        async def fake_save(phase, data):
            captured["phase"] = phase
            captured["data"] = data

        orch._save_checkpoint_phase = fake_save  # type: ignore[assignment]
        sink = WebCheckpointSink(orch)

        await sink.save("engine_execution", {"findings": 3, "per_engine_details": {}})

        # The progress summary is preserved...
        assert captured["phase"] == "engine_execution"
        assert captured["data"]["findings"] == 3
        # ...AND resume_data carries the serialized findings.
        assert "resume_data" in captured["data"]
        scan_results = captured["data"]["resume_data"]["scan_results"]
        engines = {entry["engine"] for entry in scan_results}
        assert engines == {"semgrep", "agent"}

    @pytest.mark.asyncio
    async def test_save_keeps_summary_keys_for_progress(self) -> None:
        """resume_data injection must not clobber the progress summary dict."""
        orch = _orch()
        orch.scan_results = {}
        captured: dict = {}

        async def fake_save(phase, data):
            captured["data"] = data

        orch._save_checkpoint_phase = fake_save  # type: ignore[assignment]
        sink = WebCheckpointSink(orch)

        await sink.save("engine_execution", {"findings": 5})
        # Original summary key intact; resume_data added alongside.
        assert captured["data"]["findings"] == 5
        assert captured["data"]["resume_data"] == {"scan_results": []}


class TestRestoreStateFromCheckpoint:
    def test_restores_scan_results_from_resume_data(self) -> None:
        orch = _orch()
        orch.scan_results = _scan_results()
        serialized = orch._serialize_scan_results()

        ckpt = CheckpointData(
            scan_id=1,
            current_phase=PhaseName.L3_AGENT,
            resume_data={"scan_results": serialized},
        )

        orch2 = _orch()
        assert orch2.scan_results == {}
        orch2._restore_state_from_checkpoint(ckpt)
        assert "semgrep" in orch2.scan_results
        assert orch2.scan_results["semgrep"].findings[0].cwe == "CWE-89"

    def test_no_resume_data_is_noop(self) -> None:
        orch = _orch()
        ckpt = CheckpointData(scan_id=1, current_phase=None, resume_data={})
        orch._restore_state_from_checkpoint(ckpt)
        assert orch.scan_results == {}
