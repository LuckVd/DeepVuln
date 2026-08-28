"""D3: 断点续扫 findings 持久化与恢复（单元测试）.

On resume, completed phases (engine_execution) are skipped, so the findings
they produced must be restored from the checkpoint — otherwise downstream
(exploitability/adjudication) have nothing to work on. These tests pin the
serialize/restore helpers, the WebCheckpointSink payload injection, and the
checkpoint-driven state restore.
"""

from unittest.mock import AsyncMock, MagicMock

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


def _empty_result(engine: str) -> ScanResult:
    """Canned ScanResult for mocking engine runs in _execute_engines tests."""
    return ScanResult(source_path="/tmp", engine=engine, findings=[], total_findings=0)


def _async_progress() -> MagicMock:
    """progress_callback with awaitable engine hooks (MagicMock methods aren't awaitable)."""
    cb = MagicMock()
    cb.on_engine_start = AsyncMock()
    cb.on_engine_complete = AsyncMock()
    cb.on_engine_failed = AsyncMock()
    return cb


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
        # P7-C6: resume_data now carries scan_results + completed_engines.
        # Phase 20 P-A1: plus task-granular agent progress keys.
        # Phase 20 resume fix: plus L1 products (tech_stack/attack_surface)
        # so gate + deterministic task plan rebuild identically on resume.
        assert captured["data"]["resume_data"] == {
            "scan_results": [],
            "completed_engines": [],
            "completed_agent_tasks": [],
            "partial_agent_findings": [],
            "tech_stack": {},
            "attack_surface_report": None,
        }


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


class TestFinalizeResultsResumeSafeDedup:
    """Phase 18/P5-A5: _finalize_results must not re-insert findings already
    stored for the scan (a resume re-runs finalize), and must dedup within a
    batch. Storage-level guard; semantic dedup still happens in adjudication.
    """

    @staticmethod
    def _fake_session(existing_rows):
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = [tuple(r) for r in existing_rows]
        mock_session.execute = AsyncMock(return_value=mock_result)
        return mock_session

    @pytest.mark.asyncio
    async def test_skips_findings_already_in_db(self) -> None:
        orch = _orch()
        orch.scan_results = {
            "semgrep": ScanResult(
                source_path="/tmp",
                engine="semgrep",
                findings=[
                    _finding(id="A", rule_id="rule-x", location=CodeLocation(file="app.py", line=12, function="f")),
                    _finding(id="B", rule_id="rule-y", location=CodeLocation(file="app.py", line=12, function="f")),
                    _finding(id="C", rule_id="rule-z", location=CodeLocation(file="other.py", line=5, function="g")),
                ],
                total_findings=3,
            )
        }
        # DB already has rule-x @ app.py:12 (the "A" finding) from a prior run.
        mock_session = self._fake_session([("rule-x", "app.py", 12)])
        orch.db_session_factory = lambda: mock_session

        await orch._finalize_results()

        added = [c.args[0].vuln_type for c in mock_session.add.call_args_list]
        assert sorted(added) == ["rule-y", "rule-z"]
        assert "rule-x" not in added

    @pytest.mark.asyncio
    async def test_dedups_within_batch(self) -> None:
        orch = _orch()
        orch.scan_results = {
            "semgrep": ScanResult(
                source_path="/tmp",
                engine="semgrep",
                findings=[
                    _finding(id="A", rule_id="rule-x", location=CodeLocation(file="app.py", line=12, function="f")),
                    _finding(id="A2", rule_id="rule-x", location=CodeLocation(file="app.py", line=12, function="f")),
                ],
                total_findings=2,
            )
        }
        mock_session = self._fake_session([])  # DB empty
        orch.db_session_factory = lambda: mock_session

        await orch._finalize_results()

        assert mock_session.add.call_count == 1


class TestEngineLevelCheckpoint:
    """Phase 18/P7-C6: per-engine incremental checkpoint within engine_execution.

    A crash mid-engine-execution must let resume skip engines that already
    finished (especially expensive CodeQL) instead of re-running the whole
    phase. ``completed_engines`` is persisted into resume_data as each engine
    finishes and restored on resume (intersected with restored results, so an
    engine is never marked completed without its output).
    """

    def test_restore_completed_engines_from_resume_data(self) -> None:
        orch = _orch()
        orch.scan_results = _scan_results()  # semgrep + agent
        serialized = orch._serialize_scan_results()
        ckpt = CheckpointData(
            scan_id=1,
            current_phase=PhaseName.L3_AGENT,
            resume_data={
                "scan_results": serialized,
                "completed_engines": ["semgrep"],
            },
        )

        orch2 = _orch()
        orch2._restore_state_from_checkpoint(ckpt)
        # semgrep restored (has result) -> marked completed; agent has a result
        # but wasn't listed as completed -> not in the set.
        assert orch2._completed_engines == {"semgrep"}
        assert set(orch2.scan_results.keys()) == {"semgrep", "agent"}

    def test_completed_engines_intersect_restored_results(self) -> None:
        """An engine listed completed but with no restored result must NOT be
        marked completed (avoids 'completed but no output' on resume)."""
        orch = _orch()
        ckpt = CheckpointData(
            scan_id=1,
            current_phase=None,
            resume_data={"scan_results": [], "completed_engines": ["codeql", "semgrep"]},
        )
        orch._restore_state_from_checkpoint(ckpt)
        assert orch._completed_engines == set()

    @pytest.mark.asyncio
    async def test_completed_engine_not_rerun_on_resume(self) -> None:
        """CodeQL already in _completed_engines -> must not be re-run; other
        engines still run."""
        orch = _orch()
        orch.progress_callback = _async_progress()
        orch._completed_engines = {"codeql"}
        orch._save_checkpoint_phase = AsyncMock()
        orch._run_engine_with_timeout = AsyncMock(return_value=_empty_result("codeql"))
        orch._run_engine_concurrent = AsyncMock(return_value=_empty_result("semgrep"))

        engines = {"codeql": MagicMock(), "semgrep": MagicMock(), "agent": MagicMock()}
        await orch._execute_engines(engines)

        # CodeQL was already completed -> NOT re-run.
        orch._run_engine_with_timeout.assert_not_called()
        # The concurrent engines still ran.
        assert orch._run_engine_concurrent.call_count == 2

    @pytest.mark.asyncio
    async def test_engine_checkpoint_written_after_each_engine(self) -> None:
        """As engines finish, a mid-phase checkpoint is written whose
        resume_data carries the growing completed_engines set."""
        orch = _orch()
        orch.progress_callback = _async_progress()
        saved: list[tuple[str, dict]] = []

        async def fake_save(phase, data):
            saved.append((phase, data.get("resume_data", {})))

        orch._save_checkpoint_phase = fake_save  # type: ignore[assignment]
        orch._run_engine_with_timeout = AsyncMock(return_value=_empty_result("codeql"))
        orch._run_engine_concurrent = AsyncMock(return_value=_empty_result("semgrep"))

        await orch._execute_engines(
            {"codeql": MagicMock(), "semgrep": MagicMock(), "agent": MagicMock()}
        )

        # Every mid-phase save is for the engine_execution phase...
        assert all(phase == "engine_execution" for phase, _ in saved)
        # ...and at least one carries completed_engines containing codeql
        # (the expensive engine — the core value of C6).
        completed_sets = [rd["completed_engines"] for _, rd in saved if "completed_engines" in rd]
        assert completed_sets, "no mid-phase checkpoint carried completed_engines"
        assert any("codeql" in s for s in completed_sets)
        # By the end, all three engines are recorded as completed.
        assert set(completed_sets[-1]) == {"codeql", "semgrep", "agent"}
