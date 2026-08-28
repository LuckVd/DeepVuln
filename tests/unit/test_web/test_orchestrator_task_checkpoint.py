"""Phase 20 P-A1/P-A2: 编排器任务级 checkpoint 与门控压制单元测试.

覆盖：resume_data 序列化/恢复（含旧 checkpoint 兼容）、on_task_complete
存档回调、gate 压制 → 审查队列（含逃生阀）。沿用轻量 orchestrator 模式
（无 DB / 无 LLM）。
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    SeverityLevel,
)
from src.web.services.scan_orchestrator import ScanOrchestrator


def _orch(config: dict | None = None) -> ScanOrchestrator:
    return ScanOrchestrator(
        scan_id=1,
        source_path="/tmp",
        scan_config=config or {},
        progress_callback=MagicMock(),
    )


def _finding(file: str, rule_id: str, **kw) -> Finding:
    return Finding(
        id=kw.pop("id", f"f-{file}-{rule_id}"),
        rule_id=rule_id,
        type=FindingType.VULNERABILITY,
        severity=SeverityLevel.HIGH,
        confidence=0.9,
        title="t",
        description="d",
        location=CodeLocation(file=file, line=1),
        source=kw.pop("source", "agent"),
        metadata=kw.pop("metadata", {}),
    )


class TestTaskCheckpointRoundTrip:
    @pytest.mark.asyncio
    async def test_on_task_complete_updates_state_and_saves(self) -> None:
        orch = _orch()
        orch._save_checkpoint_phase = AsyncMock()
        payloads = [_finding("users.py", "sql_injection").model_dump(mode="json")]
        await orch._on_agent_task_complete("task-01-api", payloads)
        assert orch._completed_agent_tasks == ["task-01-api"]
        assert orch._partial_agent_findings == payloads
        orch._save_checkpoint_phase.assert_awaited_once()
        assert orch._save_checkpoint_phase.await_args.args[0] == "engine_execution"
        # 任务级存档必须携带 resume_data 快照（否则 resume 丢任务状态）
        saved_payload = orch._save_checkpoint_phase.await_args.args[1]
        assert "resume_data" in saved_payload
        assert saved_payload["resume_data"]["completed_agent_tasks"] == ["task-01-api"]

    @pytest.mark.asyncio
    async def test_resume_data_carries_task_keys(self) -> None:
        orch = _orch()
        await orch._on_agent_task_complete("task-01-api", [{"rule_id": "x"}])
        await orch._on_agent_task_complete("task-02-auth", [])
        data = orch._serialize_resume_data()
        assert data["completed_agent_tasks"] == ["task-01-api", "task-02-auth"]
        assert data["partial_agent_findings"] == [{"rule_id": "x"}]
        # 既有键不受影响
        assert "completed_engines" in data and "scan_results" in data

    def test_restore_new_checkpoint(self) -> None:
        orch = _orch()
        ckpt = SimpleNamespace(
            resume_data={
                "completed_agent_tasks": ["task-01-api"],
                "partial_agent_findings": [{"rule_id": "y"}],
            }
        )
        orch._restore_state_from_checkpoint(ckpt)
        assert orch._completed_agent_tasks == ["task-01-api"]
        assert orch._partial_agent_findings == [{"rule_id": "y"}]

    def test_restore_legacy_checkpoint_without_keys(self) -> None:
        """旧 checkpoint（无任务键）恢复不报错、不产生任务状态。"""
        orch = _orch()
        ckpt = SimpleNamespace(resume_data={"completed_engines": ["semgrep"]})
        orch._restore_state_from_checkpoint(ckpt)
        assert orch._completed_agent_tasks == []
        assert orch._partial_agent_findings == []

    def test_restore_l1_products_for_gate_and_plan(self) -> None:
        """resume 恢复 tech_stack/attack_surface → gate 与任务规划可确定性重建。"""
        from src.core.models.attack_surface import AttackSurfaceReport, EntryPoint, EntryPointType

        orch = _orch()
        report = AttackSurfaceReport(source_path="/tmp")
        report.add_entry_point(
            EntryPoint(type=EntryPointType.HTTP, path="/x", handler="h", file="a.py")
        )
        ckpt = SimpleNamespace(
            resume_data={
                "tech_stack": {"frameworks": ["flask"], "databases": ["postgres"]},
                "attack_surface_report": report.model_dump(mode="json"),
            }
        )
        orch._restore_state_from_checkpoint(ckpt)
        assert orch.tech_stack == {"frameworks": ["flask"], "databases": ["postgres"]}
        assert orch.attack_surface_report_obj is not None
        assert orch.attack_surface_report_obj.total_entry_points == 1
        # 恢复后的 gate 与 planner 可用（fail-open 不再误判）
        gate = orch._evaluate_applicability_gate()
        assert gate is not None
        assert gate.signals.attack_surface_available is True

    def test_restore_skips_tasks_when_agent_engine_completed(self) -> None:
        """agent 引擎已整体完成（结果已恢复）→ 部分任务状态不得覆盖。"""
        from src.layers.l3_analysis.models import ScanResult

        orch = _orch()
        ckpt = SimpleNamespace(
            resume_data={
                "completed_engines": ["agent"],
                "scan_results": [
                    {
                        "engine": "agent",
                        "scan_result": ScanResult(
                            source_path="/tmp", engine="agent", findings=[]
                        ).model_dump(mode="json"),
                    }
                ],
                "completed_agent_tasks": ["task-01-api"],
            }
        )
        orch._restore_state_from_checkpoint(ckpt)
        assert "agent" in orch._completed_engines
        assert orch._completed_agent_tasks == []

    def test_restore_tasks_in_engine_drift_scenario(self) -> None:
        """checkpoint 声称 agent 完成 but 结果缺失（drift）→ agent 将重跑，
        任务状态应恢复以避免重做已完成任务。"""
        orch = _orch()
        ckpt = SimpleNamespace(
            resume_data={
                "completed_engines": ["agent"],
                "scan_results": [],
                "completed_agent_tasks": ["task-01-api"],
                "partial_agent_findings": [{"rule_id": "x"}],
            }
        )
        orch._restore_state_from_checkpoint(ckpt)
        assert "agent" not in orch._completed_engines  # 交集清空 → 将重跑
        assert orch._completed_agent_tasks == ["task-01-api"]
        assert orch._partial_agent_findings == [{"rule_id": "x"}]

    @pytest.mark.asyncio
    async def test_checkpoint_save_failure_never_raises(self) -> None:
        """存档失败只记日志，不中断任务执行（best-effort 契约）。"""
        orch = _orch()
        orch._save_checkpoint_phase = AsyncMock(side_effect=RuntimeError("db down"))
        await orch._on_agent_task_complete("task-01-api", [])
        assert orch._completed_agent_tasks == ["task-01-api"]


class TestGateSuppression:
    def _gate_report(self, gated: list[str]):
        from src.core.applicability_gate import ApplicabilityGate, GateReport

        decisions = [
            ApplicabilityGate._decide(cls, False, 0.8, "test") for cls in gated
        ]
        return GateReport(decisions)

    def test_gated_finding_marked_and_partitioned(self) -> None:
        orch = _orch()
        orch.gate_report = self._gate_report(["sqli"])
        findings = [
            _finding("a.py", "sql_injection"),
            _finding("b.py", "xss"),
        ]
        orch._apply_gate_suppression(findings)
        main, review = orch._split_review_queue(findings)
        assert [f.rule_id for f in main] == ["xss"]
        assert len(review) == 1
        assert review[0].metadata["gate_class"] == "sqli"
        assert "not applicable" in review[0].metadata["gate_suppressed"]

    def test_semgrep_style_rule_ids_also_matched(self) -> None:
        orch = _orch()
        orch.gate_report = self._gate_report(["ssrf"])
        findings = [_finding("a.py", "go.lang.security.audit.ssrf.request-tainted", source="semgrep")]
        orch._apply_gate_suppression(findings)
        main, review = orch._split_review_queue(findings)
        assert main == [] and len(review) == 1

    def test_escape_hatch_includes_gated(self) -> None:
        orch = _orch({"include_gated_findings": True})
        orch.gate_report = self._gate_report(["sqli"])
        findings = [_finding("a.py", "sql_injection")]
        orch._apply_gate_suppression(findings)
        main, review = orch._split_review_queue(findings)
        assert len(main) == 1 and review == []

    def test_no_gate_no_suppression(self) -> None:
        orch = _orch()
        findings = [_finding("a.py", "sql_injection")]
        orch._apply_gate_suppression(findings)  # gate_report None → no-op
        main, review = orch._split_review_queue(findings)
        assert len(main) == 1 and review == []

    def test_suspicious_and_gated_queues_are_disjoint(self) -> None:
        """is_suspicious 与 gate_suppressed 是两条独立队列（优先级：P3 在前）。"""
        orch = _orch()
        orch.gate_report = self._gate_report(["sqli"])
        suspicious = _finding("a.py", "xss", metadata={"is_suspicious": True})
        gated = _finding("b.py", "sql_injection")
        orch._apply_gate_suppression([suspicious, gated])
        main, review = orch._split_review_queue([suspicious, gated])
        assert main == []
        suspicious_q = [f for f in review if f.metadata.get("is_suspicious")]
        gated_q = [f for f in review if f.metadata.get("gate_suppressed")]
        assert len(suspicious_q) == 1
        assert len(gated_q) == 1
        assert suspicious_q[0].location.file == "a.py"
        assert gated_q[0].location.file == "b.py"


class TestBuildTaskPlanWiring:
    def test_no_attack_surface_returns_none(self) -> None:
        orch = _orch()
        assert orch._build_task_plan() is None

    def test_gate_disabled_returns_none_gate(self) -> None:
        orch = _orch({"applicability_gate": False})
        assert orch._evaluate_applicability_gate() is None

    def test_empty_plan_returns_none(self, tmp_path) -> None:
        from src.core.models.attack_surface import AttackSurfaceReport

        orch = _orch()
        orch.source_path = str(tmp_path)
        orch.attack_surface_report_obj = AttackSurfaceReport(source_path=str(tmp_path))
        assert orch._build_task_plan() is None  # 无入口点 → 兜底
