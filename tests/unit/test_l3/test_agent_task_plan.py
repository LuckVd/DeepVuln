"""Phase 20 P-A1: agent 引擎任务池执行单元测试.

覆盖：任务池全执行、per-task focus 透传、失败隔离、task_id 打标、
resume（跳过已完成任务 + 部分结果并入）、on_task_complete 回调、
sweep 预算上限、无效 plan 兜底。全部 mock LLM（patch _analyze_files）。
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.layers.l3_analysis.engines.opencode_agent import OpenCodeAgent
from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    SeverityLevel,
)


def _agent(max_files: int = 50) -> OpenCodeAgent:
    llm = MagicMock()
    llm.is_available = True
    llm.provider = "openai"
    llm.model = "test-model"
    return OpenCodeAgent(llm_client=llm, max_files=max_files)


def _finding(file: str, line: int = 1, rule_id: str = "sql_injection") -> Finding:
    return Finding(
        id=f"f-{file}-{line}",
        rule_id=rule_id,
        type=FindingType.VULNERABILITY,
        severity=SeverityLevel.HIGH,
        confidence=0.9,
        title="t",
        description="d",
        location=CodeLocation(file=file, line=line),
        source="agent",
    )


def _plan(tmp_path: Path, layout: dict[str, list[str]], focus_by_module: dict[str, list[str]] | None = None) -> dict:
    """Create the on-disk project and a matching TaskPlan payload."""
    for mod, files in layout.items():
        d = tmp_path / mod
        d.mkdir(parents=True, exist_ok=True)
        for fn in files:
            (d / fn).write_text("x = 1\n")
    tasks = []
    for i, (mod, files) in enumerate(layout.items()):
        tasks.append(
            {
                "task_id": f"task-{i + 1:02d}-{mod}",
                "name": f"{mod}-general",
                "module_dir": mod,
                "files": [f"{mod}/{fn}" for fn in files],
                "entry_point_indexes": [],
                "vulnerability_focus": (focus_by_module or {}).get(mod, ["command_injection"]),
                "priority": 1,
                "status": "pending",
            }
        )
    return {"tasks": tasks, "unassigned_files": [], "planner_meta": {}}


class TestTaskPoolExecution:
    @pytest.mark.asyncio
    async def test_all_tasks_executed_with_per_task_focus(self, tmp_path: Path) -> None:
        agent = _agent()
        plan = _plan(tmp_path, {"api": ["users.py"], "auth": ["login.py"]},
                     focus_by_module={"api": ["sqli"], "auth": ["authn_bypass"]})
        seen: list[tuple] = []

        async def fake_analyze(files, source_path, language, vulnerability_focus, context):
            seen.append(([str(f) for f in files], vulnerability_focus, context.get("audit_task")))
            return [_finding(files[0].name)]

        agent._analyze_files = fake_analyze
        result = await agent.scan(tmp_path, language="python", task_plan=plan)

        assert result.success
        assert len(seen) == 2
        focus_by_files = {f[0][0]: f[1] for f in seen}
        assert focus_by_files[str(tmp_path / "api" / "users.py")] == ["sqli"]
        assert focus_by_files[str(tmp_path / "auth" / "login.py")] == ["authn_bypass"]
        # 任务语义进入 prompt 上下文
        assert all(f[2] and "Audit task" in f[2] for f in seen)
        # findings 全部带 task_id
        task_ids = {f.metadata["task_id"] for f in result.findings}
        assert task_ids == {"task-01-api", "task-02-auth"}
        raw = result.raw_output
        assert raw["task_summary"]["tasks_total"] == 2
        assert raw["task_summary"]["tasks_completed"] == 2
        assert raw["task_summary"]["tasks_failed"] == 0

    @pytest.mark.asyncio
    async def test_failure_isolation(self, tmp_path: Path) -> None:
        agent = _agent()
        plan = _plan(tmp_path, {"good": ["ok.py"], "bad": ["crash.py"]})

        async def fake_analyze(files, source_path, language, vulnerability_focus, context):
            if "crash.py" in str(files[0]):
                raise RuntimeError("LLM exploded")
            return [_finding(files[0].name)]

        agent._analyze_files = fake_analyze
        result = await agent.scan(tmp_path, language="python", task_plan=plan)

        assert result.success  # 单任务失败不拖垮整个引擎
        stats = {s["task_id"]: s for s in result.raw_output["task_summary"]["tasks"]}
        assert stats["task-01-good"]["status"] == "completed"
        assert stats["task-02-bad"]["status"] == "failed"
        assert len(result.findings) == 1

    @pytest.mark.asyncio
    async def test_on_task_complete_callback(self, tmp_path: Path) -> None:
        agent = _agent()
        plan = _plan(tmp_path, {"api": ["users.py"]})
        callback = AsyncMock()
        agent._analyze_files = AsyncMock(return_value=[_finding("users.py")])
        await agent.scan(tmp_path, language="python", task_plan=plan, on_task_complete=callback)
        callback.assert_awaited_once()
        task_id, payloads = callback.await_args.args
        assert task_id == "task-01-api"
        assert payloads and payloads[0]["rule_id"] == "sql_injection"

    @pytest.mark.asyncio
    async def test_sweep_bounded_by_max_files(self, tmp_path: Path) -> None:
        agent = _agent(max_files=3)
        plan = _plan(tmp_path, {"m1": ["a.py", "b.py"], "m2": ["c.py"]})
        plan["unassigned_files"] = ["s1.py", "s2.py", "s3.py", "s4.py"]
        for f in ["s1.py", "s2.py", "s3.py", "s4.py"]:
            (tmp_path / f).write_text("x = 1\n")
        calls: list[int] = []

        async def fake_analyze(files, source_path, language, vulnerability_focus, context):
            calls.append(len(files))
            return []

        agent._analyze_files = fake_analyze
        result = await agent.scan(tmp_path, language="python", task_plan=plan)
        # 任务消费 3 个（=max_files）→ sweep 预算 0，不扫任何未分配文件
        assert sum(calls[:2]) == 3
        assert calls[-1:] == [] or calls[-1] == 0 or result.raw_output["task_summary"]["sweep_files"] == 0
        assert not any("s1.py" in p for p in result.raw_output["analyzed_file_paths"])


class TestResume:
    @pytest.mark.asyncio
    async def test_completed_tasks_skipped_and_findings_merged(self, tmp_path: Path) -> None:
        agent = _agent()
        plan = _plan(tmp_path, {"api": ["users.py"], "auth": ["login.py"]})
        restored = _finding("users.py")
        seen_files: list[list[str]] = []

        async def fake_analyze(files, source_path, language, vulnerability_focus, context):
            seen_files.append([str(f) for f in files])
            return [_finding(files[0].name)]

        agent._analyze_files = fake_analyze
        result = await agent.scan(
            tmp_path,
            language="python",
            task_plan=plan,
            resume_completed_tasks=["task-01-api"],
            resume_findings=[restored.model_dump(mode="json")],
        )
        # 只跑了 auth 任务
        assert len(seen_files) == 1
        assert "auth" in seen_files[0][0]
        # 恢复的 finding 在结果里且不重复
        paths = sorted(f.location.file for f in result.findings)
        assert paths == ["login.py", "users.py"]
        assert result.raw_output["task_summary"]["tasks_skipped_resumed"] == 1
        assert result.raw_output["task_summary"]["findings_restored_from_checkpoint"] == 1

    @pytest.mark.asyncio
    async def test_restored_finding_not_retagged(self, tmp_path: Path) -> None:
        agent = _agent()
        plan = _plan(tmp_path, {"api": ["users.py"]})
        restored = _finding("users.py")
        restored.metadata["task_id"] = "task-01-api"

        async def fake_analyze(files, source_path, language, vulnerability_focus, context):
            return []

        agent._analyze_files = fake_analyze
        result = await agent.scan(
            tmp_path, language="python", task_plan=plan,
            resume_completed_tasks=["task-01-api"],
            resume_findings=[restored.model_dump(mode="json")],
        )
        assert result.findings[0].metadata["task_id"] == "task-01-api"


class TestFallback:
    @pytest.mark.asyncio
    async def test_empty_plan_uses_flat_path(self, tmp_path: Path) -> None:
        agent = _agent()
        (tmp_path / "only.py").write_text("x = 1\n")
        flat_spy = AsyncMock(return_value=[])
        agent._find_analyzable_files = lambda p: [tmp_path / "only.py"]
        agent._analyze_files = flat_spy
        result = await agent.scan(tmp_path, language="python", task_plan={"tasks": []})
        flat_spy.assert_awaited_once()
        assert result.raw_output.get("task_summary") is None

    @pytest.mark.asyncio
    async def test_invalid_plan_uses_flat_path(self, tmp_path: Path) -> None:
        agent = _agent()
        (tmp_path / "only.py").write_text("x = 1\n")
        agent._find_analyzable_files = lambda p: [tmp_path / "only.py"]
        agent._analyze_files = AsyncMock(return_value=[])
        result = await agent.scan(
            tmp_path, language="python",
            task_plan={"tasks": [{"task_id": "x", "files": 42}]},  # 非法字段
        )
        assert result.success
        assert result.raw_output.get("task_summary") is None

    @pytest.mark.asyncio
    async def test_explicit_files_override_wins_over_plan(self, tmp_path: Path) -> None:
        agent = _agent()
        plan = _plan(tmp_path, {"api": ["users.py"]})
        spy = AsyncMock(return_value=[])
        agent._analyze_files = spy
        await agent.scan(tmp_path, language="python", files=["direct.py"], task_plan=plan)
        # files 覆盖 → 走扁平分支（单次调用、无任务语义）
        assert spy.await_count == 1


class TestParseTaskPlan:
    def test_none_and_empty(self) -> None:
        assert OpenCodeAgent._parse_task_plan(None) is None
        assert OpenCodeAgent._parse_task_plan({}) is None

    def test_valid(self) -> None:
        plan = OpenCodeAgent._parse_task_plan(
            {"tasks": [{"task_id": "t1", "name": "n", "files": ["a.py"]}], "unassigned_files": []}
        )
        assert plan is not None and len(plan.tasks) == 1

    def test_invalid(self) -> None:
        assert OpenCodeAgent._parse_task_plan({"tasks": "not-a-list"}) is None
