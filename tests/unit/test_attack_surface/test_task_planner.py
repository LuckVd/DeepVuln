"""Phase 20 P-A1: TaskPlanner 单元测试.

覆盖：兜底路径（无入口点/低覆盖率）、模块分组、max_tasks 上限、
gate 裁剪、风险动词推导、确定性排序。全部确定性（无 LLM）。
"""

from pathlib import Path

from src.core.applicability_gate import ApplicabilityGate
from src.core.models.attack_surface import AttackSurfaceReport, EntryPoint, EntryPointType
from src.layers.l1_intelligence.attack_surface.task_planner import TaskPlanner


def _report() -> AttackSurfaceReport:
    return AttackSurfaceReport(source_path="/tmp/project")


def _http(file: str, **kwargs) -> EntryPoint:
    return EntryPoint(type=EntryPointType.HTTP, path="/x", handler="h", file=file, **kwargs)


def _make_project(tmp_path: Path, layout: dict[str, list[str]]) -> Path:
    for mod, files in layout.items():
        d = tmp_path / mod
        d.mkdir(parents=True, exist_ok=True)
        for fn in files:
            (d / fn).write_text("# source\n")
    return tmp_path


def _gate(report, tech_stack=None):
    return ApplicabilityGate(
        tech_stack=tech_stack or {"databases": ["postgres"]},
        attack_surface=report,
        enable_probes=False,
    ).evaluate()


class TestFallbackPaths:
    def test_no_entry_points_returns_empty_plan(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, {"api": ["users.py"]})
        planner = TaskPlanner(attack_surface=_report(), gate_report=_gate(_report()))
        plan = planner.plan(proj)
        assert plan.is_empty
        assert plan.planner_meta["fallback"] == "no_entry_points"

    def test_none_attack_surface_returns_empty_plan(self, tmp_path: Path) -> None:
        planner = TaskPlanner(attack_surface=None)
        plan = planner.plan(tmp_path)
        assert plan.is_empty

    def test_low_coverage_falls_back(self, tmp_path: Path) -> None:
        """入口模块覆盖太低（<30%）→ 兜底走扁平扫描，不强行任务化。"""
        proj = _make_project(tmp_path, {"api": ["users.py"], **{f"lib{i}": ["x.py"] for i in range(10)}})
        report = _report()
        report.add_entry_point(_http("api/users.py"))
        planner = TaskPlanner(attack_surface=report, gate_report=_gate(report))
        plan = planner.plan(proj)
        assert plan.is_empty
        assert plan.planner_meta["fallback"].startswith("low_coverage")


class TestGrouping:
    def test_modules_grouped_with_gate_filtered_focus(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, {"auth": ["login.py"], "api": ["users.py"]})
        report = _report()
        report.add_entry_point(_http("auth/login.py", middleware=["auth_mw"]))
        report.add_entry_point(_http("api/users.py", params=["name"]))
        gate = _gate(report)  # 有数据库 → sqli 适用；无认证面 → auth 类裁掉
        planner = TaskPlanner(attack_surface=report, gate_report=gate)
        plan = planner.plan(proj)

        assert not plan.is_empty
        by_module = {t.module_dir: t for t in plan.tasks}
        assert set(by_module) == {"auth", "api"}
        api = by_module["api"]
        assert "sqli" in api.vulnerability_focus
        assert api.vulnerability_focus == sorted(api.vulnerability_focus)

        auth = by_module["auth"]
        assert "authn_bypass" in auth.vulnerability_focus
        # gate 裁掉的类不得出现在任何任务 focus
        for cls in gate.gated_classes():
            for task in plan.tasks:
                assert cls not in task.vulnerability_focus

    def test_entry_files_prioritized_in_task_files(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, {"api": ["users.py", "aaa_helpers.py", "zzz.py"]})
        report = _report()
        report.add_entry_point(_http("api/users.py"))
        planner = TaskPlanner(attack_surface=report, gate_report=_gate(report))
        plan = planner.plan(proj)
        task = plan.tasks[0]
        assert task.files[0] == "api/users.py"
        assert set(task.files) == {"api/users.py", "api/aaa_helpers.py", "api/zzz.py"}

    def test_absolute_entry_file_paths_group_correctly(self, tmp_path: Path) -> None:
        """检测器返回绝对路径的 entry.file —— 必须归一化后分组（回归）。"""
        proj = _make_project(tmp_path, {"auth": ["login.py"], "api": ["users.py"]})
        report = _report()
        # 绝对路径（真实检测器行为）
        report.add_entry_point(_http(str(proj / "auth" / "login.py"), middleware=["auth"]))
        report.add_entry_point(_http(str(proj / "api" / "users.py")))
        planner = TaskPlanner(attack_surface=report, gate_report=_gate(report))
        plan = planner.plan(proj)
        assert len(plan.tasks) == 2
        assert {t.module_dir for t in plan.tasks} == {"auth", "api"}
        # 任务文件必须是项目相对路径
        for t in plan.tasks:
            for f in t.files:
                assert not f.startswith("/")

    def test_unassigned_files_are_leftovers(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, {"api": ["users.py"], "webutil": ["fmt.py"]})
        report = _report()
        report.add_entry_point(_http("api/users.py"))
        planner = TaskPlanner(attack_surface=report, gate_report=_gate(report))
        plan = planner.plan(proj)
        assert plan.unassigned_files == ["webutil/fmt.py"]

    def test_priority_follows_entry_count(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, {"big": ["a.py", "b.py"], "small": ["c.py"]})
        report = _report()
        report.add_entry_point(_http("small/c.py"))
        report.add_entry_point(_http("big/a.py"))
        report.add_entry_point(_http("big/b.py"))
        planner = TaskPlanner(attack_surface=report, gate_report=_gate(report))
        plan = planner.plan(proj)
        assert plan.tasks[0].module_dir == "big"
        assert plan.tasks[0].priority == 2


class TestCaps:
    def test_max_tasks_cap_overflows_to_unassigned(self, tmp_path: Path) -> None:
        layout = {f"mod{i}": [f"f{i}.py"] for i in range(5)}
        proj = _make_project(tmp_path, layout)
        report = _report()
        for i in range(5):
            report.add_entry_point(_http(f"mod{i}/f{i}.py"))
        planner = TaskPlanner(attack_surface=report, gate_report=_gate(report), max_tasks=3)
        plan = planner.plan(proj)
        assert len(plan.tasks) == 3
        # 被裁模块的入口文件必须在未分配清单前部（sweep 优先）
        overflow_entry = {"mod3/f3.py", "mod4/f4.py"}
        assert overflow_entry & set(plan.unassigned_files[:2])

    def test_files_per_task_limit(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, {"api": [f"f{i}.py" for i in range(8)]})
        report = _report()
        report.add_entry_point(_http("api/f0.py"))
        planner = TaskPlanner(
            attack_surface=report, gate_report=_gate(report), files_per_task_limit=4
        )
        plan = planner.plan(proj)
        assert len(plan.tasks[0].files) == 4
        assert len(plan.unassigned_files) == 4


class TestRiskVerbs:
    def test_cron_maps_to_command_injection(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, {"jobs": ["backup.py"]})
        report = _report()
        report.add_entry_point(
            EntryPoint(type=EntryPointType.CRON, path="b", handler="h", file="jobs/backup.py")
        )
        planner = TaskPlanner(attack_surface=report, gate_report=_gate(report))
        plan = planner.plan(proj)
        assert plan.tasks[0].vulnerability_focus == ["command_injection"]

    def test_file_entry_maps_to_upload_and_traversal(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, {"up": ["receive.py"]})
        report = _report()
        report.add_entry_point(
            EntryPoint(type=EntryPointType.FILE, path="f", handler="h", file="up/receive.py")
        )
        planner = TaskPlanner(attack_surface=report, gate_report=_gate(report))
        plan = planner.plan(proj)
        assert set(plan.tasks[0].vulnerability_focus) >= {"file_upload", "path_traversal"}

    def test_http_file_param_adds_upload_focus(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, {"up": ["upload.py"]})
        report = _report()
        report.add_entry_point(_http("up/upload.py", params=["upload_file"]))
        planner = TaskPlanner(attack_surface=report, gate_report=_gate(report))
        plan = planner.plan(proj)
        assert "file_upload" in plan.tasks[0].vulnerability_focus


class TestDeterminism:
    def test_same_input_same_plan(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, {"api": ["users.py", "orders.py"], "auth": ["login.py"]})
        report = _report()
        report.add_entry_point(_http("api/users.py"))
        report.add_entry_point(_http("api/orders.py"))
        report.add_entry_point(_http("auth/login.py", middleware=["auth"]))
        gate = _gate(report)
        p1 = TaskPlanner(attack_surface=report, gate_report=gate).plan(proj)
        p2 = TaskPlanner(attack_surface=report, gate_report=gate).plan(proj)
        assert p1.model_dump(mode="json") == p2.model_dump(mode="json")
