"""Task planner — turns the attack surface report into audit tasks (P-A1).

The deterministic counterpart of Codebuddy's threat-modeling split: group the
L1 attack surface entry points into ≤ ``max_tasks`` risk-semantic audit tasks
(``<module>-<risk verb>``), each with a bounded file set and a gate-filtered
``vulnerability_focus``. No LLM tokens are spent on planning.

Fail-open guarantees
--------------------
- No entry points (or coverage below ``coverage_floor``) → an *empty* plan;
  the agent engine keeps its exact historical flat-scan behaviour.
- Gate-not-applicable classes never enter any task's focus (P-A2 → P-A1).
- A residual ``unassigned_files`` set lets the agent sweep leftover files
  within the remaining global ``max_files`` budget — total scan volume never
  exceeds today's flat path.
"""

from collections import defaultdict
from pathlib import Path

from src.core.applicability_gate import GateReport
from src.core.logger.logger import get_logger
from src.core.models.audit_task import AuditTask, TaskPlan
from src.core.models.attack_surface import AttackSurfaceReport


def _short(data: dict) -> str:
    return f"planner: {data}"


#: Planner-local file discovery constants (used only when the caller does not
#: supply ``analyzable_files``). Deliberately kept in sync with the agent
#: engine's discovery semantics; the agent remains the analysis authority.
PLANNER_ANALYZABLE_EXTENSIONS = frozenset(
    {".py", ".go", ".java", ".js", ".jsx", ".ts", ".tsx", ".rb", ".php"}
)
PLANNER_SKIP_DIRECTORIES = frozenset(
    {
        "node_modules", "venv", ".venv", "env", "__pycache__", ".git",
        "dist", "build", "target", "out", "vendor", "third_party",
        "migrations", "docs", "tests", "test", "spec",
    }
)


class TaskPlanner:
    """Groups entry points into risk-semantic audit tasks."""

    def __init__(
        self,
        attack_surface: AttackSurfaceReport | None,
        gate_report: GateReport | None = None,
        tech_stack: dict | None = None,
        max_tasks: int = 8,
        files_per_task_limit: int = 25,
        coverage_floor: float = 0.3,
    ) -> None:
        self.attack_surface = attack_surface
        self.gate_report = gate_report
        self.tech_stack = tech_stack or {}
        self.max_tasks = max(2, max_tasks)
        self.files_per_task_limit = max(1, files_per_task_limit)
        self.coverage_floor = coverage_floor
        self.logger = get_logger(__name__)

    # -- public API ---------------------------------------------------------

    def plan(self, source_path: Path, analyzable_files: list[Path] | None = None) -> TaskPlan:
        """Build the task plan. Always returns a valid (possibly empty) plan."""
        meta: dict = {"fallback": None}

        entry_points = list(getattr(self.attack_surface, "entry_points", None) or [])
        if not entry_points:
            meta["fallback"] = "no_entry_points"
            self.logger.info(_short(meta))
            return TaskPlan(planner_meta=meta)

        files = self._resolve_files(source_path, analyzable_files)
        if not files:
            meta["fallback"] = "no_analyzable_files"
            self.logger.info(_short(meta))
            return TaskPlan(planner_meta=meta)

        gated = set(self.gate_report.gated_classes()) if self.gate_report else set()

        # 1. Group entry points and files by module directory.
        modules: dict[str, dict] = defaultdict(
            lambda: {"entry_indexes": [], "entry_files": [], "files": []}
        )
        file_strs: list[str] = []
        for f in files:
            rel = self._rel(source_path, f)
            file_strs.append(rel)
            modules[self._module_of(rel)]["files"].append(rel)
        for idx, ep in enumerate(entry_points):
            # Detector file paths may be absolute — normalize against the scan
            # source root so entry modules group with the relative file list
            # (an absolute path would otherwise collapse every module into one
            # prefix bucket like "/tmp").
            entry_rel = self._rel(source_path, Path(str(ep.file)))
            module = self._module_of(entry_rel)
            modules[module]["entry_indexes"].append(idx)
            if entry_rel not in modules[module]["entry_files"]:
                modules[module]["entry_files"].append(entry_rel)

        entry_modules = {name: m for name, m in modules.items() if m["entry_indexes"]}
        if not entry_modules:
            meta["fallback"] = "no_modules_with_entries"
            self.logger.info(_short(meta))
            return TaskPlan(planner_meta=meta)

        # 2. Priority order: more entry points first, then stable name order.
        ordered = sorted(
            entry_modules.items(),
            key=lambda kv: (-len(kv[1]["entry_indexes"]), kv[0]),
        )

        # 3. Cap the module count — overflow modules' files fall to unassigned.
        kept = ordered[: self.max_tasks]
        overflow = ordered[self.max_tasks :]

        covered: set[str] = set()
        tasks: list[AuditTask] = []
        for name, m in kept:
            focus = self._derive_focus(m["entry_indexes"], entry_points, gated)
            # Entry files first (they justify the task), then sibling files.
            task_files: list[str] = []
            for f in m["entry_files"] + m["files"]:
                if f in covered or f in task_files:
                    continue
                task_files.append(f)
                if len(task_files) >= self.files_per_task_limit:
                    break
            covered.update(task_files)
            tasks.append(
                AuditTask(
                    task_id=f"task-{len(tasks) + 1:02d}-{name.replace('/', '-')}",
                    name=f"{name or 'root'}-{focus[0] if focus else 'general'}",
                    module_dir=name or ".",
                    files=task_files,
                    entry_point_indexes=list(m["entry_indexes"]),
                    vulnerability_focus=focus,
                    priority=len(m["entry_indexes"]),
                )
            )

        unassigned = [f for f in file_strs if f not in covered]
        # Overflow modules are audited via the unassigned sweep, not lost.
        overflow_files = {
            f for _, m in overflow for f in (m["entry_files"] + m["files"])
        }

        covered_total = len(covered)
        if covered_total < self.coverage_floor * len(file_strs):
            meta["fallback"] = (
                f"low_coverage ({covered_total}/{len(file_strs)} < "
                f"{self.coverage_floor:.0%})"
            )
            self.logger.info(_short(meta))
            return TaskPlan(planner_meta=meta)

        meta.update(
            {
                "modules_detected": len(entry_modules),
                "modules_kept": len(kept),
                "modules_overflow": len(overflow),
                "gated_classes_cut": sorted(gated),
                "covered_files": covered_total,
                "total_files": len(file_strs),
            }
        )
        # Unassigned = files not covered by any task (incl. overflow modules),
        # entry-point files of overflow modules first so they are not dropped
        # behind the sweep budget.
        unassigned_sorted = sorted(
            unassigned,
            key=lambda f: (0 if f in overflow_files else 1, f),
        )
        plan = TaskPlan(
            tasks=tasks,
            unassigned_files=unassigned_sorted,
            planner_meta=meta,
        )
        self.logger.info(
            f"TaskPlanner: {len(tasks)} task(s), "
            f"{len(unassigned_sorted)} unassigned file(s), meta={meta}"
        )
        return plan

    # -- helpers --------------------------------------------------------------

    def _resolve_files(
        self, source_path: Path, analyzable_files: list[Path] | None
    ) -> list[Path]:
        if analyzable_files is not None:
            return list(analyzable_files)
        # Self-enumeration fallback (planner-only usage, e.g. tests/tools):
        # mirrors the agent's flat discovery semantics closely enough for
        # grouping; the agent remains the authority on what it analyzes.
        files: list[Path] = []
        root = Path(source_path)
        if not root.exists():
            return files
        for path in sorted(root.rglob("*")):
            if path.suffix.lower() not in PLANNER_ANALYZABLE_EXTENSIONS:
                continue
            try:
                rel_parts = path.relative_to(root).parts
            except ValueError:
                continue
            if any(part in PLANNER_SKIP_DIRECTORIES for part in rel_parts):
                continue
            files.append(path)
        return files

    @staticmethod
    def _rel(source_path: Path, f: Path) -> str:
        try:
            return str(f.relative_to(source_path))
        except ValueError:
            return str(f)

    @staticmethod
    def _module_of(rel_path: str) -> str:
        """Module key = first 1–2 path segments (package-level grouping)."""
        parts = [p for p in Path(rel_path.replace("\\", "/")).parts[:-1] if p not in (".",)]
        if not parts:
            return ""
        return "/".join(parts[:2]) if len(parts) >= 2 else parts[0]

    def _derive_focus(
        self,
        entry_indexes: list[int],
        entry_points: list,
        gated: set[str],
    ) -> list[str]:
        """Risk verbs for one module, gate-filtered, stable order."""
        verbs: set[str] = set()
        for idx in entry_indexes:
            ep = entry_points[idx]
            etype = getattr(getattr(ep, "type", None), "value", "")
            params = [str(p).lower() for p in (getattr(ep, "params", None) or [])]
            has_file_param = any(
                any(k in p for k in ("file", "path", "upload", "attachment"))
                for p in params
            )
            if etype in ("http", "websocket", "rpc", "grpc"):
                verbs.update({"sqli", "xss", "ssrf", "open_redirect"})
                if has_file_param:
                    verbs.update({"file_upload", "path_traversal"})
                middleware = [str(mw).lower() for mw in (getattr(ep, "middleware", None) or [])]
                if any("auth" in mw or "session" in mw or "jwt" in mw for mw in middleware) or getattr(
                    ep, "auth_required", False
                ):
                    verbs.update({"authn_bypass", "authz_idor"})
            elif etype == "mq":
                verbs.add("deserialization")
            elif etype == "cron":
                verbs.add("command_injection")
            elif etype == "file":
                verbs.update({"file_upload", "path_traversal"})
        # Always-on class: any code can exec; keeps tasks without a web focus
        # from being empty.
        verbs.add("command_injection")
        # P-A2 wiring: gate-not-applicable classes never enter task focus.
        focus = sorted(v for v in verbs if v not in gated)
        return focus
