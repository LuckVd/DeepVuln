"""Audit task models for attack-surface-driven taskification (P-A1).

Inspired by the Codebuddy Security benchmark study
(docs/ai/benchmark-vs-codebuddy.md, P-A1): the L1 attack surface report is
grouped into a bounded set of risk-semantic audit tasks
(``<module>-<risk verb>``) that the agent engine executes as an isolated,
checkpointable task pool, instead of one flat size-sorted file list.

Like ``attack_surface.py`` this module lives in core/ so both L1 (the planner)
and L3 (the agent engine) can depend on it without a layering violation.
"""

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class RiskVerb(str, Enum):
    """Risk verbs — the vulnerability classes a task focuses on.

    Values intentionally reuse the vulnerability-class vocabulary already used
    in ``Finding.rule_id`` (agent findings) and the benchmark ``cwe_keywords``
    matching, so gate/planner/agent/report all speak the same taxonomy without
    introducing a new one.
    """

    SQLI = "sqli"
    XSS = "xss"
    SSRF = "ssrf"
    CMDI = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    AUTHN_BYPASS = "authn_bypass"
    AUTHZ_IDOR = "authz_idor"
    DESERIALIZATION = "deserialization"
    CRYPTO_MISUSE = "crypto_misuse"
    FILE_UPLOAD = "file_upload"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"


#: All risk-verb values as plain strings (gate decisions are keyed by these).
RISK_VERB_VALUES: frozenset[str] = frozenset(v.value for v in RiskVerb)


class AuditTask(BaseModel):
    """One risk-semantic audit task over a bounded module file set."""

    task_id: str = Field(..., description="Stable id used by task-level checkpoints")
    name: str = Field(
        ...,
        description="Human-readable risk-semantic name, e.g. 'controllers/user-authn_bypass'",
    )
    module_dir: str = Field(
        default=".",
        description="Module directory (project-relative) the task groups",
    )

    # Bounded file set (project-relative paths) audited by this task.
    files: list[str] = Field(default_factory=list)

    # Indexes into AttackSurfaceReport.entry_points (referenced, not copied).
    entry_point_indexes: list[int] = Field(default_factory=list)

    # Risk verbs (RiskVerb values) this task's audit focuses on. Already
    # filtered through the applicability gate: gated classes never appear.
    vulnerability_focus: list[str] = Field(default_factory=list)

    # Higher priority tasks get file budget first (entry-point count driven).
    priority: int = Field(default=0, ge=0)

    # Lifecycle, updated by the agent engine's task pool and checkpointed.
    status: Literal["pending", "completed", "failed"] = "pending"

    def describe(self) -> str:
        """Compact prompt-ready description of the task's audit scope."""
        focus = ", ".join(self.vulnerability_focus) if self.vulnerability_focus else "general"
        return (
            f"Audit task '{self.name}' (module: {self.module_dir}); "
            f"focus: {focus}; files: {len(self.files)}"
        )


class TaskPlan(BaseModel):
    """The full taskification product for one scan.

    ``tasks`` is the ordered (priority-descending, name-ascending) task list.
    ``unassigned_files`` holds analyzable files no task covers; the agent
    sweeps them with the leftover global ``max_files`` budget so total scan
    volume stays bounded (never larger than today's flat path).
    """

    tasks: list[AuditTask] = Field(default_factory=list)
    unassigned_files: list[str] = Field(default_factory=list)
    planner_meta: dict[str, Any] = Field(
        default_factory=dict,
        description="Grouping statistics, gating cuts and fallback reasons",
    )

    @property
    def is_empty(self) -> bool:
        """True when there is nothing to taskify (agent falls back to flat)."""
        return not self.tasks

    def completed_task_ids(self) -> list[str]:
        return [t.task_id for t in self.tasks if t.status == "completed"]

    def to_summary(self) -> dict[str, Any]:
        """Compact summary for scan-result metadata / progress events."""
        return {
            "tasks_total": len(self.tasks),
            "tasks_completed": sum(1 for t in self.tasks if t.status == "completed"),
            "tasks_failed": sum(1 for t in self.tasks if t.status == "failed"),
            "unassigned_files": len(self.unassigned_files),
            "planner_meta": self.planner_meta,
        }
