"""Pydantic schemas for API requests and responses."""

from datetime import datetime, timezone
from typing import Optional, Any, Annotated
from pydantic import (
    BaseModel,
    Field,
    ConfigDict,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic.functional_serializers import PlainSerializer


# Naive UTC datetimes are serialized with a trailing 'Z' so that JavaScript
# `new Date(...)` correctly interprets them as UTC rather than local time.
UtcDateTime = Annotated[
    datetime,
    PlainSerializer(
        lambda v: v.replace(tzinfo=timezone.utc).isoformat() if v else v,
        return_type=str,
        when_used="json",
    ),
]


# ============================================================================
# Enums
# ============================================================================

class ScanStatus(str):
    """Scan status constants."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str):
    """Scan type constants."""
    FULL = "full"
    BASE = "base"
    INCREMENTAL = "incremental"


class SeverityLevel(str):
    """Severity level constants."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str):
    """Finding status constants."""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    CONDITIONAL = "conditional"


class PhaseName(str):
    """Scan phase names."""
    L1_PREPARATION = "L1_preparation"
    L1_ATTACK_SURFACE = "L1_attack_surface"
    L2_SEMGREP = "L2_semgrep"
    L2_CODEQL = "L2_codeql"
    L3_AGENT = "L3_agent"
    L3_ADJUDICATION = "L3_adjudication"
    REPORT_GENERATION = "report_generation"


# ============================================================================
# Scan Schemas
# ============================================================================

# Single source of truth for the default engine selection. Every code path
# that needs a fallback engine list (API schema, orchestrator fallback,
# zip-upload endpoint) must reference this constant — audit A6 found three
# divergent hardcoded copies, which silently skipped the AST engine on most
# paths.
DEFAULT_SCAN_ENGINES = ["semgrep", "codeql", "agent", "ast"]


class ScanConfig(BaseModel):
    """Scan configuration schema with all supported parameters.

    P14-01f: 添加 LLM 攻击面检测、可利用性验证、对抗性验证、增量扫描等配置参数.
    """
    # Engine selection
    engines: list[str] = Field(
        default_factory=lambda: list(DEFAULT_SCAN_ENGINES),
        description="List of engines to use"
    )

    # LLM 攻击面检测 (P14-01)
    llm_detect: bool = Field(
        default=False,
        description="Enable LLM-based attack surface detection"
    )
    static_only: bool = Field(
        default=False,
        description="Use only static detection (no LLM)"
    )

    # 可利用性验证 (P14-02)
    llm_verify: bool = Field(
        default=True,
        description="Enable exploitability verification"
    )

    # Full multi-round audit: drive the RoundController rounds 1-4
    # (recon / dataflow / evidence correlation / exploitability calibration)
    # instead of the default single Round-4 verification. Experimental:
    # rounds 1-3 additionally re-run semgrep and build their own candidates;
    # any failure falls back to the Round-4-only path.
    enable_full_rounds: bool = Field(
        default=False,
        description="Run the full 4-round audit via RoundController (experimental; falls back to Round-4 verification on failure)"
    )

    # 对抗性验证 (P14-04)
    adversarial: bool = Field(
        default=False,
        description="Enable adversarial verification"
    )
    adversarial_max_rounds: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum rounds for adversarial verification"
    )
    adversarial_round_timeout: int = Field(
        default=600,
        ge=30,
        le=600,
        description="Timeout per round in seconds (default: 10 minutes)"
    )

    # AI 补漏逻辑漏洞 (E5): opt-in supplement pass that asks the LLM to surface
    # logic flaws static tools miss (missing authz/auth bypass/IDOR/business
    # logic/complex injection) on entry-point-reachable code. Off by default to
    # avoid false-positive noise on existing scans.
    logic_vuln: bool = Field(
        default=False,
        description="Enable AI logic-vulnerability supplement pass (anti-FP: entry-scoped)",
    )

    # 增量扫描 (P14-06)
    incremental: bool = Field(
        default=False,
        description="Enable incremental scan mode"
    )
    base_ref: str = Field(
        default="HEAD~1",
        description="Base reference for incremental scan (e.g., HEAD~1)"
    )
    head_ref: str = Field(
        default="HEAD",
        description="Target reference for incremental scan (e.g., HEAD)"
    )

    # Agent settings
    agent_max_files: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum files for agent to analyze"
    )

    # P3: agent low-confidence `suspicious_code` entries are pulled out of the
    # reportable set by default (they were the bulk of false positives in the
    # first mini baseline: near-guaranteed FP, confidence 0.1-0.5). Set True
    # to keep them in the final findings as before.
    include_suspicious_findings: bool = Field(
        default=False,
        description="Report agent 'suspicious' low-confidence entries as findings (default: review queue only)",
    )

    # Phase 20 P-A1: attack-surface taskification — the L1 attack surface is
    # grouped into ≤ max_tasks risk-semantic audit tasks executed by the agent
    # engine as an isolated, checkpointable task pool. Projects without entry
    # points automatically fall back to the historical flat scan.
    task_split: bool = Field(
        default=True,
        description="Enable attack-surface taskified agent audit (P-A1, auto-fallback when no entry points)",
    )
    task_concurrency: int = Field(
        default=2,
        ge=1,
        le=8,
        description="Maximum audit tasks running concurrently in the agent task pool",
    )
    max_tasks: int = Field(
        default=8,
        ge=2,
        le=16,
        description="Maximum number of audit tasks the planner may produce",
    )

    # Phase 20 P-A2: applicability gate — vulnerability classes without their
    # prerequisite surface (no auth mechanism, no HTTP, no crypto API probed…)
    # are cut from agent focus, merged into semgrep's rule exclusions, and
    # their findings routed to the review queue. Fail-open: uncertain classes
    # stay applicable.
    applicability_gate: bool = Field(
        default=True,
        description="Enable per-vulnerability-class applicability gating (P-A2, fail-open)",
    )
    include_gated_findings: bool = Field(
        default=False,
        description="Report findings of gate-not-applicable classes as findings (default: review queue only)",
    )

    # LLM model
    model: str = Field(
        default="deepseek-chat",
        description="LLM model to use for AI-based features"
    )

    # Test file filtering
    skip_tests: bool = Field(
        default=False,
        description="Skip test files during scanning"
    )


class TokenInfo(BaseModel):
    """Token consumption information."""
    used: int = 0
    budget: int = 100000
    percent: float = 0.0

    @classmethod
    def calculate(cls, used: int, budget: int) -> "TokenInfo":
        """Calculate token percentage."""
        return cls(used=used, budget=budget, percent=(used / budget * 100) if budget > 0 else 0)


class FindingSummary(BaseModel):
    """Summary of findings by severity."""
    total: int = 0
    verified: int = 0
    false_positive: int = 0
    by_severity: dict[str, int] = Field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })


class PhaseInfo(BaseModel):
    """Information about a scan phase."""
    name: str
    status: str
    progress_percent: int = 0
    duration_seconds: Optional[int] = None
    findings: int = 0
    tokens_used: int = 0


class ScanProgressResponse(BaseModel):
    """Detailed scan progress response."""
    scan_id: int
    status: str
    progress_percent: int
    current_phase: Optional[str] = None
    current_step: Optional[str] = None
    current_engine: Optional[str] = None

    # File statistics
    total_files: int = 0
    indexed_files: int = 0
    analyzed_files: int = 0
    files_with_findings: int = 0

    # Engine statistics
    engines: dict[str, Any] = Field(default_factory=dict)

    # Token statistics
    tokens: TokenInfo = Field(default_factory=TokenInfo)

    # Finding statistics
    findings: FindingSummary = Field(default_factory=FindingSummary)

    # Phase details
    phases: list[PhaseInfo] = Field(default_factory=list)

    # Concurrency status (populated from latest concurrency_update events)
    concurrency: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Time information
    started_at: Optional[UtcDateTime] = None
    estimated_completion: Optional[UtcDateTime] = None


class AgentConversationMessage(BaseModel):
    """A single message in agent conversation."""
    turn: int
    role: str  # user, assistant, system, critic, verifier
    message: str
    reasoning: Optional[str] = None
    action: Optional[str] = None
    tool_name: Optional[str] = None
    tool_input: Optional[dict] = None
    tokens: Optional[int] = None
    tokens_input: Optional[int] = None
    tokens_output: Optional[int] = None


class AdversarialStatus(BaseModel):
    """Status of adversarial verification."""
    active: bool = False
    round: int = 0
    max_rounds: int = 5
    current_findings: int = 0
    verifying_finding_id: Optional[str] = None


class AgentConversationResponse(BaseModel):
    """Agent conversation response."""
    scan_id: int
    phase: Optional[str] = None
    current_file: Optional[dict] = None
    conversation: list[AgentConversationMessage] = Field(default_factory=list)
    adversarial_status: AdversarialStatus = Field(default_factory=AdversarialStatus)


class CurrentFileResponse(BaseModel):
    """Current file being scanned."""
    scan_id: int
    current_file: Optional[dict] = None
    file_preview: Optional[dict] = None
    agent_actions_on_file: list[dict] = Field(default_factory=list)


class ScanBase(BaseModel):
    """Base scan schema."""
    name: str = Field(..., min_length=1, max_length=255, description="Scan task name")
    source_type: str = Field(..., pattern="^(local|git|zip)$", description="Source type")
    source_path: str = Field(..., description="Source path or URL")
    branch: Optional[str] = Field(None, description="Git branch (for git sources)")
    scan_type: str = Field(..., pattern="^(full|base|incremental)$")
    config: ScanConfig = Field(
        default_factory=ScanConfig,
        description="Scan configuration parameters"
    )

    @field_validator("source_path")
    @classmethod
    def validate_local_source_path(cls, v: str, info: ValidationInfo) -> str:
        """Audit 2026-09 fix: restrict local source_path scans.

        A security scanner that mirrors arbitrary server paths back into
        reports is itself a vulnerability. ``local`` scans must point to an
        existing directory, must not be a sensitive system path, and — when
        ``DEEPVULN_WEB_LOCAL_SCAN_ROOTS`` is configured — must resolve under
        one of the allowed roots. ``git``/``zip`` source types are untouched.
        """
        if info.data.get("source_type") != "local":
            return v

        sp = v.strip()
        if not sp:
            raise ValueError("local source_path 不能为空")

        from pathlib import Path

        p = Path(sp).expanduser()
        try:
            resolved = p.resolve()
        except Exception as exc:  # pragma: no cover - OS edge cases
            raise ValueError(f"local source_path 无法解析: {sp}") from exc

        # Sensitive system paths — deny even without an allowlist. The list
        # is intentionally minimal: anything broader (/opt, /home, /var…)
        # would break legitimate self-hosted deployments; strict deployments
        # should set DEEPVULN_WEB_LOCAL_SCAN_ROOTS instead.
        denied = {
            "/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/tmp",
            "/private", "/var", "/run", "/Users",
        }
        if any(str(resolved) == d or str(resolved).startswith(d + "/") for d in denied):
            raise ValueError(
                f"local source_path 指向敏感系统路径: '{sp}' 不允许扫描"
            )

        if not resolved.is_dir():
            raise ValueError(f"local source_path 不存在或不是目录: '{sp}'")

        # Optional allowlist (DEEPVULN_WEB_LOCAL_SCAN_ROOTS).
        from src.web.core.config import get_web_settings

        roots = get_web_settings().local_scan_roots_list
        if roots:
            if not any(
                resolved == Path(r).resolve() or resolved.is_relative_to(Path(r).resolve())
                for r in roots
            ):
                raise ValueError(
                    f"local source_path '{sp}' 不在允许的扫描根目录内 "
                    f"(DEEPVULN_WEB_LOCAL_SCAN_ROOTS: {', '.join(roots)})"
                )

        return v

    @model_validator(mode="after")
    def validate_git_source_path(self) -> "ScanBase":
        """当 source_type=git 时，校验 source_path 必须是有效格式。"""
        if self.source_type == "git":
            sp = self.source_path.strip()
            if sp.startswith(("http://", "https://", "git@", "ssh://")):
                return self
            # 允许 owner/repo 短格式（如 bytedance/deer-flow）
            import re
            if re.match(r"^[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+$", sp):
                return self
            raise ValueError(
                f"git source_path 必须是完整 URL（https://github.com/owner/repo）"
                f"或 owner/repo 短格式，收到: '{sp}'"
            )
        return self


class ScanCreate(ScanBase):
    """Schema for creating a scan."""
    pass


class ScanResponse(BaseModel):
    """Schema for scan response."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    source_type: str
    source_path: str
    branch: Optional[str] = None
    status: str
    scan_type: str
    config: Optional[ScanConfig] = None
    current_phase: Optional[str] = None
    progress_percent: int = 0

    # Statistics
    total_files: int = 0
    analyzed_files: Optional[int] = 0
    findings_count: int = 0
    tokens_used: int = 0
    token_usage: Optional[dict] = None  # P14-05: 详细词元使用统计

    # Severity breakdown
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    verified_count: int = 0
    false_positive_count: int = 0

    # P14-01/05/06: 扩展字段
    attack_surface: Optional[dict] = None  # P14-01: 攻击面统计
    adjudication_summary: Optional[dict] = None  # P14-03: 仲裁摘要
    adversarial_summary: Optional[dict] = None  # P14-04: 对抗性摘要
    incremental_stats: Optional[dict] = None  # P14-06: 增量扫描统计

    # Agent analysis detail
    agent_analyzed_files: Optional[list[str]] = None

    # Timestamps
    created_at: UtcDateTime
    started_at: Optional[UtcDateTime] = None
    completed_at: Optional[UtcDateTime] = None


class ScanListResponse(BaseModel):
    """Schema for paginated scan list."""
    items: list[ScanResponse]
    total: int
    page: int
    page_size: int


# ============================================================================
# Finding Schemas
# ============================================================================

class FindingBase(BaseModel):
    """Base finding schema."""
    vuln_type: str
    severity: str
    confidence: Optional[float] = None
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    function_name: Optional[str] = None
    title: str
    description: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None


class FindingCreate(FindingBase):
    """Schema for creating a finding."""
    pass


class FindingUpdate(BaseModel):
    """Schema for updating a finding."""
    status: str
    extra_metadata: Optional[dict] = None


class FindingResponse(FindingBase):
    """Schema for finding response."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    engine: str
    status: str
    cpg_path: Optional[dict] = None
    extra_metadata: Optional[dict] = None
    created_at: UtcDateTime


class FindingListResponse(BaseModel):
    """Schema for paginated finding list."""
    items: list[FindingResponse]
    total: int
    page: int
    page_size: int


# ============================================================================
# Event Schemas
# ============================================================================

class ScanEventResponse(BaseModel):
    """Schema for scan event response."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    event_type: str
    event_level: str = "info"
    message: Optional[str] = None
    details: Optional[dict] = None
    engine_name: Optional[str] = None

    # Agent fields
    agent_turn: int = 0
    agent_role: Optional[str] = None
    agent_message: Optional[str] = None

    # File fields
    file_path: Optional[str] = None
    file_index: int = 0
    file_total: int = 0

    # Token fields
    tokens_used: int = 0

    created_at: UtcDateTime


class ScanEventListResponse(BaseModel):
    """Schema for paginated event list."""
    items: list[ScanEventResponse]
    total: int
    page: int
    page_size: int


# ============================================================================
# Control Response Schemas
# ============================================================================

class PauseScanResponse(BaseModel):
    """Response for pause scan request."""
    scan_id: int
    status: str
    checkpoint_saved: bool
    paused_at: UtcDateTime
    current_phase: Optional[str] = None
    can_resume: bool


class ResumeScanResponse(BaseModel):
    """Response for resume scan request."""
    scan_id: int
    status: str
    resumed_from_phase: Optional[str] = None
    resumed_at: UtcDateTime
    task_id: str
    skip_phases: list[str] = []


class CancelScanResponse(BaseModel):
    """Response for cancel scan request."""
    scan_id: int
    status: str
    cancelled_at: UtcDateTime
    cleanup_started: bool


class ScanStatusResponse(BaseModel):
    """Response for scan status query with available actions."""
    scan_id: int
    status: str
    progress_percent: int
    current_phase: Optional[str] = None
    available_actions: list[str]
    can_pause: bool
    can_resume: bool
    can_cancel: bool


# ============================================================================
# WebSocket Event Schemas
# ============================================================================

class WebSocketEvent(BaseModel):
    """Schema for WebSocket events."""
    type: str
    message: Optional[str] = None
    data: Optional[dict] = None
    tokens_used: Optional[int] = None
    timestamp: Optional[UtcDateTime] = None
