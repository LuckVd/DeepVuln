"""Pydantic schemas for API requests and responses."""

from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field, ConfigDict


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
# Project Schemas
# ============================================================================

class ProjectBase(BaseModel):
    """Base project schema."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    source_type: str = Field(..., pattern="^(local|git|zip)$")
    source_path: str
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    extra_metadata: Optional[dict] = None


class ProjectCreate(ProjectBase):
    """Schema for creating a project."""
    pass


class ProjectUpdate(BaseModel):
    """Schema for updating a project."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    extra_metadata: Optional[dict] = None


class ProjectResponse(ProjectBase):
    """Schema for project response."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
    last_scan_id: Optional[int] = None


class ProjectListResponse(BaseModel):
    """Schema for paginated project list."""
    items: list[ProjectResponse]
    total: int
    page: int
    page_size: int


# ============================================================================
# Scan Schemas
# ============================================================================

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

    # Time information
    started_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None


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
    project_id: int
    scan_type: str = Field(..., pattern="^(full|base|incremental)$")
    config: dict = Field(default_factory=dict)


class ScanCreate(ScanBase):
    """Schema for creating a scan."""
    pass


class ScanResponse(BaseModel):
    """Schema for scan response."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    status: str
    scan_type: str
    current_phase: Optional[str] = None
    progress_percent: int = 0

    # Statistics
    total_files: int = 0
    analyzed_files: int = 0
    findings_count: int = 0
    tokens_used: int = 0

    # Timestamps
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


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
    created_at: datetime


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

    created_at: datetime


class ScanEventListResponse(BaseModel):
    """Schema for paginated event list."""
    items: list[ScanEventResponse]
    total: int
    page: int
    page_size: int


# ============================================================================
# WebSocket Event Schemas
# ============================================================================

class WebSocketEvent(BaseModel):
    """Schema for WebSocket events."""
    type: str
    message: Optional[str] = None
    data: Optional[dict] = None
    tokens_used: Optional[int] = None
    timestamp: Optional[datetime] = None
