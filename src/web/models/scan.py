"""Scan models."""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    String, Text, ForeignKey, JSON, Integer, Float, Boolean, DateTime as SADateTime
)
from sqlalchemy.orm import Mapped, mapped_column

from src.web.models.database import Base


class ScanStatus:
    """Scan status constants."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType:
    """Scan type constants."""
    FULL = "full"
    BASE = "base"
    INCREMENTAL = "incremental"


class PhaseName:
    """Scan phase names."""
    L1_PREPARATION = "L1_preparation"
    L1_ATTACK_SURFACE = "L1_attack_surface"
    L2_SEMGREP = "L2_semgrep"
    L2_CODEQL = "L2_codeql"
    L3_AGENT = "L3_agent"
    L3_ADJUDICATION = "L3_adjudication"
    REPORT_GENERATION = "report_generation"


class Scan(Base):
    """Scan model representing a vulnerability scan task."""

    __tablename__ = "scans"

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)

    # Task info
    status: Mapped[str] = mapped_column(String(50), nullable=False, default=ScanStatus.PENDING)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    config: Mapped[dict] = mapped_column(JSON, nullable=False)

    # Progress tracking (detailed)
    current_phase: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    current_step: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    current_engine: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    progress_percent: Mapped[int] = mapped_column(Integer, default=0)

    # File statistics
    total_files: Mapped[int] = mapped_column(Integer, default=0)
    indexed_files: Mapped[int] = mapped_column(Integer, default=0)
    analyzed_files: Mapped[int] = mapped_column(Integer, default=0)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    files_with_findings: Mapped[int] = mapped_column(Integer, default=0)

    # Engine statistics
    engines_completed: Mapped[int] = mapped_column(Integer, default=0)
    engines_total: Mapped[int] = mapped_column(Integer, default=5)

    # LLM/Token statistics
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    tokens_budget: Mapped[int] = mapped_column(Integer, default=100000)
    llm_requests_count: Mapped[int] = mapped_column(Integer, default=0)

    # Discovery statistics
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    verified_count: Mapped[int] = mapped_column(Integer, default=0)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)

    # Quality scores
    quality_score: Mapped[float] = mapped_column(Float, default=0.0)
    coverage_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(SADateTime, default=datetime.utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(SADateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(SADateTime, nullable=True)
    estimated_completion: Mapped[Optional[datetime]] = mapped_column(SADateTime, nullable=True)

    # Error handling
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    failed_engines: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Checkpoint data (for pause/resume)
    checkpoint_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # P14-01: 攻击面统计
    attack_surface: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # P14-03: 仲裁摘要
    adjudication_summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # P14-04: 对抗性摘要
    adversarial_summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # P14-05: Token 使用详情 (扩展 tokens_used 为 JSON)
    token_usage: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # P14-06: 增量扫描统计
    incremental_stats: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Result reference
    report_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<Scan {self.id}: {self.status}>"


class ScanPhase(Base):
    """Scan phase model for tracking individual phase execution."""

    __tablename__ = "scan_phases"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)

    # Phase info
    phase_name: Mapped[str] = mapped_column(String(100), nullable=False)
    engine_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False)

    # Progress description
    current_step: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0)

    # Statistics (engine-level)
    files_processed: Mapped[int] = mapped_column(Integer, default=0)
    findings_found: Mapped[int] = mapped_column(Integer, default=0)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamps
    started_at: Mapped[Optional[datetime]] = mapped_column(SADateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(SADateTime, nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Output data
    output_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    output_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Error
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(SADateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<ScanPhase {self.phase_name}: {self.status}>"


class ScanEvent(Base):
    """Scan event model for real-time progress tracking."""

    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    phase_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_phases.id", ondelete="CASCADE"), nullable=True)

    # Event info
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    event_level: Mapped[str] = mapped_column(String(20), default="info")

    # Event content
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Engine info
    engine_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Agent specific (adversarial debate/dialogue)
    agent_turn: Mapped[int] = mapped_column(Integer, default=0)
    agent_role: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    agent_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    agent_reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # File processing info
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_index: Mapped[int] = mapped_column(Integer, default=0)
    file_total: Mapped[int] = mapped_column(Integer, default=0)

    # Token consumption
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    tokens_input: Mapped[int] = mapped_column(Integer, default=0)
    tokens_output: Mapped[int] = mapped_column(Integer, default=0)

    # Associated finding
    finding_id: Mapped[Optional[int]] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)

    # Sequence for ordering
    sequence: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(SADateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<ScanEvent {self.event_type}: {self.message}>"
