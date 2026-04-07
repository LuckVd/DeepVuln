"""Finding model."""

from datetime import datetime
from typing import Optional

from sqlalchemy import String, Text, ForeignKey, JSON, Float, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime as SADateTime

from src.web.models.database import Base


class Finding(Base):
    """Finding model representing a discovered vulnerability."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    phase_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_phases.id", ondelete="CASCADE"), nullable=True)

    # Vulnerability info
    vuln_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Location info
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    line_start: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    line_end: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    function_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Details
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Status
    status: Mapped[str] = mapped_column(String(50), default="pending")

    # Engine source
    engine: Mapped[str] = mapped_column(String(50), nullable=False)

    # Additional metadata
    extra_metadata: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)

    # CPG path (from Phase 9 integration)
    cpg_path: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(SADateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Finding {self.vuln_type}: {self.severity} at {self.file_path}:{self.line_start}>"
