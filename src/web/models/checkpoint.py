"""Checkpoint and utility models."""

from datetime import datetime
from typing import Optional

from sqlalchemy import String, Text, ForeignKey, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime as SADateTime

from src.web.models.database import Base


class ScanFile(Base):
    """Scan file model for incremental scanning support."""

    __tablename__ = "scan_files"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(SADateTime, default=datetime.utcnow)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    def __repr__(self) -> str:
        return f"<ScanFile {self.file_path}: {self.findings_count} findings>"


class ApiKey(Base):
    """API Key model for authentication."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(SADateTime, default=datetime.utcnow)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(SADateTime, nullable=True)

    def __repr__(self) -> str:
        return f"<ApiKey {self.name}: {'active' if self.is_active else 'inactive'}>"
