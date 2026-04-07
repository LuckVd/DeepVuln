"""Project model."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime

from src.web.models.database import Base


class Project(Base):
    """Project model representing a code repository to scan."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)  # local, git, zip
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    branch: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    commit_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_scan_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scans.id"), nullable=True)
    extra_metadata: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<Project {self.id}: {self.name}>"
