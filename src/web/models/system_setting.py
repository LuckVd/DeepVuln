"""System settings models."""

from datetime import datetime
from typing import Optional

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.web.models.database import Base


class SystemSetting(Base):
    """System configuration model for non-LLM settings."""

    __tablename__ = "system_settings"

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Configuration key (unique identifier)
    key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)

    # Configuration value (JSON string for complex values)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Category for grouping
    category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Human-readable description
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamp
    updated_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<SystemSetting {self.key}={self.value}>"
