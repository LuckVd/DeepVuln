"""LLM configuration models."""

from datetime import datetime
from typing import Optional

from sqlalchemy import String, Text, Float, Integer, Boolean, DateTime as SADateTime
from sqlalchemy.orm import Mapped, mapped_column

from src.web.models.database import Base


class LLMProvider:
    """LLM provider constants."""
    OPENAI = "openai"
    AZURE = "azure"
    OLLAMA = "ollama"
    CUSTOM = "custom"


class LLMConfigType:
    """LLM config type constants."""
    AGENT_SCAN = "agent_scan"      # For agent-based scanning
    VERIFICATION = "verification"  # For adversarial verification
    BOTH = "both"                  # Can be used for both


class LLMConfig(Base):
    """LLM configuration model."""

    __tablename__ = "llm_configs"

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Configuration info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    api_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    base_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    model: Mapped[str] = mapped_column(String(255), nullable=False)

    # Model parameters
    context_size: Mapped[int] = mapped_column(Integer, default=4096)
    temperature: Mapped[float] = mapped_column(Float, default=0)
    max_tokens: Mapped[int] = mapped_column(Integer, default=4096)
    timeout: Mapped[int] = mapped_column(Integer, default=120)

    # Advanced LLM settings
    max_retries: Mapped[int] = mapped_column(Integer, default=3)
    max_concurrent_requests: Mapped[int] = mapped_column(Integer, default=10)
    batch_max_chars: Mapped[int] = mapped_column(Integer, default=12000)
    batch_size: Mapped[int] = mapped_column(Integer, default=20)

    # Configuration type
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    config_type: Mapped[str] = mapped_column(String(50), default="both")

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(SADateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(SADateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<LLMConfig {self.id}: {self.name} ({self.provider}/{self.model})>"

    def get_client_config(self) -> dict:
        """Get configuration dict for LLM client initialization.

        Returns:
            Dictionary with client configuration
        """
        return {
            "model": self.model,
            "api_key": self.api_key,
            "base_url": self.base_url,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "timeout": self.timeout,
        }
