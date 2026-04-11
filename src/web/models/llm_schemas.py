"""Pydantic schemas for LLM configuration API."""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, validator


class LLMProvider:
    """LLM provider constants."""
    OPENAI = "openai"
    AZURE = "azure"
    OLLAMA = "ollama"
    CUSTOM = "custom"


class LLMConfigType:
    """LLM config type constants."""
    AGENT_SCAN = "agent_scan"
    VERIFICATION = "verification"
    BOTH = "both"


# ============================================================================
# Request Schemas
# ============================================================================


class LLMConfigCreate(BaseModel):
    """Schema for creating LLM configuration."""

    name: str = Field(..., min_length=1, max_length=255, description="Configuration name")
    provider: str = Field(..., description="LLM provider (openai/azure/ollama/custom)")
    api_key: Optional[str] = Field(None, description="API key for the provider")
    base_url: Optional[str] = Field(None, description="Base URL for API endpoints")
    model: str = Field(..., min_length=1, max_length=255, description="Model name")
    context_size: Optional[int] = Field(4096, ge=1, le=1000000, description="Context window size")
    temperature: Optional[float] = Field(0, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: Optional[int] = Field(4096, ge=1, le=100000, description="Max tokens per response")
    timeout: Optional[int] = Field(120, ge=10, le=600, description="Request timeout in seconds")
    max_retries: Optional[int] = Field(3, ge=0, le=10, description="Max retry attempts")
    max_concurrent_requests: Optional[int] = Field(5, ge=1, le=50, description="Max concurrent LLM requests")
    batch_max_chars: Optional[int] = Field(12000, ge=1000, le=100000, description="Max chars per batch")
    batch_size: Optional[int] = Field(20, ge=1, le=100, description="Batch size for processing")
    config_type: Optional[str] = Field("both", description="Config type (agent_scan/verification/both)")
    is_default: Optional[bool] = Field(False, description="Set as default config")

    @validator("provider")
    def validate_provider(cls, v):
        """Validate provider is supported."""
        valid_providers = [LLMProvider.OPENAI, LLMProvider.AZURE, LLMProvider.OLLAMA, LLMProvider.CUSTOM]
        if v not in valid_providers:
            raise ValueError(f"Provider must be one of: {', '.join(valid_providers)}")
        return v

    @validator("config_type")
    def validate_config_type(cls, v):
        """Validate config type."""
        valid_types = [LLMConfigType.AGENT_SCAN, LLMConfigType.VERIFICATION, LLMConfigType.BOTH]
        if v not in valid_types:
            raise ValueError(f"Config type must be one of: {', '.join(valid_types)}")
        return v


class LLMConfigUpdate(BaseModel):
    """Schema for updating LLM configuration."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    provider: Optional[str] = Field(None)
    api_key: Optional[str] = Field(None)
    base_url: Optional[str] = Field(None)
    model: Optional[str] = Field(None, min_length=1, max_length=255)
    context_size: Optional[int] = Field(None, ge=1, le=1000000)
    temperature: Optional[float] = Field(None, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(None, ge=1, le=100000)
    timeout: Optional[int] = Field(None, ge=10, le=600)
    max_retries: Optional[int] = Field(None, ge=0, le=10)
    max_concurrent_requests: Optional[int] = Field(None, ge=1, le=50)
    batch_max_chars: Optional[int] = Field(None, ge=1000, le=100000)
    batch_size: Optional[int] = Field(None, ge=1, le=100)
    config_type: Optional[str] = Field(None)
    is_default: Optional[bool] = Field(None)


class LLMConfigValidate(BaseModel):
    """Schema for LLM config validation request."""

    test_prompt: Optional[str] = Field("Hello, are you working?", description="Test prompt")


# ============================================================================
# Response Schemas
# ============================================================================


class LLMConfigResponse(BaseModel):
    """Schema for LLM configuration response."""

    id: int
    name: str
    provider: str
    api_key: Optional[str] = None  # Will be masked in response
    base_url: Optional[str]
    model: str
    context_size: int
    temperature: float
    max_tokens: int
    timeout: int
    max_retries: Optional[int] = None
    max_concurrent_requests: int = 5
    batch_max_chars: Optional[int] = None
    batch_size: Optional[int] = None
    is_default: bool
    config_type: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class LLMConfigListItem(BaseModel):
    """Schema for LLM config list item (masked sensitive data)."""

    id: int
    name: str
    provider: str
    model: str
    max_concurrent_requests: int = 5
    is_default: bool
    config_type: str
    # API key is masked
    has_api_key: bool
    created_at: datetime

    @classmethod
    def from_orm(cls, obj) -> "LLMConfigListItem":
        """Create from ORM object with masked API key."""
        return cls(
            id=obj.id,
            name=obj.name,
            provider=obj.provider,
            model=obj.model,
            max_concurrent_requests=getattr(obj, 'max_concurrent_requests', 5),
            is_default=obj.is_default,
            config_type=obj.config_type,
            has_api_key = bool(obj.api_key),
            created_at=obj.created_at,
        )


class LLMConfigListResponse(BaseModel):
    """Schema for LLM config list response."""

    items: List[LLMConfigListItem]
    total: int


class LLMValidationResponse(BaseModel):
    """Schema for LLM config validation response."""

    success: bool
    message: str
    model_info: Optional[dict] = None
    latency_ms: Optional[int] = None


class LLMModelsResponse(BaseModel):
    """Schema for available models response."""

    models: List[str]
    provider: str
