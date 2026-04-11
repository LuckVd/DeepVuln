"""Pydantic schemas for system settings API."""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class SystemSettingCreate(BaseModel):
    """Schema for creating/updating system setting."""
    key: str = Field(..., min_length=1, max_length=255)
    value: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None


class SystemSettingResponse(BaseModel):
    """Schema for system setting response."""
    id: int
    key: str
    value: Optional[str]
    category: Optional[str]
    description: Optional[str]
    updated_at: str

    class Config:
        from_attributes = True


class SystemSettingsBatch(BaseModel):
    """Schema for batch update of system settings."""
    settings: Dict[str, Optional[str]] = Field(default_factory=dict)


class SystemSettingsResponse(BaseModel):
    """Schema for all system settings response."""
    settings: Dict[str, SystemSettingResponse]
    categories: Dict[str, Dict[str, Any]]
