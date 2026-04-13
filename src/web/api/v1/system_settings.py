"""System settings management API endpoints."""

from typing import Dict, Any
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.api.deps import get_db
from src.web.core.security import require_api_key
from src.web.models.system_schemas import (
    SystemSettingResponse,
    SystemSettingsBatch,
    SystemSettingsResponse,
)
from src.web.repositories.system_setting import SystemSettingRepository

router = APIRouter()


# Define default settings
DEFAULT_SETTINGS = {
    # General settings
    "general.timezone": "Asia/Shanghai",

    # Scan settings
    "scan.timeout": "300",
    "scan.max_concurrent_files": "10",

    # Threat intelligence
    "threat_intel.github_token": "",
    "threat_intel.nvd_api_key": "",
}

SETTING_DESCRIPTIONS = {
    "scan.timeout": "扫描超时时间（秒）",
    "scan.max_concurrent_files": "最大并发扫描文件数",
    "threat_intel.github_token": "GitHub Personal Access Token (可选)",
    "threat_intel.nvd_api_key": "NVD API Key (可选)",
}


@router.get("/system-settings", response_model=SystemSettingsResponse)
async def get_system_settings(
    db: AsyncSession = Depends(get_db)
):
    """Get all system settings grouped by category."""
    repo = SystemSettingRepository()
    settings = await repo.get_all(db)

    # Build settings dict
    settings_dict: Dict[str, SystemSettingResponse] = {}
    categories: Dict[str, Dict[str, Any]] = {
        "general": {},
        "scan": {},
        "verification": {},
        "threat_intel": {},
    }

    for setting in settings:
        # Parse category from key (e.g., "scan.timeout" -> category="scan")
        category = setting.category or setting.key.split('.')[0]

        settings_dict[setting.key] = SystemSettingResponse(
            id=setting.id,
            key=setting.key,
            value=setting.value,
            category=setting.category,
            description=setting.description,
            updated_at=setting.updated_at.isoformat()
        )

        # Add to category
        if category not in categories:
            categories[category] = {}
        categories[category][setting.key] = setting.value

    # Add defaults for missing settings
    for key, default_value in DEFAULT_SETTINGS.items():
        if key not in settings_dict:
            category = key.split('.')[0]
            settings_dict[key] = SystemSettingResponse(
                id=0,
                key=key,
                value=default_value,
                category=category,
                description=SETTING_DESCRIPTIONS.get(key),
                updated_at=datetime.utcnow().isoformat()
            )
            if category in categories:
                categories[category][key] = default_value

    return SystemSettingsResponse(
        settings=settings_dict,
        categories=categories
    )


@router.put("/system-settings", response_model=SystemSettingsResponse)
async def update_system_settings(
    batch: SystemSettingsBatch,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_api_key),
):
    """Batch update system settings."""
    repo = SystemSettingRepository()

    # Update each setting
    for key, value in batch.settings.items():
        category = key.split('.')[0]
        await repo.upsert(
            db,
            key=key,
            value=value,
            category=category,
            description=SETTING_DESCRIPTIONS.get(key)
        )

    await db.commit()

    # Return updated settings
    return await get_system_settings(db)
