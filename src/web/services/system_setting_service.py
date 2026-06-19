"""Service for retrieving system configuration from database."""

import logging
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from src.web.repositories.system_setting import SystemSettingRepository

logger = logging.getLogger(__name__)


class SystemSettingService:
    """Service for retrieving system configurations from the database."""

    # Default values
    DEFAULTS = {
        "scan.timeout": "300",
        "scan.max_concurrent_files": "10",
        "threat_intel.github_token": "",
        "threat_intel.nvd_api_key": "",
    }

    @staticmethod
    async def get(db: AsyncSession, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a system setting value.

        Args:
            db: Database session
            key: Setting key
            default: Default value if not found

        Returns:
            Setting value or default
        """
        repo = SystemSettingRepository()
        setting = await repo.get_by_key(db, key)

        if setting is None:
            return default or SystemSettingService.DEFAULTS.get(key)
        return setting.value

    @staticmethod
    async def get_int(db: AsyncSession, key: str, default: int = 0) -> int:
        """
        Get a system setting value as integer.

        Args:
            db: Database session
            key: Setting key
            default: Default value if not found or invalid

        Returns:
            Setting value as integer
        """
        value = await SystemSettingService.get(db, key)
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    @staticmethod
    async def get_all(db: AsyncSession, category: Optional[str] = None) -> dict[str, str]:
        """
        Get all system settings, optionally filtered by category.

        Args:
            db: Database session
            category: Optional category filter

        Returns:
            Dictionary of setting key -> value
        """
        repo = SystemSettingRepository()
        settings = await repo.get_all(db)

        result = {}
        for setting in settings:
            if category is None or setting.category == category:
                result[setting.key] = setting.value

        return result

    @staticmethod
    async def get_scan_config(db: AsyncSession) -> dict[str, Any]:
        """
        Get scan configuration from database.

        Args:
            db: Database session

        Returns:
            Dictionary with scan configuration
        """
        return {
            "timeout": await SystemSettingService.get_int(db, "scan.timeout", 300),
            "max_concurrent_files": await SystemSettingService.get_int(db, "scan.max_concurrent_files", 10),
        }

    @staticmethod
    async def get_verification_config(db: AsyncSession) -> dict[str, Any]:
        """
        Get verification configuration from database.

        Note: LLM concurrent requests are now configured per LLM config
        in the database, not as a global system setting.

        Args:
            db: Database session

        Returns:
            Empty dictionary (config moved to LLM configs)
        """
        return {}

    @staticmethod
    async def get_threat_intel_config(db: AsyncSession) -> dict[str, Any]:
        """
        Get threat intelligence configuration from database.

        Args:
            db: Database session

        Returns:
            Dictionary with threat intelligence configuration
        """
        return {
            "github_token": await SystemSettingService.get(db, "threat_intel.github_token", ""),
            "nvd_api_key": await SystemSettingService.get(db, "threat_intel.nvd_api_key", ""),
        }
