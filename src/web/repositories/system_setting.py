"""Repository for system settings CRUD operations."""

from typing import Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.web.models.system_setting import SystemSetting


class SystemSettingRepository:
    """Repository for system settings."""

    async def get(self, db: AsyncSession, key: str) -> Optional[SystemSetting]:
        """Get a setting by key."""
        result = await db.execute(
            select(SystemSetting).where(SystemSetting.key == key)
        )
        return result.scalar_one_or_none()

    async def get_all(self, db: AsyncSession) -> list[SystemSetting]:
        """Get all settings."""
        result = await db.execute(select(SystemSetting))
        return list(result.scalars().all())

    async def get_by_category(
        self, db: AsyncSession, category: str
    ) -> list[SystemSetting]:
        """Get all settings in a category."""
        result = await db.execute(
            select(SystemSetting).where(SystemSetting.category == category)
        )
        return list(result.scalars().all())

    async def create(
        self, db: AsyncSession, obj_in: SystemSetting
    ) -> SystemSetting:
        """Create a new setting."""
        db.add(obj_in)
        await db.flush()
        return obj_in

    async def update(
        self, db: AsyncSession, obj_in: SystemSetting
    ) -> SystemSetting:
        """Update a setting (already tracked)."""
        await db.flush()
        return obj_in

    async def upsert(
        self, db: AsyncSession, key: str, value: Optional[str],
        category: Optional[str] = None, description: Optional[str] = None
    ) -> SystemSetting:
        """Create or update a setting."""
        setting = await self.get(db, key)
        if setting:
            setting.value = value
            setting.category = category
            setting.description = description
        else:
            setting = SystemSetting(
                key=key,
                value=value,
                category=category,
                description=description
            )
            db.add(setting)
        await db.flush()
        return setting

    async def delete(self, db: AsyncSession, key: str) -> bool:
        """Delete a setting by key."""
        setting = await self.get(db, key)
        if setting:
            await db.delete(setting)
            return True
        return False
