"""Repository for LLM configuration management."""

from typing import Any, List, Optional
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.models.llm_config import LLMConfig, LLMConfigType, LLMProvider
from src.web.repositories.base import AsyncRepository


class LLMConfigRepository(AsyncRepository[LLMConfig, Any, Any]):
    """Repository for LLM configuration CRUD operations."""

    def __init__(self):
        super().__init__(model=LLMConfig)

    async def get_by_provider(self, db: AsyncSession, provider: str) -> Optional[LLMConfig]:
        """Get configs by provider.

        Args:
            db: Database session
            provider: Provider name (openai/azure/ollama/custom)

        Returns:
            List of configs with the specified provider
        """
        result = await db.execute(
            select(LLMConfig)
            .where(LLMConfig.provider == provider)
            .order_by(LLMConfig.created_at.desc())
        )
        return result.scalars().all()

    async def get_by_config_type(
        self, db: AsyncSession, config_type: str
    ) -> List[LLMConfig]:
        """Get configs by type.

        Args:
            db: Database session
            config_type: Config type (agent_scan/verification/both)

        Returns:
            List of configs with the specified type
        """
        result = await db.execute(
            select(LLMConfig)
            .where(
                and_(
                    LLMConfig.config_type == config_type,
                    LLMConfig.config_type == "both"
                )
            )
            .order_by(LLMConfig.is_default.desc(), LLMConfig.created_at.desc())
        )
        return result.scalars().all()

    async def get_default(
        self, db: AsyncSession, config_type: Optional[str] = None
    ) -> Optional[LLMConfig]:
        """Get default config for a specific type.

        Args:
            db: Database session
            config_type: Optional config type filter

        Returns:
            Default config or None
        """
        query = select(LLMConfig).where(LLMConfig.is_default == True)

        if config_type:
            query = query.where(
                (LLMConfig.config_type == config_type) |
                (LLMConfig.config_type == "both")
            )

        result = await db.execute(query.order_by(LLMConfig.created_at.desc()))
        return result.scalar_one_or_none()

    async def set_default(
        self, db: AsyncSession, config_id: int
    ) -> Optional[LLMConfig]:
        """Set a config as default, unsetting others of the same type.

        Args:
            db: Database session
            config_id: ID of the config to set as default

        Returns:
            Updated config or None if not found
        """
        # Get the config
        config = await self.get(db, id=config_id)
        if not config:
            return None

        # Unset other defaults of the same type
        await db.execute(
            select(LLMConfig).where(
                and_(
                    LLMConfig.is_default == True,
                    LLMConfig.config_type == config.config_type
                )
            )
        )

        # Set this as default
        config.is_default = True
        updated = await self.update(db, db_obj=config, obj_in={"is_default": True})

        # Update other configs with same type to is_default=False
        from sqlalchemy import update
        await db.execute(
            update(LLMConfig)
            .where(
                and_(
                    LLMConfig.id != config_id,
                    LLMConfig.config_type == config.config_type
                )
            )
            .values(is_default=False)
        )
        await db.commit()

        return updated

    async def get_for_agent_scan(self, db: AsyncSession) -> Optional[LLMConfig]:
        """Get config for agent scanning.

        Args:
            db: Database session

        Returns:
            Config for agent scan or default
        """
        # Try to get agent_scan specific config first
        result = await db.execute(
            select(LLMConfig)
            .where(
                (LLMConfig.config_type == LLMConfigType.AGENT_SCAN) |
                (LLMConfig.config_type == LLMConfigType.BOTH)
            )
            .order_by(LLMConfig.is_default.desc(), LLMConfig.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get_for_verification(self, db: AsyncSession) -> Optional[LLMConfig]:
        """Get config for adversarial verification.

        Args:
            db: Database session

        Returns:
            Config for verification or default
        """
        # Try to get verification specific config first
        result = await db.execute(
            select(LLMConfig)
            .where(
                (LLMConfig.config_type == LLMConfigType.VERIFICATION) |
                (LLMConfig.config_type == LLMConfigType.BOTH)
            )
            .order_by(LLMConfig.is_default.desc(), LLMConfig.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()
