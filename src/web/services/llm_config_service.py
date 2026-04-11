"""Service for retrieving LLM configuration from database."""

import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.web.models.llm_config import LLMConfig, LLMConfigType

logger = logging.getLogger(__name__)


class LLMConfigService:
    """Service for retrieving LLM configurations from the database."""

    @staticmethod
    async def get_config_by_type(
        db: AsyncSession,
        config_type: str,
        provider: Optional[str] = None
    ) -> Optional[LLMConfig]:
        """
        Get the default LLM configuration for a specific type.

        Args:
            db: Database session
            config_type: Configuration type (agent_scan, verification, both)
            provider: Optional provider filter

        Returns:
            LLMConfig object or None
        """
        # First try to get the exact config type
        query = select(LLMConfig).where(
            (LLMConfig.config_type == config_type) &
            (LLMConfig.is_default == True)
        )

        if provider:
            query = query.where(LLMConfig.provider == provider)

        result = await db.execute(query)
        config = result.scalar_one_or_none()

        # If no exact match, try to get a "both" type config
        if not config and config_type != "both":
            query = select(LLMConfig).where(
                (LLMConfig.config_type == "both") &
                (LLMConfig.is_default == True)
            )
            if provider:
                query = query.where(LLMConfig.provider == provider)
            result = await db.execute(query)
            config = result.scalar_one_or_none()

        # If still no match, get any config of the right type
        if not config:
            query = select(LLMConfig).where(LLMConfig.config_type == config_type)
            if provider:
                query = query.where(LLMConfig.provider == provider)
            query = query.order_by(LLMConfig.is_default.desc())
            result = await db.execute(query)
            config = result.scalar_one_or_none()

        return config

    @staticmethod
    async def get_agent_scan_config(
        db: AsyncSession,
        provider: Optional[str] = None
    ) -> Optional[LLMConfig]:
        """Get LLM configuration for agent scanning."""
        return await LLMConfigService.get_config_by_type(
            db, LLMConfigType.AGENT_SCAN, provider
        )

    @staticmethod
    async def get_verification_config(
        db: AsyncSession,
        provider: Optional[str] = None
    ) -> Optional[LLMConfig]:
        """Get LLM configuration for adversarial verification."""
        return await LLMConfigService.get_config_by_type(
            db, LLMConfigType.VERIFICATION, provider
        )

    @staticmethod
    def create_llm_client(config: LLMConfig):
        """
        Create an LLM client from a database configuration.

        Args:
            config: LLMConfig object

        Returns:
            LLMClient instance
        """
        from src.layers.l3_analysis.llm.openai_client import OpenAIClient
        from src.layers.l3_analysis.llm.ollama_client import OllamaClient

        if config.provider in ("openai", "custom"):
            return OpenAIClient(
                model=config.model,
                api_key=config.api_key,
                base_url=config.base_url,
                max_tokens=config.max_tokens,
                temperature=config.temperature,
                timeout=config.timeout,
                max_retries=getattr(config, 'max_retries', 3),
            )
        elif config.provider == "ollama":
            return OllamaClient(
                model=config.model,
                base_url=config.base_url or "http://localhost:11434",
                max_tokens=config.max_tokens,
                temperature=config.temperature,
                timeout=config.timeout,
            )
        else:
            raise ValueError(f"Unsupported provider: {config.provider}")
