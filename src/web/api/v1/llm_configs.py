"""LLM configuration management API endpoints."""

import asyncio
from typing import Annotated
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.web.api.deps import get_db
from src.web.core.security import require_api_key
from src.web.models.llm_config import LLMConfig
from src.web.models.llm_schemas import (
    LLMConfigCreate,
    LLMConfigUpdate,
    LLMConfigResponse,
    LLMConfigListResponse,
    LLMConfigListItem,
    LLMConfigValidate,
    LLMValidationResponse,
    LLMModelsResponse,
)
from src.web.repositories.llm_config import LLMConfigRepository

router = APIRouter()


# ============================================================================
# CRUD Endpoints
# ============================================================================


@router.get("/llm-configs", response_model=LLMConfigListResponse)
async def list_llm_configs(
    provider: str = None,
    config_type: str = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """List all LLM configurations."""
    repo = LLMConfigRepository()

    # Build query
    query = select(LLMConfig)

    if provider:
        query = query.where(LLMConfig.provider == provider)

    if config_type:
        query = query.where(LLMConfig.config_type == config_type)

    # Get total count
    count_result = await db.execute(select(LLMConfig.id).select_from(query.subquery()))
    total = len(count_result.all())

    # Apply pagination
    query = query.order_by(LLMConfig.is_default.desc(), LLMConfig.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    configs = result.scalars().all()

    # Convert to response format (mask API keys)
    items = [
        LLMConfigListItem(
            id=c.id,
            name=c.name,
            provider=c.provider,
            model=c.model,
            max_concurrent_requests=c.max_concurrent_requests,
            is_default=c.is_default,
            config_type=c.config_type,
            has_api_key=bool(c.api_key),
            created_at=c.created_at,
        )
        for c in configs
    ]

    return LLMConfigListResponse(items=items, total=total)


@router.post("/llm-configs", response_model=LLMConfigResponse, status_code=status.HTTP_201_CREATED)
async def create_llm_config(
    config: LLMConfigCreate,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """Create a new LLM configuration."""
    repo = LLMConfigRepository()

    # Check if name already exists
    existing = await db.execute(
        select(LLMConfig).where(LLMConfig.name == config.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Configuration with name '{config.name}' already exists"
        )

    # If setting as default, unset other defaults of same type
    if config.is_default:
        from sqlalchemy import update
        await db.execute(
            update(LLMConfig)
            .where(LLMConfig.config_type == config.config_type)
            .values(is_default=False)
        )

    # Create config
    config_dict = config.model_dump(exclude_unset=True)
    db_config = LLMConfig(**config_dict)
    created = await repo.create(db, obj_in=db_config)
    await db.commit()
    await db.refresh(created)

    return LLMConfigResponse.model_validate(created)


@router.get("/llm-configs/{config_id}", response_model=LLMConfigResponse)
async def get_llm_config(
    config_id: int,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """Get a specific LLM configuration."""
    repo = LLMConfigRepository()
    config = await repo.get(db, id=config_id)

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration {config_id} not found"
        )

    # Mask API key in response
    response = LLMConfigResponse.model_validate(config)
    if config.api_key:
        response.api_key = "***" + config.api_key[-4:] if len(config.api_key) > 4 else "***"

    return response


@router.put("/llm-configs/{config_id}", response_model=LLMConfigResponse)
async def update_llm_config(
    config_id: int,
    config_update: LLMConfigUpdate,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """Update an LLM configuration."""
    repo = LLMConfigRepository()
    config = await repo.get(db, id=config_id)

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration {config_id} not found"
        )

    # If setting as default, unset other defaults
    if config_update.is_default and not config.is_default:
        from sqlalchemy import update
        await db.execute(
            update(LLMConfig)
            .where(
                (LLMConfig.config_type == config.config_type) &
                (LLMConfig.id != config_id)
            )
            .values(is_default=False)
        )

    # Update config
    update_dict = config_update.model_dump(exclude_unset=True)

    # Skip API key update if it's masked (starts with ***)
    if "api_key" in update_dict and update_dict["api_key"].startswith("***"):
        del update_dict["api_key"]

    update_dict["updated_at"] = datetime.utcnow()

    updated = await repo.update(db, db_obj=config, obj_in=update_dict)
    await db.commit()
    await db.refresh(updated)

    return LLMConfigResponse.model_validate(updated)


@router.delete("/llm-configs/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_llm_config(
    config_id: int,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """Delete an LLM configuration."""
    repo = LLMConfigRepository()
    config = await repo.get(db, id=config_id)

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration {config_id} not found"
        )

    await db.delete(config)
    await db.commit()


# ============================================================================
# Validation Endpoints
# ============================================================================


@router.post("/llm-configs/{config_id}/validate", response_model=LLMValidationResponse)
async def validate_llm_config(
    config_id: int,
    request: LLMConfigValidate = LLMConfigValidate(),
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """Validate an LLM configuration by testing the connection."""
    repo = LLMConfigRepository()
    config = await repo.get(db, id=config_id)

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration {config_id} not found"
        )

    # Import validation service
    from src.web.services.llm_validation import LLMValidationService

    validation_service = LLMValidationService()

    try:
        result = await asyncio.to_thread(
            validation_service.validate_config,
            config,
            request.test_prompt
        )

        return LLMValidationResponse(
            success=result["success"],
            message=result["message"],
            model_info=result.get("model_info"),
            latency_ms=result.get("latency_ms"),
        )
    except Exception as e:
        return LLMValidationResponse(
            success=False,
            message=f"Validation failed: {str(e)}"
        )


@router.get("/llm-configs/{config_id}/models", response_model=LLMModelsResponse)
async def list_available_models(
    config_id: int,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """Get available models for an LLM configuration."""
    repo = LLMConfigRepository()
    config = await repo.get(db, id=config_id)

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration {config_id} not found"
        )

    # Import model detection service
    from src.web.services.llm_validation import LLMValidationService

    validation_service = LLMValidationService()

    try:
        models = await asyncio.to_thread(
            validation_service.get_available_models,
            config
        )

        return LLMModelsResponse(
            models=models,
            provider=config.provider
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch models: {str(e)}"
        )


@router.post("/llm-configs/{config_id}/detect-context", response_model=dict)
async def detect_context_size(
    config_id: int,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
):
    """Auto-detect context size for the configured model."""
    repo = LLMConfigRepository()
    config = await repo.get(db, id=config_id)

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration {config_id} not found"
        )

    # Import validation service
    from src.web.services.llm_validation import LLMValidationService

    validation_service = LLMValidationService()

    try:
        context_size = validation_service.detect_context_size(config.model, config.provider)

        # Update config with detected context size
        from sqlalchemy import update
        await db.execute(
            update(LLMConfig)
            .where(LLMConfig.id == config_id)
            .values(context_size=context_size, updated_at=datetime.utcnow())
        )
        await db.commit()

        return {
            "model": config.model,
            "provider": config.provider,
            "detected_context_size": context_size
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to detect context size: {str(e)}"
        )
