"""FastAPI dependency injection providers."""

from typing import AsyncGenerator

from fastapi import Depends

from src.web.models.database import AsyncSessionLocal


async def get_db() -> AsyncGenerator:
    """
    Get database session.

    Yields:
        AsyncSession: Database session

    Example:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(Item))
            return result.scalars().all()
    """
    async with AsyncSessionLocal() as session:
        yield session
