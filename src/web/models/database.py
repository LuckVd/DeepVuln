"""Database models and session management."""

from datetime import datetime
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import MetaData


# Convention for naming constraints automatically
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
}

metadata = MetaData(naming_convention=convention)


class Base(DeclarativeBase):
    """Base class for all database models."""
    metadata = metadata


# Global variables - initialized by init_db()
engine: Optional[async_sessionmaker] = None
AsyncSessionLocal: Optional[async_sessionmaker] = None


def get_engine():
    """Get the database engine (lazy initialization)."""
    global engine, AsyncSessionLocal
    if engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return engine


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get database session for dependency injection."""
    if AsyncSessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db(database_url: str = "postgresql+asyncpg://user:pass@localhost/deepvuln") -> None:
    """Initialize database - create engine and tables if they don't exist."""
    global engine, AsyncSessionLocal

    engine = create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )

    AsyncSessionLocal = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Close database connections."""
    global engine
    if engine is not None:
        await engine.dispose()
        engine = None
        AsyncSessionLocal = None
