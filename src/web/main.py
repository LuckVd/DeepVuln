"""FastAPI application initialization and configuration."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.web.core.config import get_database_settings, get_web_settings
from src.web.models.database import init_db, close_db

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manage application startup and shutdown events.

    Startup:
        - Initialize database connection
        - Create tables if they don't exist
        - Start Redis pub/sub subscriber for WebSocket relay

    Shutdown:
        - Stop Redis subscriber
        - Close database connections
    """
    # Startup
    db_settings = get_database_settings()
    web_settings = get_web_settings()

    logger.info(f"Starting DeepVuln Web Service on {web_settings.host}:{web_settings.port}")
    logger.info(f"Database: {db_settings.url}")

    try:
        # Initialize database
        await init_db(db_settings.url)
        logger.info("Database initialized")

        # Start Redis pub/sub subscriber for cross-process WS relay
        from src.web.api.websocket import get_connection_manager
        manager = get_connection_manager()
        await manager.start_redis_subscriber()
        logger.info("Redis subscriber started")

        yield

    finally:
        # Stop Redis subscriber
        from src.web.api.websocket import get_connection_manager
        manager = get_connection_manager()
        await manager.stop_redis_subscriber()
        logger.info("Redis subscriber stopped")

        # Shutdown
        await close_db()
        logger.info("DeepVuln Web Service stopped")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns:
        FastAPI application instance
    """
    web_settings = get_web_settings()

    app = FastAPI(
        title="DeepVuln API",
        description="Intelligent vulnerability analysis platform API",
        version="0.9.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=web_settings.cors_origins,
        allow_credentials=web_settings.cors_allow_credentials,
        allow_methods=web_settings.cors_allow_methods,
        allow_headers=web_settings.cors_allow_headers,
    )

    # Include routers
    _include_routers(app)

    # Root endpoint
    @app.get("/")
    async def root() -> dict:
        """Root endpoint with API information."""
        return {
            "name": "DeepVuln API",
            "version": "0.9.0",
            "status": "running",
            "docs": "/docs",
            "health": "/health"
        }

    # Health check endpoint
    @app.get("/health")
    async def health() -> dict:
        """Health check endpoint."""
        return {"status": "healthy"}

    return app


def _include_routers(app: FastAPI) -> None:
    """
    Include all API routers.

    Args:
        app: FastAPI application instance
    """
    from src.web.api.v1 import api as v1_api

    app.include_router(
        v1_api.router,
        prefix=get_web_settings().api_prefix,
    )


# Create application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    web_settings = get_web_settings()

    uvicorn.run(
        "src.web.main:app",
        host=web_settings.host,
        port=web_settings.port,
        reload=web_settings.reload,
        workers=web_settings.workers if not web_settings.reload else 1,
    )
