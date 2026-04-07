"""Web service core configuration."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database configuration settings."""
    model_config = SettingsConfigDict(
        env_prefix="DEEPVULN_DB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    url: str = Field(
        default="postgresql+asyncpg://deepvuln:deepvuln@localhost:5432/deepvuln",
        description="Database connection URL"
    )
    echo: bool = Field(
        default=False,
        description="Echo SQL queries for debugging"
    )
    pool_size: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Database connection pool size"
    )
    max_overflow: int = Field(
        default=20,
        ge=0,
        le=100,
        description="Maximum overflow connections"
    )


class WebSettings(BaseSettings):
    """Web service configuration settings."""
    model_config = SettingsConfigDict(
        env_prefix="DEEPVULN_WEB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = Field(
        default="0.0.0.0",
        description="Host to bind to"
    )
    port: int = Field(
        default=8000,
        ge=1024,
        le=65535,
        description="Port to bind to"
    )
    workers: int = Field(
        default=1,
        ge=1,
        le=10,
        description="Number of worker processes"
    )
    reload: bool = Field(
        default=False,
        description="Enable auto-reload for development"
    )

    # CORS
    cors_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        description="Allowed CORS origins"
    )
    cors_allow_credentials: bool = Field(
        default=True,
        description="Allow credentials in CORS"
    )
    cors_allow_methods: list[str] = Field(
        default=["*"],
        description="Allowed CORS methods"
    )
    cors_allow_headers: list[str] = Field(
        default=["*"],
        description="Allowed CORS headers"
    )

    # API
    api_prefix: str = Field(
        default="/api/v1",
        description="API route prefix"
    )
    websocket_path: str = Field(
        default="/api/v1/ws",
        description="WebSocket route path"
    )

    # Pagination
    default_page_size: int = Field(
        default=20,
        ge=1,
        le=1000,
        description="Default page size for pagination"
    )
    max_page_size: int = Field(
        default=1000,
        ge=1,
        le=10000,
        description="Maximum page size for pagination"
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS origins from string or list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v


class SecuritySettings(BaseSettings):
    """Security configuration settings."""
    model_config = SettingsConfigDict(
        env_prefix="DEEPVULN_SECURITY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # API Key
    api_key_enabled: bool = Field(
        default=True,
        description="Enable API key authentication"
    )
    api_key_header: str = Field(
        default="X-API-Key",
        description="Header name for API key"
    )
    api_keys_env: str = Field(
        default="DEEPVULN_API_KEYS",
        description="Environment variable containing comma-separated API keys"
    )

    # Rate limiting
    rate_limit_enabled: bool = Field(
        default=False,
        description="Enable rate limiting"
    )
    rate_limit_requests: int = Field(
        default=100,
        ge=1,
        description="Max requests per rate limit window"
    )
    rate_limit_window: int = Field(
        default=60,
        ge=1,
        description="Rate limit window in seconds"
    )

    def get_api_keys(self) -> set[str]:
        """Get API keys from environment variable."""
        if not self.api_key_enabled:
            return set()
        import os
        keys_str = os.getenv(self.api_keys_env, "")
        return {key.strip() for key in keys_str.split(",") if key.strip()}


@lru_cache
def get_web_settings() -> WebSettings:
    """Get cached web settings instance."""
    return WebSettings()


@lru_cache
def get_database_settings() -> DatabaseSettings:
    """Get cached database settings instance."""
    return DatabaseSettings()


@lru_cache
def get_security_settings() -> SecuritySettings:
    """Get cached security settings instance."""
    return SecuritySettings()
