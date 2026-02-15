"""Application settings using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.core.config.loader import ConfigLoader


class WorkspaceSettings(BaseSettings):
    """Workspace configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="DEEPVULN_WORKSPACE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    base_dir: Path | None = Field(
        default=None,
        description="Base directory for workspaces",
    )
    max_workspaces: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum concurrent workspaces",
    )
    auto_cleanup: bool = Field(
        default=True,
        description="Auto cleanup workspaces on exit",
    )
    prefix: str = Field(
        default="deepvuln_",
        description="Workspace directory name prefix",
    )

    @field_validator("base_dir", mode="before")
    @classmethod
    def validate_base_dir(cls, v: str | None) -> Path | None:
        """Validate and convert base_dir to Path."""
        if v is None or v == "":
            return None
        return Path(v)


class GitSettings(BaseSettings):
    """Git operation configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="DEEPVULN_GIT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    clone_timeout: int = Field(
        default=300,
        ge=10,
        le=3600,
        description="Clone timeout in seconds",
    )
    default_depth: int = Field(
        default=0,
        ge=0,
        description="Default clone depth (0 = full)",
    )
    retry_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Retry attempts for network operations",
    )
    retry_delay: int = Field(
        default=5,
        ge=1,
        le=60,
        description="Retry delay in seconds",
    )
    verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates",
    )


class LoggingSettings(BaseSettings):
    """Logging configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="DEEPVULN_LOGGING_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    level: str = Field(
        default="INFO",
        description="Log level",
    )
    format: str = Field(
        default="[%(name)s] %(message)s",
        description="Log format string",
    )
    file: Path | None = Field(
        default=None,
        description="Log file path",
    )
    use_rich: bool = Field(
        default=True,
        description="Use Rich console for output",
    )

    @field_validator("level", mode="before")
    @classmethod
    def validate_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v_upper

    @field_validator("file", mode="before")
    @classmethod
    def validate_file(cls, v: str | None) -> Path | None:
        """Validate and convert file to Path."""
        if v is None or v == "":
            return None
        return Path(v)


class FetcherSettings(BaseSettings):
    """Fetcher configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="DEEPVULN_FETCHER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    default_branch: str = Field(
        default="main",
        description="Default branch when not specified",
    )


class Settings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_prefix="DEEPVULN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    workspace: WorkspaceSettings = Field(default_factory=WorkspaceSettings)
    git: GitSettings = Field(default_factory=GitSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    fetcher: FetcherSettings = Field(default_factory=FetcherSettings)

    @classmethod
    def from_yaml(cls, path: Path) -> "Settings":
        """Load settings from YAML file.

        Args:
            path: Path to YAML configuration file.

        Returns:
            Settings instance with values from YAML.
        """
        loader = ConfigLoader(path)
        config = loader.load()

        # Extract nested configurations
        workspace_config = config.get("workspace", {})
        git_config = config.get("git", {})
        logging_config = config.get("logging", {})
        fetcher_config = config.get("fetcher", {})

        return cls(
            workspace=WorkspaceSettings(**workspace_config),
            git=GitSettings(**git_config),
            logging=LoggingSettings(**logging_config),
            fetcher=FetcherSettings(**fetcher_config),
        )

    @classmethod
    def load(cls) -> "Settings":
        """Load settings from default locations.

        Priority: Environment variables > .env > config/default.yaml > defaults

        Returns:
            Settings instance.
        """
        # Try to load from default YAML first
        default_path = Path(__file__).parent.parent.parent.parent / "config" / "default.yaml"
        if default_path.exists():
            return cls.from_yaml(default_path)

        # Environment variables and .env are automatically loaded by pydantic-settings
        return cls()


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance.

    Returns:
        Settings singleton.
    """
    return Settings.load()
