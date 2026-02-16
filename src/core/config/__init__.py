"""Configuration management for DeepVuln."""

from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

logger = get_logger(__name__)

# Default config paths
DEFAULT_CONFIG_PATHS = [
    Path("config.local.toml"),
    Path("config.toml"),
    Path.home() / ".deepvuln" / "config.toml",
]


def load_config(config_path: Path | str | None = None) -> dict[str, Any]:
    """Load configuration from TOML file.

    Args:
        config_path: Path to config file. If None, searches default paths.

    Returns:
        Configuration dictionary.
    """
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    # Determine config path
    if config_path:
        path = Path(config_path)
    else:
        path = None
        for default_path in DEFAULT_CONFIG_PATHS:
            if default_path.exists():
                path = default_path
                break

    if not path or not path.exists():
        logger.debug("No config file found, using defaults")
        return get_default_config()

    try:
        with open(path, "rb") as f:
            config = tomllib.load(f)
        logger.info(f"Loaded config from {path}")
        return config
    except Exception as e:
        logger.warning(f"Failed to load config from {path}: {e}")
        return get_default_config()


def get_default_config() -> dict[str, Any]:
    """Get default configuration.

    Returns:
        Default configuration dictionary.
    """
    return {
        "threat_intel": {
            "github_token": None,
            "nvd_api_key": None,
        },
        "scan": {
            "timeout": 300,
            "max_concurrent": 10,
        },
        "database": {
            "path": "./data/threat_intel.db",
            "auto_sync_days": 7,
        },
        "logging": {
            "level": "INFO",
            "file": "./logs/deepvuln.log",
        },
    }


def get_github_token() -> str | None:
    """Get GitHub token from config or environment.

    Priority:
    1. GITHUB_TOKEN environment variable
    2. Config file

    Returns:
        GitHub token or None.
    """
    import os

    # Check environment first
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token

    # Check config file
    config = load_config()
    return config.get("threat_intel", {}).get("github_token")


def get_nvd_api_key() -> str | None:
    """Get NVD API key from config or environment.

    Priority:
    1. NVD_API_KEY environment variable
    2. Config file

    Returns:
        NVD API key or None.
    """
    import os

    # Check environment first
    key = os.environ.get("NVD_API_KEY")
    if key:
        return key

    # Check config file
    config = load_config()
    return config.get("threat_intel", {}).get("nvd_api_key")


def get_database_path() -> str:
    """Get database path from config.

    Returns:
        Database path string.
    """
    config = load_config()
    return config.get("database", {}).get("path", "./data/threat_intel.db")


def get_scan_timeout() -> int:
    """Get scan timeout from config.

    Returns:
        Timeout in seconds.
    """
    config = load_config()
    return config.get("scan", {}).get("timeout", 300)


def get_auto_sync_days() -> int:
    """Get auto sync interval from config.

    Returns:
        Days between syncs.
    """
    config = load_config()
    return config.get("database", {}).get("auto_sync_days", 7)
