"""Configuration management for DeepVuln."""

from pathlib import Path
from typing import Any

# Lazy logger to avoid circular import
_logger = None

def _get_logger():
    global _logger
    if _logger is None:
        from src.core.logger.logger import get_logger
        _logger = get_logger(__name__)
    return _logger

# Default config paths
DEFAULT_CONFIG_PATHS = [
    Path("config.local.toml"),
    Path("config.toml"),
    Path.home() / ".deepvuln" / "config.toml",
]

# Config cache to avoid repeated loading
_config_cache: dict[str, Any] | None = None
_github_token_cache: str | None = None
_nvd_api_key_cache: str | None = None


def load_config(config_path: Path | str | None = None, force_reload: bool = False) -> dict[str, Any]:
    """Load configuration from TOML file.

    Args:
        config_path: Path to config file. If None, searches default paths.
        force_reload: Force reload config even if cached.

    Returns:
        Configuration dictionary.
    """
    global _config_cache

    # Return cached config if available and not forcing reload
    if _config_cache is not None and not force_reload:
        return _config_cache

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
        _get_logger().debug("No config file found, using defaults")
        _config_cache = get_default_config()
        return _config_cache

    try:
        with open(path, "rb") as f:
            config = tomllib.load(f)
        _get_logger().info(f"Loaded config from {path}")
        _config_cache = config
        return config
    except Exception as e:
        _get_logger().warning(f"Failed to load config from {path}: {e}")
        _config_cache = get_default_config()
        return _config_cache


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
        "llm": {
            "provider": "openai",
            "model": "gpt-4",
            "timeout": 120,
            "max_retries": 3,
            "max_tokens": 4096,
            "temperature": 0.1,
            "openai": {
                "api_key": None,
                "base_url": "https://api.openai.com/v1",
                "organization": None,
            },
            "azure": {
                "api_key": None,
                "endpoint": None,
                "deployment": None,
                "api_version": "2024-02-15-preview",
            },
            "ollama": {
                "base_url": "http://localhost:11434",
                "model": "llama2",
            },
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
    global _github_token_cache

    # Return cached token if available
    if _github_token_cache is not None:
        return _github_token_cache if _github_token_cache else None

    import os

    # Check environment first
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        _github_token_cache = token
        return token

    # Check config file
    config = load_config()
    token = config.get("threat_intel", {}).get("github_token")
    _github_token_cache = token or ""
    return token


def get_nvd_api_key() -> str | None:
    """Get NVD API key from config or environment.

    Priority:
    1. NVD_API_KEY environment variable
    2. Config file

    Returns:
        NVD API key or None.
    """
    global _nvd_api_key_cache

    # Return cached key if available
    if _nvd_api_key_cache is not None:
        return _nvd_api_key_cache if _nvd_api_key_cache else None

    import os

    # Check environment first
    key = os.environ.get("NVD_API_KEY")
    if key:
        _nvd_api_key_cache = key
        return key

    # Check config file
    config = load_config()
    key = config.get("threat_intel", {}).get("nvd_api_key")
    _nvd_api_key_cache = key or ""
    return key


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


# =============================================================================
# LLM Configuration
# =============================================================================

# LLM config cache
_llm_config_cache: dict[str, Any] | None = None


def get_llm_config(force_reload: bool = False) -> dict[str, Any]:
    """Get LLM configuration with environment variable overrides.

    Priority:
    1. Environment variables (highest)
    2. Config file
    3. Default values (lowest)

    Args:
        force_reload: Force reload config even if cached.

    Returns:
        LLM configuration dictionary.
    """
    global _llm_config_cache

    if _llm_config_cache is not None and not force_reload:
        return _llm_config_cache

    import os

    config = load_config(force_reload=force_reload)
    llm_config = config.get("llm", {})

    # Build merged config with environment variable overrides
    result = {
        "provider": llm_config.get("provider", "openai"),
        "model": llm_config.get("model"),  # No default - must be configured
        "timeout": llm_config.get("timeout", 120),
        "max_retries": llm_config.get("max_retries", 3),
        "max_tokens": llm_config.get("max_tokens", 4096),
        "temperature": llm_config.get("temperature", 0.1),
    }

    # OpenAI config with env overrides
    openai_config = llm_config.get("openai", {})
    result["openai"] = {
        "api_key": os.getenv("OPENAI_API_KEY") or openai_config.get("api_key"),
        "base_url": os.getenv("OPENAI_BASE_URL") or openai_config.get("base_url", "https://api.openai.com/v1"),
        "organization": os.getenv("OPENAI_ORG_ID") or openai_config.get("organization"),
    }

    # Azure config with env overrides
    azure_config = llm_config.get("azure", {})
    result["azure"] = {
        "api_key": os.getenv("AZURE_OPENAI_API_KEY") or azure_config.get("api_key"),
        "endpoint": os.getenv("AZURE_OPENAI_ENDPOINT") or azure_config.get("endpoint"),
        "deployment": azure_config.get("deployment"),
        "api_version": azure_config.get("api_version", "2024-02-15-preview"),
    }

    # Ollama config with env overrides
    ollama_config = llm_config.get("ollama", {})
    result["ollama"] = {
        "base_url": os.getenv("OLLAMA_BASE_URL") or ollama_config.get("base_url", "http://localhost:11434"),
        "model": ollama_config.get("model", "llama2"),
    }

    _llm_config_cache = result
    return result


def get_llm_provider() -> str:
    """Get the default LLM provider.

    Returns:
        Provider name: "openai", "azure", "ollama", or "custom".
    """
    config = get_llm_config()
    return config.get("provider", "openai")


def get_llm_model() -> str:
    """Get the default LLM model.

    Returns:
        Model name.
    """
    config = get_llm_config()
    return config.get("model", "gpt-4")


def get_openai_config() -> dict[str, Any]:
    """Get OpenAI-specific configuration.

    Returns:
        OpenAI config with api_key, base_url, organization.
    """
    config = get_llm_config()
    return config.get("openai", {})


def get_azure_config() -> dict[str, Any]:
    """Get Azure OpenAI-specific configuration.

    Returns:
        Azure config with api_key, endpoint, deployment, api_version.
    """
    config = get_llm_config()
    return config.get("azure", {})


def get_ollama_config() -> dict[str, Any]:
    """Get Ollama-specific configuration.

    Returns:
        Ollama config with base_url, model.
    """
    config = get_llm_config()
    return config.get("ollama", {})
