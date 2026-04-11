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
    Path("/app/config.local.toml"),  # Docker container path
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
            "max_concurrent_files": 10,
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
    """Get GitHub token from environment variable.

    P18: Config file reading removed. Use environment variable or database.

    Priority:
    1. GITHUB_TOKEN environment variable
    2. Database (via SystemSettingService for Web)

    For CLI: Set GITHUB_TOKEN environment variable.
    For Web: Configure via Settings page.

    Returns:
        GitHub token or None.
    """
    global _github_token_cache

    # Return cached token if available
    if _github_token_cache is not None:
        return _github_token_cache if _github_token_cache else None

    import os

    # Check environment variable
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        _github_token_cache = token
        return token

    # No database access in this function (for CLI compatibility)
    # Web services should use SystemSettingService instead
    _github_token_cache = ""
    return None


def get_nvd_api_key() -> str | None:
    """Get NVD API key from environment variable.

    P18: Config file reading removed. Use environment variable or database.

    Priority:
    1. NVD_API_KEY environment variable
    2. Database (via SystemSettingService for Web)

    For CLI: Set NVD_API_KEY environment variable.
    For Web: Configure via Settings page.

    Returns:
        NVD API key or None.
    """
    global _nvd_api_key_cache

    # Return cached key if available
    if _nvd_api_key_cache is not None:
        return _nvd_api_key_cache if _nvd_api_key_cache else None

    import os

    # Check environment variable
    key = os.environ.get("NVD_API_KEY")
    if key:
        _nvd_api_key_cache = key
        return key

    # No database access in this function (for CLI compatibility)
    # Web services should use SystemSettingService instead
    _nvd_api_key_cache = ""
    return None


def get_database_path() -> str:
    """Get database path from config or environment.

    Internal config (not user-facing), still uses config file.

    Returns:
        Database path string.
    """
    import os
    return os.getenv("THREAT_INTEL_DB_PATH", "./data/threat_intel.db")


def get_scan_timeout() -> int:
    """Get scan timeout from environment variable.

    P18: Moved to environment variable. For Web, use SystemSettingService.

    Returns:
        Timeout in seconds.
    """
    import os
    return int(os.getenv("SCAN_TIMEOUT", "300"))


def get_max_concurrent_files() -> int:
    """Get max concurrent files from environment variable.

    P18: Moved to environment variable. For Web, use SystemSettingService.

    Returns:
        Maximum concurrent files.
    """
    import os
    return int(os.getenv("SCAN_MAX_CONCURRENT_FILES", "10"))


def get_auto_sync_days() -> int:
    """Get auto sync interval from config.

    Internal config (not user-facing), still uses config file.

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
    """Get LLM configuration from environment variables only.

    .. deprecated::
        P18: This function is deprecated. Use database LLM configs instead.
        See: src.web.services.llm_config_service.LLMConfigService

        For CLI usage, set these environment variables:
        - OPENAI_API_KEY or LLM_API_KEY
        - OPENAI_BASE_URL or LLM_BASE_URL
        - LLM_MODEL
        - LLM_TIMEOUT
        - LLM_MAX_RETRIES
        - LLM_MAX_CONCURRENT_REQUESTS

    Args:
        force_reload: Force reload config even if cached.

    Returns:
        LLM configuration dictionary.
    """
    global _llm_config_cache

    if _llm_config_cache is not None and not force_reload:
        return _llm_config_cache

    import os

    # Build config from environment variables only (P18: config file removed)
    result = {
        "provider": os.getenv("LLM_PROVIDER", "openai"),
        "model": os.getenv("LLM_MODEL"),
        "timeout": int(os.getenv("LLM_TIMEOUT", "120")),
        "max_retries": int(os.getenv("LLM_MAX_RETRIES", "3")),
        "max_tokens": int(os.getenv("LLM_MAX_TOKENS", "4096")),
        "temperature": float(os.getenv("LLM_TEMPERATURE", "0.1")),
        "max_concurrent_requests": int(os.getenv("LLM_MAX_CONCURRENT_REQUESTS", "5")),
    }

    # OpenAI config from environment variables
    result["openai"] = {
        "api_key": os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY"),
        "base_url": os.getenv("OPENAI_BASE_URL") or os.getenv("LLM_BASE_URL", "https://api.openai.com/v1"),
        "organization": os.getenv("OPENAI_ORG_ID"),
    }

    # Azure config from environment variables
    result["azure"] = {
        "api_key": os.getenv("AZURE_OPENAI_API_KEY"),
        "endpoint": os.getenv("AZURE_OPENAI_ENDPOINT"),
        "deployment": os.getenv("AZURE_OPENAI_DEPLOYMENT"),
        "api_version": os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview"),
    }

    # Ollama config from environment variables
    result["ollama"] = {
        "base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        "model": os.getenv("OLLAMA_MODEL", "llama2"),
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


def get_llm_batch_size() -> int:
    """Get LLM batch size from environment variable.

    Used for batch analysis in entry point detection.
    Note: This is deprecated in favor of batch_max_chars.

    P18: Reads from LLM_BATCH_SIZE environment variable.

    Returns:
        Number of files per batch (default: 20).
    """
    import os
    return int(os.getenv("LLM_BATCH_SIZE", "20"))


def get_llm_batch_max_chars() -> int:
    """Get LLM batch max characters from environment variable.

    Used for character-based batching in entry point detection.
    This ensures each batch doesn't exceed the character limit,
    preventing LLM response truncation.

    P18: Reads from LLM_BATCH_MAX_CHARS environment variable.

    Returns:
        Maximum characters per batch (default: 12000).
    """
    import os
    return int(os.getenv("LLM_BATCH_MAX_CHARS", "12000"))


# =============================================================================
# P6-07: Directory Classification Configuration
# =============================================================================

_directory_config_cache: dict[str, Any] | None = None


def get_directory_classification_config(force_reload: bool = False) -> dict[str, Any]:
    """
    P6-07: Get directory classification configuration.

    Returns:
        Directory classification config with:
        - enabled: bool (default True)
        - custom_dirs: dict[str, list[str]] - custom directory rules
        - multipliers: dict[str, float] - custom score multipliers
    """
    global _directory_config_cache

    if _directory_config_cache is not None and not force_reload:
        return _directory_config_cache

    config = load_config(force_reload=force_reload)
    dir_config = config.get("directory_classification", {})

    result = {
        "enabled": dir_config.get("enabled", True),
        "custom_dirs": dir_config.get("custom_dirs", {}),
        "multipliers": dir_config.get("multipliers", {}),
    }

    _directory_config_cache = result
    return result


def is_directory_classification_enabled() -> bool:
    """
    P6-07: Check if directory classification is enabled.

    Returns:
        True if directory classification is enabled (default True).
    """
    config = get_directory_classification_config()
    return config.get("enabled", True)


def get_custom_directory_rules() -> dict[str, list[str]]:
    """
    P6-07: Get custom directory classification rules.

    Returns:
        Dict mapping directory class names to list of directory patterns.
        Example: {"challenge_code": ["my-vuln-app"], "test_code": ["__tests__"]}
    """
    config = get_directory_classification_config()
    return config.get("custom_dirs", {})


def get_custom_score_multipliers() -> dict[str, float]:
    """
    P6-07: Get custom score multipliers for directory classes.

    Returns:
        Dict mapping directory class names to multiplier values.
        Example: {"test_code": 0.5, "challenge_code": 0.0}
    """
    config = get_directory_classification_config()
    return config.get("multipliers", {})
