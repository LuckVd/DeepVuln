"""Configuration loader for YAML files."""

from pathlib import Path
from typing import Any

import yaml

from src.core.exceptions.errors import ConfigurationError


class ConfigLoader:
    """Load and merge configuration from YAML files."""

    def __init__(self, config_path: Path | None = None) -> None:
        """Initialize the config loader.

        Args:
            config_path: Path to configuration file.
        """
        self.config_path = config_path
        self._config: dict[str, Any] = {}

    def load(self, path: Path | None = None) -> dict[str, Any]:
        """Load configuration from a YAML file.

        Args:
            path: Path to YAML file. Uses config_path if not provided.

        Returns:
            Loaded configuration dictionary.

        Raises:
            ConfigurationError: If file cannot be loaded.
        """
        load_path = path or self.config_path
        if not load_path:
            return {}

        try:
            with open(load_path, encoding="utf-8") as f:
                self._config = yaml.safe_load(f) or {}
            return self._config
        except FileNotFoundError as e:
            raise ConfigurationError(
                f"Configuration file not found: {load_path}",
                config_key=str(load_path),
                details={"path": str(load_path)},
            ) from e
        except yaml.YAMLError as e:
            raise ConfigurationError(
                f"Invalid YAML in configuration file: {load_path}",
                config_key=str(load_path),
                details={"error": str(e)},
            ) from e

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key.

        Supports dot notation for nested keys (e.g., 'workspace.base_dir').

        Args:
            key: Configuration key (supports dot notation).
            default: Default value if key not found.

        Returns:
            Configuration value or default.
        """
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def get_section(self, section: str) -> dict[str, Any]:
        """Get an entire configuration section.

        Args:
            section: Section name.

        Returns:
            Configuration section dictionary.
        """
        result = self._config.get(section, {})
        return result if isinstance(result, dict) else {}

    @property
    def config(self) -> dict[str, Any]:
        """Return the loaded configuration."""
        return self._config

    @staticmethod
    def load_default() -> dict[str, Any]:
        """Load the default configuration file.

        Returns:
            Default configuration dictionary.
        """
        default_path = Path(__file__).parent.parent.parent.parent / "config" / "default.yaml"
        loader = ConfigLoader(default_path)
        try:
            return loader.load()
        except ConfigurationError:
            return {}
