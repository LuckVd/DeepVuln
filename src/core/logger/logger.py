"""Logging system with Rich support."""

import logging
import sys

from rich.console import Console
from rich.logging import RichHandler

from src.core.config.settings import LoggingSettings, get_settings

# Global console instance
_console: Console | None = None
_loggers: dict[str, logging.Logger] = {}


def setup_logging(settings: LoggingSettings | None = None) -> None:
    """Setup logging configuration.

    Args:
        settings: Logging settings. Uses global settings if not provided.
    """
    global _console

    if settings is None:
        settings = get_settings().logging

    # Create console if using Rich
    if settings.use_rich:
        _console = Console(stderr=True)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, settings.level))

    # Remove existing handlers
    root_logger.handlers.clear()

    # Add Rich handler or standard handler
    handler: RichHandler | logging.StreamHandler
    if settings.use_rich:
        handler = RichHandler(
            console=_console,
            show_path=True,
            show_time=True,
            rich_tracebacks=True,
            markup=True,
        )
    else:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(settings.format)
        handler.setFormatter(formatter)

    root_logger.addHandler(handler)

    # Add file handler if specified
    if settings.file:
        settings.file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(settings.file, encoding="utf-8")
        file_handler.setLevel(getattr(logging, settings.level))
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Get or create a logger by name.

    Args:
        name: Logger name (typically __name__).

    Returns:
        Configured logger instance.
    """
    if name not in _loggers:
        logger = logging.getLogger(name)
        _loggers[name] = logger

        # Setup logging if not already done
        if not logging.getLogger().handlers:
            setup_logging()

    return _loggers[name]


def get_console() -> Console:
    """Get the global Rich console instance.

    Returns:
        Console instance.
    """
    global _console
    if _console is None:
        _console = Console(stderr=True)
    return _console
