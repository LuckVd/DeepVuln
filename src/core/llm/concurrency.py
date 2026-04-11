"""
LLM Concurrency Manager - Global concurrency control for LLM API calls.

This module provides a centralized concurrency control mechanism to prevent
API rate limiting when making parallel LLM requests.

Key Features:
- Semaphore-based concurrency limiting
- Configurable limits per provider type
- Global singleton manager for consistent control
- Context manager for easy integration
- Statistics tracking for monitoring
"""

import asyncio
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, TypeVar

# For type hints
from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar("T")


class LLMProvider(Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    AZURE = "azure"
    GLM = "glm"
    ANTHROPIC = "anthropic"
    LOCAL = "local"
    UNKNOWN = "unknown"


# Default concurrency limits per provider (conservative values to avoid rate limiting)
DEFAULT_CONCURRENCY_LIMITS: dict[LLMProvider, int] = {
    LLMProvider.OPENAI: 10,       # OpenAI allows higher rates
    LLMProvider.AZURE: 5,         # Azure typically has lower limits
    LLMProvider.GLM: 2,           # GLM has strict rate limits, reduced from 3 to avoid 429 errors
    LLMProvider.ANTHROPIC: 8,     # Anthropic moderate limits
    LLMProvider.LOCAL: 20,        # Local models no API limits
    LLMProvider.UNKNOWN: 5,       # Default conservative limit
}


@dataclass
class ConcurrencyStats:
    """Statistics for concurrency monitoring."""
    total_requests: int = 0
    concurrent_requests: int = 0
    max_concurrent_seen: int = 0
    total_wait_time_ms: float = 0.0
    rate_limit_hits: int = 0
    last_request_time: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "concurrent_requests": self.concurrent_requests,
            "max_concurrent_seen": self.max_concurrent_seen,
            "total_wait_time_ms": self.total_wait_time_ms,
            "rate_limit_hits": self.rate_limit_hits,
            "last_request_time": self.last_request_time.isoformat() if self.last_request_time else None,
        }


class LLMConcurrencyManager:
    """
    Global concurrency manager for LLM API calls.

    Uses asyncio.Semaphore to limit concurrent requests and prevent
    API rate limiting errors.

    Usage:
        # Initialize with custom limits
        manager = LLMConcurrencyManager(max_concurrent=10)

        # Use as context manager
        async with manager:
            result = await llm_client.complete(prompt)

        # Or use the decorator
        @with_llm_concurrency
        async def my_llm_call():
            return await llm_client.complete(prompt)

    Example with parallel execution:
        manager = LLMConcurrencyManager(max_concurrent=5)

        async def verify_finding(finding):
            async with manager:
                return await llm_verify(finding)

        # This will limit to 5 concurrent LLM calls
        results = await asyncio.gather(*[
            verify_finding(f) for f in findings
        ])
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        provider: LLMProvider = LLMProvider.UNKNOWN,
    ):
        """
        Initialize the concurrency manager.

        Args:
            max_concurrent: Maximum number of concurrent LLM requests.
            provider: LLM provider type (used for default limits).
        """
        self._max_concurrent = max_concurrent
        self._provider = provider
        self._semaphore: asyncio.Semaphore | None = None
        self._stats = ConcurrencyStats()
        self._lock = asyncio.Lock()

    @property
    def max_concurrent(self) -> int:
        """Get the maximum concurrent requests."""
        return self._max_concurrent

    @max_concurrent.setter
    def max_concurrent(self, value: int) -> None:
        """Set the maximum concurrent requests (requires re-initialization)."""
        if value < 1:
            raise ValueError("max_concurrent must be at least 1")
        self._max_concurrent = value
        # Recreate semaphore with new limit
        self._semaphore = asyncio.Semaphore(value)

    @property
    def provider(self) -> LLMProvider:
        """Get the LLM provider."""
        return self._provider

    @property
    def stats(self) -> ConcurrencyStats:
        """Get concurrency statistics."""
        return self._stats

    def _ensure_semaphore(self) -> asyncio.Semaphore:
        """Ensure semaphore is initialized (lazy initialization)."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrent)
        return self._semaphore

    async def __aenter__(self) -> "LLMConcurrencyManager":
        """Enter the concurrency context (acquire semaphore)."""
        semaphore = self._ensure_semaphore()
        await semaphore.acquire()

        # Update stats
        async with self._lock:
            self._stats.total_requests += 1
            self._stats.concurrent_requests += 1
            self._stats.max_concurrent_seen = max(
                self._stats.max_concurrent_seen,
                self._stats.concurrent_requests
            )
            self._stats.last_request_time = datetime.now()

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the concurrency context (release semaphore)."""
        semaphore = self._ensure_semaphore()
        semaphore.release()

        # Update stats
        async with self._lock:
            self._stats.concurrent_requests -= 1

    async def execute(self, coro: Callable[[], T]) -> T:
        """
        Execute a coroutine with concurrency control.

        Args:
            coro: The coroutine to execute.

        Returns:
            The result of the coroutine.

        Example:
            result = await manager.execute(llm_client.complete(prompt))
        """
        async with self:
            return await coro

    async def execute_many(
        self,
        coros: list[Callable[[], T]],
        return_exceptions: bool = True,
    ) -> list[T | Exception]:
        """
        Execute multiple coroutines with concurrency control.

        Args:
            coros: List of coroutines to execute.
            return_exceptions: If True, exceptions are returned in results.

        Returns:
            List of results (or exceptions if return_exceptions=True).

        Example:
            results = await manager.execute_many([
                lambda: llm_client.complete(p1),
                lambda: llm_client.complete(p2),
            ])
        """
        async def execute_one(coro: Callable[[], T]) -> T | Exception:
            try:
                async with self:
                    return await coro()
            except Exception as e:
                if return_exceptions:
                    return e
                raise

        return await asyncio.gather(
            *[execute_one(c) for c in coros],
            return_exceptions=return_exceptions,
        )

    def reset_stats(self) -> None:
        """Reset concurrency statistics."""
        self._stats = ConcurrencyStats()

    @classmethod
    def from_provider(cls, provider: LLMProvider, custom_limit: int | None = None) -> "LLMConcurrencyManager":
        """
        Create a manager with default limits for a specific provider.

        Args:
            provider: The LLM provider.
            custom_limit: Override the default limit (optional).

        Returns:
            Configured LLMConcurrencyManager.
        """
        limit = custom_limit or DEFAULT_CONCURRENCY_LIMITS.get(provider, 5)
        return cls(max_concurrent=limit, provider=provider)


# Global concurrency manager singletons - split by usage
_agent_scan_manager: LLMConcurrencyManager | None = None
_verification_manager: LLMConcurrencyManager | None = None


def get_agent_scan_concurrency_manager() -> LLMConcurrencyManager:
    """
    Get the concurrency manager for agent scanning LLM calls.

    Returns:
        The agent scan LLMConcurrencyManager instance.
    """
    global _agent_scan_manager
    if _agent_scan_manager is None:
        # P18: Default changed from 5 to 10 to match database default
        max_concurrent = 10  # Default fallback
        try:
            import os
            max_concurrent = int(os.getenv("AGENT_SCAN_LLM_CONCURRENT", "10"))
        except Exception:
            pass
        _agent_scan_manager = LLMConcurrencyManager(max_concurrent=max_concurrent)
    return _agent_scan_manager


def get_verification_concurrency_manager() -> LLMConcurrencyManager:
    """
    Get the concurrency manager for adversarial verification LLM calls.

    Returns:
        The verification LLMConcurrencyManager instance.
    """
    global _verification_manager
    if _verification_manager is None:
        # P18: Default changed from 2 to 10 to match database default
        max_concurrent = 10  # Default fallback
        try:
            import os
            max_concurrent = int(os.getenv("VERIFICATION_LLM_CONCURRENT", "10"))
        except Exception:
            pass
        _verification_manager = LLMConcurrencyManager(max_concurrent=max_concurrent)
    return _verification_manager


def get_global_concurrency_manager() -> LLMConcurrencyManager:
    """
    Get the global concurrency manager (legacy, for backward compatibility).

    .. deprecated::
        Use get_agent_scan_concurrency_manager() or get_verification_concurrency_manager() instead.
        This will be removed in a future version.

    Returns:
        The global LLMConcurrencyManager instance (agent scan manager).
    """
    return get_agent_scan_concurrency_manager()


def set_global_concurrency_manager(manager: LLMConcurrencyManager) -> None:
    """
    Set the global concurrency manager (legacy).

    .. deprecated::
        Use set_agent_scan_concurrency_manager() instead.
    """
    global _agent_scan_manager
    _agent_scan_manager = manager


async def initialize_concurrency_managers_from_db(db_session_factory) -> None:
    """
    Initialize concurrency managers from database configuration.

    This should be called during application startup to load
    concurrency settings from the database.

    Args:
        db_session_factory: Factory for creating database sessions
    """
    global _agent_scan_manager, _verification_manager

    try:
        from src.web.services.llm_config_service import LLMConfigService

        # Get agent scan config
        async with db_session_factory() as db:
            agent_config = await LLMConfigService.get_agent_scan_config(db)
            if agent_config and hasattr(agent_config, 'max_concurrent_requests'):
                max_concurrent = agent_config.max_concurrent_requests
                _agent_scan_manager = LLMConcurrencyManager(max_concurrent=max_concurrent)
                logger = __import__('logging').getLogger(__name__)
                logger.info(f"Initialized agent scan concurrency manager: max_concurrent={max_concurrent}")

            # Get verification config
            verify_config = await LLMConfigService.get_verification_config(db)
            if verify_config and hasattr(verify_config, 'max_concurrent_requests'):
                max_concurrent = verify_config.max_concurrent_requests
                _verification_manager = LLMConcurrencyManager(max_concurrent=max_concurrent)
                logger.info(f"Initialized verification concurrency manager: max_concurrent={max_concurrent}")
    except Exception as e:
        logger = __import__('logging').getLogger(__name__)
        logger.warning(f"Failed to initialize concurrency managers from database: {e}")
        # Fall back to defaults is handled by the getter functions


def set_agent_scan_concurrency_manager(manager: LLMConcurrencyManager) -> None:
    """
    Set the agent scan concurrency manager.

    Args:
        manager: The LLMConcurrencyManager to use for agent scanning.
    """
    global _agent_scan_manager
    _agent_scan_manager = manager


def set_verification_concurrency_manager(manager: LLMConcurrencyManager) -> None:
    """
    Set the verification concurrency manager.

    Args:
        manager: The LLMConcurrencyManager to use for adversarial verification.
    """
    global _verification_manager
    _verification_manager = manager


def set_global_concurrency_manager(manager: LLMConcurrencyManager) -> None:
    """
    Set the global concurrency manager.

    Args:
        manager: The LLMConcurrencyManager to use globally.
    """
    global _global_manager
    _global_manager = manager


def configure_global_concurrency(
    max_concurrent: int,
    provider: LLMProvider = LLMProvider.UNKNOWN,
) -> LLMConcurrencyManager:
    """
    Configure the global concurrency manager.

    Args:
        max_concurrent: Maximum concurrent requests.
        provider: LLM provider type.

    Returns:
        The configured global manager.
    """
    manager = LLMConcurrencyManager(max_concurrent=max_concurrent, provider=provider)
    set_global_concurrency_manager(manager)
    return manager


@asynccontextmanager
async def with_llm_concurrency():
    """
    Context manager using the global concurrency manager.

    Usage:
        async with with_llm_concurrency():
            result = await llm_client.complete(prompt)
    """
    manager = get_global_concurrency_manager()
    async with manager:
        yield manager


def with_concurrency_control(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator to wrap an async function with concurrency control.

    Usage:
        @with_concurrency_control
        async def my_llm_call(prompt: str):
            return await llm_client.complete(prompt)
    """
    async def wrapper(*args, **kwargs) -> T:
        manager = get_global_concurrency_manager()
        async with manager:
            return await func(*args, **kwargs)
    return wrapper


# =============================================================================
# P18: Async functions to get concurrency managers from database
# =============================================================================


async def get_agent_scan_concurrency_manager_from_db(
    db_session_factory: Callable[[], AsyncSession]
) -> LLMConcurrencyManager:
    """
    Get agent scan concurrency manager with config from database.

    This function reads the latest max_concurrent_requests from the database
    and creates a new concurrency manager with that value.

    Args:
        db_session_factory: Factory for creating database sessions

    Returns:
        LLMConcurrencyManager configured with database value
    """
    try:
        from src.web.services.llm_config_service import LLMConfigService

        async with db_session_factory() as db:
            agent_config = await LLMConfigService.get_agent_scan_config(db)
            if agent_config and hasattr(agent_config, 'max_concurrent_requests'):
                max_concurrent = agent_config.max_concurrent_requests
                logger = __import__('logging').getLogger(__name__)
                logger.info(f"Using agent scan concurrency from DB: max_concurrent={max_concurrent}")
                return LLMConcurrencyManager(max_concurrent=max_concurrent)
    except Exception as e:
        logger = __import__('logging').getLogger(__name__)
        logger.warning(f"Failed to get agent scan concurrency from DB: {e}, using default")

    # Fall back to default
    return get_agent_scan_concurrency_manager()


async def get_verification_concurrency_manager_from_db(
    db_session_factory: Callable[[], AsyncSession]
) -> LLMConcurrencyManager:
    """
    Get verification concurrency manager with config from database.

    This function reads the latest max_concurrent_requests from the database
    and creates a new concurrency manager with that value.

    Args:
        db_session_factory: Factory for creating database sessions

    Returns:
        LLMConcurrencyManager configured with database value
    """
    try:
        from src.web.services.llm_config_service import LLMConfigService

        async with db_session_factory() as db:
            verify_config = await LLMConfigService.get_verification_config(db)
            if verify_config and hasattr(verify_config, 'max_concurrent_requests'):
                max_concurrent = verify_config.max_concurrent_requests
                logger = __import__('logging').getLogger(__name__)
                logger.info(f"Using verification concurrency from DB: max_concurrent={max_concurrent}")
                return LLMConcurrencyManager(max_concurrent=max_concurrent)
    except Exception as e:
        logger = __import__('logging').getLogger(__name__)
        logger.warning(f"Failed to get verification concurrency from DB: {e}, using default")

    # Fall back to default
    return get_verification_concurrency_manager()
