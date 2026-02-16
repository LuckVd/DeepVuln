"""Rate limiter for API requests using token bucket algorithm."""

import asyncio
import time
from dataclasses import dataclass, field

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RateLimiter:
    """Token bucket rate limiter for API requests.

    Implements a token bucket algorithm to limit the rate of requests.
    Tokens are added at a fixed rate up to a maximum capacity.
    Each request consumes one token.
    """

    rate: float = 5.0
    """Tokens added per second (requests per second)."""

    capacity: float = 10.0
    """Maximum number of tokens."""

    _tokens: float = field(default=0.0, init=False, repr=False)
    _last_update: float = field(default_factory=time.time, init=False, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        """Initialize tokens to capacity."""
        self._tokens = self.capacity

    @classmethod
    def from_requests_per_window(
        cls, requests: int, window_seconds: float = 30.0
    ) -> "RateLimiter":
        """Create a rate limiter from requests per time window.

        Args:
            requests: Number of requests allowed.
            window_seconds: Time window in seconds.

        Returns:
            RateLimiter instance.
        """
        rate = requests / window_seconds
        # Allow burst up to the request count
        return cls(rate=rate, capacity=float(requests))

    async def acquire(self, tokens: float = 1.0) -> None:
        """Acquire tokens, waiting if necessary.

        Args:
            tokens: Number of tokens to acquire.
        """
        async with self._lock:
            while True:
                self._refill()

                if self._tokens >= tokens:
                    self._tokens -= tokens
                    logger.debug(
                        f"Acquired {tokens} token(s), {self._tokens:.2f} remaining"
                    )
                    return

                # Calculate wait time
                needed = tokens - self._tokens
                wait_time = needed / self.rate

                logger.debug(
                    f"Rate limited: need {tokens} token(s), have {self._tokens:.2f}, "
                    f"waiting {wait_time:.2f}s"
                )

                # Release lock while waiting
                self._lock.release()
                try:
                    await asyncio.sleep(wait_time)
                finally:
                    await self._lock.acquire()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self._last_update

        # Add tokens based on elapsed time
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_update = now

    @property
    def available(self) -> float:
        """Get current available tokens without refilling.

        Returns:
            Approximate available tokens.
        """
        return self._tokens

    def reset(self) -> None:
        """Reset the rate limiter to full capacity."""
        self._tokens = self.capacity
        self._last_update = time.time()


class MultiRateLimiter:
    """Rate limiter supporting multiple endpoints with different limits."""

    def __init__(self) -> None:
        """Initialize multi-rate limiter."""
        self._limiters: dict[str, RateLimiter] = {}

    def add_limiter(
        self,
        name: str,
        rate: float,
        capacity: float | None = None,
    ) -> None:
        """Add a rate limiter for a named endpoint.

        Args:
            name: Limiter name.
            rate: Tokens per second.
            capacity: Maximum tokens (defaults to rate * 2).
        """
        if capacity is None:
            capacity = rate * 2
        self._limiters[name] = RateLimiter(rate=rate, capacity=capacity)

    def add_limiter_from_window(
        self,
        name: str,
        requests: int,
        window_seconds: float = 30.0,
    ) -> None:
        """Add a rate limiter based on requests per window.

        Args:
            name: Limiter name.
            requests: Number of requests allowed.
            window_seconds: Time window in seconds.
        """
        self._limiters[name] = RateLimiter.from_requests_per_window(
            requests, window_seconds
        )

    async def acquire(self, name: str, tokens: float = 1.0) -> None:
        """Acquire tokens from a named limiter.

        Args:
            name: Limiter name.
            tokens: Number of tokens to acquire.

        Raises:
            KeyError: If limiter doesn't exist.
        """
        if name not in self._limiters:
            raise KeyError(f"No rate limiter named: {name}")
        await self._limiters[name].acquire(tokens)

    def get_limiter(self, name: str) -> RateLimiter | None:
        """Get a rate limiter by name.

        Args:
            name: Limiter name.

        Returns:
            RateLimiter or None.
        """
        return self._limiters.get(name)

    def get_all_stats(self) -> dict[str, dict[str, float]]:
        """Get statistics for all limiters.

        Returns:
            Dictionary of limiter stats.
        """
        return {
            name: {
                "rate": limiter.rate,
                "capacity": limiter.capacity,
                "available": limiter.available,
            }
            for name, limiter in self._limiters.items()
        }
