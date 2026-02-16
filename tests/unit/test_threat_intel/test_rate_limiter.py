"""Tests for rate limiter."""

import asyncio

import pytest

from src.layers.l1_intelligence.threat_intel.core.rate_limiter import (
    MultiRateLimiter,
    RateLimiter,
)


class TestRateLimiter:
    """Tests for RateLimiter."""

    def test_create_rate_limiter(self) -> None:
        """Test creating a rate limiter."""
        limiter = RateLimiter(rate=10.0, capacity=20.0)

        assert limiter.rate == 10.0
        assert limiter.capacity == 20.0
        assert limiter.available == 20.0

    def test_from_requests_per_window(self) -> None:
        """Test creating rate limiter from requests per window."""
        limiter = RateLimiter.from_requests_per_window(50, 30.0)

        # 50 requests per 30 seconds = ~1.67 requests per second
        assert limiter.rate == pytest.approx(50 / 30, rel=0.01)
        assert limiter.capacity == 50.0

    @pytest.mark.asyncio
    async def test_acquire_immediate(self) -> None:
        """Test immediate token acquisition."""
        limiter = RateLimiter(rate=10.0, capacity=10.0)

        # Should succeed immediately with full capacity
        await limiter.acquire(1)
        assert limiter.available == pytest.approx(9.0, abs=0.1)

    @pytest.mark.asyncio
    async def test_acquire_multiple(self) -> None:
        """Test acquiring multiple tokens."""
        limiter = RateLimiter(rate=10.0, capacity=10.0)

        await limiter.acquire(5)
        assert limiter.available == pytest.approx(5.0, abs=0.1)

    @pytest.mark.asyncio
    async def test_acquire_with_wait(self) -> None:
        """Test acquisition with waiting."""
        limiter = RateLimiter(rate=10.0, capacity=2.0)

        # Use all tokens
        await limiter.acquire(2)

        # This should wait and succeed
        start = asyncio.get_event_loop().time()
        await limiter.acquire(1)
        elapsed = asyncio.get_event_loop().time() - start

        # Should have waited approximately 0.1 seconds (1/10)
        # Use a lower threshold to account for timing variations
        assert elapsed >= 0.05  # At least some wait

    def test_reset(self) -> None:
        """Test reset functionality."""
        limiter = RateLimiter(rate=10.0, capacity=10.0)
        limiter._tokens = 0  # Use all tokens

        limiter.reset()

        assert limiter.available == 10.0


class TestMultiRateLimiter:
    """Tests for MultiRateLimiter."""

    def test_add_limiter(self) -> None:
        """Test adding limiters."""
        multi = MultiRateLimiter()
        multi.add_limiter("api1", rate=10.0, capacity=20.0)

        limiter = multi.get_limiter("api1")
        assert limiter is not None
        assert limiter.rate == 10.0

    def test_add_limiter_from_window(self) -> None:
        """Test adding limiter from window."""
        multi = MultiRateLimiter()
        multi.add_limiter_from_window("api2", requests=50, window_seconds=30.0)

        limiter = multi.get_limiter("api2")
        assert limiter is not None
        assert limiter.capacity == 50.0

    @pytest.mark.asyncio
    async def test_acquire(self) -> None:
        """Test acquiring from named limiter."""
        multi = MultiRateLimiter()
        multi.add_limiter("test", rate=10.0, capacity=10.0)

        await multi.acquire("test", 1)

        limiter = multi.get_limiter("test")
        assert limiter is not None
        assert limiter.available == pytest.approx(9.0, abs=0.1)

    def test_acquire_nonexistent_raises(self) -> None:
        """Test acquiring from nonexistent limiter raises."""
        multi = MultiRateLimiter()

        with pytest.raises(KeyError):
            asyncio.run(multi.acquire("nonexistent"))

    def test_get_all_stats(self) -> None:
        """Test getting all stats."""
        multi = MultiRateLimiter()
        multi.add_limiter("api1", rate=10.0, capacity=20.0)
        multi.add_limiter("api2", rate=5.0, capacity=10.0)

        stats = multi.get_all_stats()

        assert "api1" in stats
        assert "api2" in stats
        assert stats["api1"]["rate"] == 10.0
        assert stats["api2"]["rate"] == 5.0
