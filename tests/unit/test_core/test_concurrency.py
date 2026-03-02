"""
Tests for LLM Concurrency Manager.

These tests verify the concurrency control logic for parallel LLM API calls.
"""

import asyncio
from datetime import datetime

import pytest

from src.core.llm.concurrency import (
    LLMConcurrencyManager,
    LLMProvider,
    ConcurrencyStats,
    get_global_concurrency_manager,
    set_global_concurrency_manager,
    configure_global_concurrency,
    with_concurrency_control,
    with_llm_concurrency,
    DEFAULT_CONCURRENCY_LIMITS,
)


class TestLLMConcurrencyManager:
    """Tests for LLMConcurrencyManager class."""

    def test_init_default(self):
        """Test default initialization."""
        manager = LLMConcurrencyManager()
        assert manager.max_concurrent == 5
        assert manager.provider == LLMProvider.UNKNOWN

        assert manager.stats.total_requests == 0

    def test_init_custom(self):
        """Test custom initialization."""
        manager = LLMConcurrencyManager(max_concurrent=10, provider=LLMProvider.OPENAI)
        assert manager.max_concurrent == 10
        assert manager.provider == LLMProvider.OPENAI

    def test_from_provider(self):
        """Test creation from provider type."""
        # Test each provider
        for provider, expected_limit in DEFAULT_CONCURRENCY_LIMITS.items():
            manager = LLMConcurrencyManager.from_provider(provider)
            assert manager.max_concurrent == expected_limit
            assert manager.provider == provider

    def test_from_provider_custom_limit(self):
        """Test creation from provider with custom limit."""
        manager = LLMConcurrencyManager.from_provider(LLMProvider.OPENAI, custom_limit=20)
        assert manager.max_concurrent == 20
        assert manager.provider == LLMProvider.OPENAI

    def test_set_max_concurrent(self):
        """Test setting max_concurrent."""
        manager = LLMConcurrencyManager(max_concurrent=5)
        manager.max_concurrent = 10
        assert manager.max_concurrent == 10

        with pytest.raises(ValueError):
            manager.max_concurrent = 0

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager."""
        manager = LLMConcurrencyManager(max_concurrent=2)

        # Test single acquisition
        async with manager:
            assert manager.stats.concurrent_requests == 1
            assert manager.stats.total_requests == 1

        assert manager.stats.concurrent_requests == 0

    @pytest.mark.asyncio
    async def test_concurrent_limit(self):
        """Test that concurrent limit is respected."""
        manager = LLMConcurrencyManager(max_concurrent=2)
        execution_order = []

        async def track_execution(task_id: int):
            async with manager:
                execution_order.append(f"start_{task_id}")
                await asyncio.sleep(0.1)
                execution_order.append(f"end_{task_id}")

        # Run 4 tasks with limit of 2
        tasks = [track_execution(i) for i in range(4)]
        await asyncio.gather(*tasks)

        # Verify max concurrent was respected
        # With limit of 2, we should never have more than 2 concurrent
        assert manager.stats.max_concurrent_seen <= 2
        assert manager.stats.total_requests == 4

    @pytest.mark.asyncio
    async def test_execute(self):
        """Test execute method."""
        manager = LLMConcurrencyManager(max_concurrent=2)

        async def sample_task():
            await asyncio.sleep(0.1)
            return "result"

        result = await manager.execute(sample_task())
        assert result == "result"
        assert manager.stats.total_requests == 1

    @pytest.mark.asyncio
    async def test_execute_many(self):
        """Test execute_many method."""
        manager = LLMConcurrencyManager(max_concurrent=2)

        async def sample_task(value: int):
            await asyncio.sleep(0.05)
            return value * 2

        results = await manager.execute_many([
            lambda: sample_task(1),
            lambda: sample_task(2),
            lambda: sample_task(3),
        ])

        assert len(results) == 3
        # Results may be in any order due to parallel execution
        assert all(isinstance(r, int) for r in results)

    @pytest.mark.asyncio
    async def test_execute_many_with_exceptions(self):
        """Test execute_many with exceptions."""
        manager = LLMConcurrencyManager(max_concurrent=2)

        async def failing_task():
            raise ValueError("Test error")

        async def success_task():
            return "success"

        results = await manager.execute_many(
            [lambda: failing_task(), lambda: success_task()],
            return_exceptions=True,
        )

        assert len(results) == 2
        assert any(isinstance(r, ValueError) for r in results)
        assert any(r == "success" for r in results)

    @pytest.mark.asyncio
    async def test_execute_many_propagate_exceptions(self):
        """Test execute_many propagates exceptions when return_exceptions=False."""
        manager = LLMConcurrencyManager(max_concurrent=2)

        async def failing_task():
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            await manager.execute_many(
                [lambda: failing_task()],
                return_exceptions=False,
            )

    def test_stats_tracking(self):
        """Test statistics tracking."""
        manager = LLMConcurrencyManager(max_concurrent=5)

        # Initial stats
        assert manager.stats.total_requests == 0
        assert manager.stats.concurrent_requests == 0
        assert manager.stats.max_concurrent_seen == 0

    def test_reset_stats(self):
        """Test stats reset."""
        manager = LLMConcurrencyManager()

        # Simulate some activity
        manager._stats.total_requests = 10

        manager.reset_stats()
        assert manager.stats.total_requests == 0


class TestGlobalManager:
    """Tests for global manager functions."""

    def teardown_method(self):
        """Reset global manager after each test."""
        set_global_concurrency_manager(None)

    def test_get_global_manager_creates_default(self):
        """Test that get_global_concurrency_manager creates default."""
        manager = get_global_concurrency_manager()
        assert manager is not None
        assert manager.max_concurrent == 5

    def test_set_global_manager(self):
        """Test setting global manager."""
        custom_manager = LLMConcurrencyManager(max_concurrent=15)
        set_global_concurrency_manager(custom_manager)

        manager = get_global_concurrency_manager()
        assert manager.max_concurrent == 15

    def test_configure_global_concurrency(self):
        """Test configure_global_concurrency helper."""
        manager = configure_global_concurrency(10, LLMProvider.OPENAI)

        assert manager.max_concurrent == 10
        assert manager.provider == LLMProvider.OPENAI

        # Verify it's the global manager
        global_manager = get_global_concurrency_manager()
        assert global_manager is manager

    @pytest.mark.asyncio
    async def test_with_llm_concurrency(self):
        """Test with_llm_concurrency context manager."""
        configure_global_concurrency(2)

        execution_count = 0

        async def inner_task():
            nonlocal execution_count
            execution_count += 1
            await asyncio.sleep(0.1)

        # Run multiple tasks through the context manager
        async with with_llm_concurrency():
            await inner_task()

        assert execution_count == 1


class TestConcurrencyStats:
    """Tests for ConcurrencyStats dataclass."""

    def test_init(self):
        """Test default initialization."""
        stats = ConcurrencyStats()
        assert stats.total_requests == 0
        assert stats.concurrent_requests == 0
        assert stats.max_concurrent_seen == 0
        assert stats.total_wait_time_ms == 0.0
        assert stats.rate_limit_hits == 0
        assert stats.last_request_time is None

    def test_to_dict(self):
        """Test to_dict method."""
        stats = ConcurrencyStats(
            total_requests=10,
            concurrent_requests=2,
            max_concurrent_seen=5,
            total_wait_time_ms=100.5,
            rate_limit_hits=1,
            last_request_time=datetime(2026, 3, 3, 12, 0, 0),
        )

        d = stats.to_dict()
        assert d["total_requests"] == 10
        assert d["concurrent_requests"] == 2
        assert d["max_concurrent_seen"] == 5
        assert d["total_wait_time_ms"] == 100.5
        assert d["rate_limit_hits"] == 1
        assert "last_request_time" in d


class TestConcurrencyIntegration:
    """Integration tests for concurrency control."""

    @pytest.mark.asyncio
    async def test_parallel_execution_with_limit(self):
        """Test that parallel execution respects the limit."""
        manager = LLMConcurrencyManager(max_concurrent=3)
        max_seen = 0
        current = 0

        async def track_concurrent(task_id: int):
            nonlocal max_seen, current
            async with manager:
                current += 1
                max_seen = max(max_seen, current)
                await asyncio.sleep(0.05)
                current -= 1
            return task_id

        # Run 10 tasks with limit of 3
        results = await asyncio.gather(*[
            track_concurrent(i) for i in range(10)
        ])

        assert len(results) == 10
        assert max_seen <= 3  # Never exceeded the limit
        assert manager.stats.total_requests == 10

    @pytest.mark.asyncio
    async def test_simulated_llm_calls(self):
        """Test simulated LLM API calls with concurrency control."""
        manager = LLMConcurrencyManager(max_concurrent=5)
        call_count = 0

        async def simulated_llm_call(prompt: str) -> str:
            nonlocal call_count
            async with manager:
                call_count += 1
                await asyncio.sleep(0.01)  # Simulate API latency
                return f"Response to: {prompt}"

        # Simulate multiple parallel LLM calls
        prompts = [f"Prompt {i}" for i in range(20)]
        results = await asyncio.gather(*[
            simulated_llm_call(p) for p in prompts
        ])

        assert len(results) == 20
        assert call_count == 20
        assert manager.stats.max_concurrent_seen <= 5
