"""Tests for threat-intel CLI async helpers."""

import asyncio

import pytest

from src.cli.intel import run_async


class TestRunAsync:
    """Tests for CLI async loop management."""

    def test_run_async_restores_previous_loop(self) -> None:
        previous_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(previous_loop)

        try:
            result = run_async(asyncio.sleep(0, result="ok"))

            assert result == "ok"
            assert asyncio.get_event_loop() is previous_loop
        finally:
            asyncio.set_event_loop(None)
            previous_loop.close()

    def test_run_async_leaves_no_current_loop_when_none_existed(self) -> None:
        asyncio.set_event_loop(None)

        result = run_async(asyncio.sleep(0, result="ok"))

        assert result == "ok"
        with pytest.raises(RuntimeError, match="There is no current event loop"):
            asyncio.get_event_loop()
