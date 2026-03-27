"""
Pytest fixtures for builder tests.

Provides automatic save/restore of BuilderRegistry to prevent test pollution.
"""

import pytest

from src.layers.l3_analysis.build.builders.base import BuilderRegistry


@pytest.fixture(autouse=True)
def restore_builder_registry():
    """Automatically save and restore BuilderRegistry for each test.

    This prevents tests that clear the registry from affecting subsequent tests.
    """
    # Save original state
    original_builders = dict(BuilderRegistry._builders)

    yield

    # Restore original state
    BuilderRegistry._builders.clear()
    BuilderRegistry._builders.update(original_builders)
