"""Unit tests for repository base class."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.repositories.base import AsyncRepository
from src.web.models.project import Project


class TestAsyncRepository:
    """Test the base AsyncRepository class."""

    @pytest.mark.asyncio
    async def test_repository_initialization(self):
        """Test that repository can be initialized with a model."""
        repo = AsyncRepository(Project)
        assert repo.model == Project

    def test_get_method_exists(self):
        """Test that the repository has the expected methods."""
        repo = AsyncRepository(Project)
        assert hasattr(repo, "get")
        assert hasattr(repo, "get_multi")
        assert hasattr(repo, "count")
        assert hasattr(repo, "create")
        assert hasattr(repo, "update")
        assert hasattr(repo, "delete")
        assert hasattr(repo, "exists")
