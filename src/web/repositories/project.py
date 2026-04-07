"""Project repository for database operations."""

from typing import Optional, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.models.project import Project
from src.web.models.schemas import ProjectCreate, ProjectUpdate
from src.web.repositories.base import AsyncRepository


class ProjectRepository(
    AsyncRepository[Project, ProjectCreate, ProjectUpdate]
):
    """Repository for Project model."""

    def __init__(self):
        """Initialize repository with Project model."""
        super().__init__(Project)

    async def get_by_name(
        self,
        db: AsyncSession,
        *,
        name: str
    ) -> Optional[Project]:
        """
        Get a project by name.

        Args:
            db: Database session
            name: Project name

        Returns:
            Project instance or None
        """
        result = await db.execute(
            select(Project).where(Project.name == name)
        )
        return result.scalar_one_or_none()

    async def get_with_scans(
        self,
        db: AsyncSession,
        *,
        id: int
    ) -> Optional[Project]:
        """
        Get a project with its scans.

        Args:
            db: Database session
            id: Project ID

        Returns:
            Project instance with scans loaded
        """
        result = await db.execute(
            select(Project)
            .where(Project.id == id)
        )
        project = result.scalar_one_or_none()
        return project

    async def list_by_source_type(
        self,
        db: AsyncSession,
        *,
        source_type: str,
        skip: int = 0,
        limit: int = 100
    ) -> list[Project]:
        """
        List projects by source type.

        Args:
            db: Database session
            source_type: Source type to filter by
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            List of projects
        """
        result = await db.execute(
            select(Project)
            .where(Project.source_type == source_type)
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())
