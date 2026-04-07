"""Base repository for database operations."""

from typing import Any, Generic, TypeVar, Type, Optional

from pydantic import BaseModel
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.models.database import Base


ModelType = TypeVar("ModelType", bound=Base)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)


class AsyncRepository(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    """
    Base repository for async database operations.

    Provides common CRUD operations for all models.
    """

    def __init__(self, model: Type[ModelType]):
        """
        Initialize repository with a model.

        Args:
            model: SQLAlchemy model class
        """
        self.model = model

    async def get(
        self,
        db: AsyncSession,
        id: int
    ) -> Optional[ModelType]:
        """
        Get a single record by ID.

        Args:
            db: Database session
            id: Record ID

        Returns:
            Model instance or None
        """
        result = await db.execute(select(self.model).where(self.model.id == id))
        return result.scalar_one_or_none()

    async def get_multi(
        self,
        db: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[list[Any]] = None
    ) -> list[ModelType]:
        """
        Get multiple records with pagination.

        Args:
            db: Database session
            skip: Number of records to skip
            limit: Maximum number of records to return
            filters: Optional list of SQLAlchemy filter expressions

        Returns:
            List of model instances
        """
        query = select(self.model)

        if filters:
            for filter_expr in filters:
                query = query.where(filter_expr)

        query = query.offset(skip).limit(limit)
        result = await db.execute(query)
        return list(result.scalars().all())

    async def count(
        self,
        db: AsyncSession,
        *,
        filters: Optional[list[Any]] = None
    ) -> int:
        """
        Count records matching filters.

        Args:
            db: Database session
            filters: Optional list of SQLAlchemy filter expressions

        Returns:
            Count of matching records
        """
        from sqlalchemy import func

        query = select(func.count(self.model.id))

        if filters:
            for filter_expr in filters:
                query = query.where(filter_expr)

        result = await db.execute(query)
        return result.scalar_one()

    async def create(
        self,
        db: AsyncSession,
        *, obj_in: CreateSchemaType
    ) -> ModelType:
        """
        Create a new record.

        Args:
            db: Database session
            obj_in: Pydantic schema with create data

        Returns:
            Created model instance
        """
        obj_data = obj_in.model_dump() if hasattr(obj_in, "model_dump") else obj_in.dict()
        db_obj = self.model(**obj_data)
        db.add(db_obj)
        await db.flush()
        await db.refresh(db_obj)
        return db_obj

    async def update(
        self,
        db: AsyncSession,
        *,
        db_obj: ModelType,
        obj_in: UpdateSchemaType | dict[str, Any]
    ) -> ModelType:
        """
        Update an existing record.

        Args:
            db: Database session
            db_obj: Existing model instance to update
            obj_in: Pydantic schema or dict with update data

        Returns:
            Updated model instance
        """
        if isinstance(obj_in, dict):
            update_data = obj_in
        else:
            update_data = obj_in.model_dump(exclude_unset=True) if hasattr(obj_in, "model_dump") else obj_in.dict(exclude_unset=True)

        for field, value in update_data.items():
            if hasattr(db_obj, field) and value is not None:
                setattr(db_obj, field, value)

        db.add(db_obj)
        await db.flush()
        await db.refresh(db_obj)
        return db_obj

    async def delete(
        self,
        db: AsyncSession,
        *,
        id: int
    ) -> bool:
        """
        Delete a record by ID.

        Args:
            db: Database session
            id: Record ID

        Returns:
            True if deleted, False if not found
        """
        result = await db.execute(delete(self.model).where(self.model.id == id))
        return result.rowcount > 0

    async def exists(
        self,
        db: AsyncSession,
        *,
        id: int
    ) -> bool:
        """
        Check if a record exists by ID.

        Args:
            db: Database session
            id: Record ID

        Returns:
            True if exists, False otherwise
        """
        result = await db.execute(
            select(self.model.id).where(self.model.id == id).limit(1)
        )
        return result.scalar_one_or_none() is not None
