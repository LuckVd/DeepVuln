"""Project management API endpoints."""

import os
import shutil
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.api.deps import get_db
from src.web.core.security import require_api_key, optional_api_key
from src.web.models.schemas import (
    ProjectCreate,
    ProjectUpdate,
    ProjectResponse,
    ProjectListResponse,
)
from src.web.repositories.project import ProjectRepository
from src.web.repositories.scan import ScanRepository

router = APIRouter()


@router.post("/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    project: ProjectCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectResponse:
    """
    Create a new project.

    Args:
        project: Project creation data
        db: Database session

    Returns:
        Created project with generated ID and timestamps

    Raises:
        HTTPException 400: If project name already exists
    """
    repo = ProjectRepository()

    # Check for duplicate name
    existing = await repo.get_by_name(db, name=project.name)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Project with name '{project.name}' already exists"
        )

    # Create project
    created = await repo.create(db, obj_in=project)
    return ProjectResponse.model_validate(created)


@router.get("/projects", response_model=ProjectListResponse)
async def list_projects(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Number of items per page"),
    source_type: str | None = Query(None, description="Filter by source type"),
) -> ProjectListResponse:
    """
    List all projects with pagination.

    Args:
        db: Database session
        page: Page number (1-indexed)
        page_size: Number of items per page (max 100)
        source_type: Optional filter by source type (local/git/zip)

    Returns:
        Paginated list of projects with total count
    """
    repo = ProjectRepository()
    skip = (page - 1) * page_size

    if source_type:
        items = await repo.list_by_source_type(
            db, source_type=source_type, skip=skip, limit=page_size
        )
        # Count total for this source type
        from sqlalchemy import select, func
        from src.web.models.project import Project
        count_result = await db.execute(
            select(func.count()).select_from(Project).where(Project.source_type == source_type)
        )
        total = count_result.scalar_one() or 0
    else:
        items = await repo.get_multi(db, skip=skip, limit=page_size)
        total = await repo.count(db)

    return ProjectListResponse(
        items=[ProjectResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/projects/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> ProjectResponse:
    """
    Get project by ID.

    Args:
        project_id: Project ID
        db: Database session

    Returns:
        Project details

    Raises:
        HTTPException 404: If project not found
    """
    repo = ProjectRepository()
    project = await repo.get(db, id=project_id)

    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )

    return ProjectResponse.model_validate(project)


@router.put("/projects/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: int,
    project: ProjectUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(require_api_key)] = None,
) -> ProjectResponse:
    """
    Update a project.

    Args:
        project_id: Project ID
        project: Project update data (all fields optional)
        db: Database session

    Returns:
        Updated project

    Raises:
        HTTPException 404: If project not found
        HTTPException 400: If new name conflicts with existing project
    """
    repo = ProjectRepository()
    db_project = await repo.get(db, id=project_id)

    if db_project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )

    # Check for name conflict if name is being updated
    if project.name is not None and project.name != db_project.name:
        existing = await repo.get_by_name(db, name=project.name)
        if existing is not None and existing.id != project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Project with name '{project.name}' already exists"
            )

    # Update project
    updated = await repo.update(db, db_obj=db_project, obj_in=project)
    return ProjectResponse.model_validate(updated)


@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(require_api_key)] = None,
) -> None:
    """
    Delete a project.

    Note: This will cascade delete all associated scans and findings.

    Args:
        project_id: Project ID
        db: Database session

    Raises:
        HTTPException 404: If project not found
    """
    repo = ProjectRepository()
    project = await repo.get(db, id=project_id)

    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )

    await repo.delete(db, id=project_id)


@router.get("/projects/{project_id}/scans")
async def get_project_scans(
    project_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
    limit: int = Query(50, ge=1, le=500, description="Maximum number of scans to return"),
) -> dict:
    """
    Get scan history for a project.

    Args:
        project_id: Project ID
        db: Database session
        limit: Maximum number of scans to return (default 50, max 500)

    Returns:
        Dictionary with scan history

    Raises:
        HTTPException 404: If project not found
    """
    project_repo = ProjectRepository()
    scan_repo = ScanRepository()

    # Verify project exists
    project = await project_repo.get(db, id=project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )

    # Get scans for this project
    scans = await scan_repo.list_by_project(
        db, project_id=project_id, skip=0, limit=limit
    )

    from src.web.models.schemas import ScanResponse

    return {
        "project_id": project_id,
        "project_name": project.name,
        "total": len(scans),
        "scans": [
            {
                "id": scan.id,
                "status": scan.status,
                "scan_type": scan.scan_type,
                "progress_percent": scan.progress_percent,
                "findings_count": scan.findings_count,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            }
            for scan in scans
        ],
    }


@router.post("/projects/upload-zip", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project_from_zip(
    name: Annotated[str, Form(description="Project name")],
    file: Annotated[UploadFile, File(description="ZIP file containing source code")],
    description: Annotated[str | None, Form(description="Project description")] = None,
    branch: Annotated[str | None, Form(description="Branch name")] = None,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
) -> ProjectResponse:
    """
    Create a project from an uploaded ZIP file.

    Args:
        name: Project name
        file: ZIP file containing source code
        description: Optional project description
        branch: Optional branch name (for metadata)
        db: Database session

    Returns:
        Created project with generated ID and timestamps

    Raises:
        HTTPException 400: If file is not a ZIP or project name already exists
    """
    from src.web.models.schemas import ProjectCreate
    from src.web.core.config import get_web_settings

    # Validate file type
    if not file.filename or not file.filename.lower().endswith('.zip'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only ZIP files are allowed"
        )

    repo = ProjectRepository()

    # Check for duplicate name
    existing = await repo.get_by_name(db, name=name)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Project with name '{name}' already exists"
        )

    # Create uploads directory if it doesn't exist
    web_settings = get_web_settings()
    upload_dir = Path(web_settings.upload_dir) if hasattr(web_settings, 'upload_dir') else Path("/opt/projects/deepvuln/uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)

    # Generate unique filename
    file_id = str(uuid.uuid4())
    file_path = upload_dir / f"{file_id}.zip"

    # Save uploaded file
    try:
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save file: {str(e)}"
        )

    # Extract ZIP file to a directory for scanning
    extract_dir = upload_dir / file_id
    extract_dir.mkdir(exist_ok=True)
    try:
        shutil.unpack_archive(file_path, extract_dir)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to extract ZIP file: {str(e)}"
        )

    # Create project with extracted directory path for scanning
    project_data = ProjectCreate(
        name=name,
        description=description,
        source_type="zip",
        source_path=str(extract_dir),  # Use extracted directory for scanning
        branch=branch,
    )

    created = await repo.create(db, obj_in=project_data)
    return ProjectResponse.model_validate(created)