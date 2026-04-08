"""New scan API endpoints using coroutine-based scanning.

This module provides updated scan endpoints that use the new modular
scan service with coroutine-based execution instead of Celery subprocess calls.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.api.deps import get_db
from src.web.core.security import require_api_key
from src.web.models.schemas import ScanResponse, ScanCreate
from src.web.models.scan import ScanStatus
from src.web.models.project import Project
from src.web.repositories.scan import ScanRepository
from src.web.repositories.project import ProjectRepository
from src.web.models.database import get_session_local

router = APIRouter()


@router.post("/scans/{scan_id}/start-v2", response_model=dict)
async def start_scan_v2(
    scan_id: int,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Start a scan using the new coroutine-based service.

    This endpoint replaces Celery with FastAPI BackgroundTasks,
    providing faster execution and better resource utilization.

    Args:
        scan_id: ID of the scan to start
        background_tasks: FastAPI background tasks
        db: Database session

    Returns:
        Dictionary with status

    Raises:
        HTTPException 404: If scan not found
        HTTPException 400: If scan cannot be started
    """
    from src.web.services.scan.background import get_scan_manager

    # Verify scan exists
    scan_repo = ScanRepository()
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found"
        )

    # Check if scan can be started
    if scan.status != ScanStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail=f"Scan {scan_id} is not in pending status (current: {scan.status})"
        )

    # Get project details
    project_repo = ProjectRepository()
    project = await project_repo.get(db, id=scan.project_id)
    if project is None:
        raise HTTPException(
            status_code=404,
            detail=f"Project {scan.project_id} not found"
        )

    # Prepare scan configuration
    config = {
        "scan_type": scan.scan_type.value if hasattr(scan.scan_type, 'value') else scan.scan_type,
        "engines": ["semgrep", "codeql", "agent"],
        "llm_verify": False,  # Can be configured from scan.config
        "adversarial": False,
        "include_low_severity": True,
    }

    # Override with scan config if available
    if scan.config:
        try:
            scan_config = json.loads(scan.config) if isinstance(scan.config, str) else scan.config
            config.update(scan_config)
        except:
            pass

    # Update status to running
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.utcnow()
    await db.commit()

    # Submit to background scan manager
    scan_manager = get_scan_manager()
    submitted = await scan_manager.submit_scan(
        scan_id=scan_id,
        project_id=project.id,
        source_path=project.source_path,
        config=config,
        db_session_factory=get_session_local,
    )

    if not submitted:
        # Revert status if at capacity
        scan.status = ScanStatus.PENDING
        scan.started_at = None
        await db.commit()
        raise HTTPException(
            status_code=503,
            detail="Scan capacity reached, please try again later"
        )

    return {
        "scan_id": scan_id,
        "status": "started",
        "message": "Scan is running in the background"
    }


@router.post("/scans/quick-scan", response_model=dict)
async def quick_scan(
    project_id: int,
    background_tasks: BackgroundTasks,
    scan_type: str = Query("base", description="Scan type: base or full"),
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Create and start a scan in one request.

    This is a convenience endpoint that creates a scan and immediately
    starts it, reducing the number of API calls needed.

    Args:
        project_id: Project ID to scan
        background_tasks: FastAPI background tasks
        scan_type: Type of scan (base or full)
        db: Database session

    Returns:
        Dictionary with scan_id and status
    """
    from src.web.services.scan.background import get_scan_manager

    # Get project
    project_repo = ProjectRepository()
    project = await project_repo.get(db, id=project_id)
    if project is None:
        raise HTTPException(
            status_code=404,
            detail=f"Project {project_id} not found"
        )

    # Create scan
    scan_repo = ScanRepository()
    scan = await scan_repo.create(db, obj_in={
        "project_id": project_id,
        "scan_type": scan_type,
        "config": {"engines": ["semgrep", "codeql", "agent"]},
        "status": ScanStatus.PENDING,
    })

    await db.refresh(scan)

    # Prepare configuration
    config = {
        "scan_type": scan_type,
        "engines": ["semgrep", "codeql", "agent"],
        "llm_verify": scan_type == "full",
        "adversarial": scan_type == "full",
        "include_low_severity": True,
    }

    # Update status and submit
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.utcnow()
    await db.commit()

    # Submit to background scan manager
    scan_manager = get_scan_manager()
    submitted = await scan_manager.submit_scan(
        scan_id=scan.id,
        project_id=project.id,
        source_path=project.source_path,
        config=config,
        db_session_factory=get_session_local,
    )

    if not submitted:
        # Clean up failed scan
        await db.delete(scan)
        await db.commit()
        raise HTTPException(
            status_code=503,
            detail="Scan capacity reached, please try again later"
        )

    return {
        "scan_id": scan.id,
        "status": "started",
        "project_id": project_id,
        "scan_type": scan_type,
    }


@router.get("/scan-manager/status")
async def get_scan_manager_status() -> dict:
    """Get the status of the background scan manager.

    Returns:
        Dictionary with manager status including running scans
    """
    from src.web.services.scan.background import get_scan_manager

    manager = get_scan_manager()
    return await manager.get_status()
