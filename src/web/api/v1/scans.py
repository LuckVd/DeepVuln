"""Scan management API endpoints."""

import json
import csv
from datetime import datetime, timezone
from typing import Annotated
from io import StringIO

from fastapi import APIRouter, Depends, HTTPException, Query, status, UploadFile, Form
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from src.web.api.deps import get_db
from src.web.core.security import require_api_key, optional_api_key
from src.web.models.schemas import (
    ScanCreate,
    ScanResponse,
    ScanListResponse,
    ScanProgressResponse,
    AgentConversationResponse,
    AgentConversationMessage,
    AdversarialStatus,
    CurrentFileResponse,
    PhaseInfo,
    TokenInfo,
    FindingSummary,
    PauseScanResponse,
    ResumeScanResponse,
    CancelScanResponse,
    ScanStatusResponse,
    FindingUpdate,
    FindingResponse,
)
from src.web.repositories.scan import ScanRepository
from src.web.repositories.finding import FindingRepository
from src.web.repositories.event import ScanPhaseRepository, ScanEventRepository

router = APIRouter()


def _iso(dt: datetime | None) -> str | None:
    """Serialize a naive-UTC datetime to an ISO 8601 string with 'Z' suffix.

    This ensures JavaScript `new Date(...)` treats the value as UTC.
    """
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc).isoformat()


@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan: ScanCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> ScanResponse:
    """
    Create a new scan.

    Args:
        scan: Scan creation data (includes name, source_type, source_path, etc.)
        db: Database session

    Returns:
        Created scan with generated ID and timestamps
    """
    scan_repo = ScanRepository()

    # Create scan directly with source info
    created = await scan_repo.create(db, obj_in=scan)
    return ScanResponse.model_validate(created)


@router.post("/scans/upload-zip", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan_from_zip(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
    file: UploadFile = ...,
    name: str = Form(...),
    description: str = Form(""),
    scan_type: str = Form("full"),
    config: str = Form("{}"),
) -> ScanResponse:
    """
    Create a new scan from uploaded ZIP file.

    Args:
        file: Uploaded ZIP file
        name: Scan task name
        description: Optional description
        scan_type: Type of scan (full/base/incremental)
        config: Scan configuration JSON
        db: Database session

    Returns:
        Created scan with generated ID and timestamps
    """
    import os
    import shutil
    import uuid
    from pathlib import Path

    from src.web.core.config import get_web_settings

    # Save uploaded file
    upload_dir = Path(get_web_settings().upload_dir) / "scans"
    upload_dir.mkdir(parents=True, exist_ok=True)

    file_id = str(uuid.uuid4())
    file_path = upload_dir / f"{file_id}.zip"

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Create scan with ZIP file reference
    scan_repo = ScanRepository()

    # Parse config JSON
    import json as json_lib
    try:
        config_dict = json_lib.loads(config) if config else {"engines": ["semgrep", "codeql", "agent"]}
    except:
        config_dict = {"engines": ["semgrep", "codeql", "agent"]}

    scan_data = ScanCreate(
        name=name,
        source_type="zip",
        source_path=str(file_path),
        scan_type=scan_type,
        config=config_dict,
    )

    created = await scan_repo.create(db, obj_in=scan_data)
    return ScanResponse.model_validate(created)


@router.post("/scans/{scan_id}/start", response_model=dict)
async def start_scan(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(require_api_key)] = None,
) -> dict:
    """
    Start a scan by dispatching it to Celery.

    Args:
        scan_id: ID of the scan to start
        db: Database session

    Returns:
        Dictionary with task_id and status

    Raises:
        HTTPException 404: If scan not found
        HTTPException 400: If scan cannot be started
    """
    from src.web.services.scan_executor import get_scan_executor
    from src.web.models.scan import ScanStatus

    executor = get_scan_executor()

    # Verify scan exists
    scan_repo = ScanRepository()
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Check if scan can be started
    if scan.status != ScanStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan {scan_id} is not in pending status (current: {scan.status})"
        )

    # Start the scan
    result = await executor.start_scan(scan_id)

    return result


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=1000, description="Number of items per page"),
    status: str | None = Query(None, description="Filter by scan status"),
    project_id: int | None = Query(None, description="Filter by project ID"),
) -> ScanListResponse:
    """
    List all scans with pagination.

    Args:
        db: Database session
        page: Page number (1-indexed)
        page_size: Number of items per page (max 1000)
        status: Optional filter by scan status
        project_id: Optional filter by project ID

    Returns:
        Paginated list of scans with total count
    """
    from src.web.models.scan import Scan

    scan_repo = ScanRepository()
    skip = (page - 1) * page_size

    # Build base query with ordering
    query = select(Scan).order_by(Scan.created_at.desc())

    # Apply filters
    filters = []
    if status:
        filters.append(Scan.status == status)
    if project_id is not None:
        filters.append(Scan.project_id == project_id)

    # Apply filters to query
    for filter_expr in filters:
        query = query.where(filter_expr)

    # Get paginated items
    query = query.offset(skip).limit(page_size)
    result = await db.execute(query)
    items = list(result.scalars().all())

    # Count total
    count_query = select(func.count()).select_from(Scan)
    for filter_expr in filters:
        count_query = count_query.where(filter_expr)
    count_result = await db.execute(count_query)
    total = count_result.scalar_one() or 0

    return ScanListResponse(
        items=[ScanResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> ScanResponse:
    """
    Get scan by ID.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        Scan details

    Raises:
        HTTPException 404: If scan not found
    """
    scan_repo = ScanRepository()
    scan = await scan_repo.get(db, id=scan_id)

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    return ScanResponse.model_validate(scan)


@router.get("/scans/{scan_id}/progress", response_model=ScanProgressResponse)
async def get_scan_progress(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> ScanProgressResponse:
    """
    Get detailed scan progress.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        Detailed scan progress including engine status, tokens, findings

    Raises:
        HTTPException 404: If scan not found
    """
    scan_repo = ScanRepository()
    phase_repo = ScanPhaseRepository()

    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Get phases
    phases = await phase_repo.get_by_scan(db, scan_id=scan_id)

    # Build phase info list
    phase_info_list = []
    completed_engines = 0
    running_engines = 0
    pending_engines = 0

    for phase in phases:
        status_map = {
            "pending": "pending",
            "running": "running",
            "completed": "completed",
            "failed": "failed",
            "skipped": "skipped"
        }
        phase_info_list.append(PhaseInfo(
            name=phase.phase_name,
            status=status_map.get(phase.status, phase.status),
            progress_percent=phase.progress_percent or 0,
            duration_seconds=phase.duration_seconds,
            findings=phase.findings_found or 0,
            tokens_used=phase.tokens_used or 0,
        ))

        if phase.status == "completed":
            completed_engines += 1
        elif phase.status == "running":
            running_engines += 1
        elif phase.status == "pending":
            pending_engines += 1

    # Build engines dict
    engines_dict = {
        "completed": [p.phase_name for p in phases if p.status == "completed"],
        "running": [p.phase_name for p in phases if p.status == "running"] or None,
        "pending": [p.phase_name for p in phases if p.status == "pending"],
    }

    # Calculate token info
    tokens = TokenInfo.calculate(
        used=scan.tokens_used or 0,
        budget=scan.tokens_budget or 100000
    )

    # Build findings summary
    findings_summary = FindingSummary(
        total=scan.findings_count or 0,
        verified=scan.verified_count or 0,
        false_positive=scan.false_positive_count or 0,
        by_severity={
            "critical": scan.critical_count or 0,
            "high": scan.high_count or 0,
            "medium": scan.medium_count or 0,
            "low": scan.low_count or 0,
            "info": scan.info_count or 0,
        }
    )

    return ScanProgressResponse(
        scan_id=scan.id,
        status=scan.status,
        progress_percent=scan.progress_percent or 0,
        current_phase=scan.current_phase,
        current_step=scan.current_step,
        current_engine=scan.current_engine,
        total_files=scan.total_files or 0,
        indexed_files=scan.indexed_files or 0,
        analyzed_files=scan.analyzed_files or 0,
        files_with_findings=scan.files_with_findings or 0,
        engines=engines_dict,
        tokens=tokens,
        findings=findings_summary,
        phases=phase_info_list,
        started_at=scan.started_at,
    )


@router.get("/scans/{scan_id}/phases")
async def get_scan_phases(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> dict:
    """
    Get scan phases details.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        List of scan phases with their status

    Raises:
        HTTPException 404: If scan not found
    """
    scan_repo = ScanRepository()
    phase_repo = ScanPhaseRepository()

    # Verify scan exists
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    phases = await phase_repo.get_by_scan(db, scan_id=scan_id)

    return {
        "scan_id": scan_id,
        "total": len(phases),
        "phases": [
            {
                "id": phase.id,
                "name": phase.phase_name,
                "engine_name": phase.engine_name,
                "status": phase.status,
                "current_step": phase.current_step,
                "progress_percent": phase.progress_percent,
                "files_processed": phase.files_processed,
                "findings_found": phase.findings_found,
                "tokens_used": phase.tokens_used,
                "started_at": _iso(phase.started_at),
                "completed_at": _iso(phase.completed_at),
                "duration_seconds": phase.duration_seconds,
                "error_message": phase.error_message,
            }
            for phase in phases
        ],
    }


@router.get("/scans/{scan_id}/events")
async def get_scan_events(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    event_type: str | None = Query(None, description="Filter by event type"),
) -> dict:
    """
    Get scan event stream.

    Args:
        scan_id: Scan ID
        db: Database session
        page: Page number
        page_size: Page size
        event_type: Optional event type filter

    Returns:
        Paginated list of scan events

    Raises:
        HTTPException 404: If scan not found
    """
    scan_repo = ScanRepository()
    event_repo = ScanEventRepository()

    # Verify scan exists
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    skip = (page - 1) * page_size
    events = await event_repo.get_by_scan(
        db, scan_id=scan_id, skip=skip, limit=page_size, event_type=event_type
    )

    return {
        "scan_id": scan_id,
        "total": len(events),
        "page": page,
        "page_size": page_size,
        "events": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "event_level": event.event_level,
                "message": event.message,
                "details": event.details,
                "engine_name": event.engine_name,
                "file_path": event.file_path,
                "file_index": event.file_index,
                "file_total": event.file_total,
                "tokens_used": event.tokens_used,
                "agent_turn": event.agent_turn,
                "agent_role": event.agent_role,
                "agent_message": event.agent_message,
                "created_at": _iso(event.created_at),
            }
            for event in events
        ],
    }


@router.get("/scans/{scan_id}/agent-conversation", response_model=AgentConversationResponse)
async def get_agent_conversation(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
    limit: int = Query(100, ge=1, le=500, description="Maximum number of messages"),
) -> AgentConversationResponse:
    """
    Get agent conversation for a scan.

    Args:
        scan_id: Scan ID
        db: Database session
        limit: Maximum number of messages to return

    Returns:
        Agent conversation with adversarial debate

    Raises:
        HTTPException 404: If scan not found
    """
    scan_repo = ScanRepository()
    event_repo = ScanEventRepository()

    # Verify scan exists
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Get agent conversation events
    agent_events = await event_repo.get_agent_conversation(
        db, scan_id=scan_id, limit=limit
    )

    # Build conversation messages
    conversation = []
    for event in agent_events:
        # Determine tokens
        tokens = event.tokens_used or 0
        tokens_input = None
        tokens_output = None

        # Parse from details if available
        if event.details:
            tokens_input = event.details.get("tokens_input")
            tokens_output = event.details.get("tokens_output")

        conversation.append(AgentConversationMessage(
            turn=event.agent_turn or 0,
            role=event.agent_role or "unknown",
            message=event.agent_message or event.message or "",
            reasoning=event.details.get("reasoning") if event.details else None,
            action=event.details.get("action") if event.details else None,
            tool_name=event.details.get("tool_name") if event.details else None,
            tool_input=event.details.get("tool_input") if event.details else None,
            tokens=tokens if tokens > 0 else None,
            tokens_input=tokens_input,
            tokens_output=tokens_output,
        ))

    # Get current phase (from most recent event)
    current_phase = scan.current_phase
    current_file = None
    if agent_events:
        latest_event = agent_events[-1]
        if latest_event.file_path:
            current_file = {
                "path": latest_event.file_path,
                "index": latest_event.file_index,
                "total": latest_event.file_total,
            }

    return AgentConversationResponse(
        scan_id=scan_id,
        phase=current_phase,
        current_file=current_file,
        conversation=conversation,
        adversarial_status=AdversarialStatus(
            active=scan.status == "running",
            round=0,  # TODO: Track from events
            max_rounds=5,
            current_findings=scan.findings_count or 0,
        ),
    )


@router.get("/scans/{scan_id}/current-file", response_model=CurrentFileResponse)
async def get_current_file(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> CurrentFileResponse:
    """
    Get current file being scanned with details.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        Current file with preview and agent actions

    Raises:
        HTTPException 404: If scan not found
    """
    scan_repo = ScanRepository()
    event_repo = ScanEventRepository()

    # Verify scan exists
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Get recent events to find current file
    recent_events = await event_repo.get_recent_by_scan(
        db, scan_id=scan_id, limit=50
    )

    current_file = None
    file_preview = None
    agent_actions = []

    # Find most recent file_start or file_complete event
    for event in recent_events:
        if event.event_type == "file_start" and event.file_path:
            current_file = {
                "path": event.file_path,
                "index": event.file_index,
                "total": event.file_total,
            }
            break
        elif event.event_type == "file_complete" and event.file_path:
            # Most recently completed file
            current_file = {
                "path": event.file_path,
                "index": event.file_index,
                "total": event.file_total,
                "completed": True
            }
            break

    # Build agent actions from events
    for event in recent_events:
        if event.event_type in ["agent_action", "adversarial_start", "adversarial_round"]:
            agent_actions.append({
                "timestamp": _iso(event.created_at),
                "action": event.event_type,
                "message": event.message,
                "details": event.details,
            })

    return CurrentFileResponse(
        scan_id=scan_id,
        current_file=current_file,
        file_preview=file_preview,  # TODO: Implement file preview
        agent_actions_on_file=agent_actions,
    )


@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=1000),
    severity: str | None = Query(None, description="Filter by severity"),
    status: str | None = Query(None, description="Filter by status"),
) -> dict:
    """
    Get findings for a scan.

    Args:
        scan_id: Scan ID
        db: Database session
        page: Page number
        page_size: Page size
        severity: Optional severity filter
        status: Optional status filter

    Returns:
        Paginated list of findings

    Raises:
        HTTPException 404: If scan not found
    """
    scan_repo = ScanRepository()
    finding_repo = FindingRepository()

    # Verify scan exists
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    skip = (page - 1) * page_size
    findings = await finding_repo.get_by_scan(
        db, scan_id=scan_id, skip=skip, limit=page_size, severity=severity, status=status
    )

    # Get summary
    summary = await finding_repo.get_summary(db, scan_id=scan_id)

    return {
        "scan_id": scan_id,
        "total": summary.get("total", 0),
        "page": page,
        "page_size": page_size,
        "summary": summary,
        "findings": [
            {
                "id": f.id,
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "file_path": f.file_path,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "function_name": f.function_name,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "engine": f.engine,
                "status": f.status,
                "cpg_path": f.cpg_path,
                "created_at": _iso(f.created_at),
            }
            for f in findings
        ],
    }


@router.patch("/scans/{scan_id}/findings/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    scan_id: int,
    finding_id: int,
    status_update: FindingUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: None = Depends(require_api_key),
) -> FindingResponse:
    """
    Update the status of a finding.

    Args:
        scan_id: Scan ID
        finding_id: Finding ID
        status_update: Status update data
        db: Database session

    Returns:
        Updated finding

    Raises:
        HTTPException 404: If scan or finding not found
        HTTPException 400: If status is invalid
    """
    from src.web.models.finding import Finding, FindingStatus

    scan_repo = ScanRepository()
    finding_repo = FindingRepository()

    # Verify scan exists
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Verify finding exists and belongs to scan
    finding = await finding_repo.get(db, id=finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found in scan {scan_id}"
        )

    # Validate status
    valid_statuses = [
        FindingStatus.PENDING,
        FindingStatus.CONFIRMED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.CONDITIONAL,
    ]
    if status_update.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {[s.value for s in valid_statuses]}"
        )

    # Update finding
    updated_finding = await finding_repo.update(
        db,
        db_obj=finding,
        obj_in={"status": status_update.status, "extra_metadata": status_update.extra_metadata}
    )

    return FindingResponse.model_validate(updated_finding)


@router.get("/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> dict:
    """
    Get scan report.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        Scan report

    Raises:
        HTTPException 404: If scan not found
    """
    scan_repo = ScanRepository()
    finding_repo = FindingRepository()

    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Get findings summary
    summary = await finding_repo.get_summary(db, scan_id=scan_id)

    # Get recent events for timeline
    event_repo = ScanEventRepository()
    recent_events = await event_repo.get_recent_by_scan(
        db, scan_id=scan_id, limit=20
    )

    return {
        "scan_id": scan_id,
        "project_id": scan.project_id,
        "status": scan.status,
        "scan_type": scan.scan_type,
        "progress_percent": scan.progress_percent,
        "findings": summary,
        "timeline": [
            {
                "timestamp": e.created_at.isoformat() if e.created_at else None,
                "type": e.event_type,
                "message": e.message,
                "details": e.details,
            }
            for e in recent_events
        ],
        "created_at": _iso(scan.created_at),
        "started_at": _iso(scan.started_at),
        "completed_at": _iso(scan.completed_at),
        "report_path": scan.report_path,
    }


@router.get("/scans/{scan_id}/report/csv")
async def export_scan_report_csv(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> StreamingResponse:
    """
    Export scan report as CSV.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        CSV file

    Raises:
        HTTPException 404: If scan not found
    """
    scan_repo = ScanRepository()
    finding_repo = FindingRepository()

    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Get findings
    findings_result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.severity.desc(), Finding.id)
    )
    findings = findings_result.scalars().all()

    # Create CSV
    output = StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "ID", "Severity", "Confidence", "Vulnerability Type",
        "File Path", "Line Start", "Line End", "Function",
        "Engine", "Status", "Description", "Created At"
    ])

    # Rows
    for finding in findings:
        writer.writerow([
            finding.id,
            finding.severity,
            f"{finding.confidence:.2f}",
            finding.vuln_type,
            finding.file_path,
            finding.line_start or "",
            finding.line_end or "",
            finding.function_name or "",
            finding.engine,
            finding.status,
            (finding.description or "")[:200],  # Truncate long descriptions
            _iso(finding.created_at) or "",
        ])

    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"deepvuln_scan_{scan_id}_{timestamp}.csv"

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue().encode('utf-8')]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


@router.get("/scans/{scan_id}/report/pdf")
async def export_scan_report_pdf(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> Response:
    """
    Export scan report as PDF (placeholder).

    Note: This is a placeholder implementation. For production use,
    consider using libraries like reportlab, weasyprint, or
    a dedicated PDF generation service.

    Args:
        scan_id: Scan ID
        db: Database session

    Returns:
        PDF file (placeholder)

    Raises:
        HTTPException 404: If scan not found
    """
    scan_repo = ScanRepository()

    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Get findings
    finding_repo = FindingRepository()
    findings_result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.severity.desc(), Finding.id)
    )
    findings = findings_result.scalars().all()

    # Create a simple text-based report as PDF placeholder
    # In production, use a proper PDF library
    lines = [
        f"DeepVuln Security Scan Report",
        f"=" * 50,
        f"",
        f"Scan ID: {scan_id}",
        f"Scan Name: {scan.name}",
        f"Status: {scan.status}",
        f"Created: {scan.created_at.isoformat() if scan.created_at else 'N/A'}",
        f"",
        f"Findings Summary",
        f"-" * 50,
        f"Total Findings: {len(findings)}",
        f"",
    ]

    # Group by severity
    severity_counts = {}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    for severity, count in sorted(severity_counts.items(), reverse=True):
        lines.append(f"{severity.upper()}: {count}")

    lines.append("")
    lines.append("Detailed Findings")
    lines.append("-" * 50)

    for i, finding in enumerate(findings[:50], 1):  # Limit to 50 findings
        lines.extend([
            f"",
            f"#{i}. {finding.vuln_type}",
            f"   Severity: {finding.severity}",
            f"   Location: {finding.file_path}:{finding.line_start}",
            f"   Engine: {finding.engine}",
            f"   Status: {finding.status}",
        ])
        if finding.description:
            lines.append(f"   Description: {finding.description[:100]}")

    report_text = "\n".join(lines)

    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"deepvuln_scan_{scan_id}_{timestamp}.txt"

    # Return as text file (PDF placeholder)
    return Response(
        content=report_text.encode('utf-8'),
        media_type="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


# ============================================================================
# Control Endpoints (P11-04)
# ============================================================================

@router.post("/scans/{scan_id}/pause", response_model=PauseScanResponse)
async def pause_scan(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: None = Depends(require_api_key),
) -> PauseScanResponse:
    """
    Pause a running scan.

    Args:
        scan_id: ID of the scan to pause
        db: Database session

    Returns:
        Pause result with checkpoint status

    Raises:
        HTTPException 404: If scan not found
        HTTPException 400: If scan cannot be paused
    """
    from src.web.services.scan_executor import get_scan_executor
    from src.web.models.scan import ScanStatus

    executor = get_scan_executor()

    # Check if scan exists first
    scan_repo = ScanRepository()
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Check if scan can be paused
    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan {scan_id} is not running (current: {scan.status})",
        )

    # Pause the scan
    result = await executor.pause_scan(scan_id=scan_id)

    return PauseScanResponse(**result)


@router.post("/scans/{scan_id}/resume", response_model=ResumeScanResponse)
async def resume_scan(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: None = Depends(require_api_key),
) -> ResumeScanResponse:
    """
    Resume a paused scan.

    Args:
        scan_id: ID of the scan to resume
        db: Database session

    Returns:
        Resume result with task ID

    Raises:
        HTTPException 404: If scan not found
        HTTPException 400: If scan cannot be resumed
    """
    from src.web.services.scan_executor import get_scan_executor
    from src.web.models.scan import ScanStatus

    executor = get_scan_executor()

    # Check if scan exists first
    scan_repo = ScanRepository()
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Check if scan can be resumed
    if scan.status != ScanStatus.PAUSED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan {scan_id} is not paused (current: {scan.status})",
        )

    # Resume the scan
    result = await executor.resume_scan(scan_id=scan_id)

    return ResumeScanResponse(**result)


@router.post("/scans/{scan_id}/cancel", response_model=CancelScanResponse)
async def cancel_scan(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: None = Depends(require_api_key),
) -> CancelScanResponse:
    """
    Cancel a scan.

    Args:
        scan_id: ID of the scan to cancel
        db: Database session

    Returns:
        Cancel result

    Raises:
        HTTPException 404: If scan not found
        HTTPException 400: If scan cannot be cancelled
    """
    from src.web.services.scan_executor import get_scan_executor
    from src.web.models.scan import ScanStatus

    executor = get_scan_executor()

    # Check if scan exists first
    scan_repo = ScanRepository()
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Check if scan can be cancelled
    if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan {scan_id} cannot be cancelled (current: {scan.status})",
        )

    # Cancel the scan
    result = await executor.cancel_scan(scan_id=scan_id)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel scan {scan_id}",
        )

    return CancelScanResponse(
        scan_id=scan_id,
        status=ScanStatus.CANCELLED,
        cancelled_at=datetime.now(),
        cleanup_started=True,
    )


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_control_status(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> ScanStatusResponse:
    """
    Get scan status with available control actions.

    Args:
        scan_id: ID of the scan
        db: Database session

    Returns:
        Scan status with available actions

    Raises:
        HTTPException 404: If scan not found
    """
    from src.web.models.scan import ScanStatus

    scan_repo = ScanRepository()

    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Determine available actions based on status
    available_actions = []
    can_pause = False
    can_resume = False
    can_cancel = False

    if scan.status == ScanStatus.RUNNING:
        available_actions = ["pause", "cancel"]
        can_pause = True
        can_cancel = True
    elif scan.status == ScanStatus.PENDING:
        available_actions = ["cancel"]
        can_cancel = True
    elif scan.status == ScanStatus.PAUSED:
        available_actions = ["resume", "cancel"]
        can_resume = True
        can_cancel = True
    elif scan.status == ScanStatus.FAILED:
        available_actions = ["retry", "cancel"]
        can_cancel = True

    return ScanStatusResponse(
        scan_id=scan_id,
        status=scan.status,
        progress_percent=scan.progress_percent,
        current_phase=scan.current_phase,
        available_actions=available_actions,
        can_pause=can_pause,
        can_resume=can_resume,
        can_cancel=can_cancel,
    )


# ============================================================================
# P14-08: Extended Query Endpoints
# ============================================================================

@router.get("/scans/{scan_id}/adversarial-debate")
async def get_adversarial_debate(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
    finding_id: Annotated[str | None, Query(description="Filter by specific finding ID")] = None,
) -> dict:
    """
    Get adversarial verification debate content (P14-08b).

    Returns the multi-round debate records between Attacker and Defender
    for verified findings.

    Args:
        scan_id: ID of the scan
        db: Database session
        finding_id: Optional filter for specific finding

    Returns:
        Dictionary with debate records and final verdicts
    """
    scan_repo = ScanRepository()
    finding_repo = FindingRepository()

    # Verify scan exists
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Get findings with adversarial verification data
    from src.web.models.finding import Finding as FindingModel
    from sqlalchemy import select

    query = select(FindingModel).where(
        FindingModel.scan_id == scan_id
    )

    if finding_id:
        query = query.where(FindingModel.id == finding_id)

    result = await db.execute(query)
    findings = result.scalars().all()

    # Extract adversarial verification data
    debates = []
    for finding in findings:
        if finding.extra_metadata:
            adv_data = finding.extra_metadata.get("adversarial_verification")
            if adv_data:
                debates.append({
                    "finding_id": finding.id,
                    "finding_title": finding.title,
                    "vuln_type": finding.vuln_type,
                    "status": adv_data.get("status"),
                    "confidence": adv_data.get("confidence"),
                    "rounds_count": adv_data.get("rounds_count", 0),
                    "rounds": adv_data.get("rounds", []),
                    "verdict": adv_data.get("verdict"),
                    "reasoning": adv_data.get("reasoning"),
                    "timeout": adv_data.get("timeout", False),
                })

    return {
        "scan_id": scan_id,
        "total_debates": len(debates),
        "debates": debates,
    }


@router.get("/scans/{scan_id}/token-usage")
async def get_token_usage(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> dict:
    """
    Get token usage statistics for a scan (P14-08c).

    Returns detailed token consumption with cost breakdown.

    Args:
        scan_id: ID of the scan
        db: Database session

    Returns:
        Dictionary with token usage statistics
    """
    scan_repo = ScanRepository()

    # Verify scan exists
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Extract token usage from scan record
    token_usage = scan.token_usage or {}
    tokens_used = scan.tokens_used or 0
    tokens_budget = scan.tokens_budget or 100000

    # Calculate cost (simple rate: $0.002 per 1K tokens)
    estimated_cost = token_usage.get("estimated_cost", round(tokens_used * 0.002 / 1000, 4))

    return {
        "scan_id": scan_id,
        "total_tokens": tokens_used,
        "tokens_budget": tokens_budget,
        "percent_used": round((tokens_used / tokens_budget * 100) if tokens_budget > 0 else 0, 2),
        "estimated_cost": estimated_cost,
        "breakdown": {
            "prompt_tokens": token_usage.get("prompt_tokens", 0),
            "completion_tokens": token_usage.get("completion_tokens", 0),
        },
    }


@router.get("/scans/{scan_id}/incremental-stats")
async def get_incremental_stats(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(optional_api_key)] = None,
) -> dict:
    """
    Get incremental scan statistics (P14-08d).

    Returns information about files changed and scanned in incremental mode.

    Args:
        scan_id: ID of the scan
        db: Database session

    Returns:
        Dictionary with incremental scan statistics
    """
    scan_repo = ScanRepository()

    # Verify scan exists
    scan = await scan_repo.get(db, id=scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Check if this was an incremental scan
    is_incremental = scan.scan_type == "incremental"
    incremental_stats = scan.incremental_stats or {}

    if not is_incremental and not incremental_stats:
        return {
            "scan_id": scan_id,
            "is_incremental": False,
            "message": "This was not an incremental scan",
        }

    return {
        "scan_id": scan_id,
        "is_incremental": True,
        "base_ref": incremental_stats.get("base_ref"),
        "head_ref": incremental_stats.get("head_ref"),
        "changed_files": {
            "total": incremental_stats.get("changed_files_count", 0),
            "added": incremental_stats.get("added_files", 0),
            "modified": incremental_stats.get("modified_files", 0),
            "deleted": incremental_stats.get("deleted_files_count", 0),
            "renamed": incremental_stats.get("renamed_files_count", 0),
        },
        "scanning": {
            "files_to_scan": incremental_stats.get("files_to_scan_count", 0),
            "total_files": scan.total_files,
        },
    }


# ============================================================================
# WebSocket Endpoint
# ============================================================================

from fastapi import WebSocket

from src.web.api.websocket import get_connection_manager


@router.websocket("/ws/{scan_id}")
async def websocket_scan_updates(
    websocket: WebSocket,
    scan_id: int,
) -> None:
    """
    WebSocket endpoint for real-time scan updates.

    Clients can connect to receive real-time updates about scan progress,
    including phase changes, findings, and completion status.

    Args:
        websocket: WebSocket connection
        scan_id: ID of the scan to monitor
    """
    manager = get_connection_manager()

    try:
        await manager.connect(websocket, scan_id)

        # Keep connection alive and handle incoming messages
        while True:
            data = await websocket.receive_text()

            # Handle client messages (e.g., ping, subscribe)
            try:
                message = json.loads(data)
                if message.get("type") == "ping":
                    # Respond with pong
                    from src.web.api.websocket import WebSocketEvent
                    await manager.send_personal(
                        WebSocketEvent(event_type="pong", data={}),
                        websocket,
                    )
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from WebSocket client: {data}")

    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
        await manager.disconnect(websocket)
