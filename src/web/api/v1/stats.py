"""Dashboard statistics API endpoints."""

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_

from src.web.api.deps import get_db
from src.web.core.security import require_auth
from src.web.models.scan import Scan, ScanStatus
from src.web.models.finding import Finding

router = APIRouter(dependencies=[Depends(require_auth)])


@router.get("/stats/dashboard")
async def get_dashboard_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """
    Get dashboard statistics.

    Returns:
        Dictionary with total scans, active scans, vulnerabilities count,
        and critical vulnerabilities count
    """
    # Total scans count
    total_scans_result = await db.execute(
        select(func.count()).select_from(Scan)
    )
    total_scans = total_scans_result.scalar_one() or 0

    # Active scans (running)
    active_scans_result = await db.execute(
        select(func.count()).select_from(Scan).where(
            Scan.status == ScanStatus.RUNNING
        )
    )
    active_scans = active_scans_result.scalar_one() or 0

    # Total vulnerabilities across all scans
    total_vulns_result = await db.execute(
        select(func.count()).select_from(Finding)
    )
    total_vulns = total_vulns_result.scalar_one() or 0

    # Critical vulnerabilities
    critical_vulns_result = await db.execute(
        select(func.count()).select_from(Finding).where(
            Finding.severity == "critical"
        )
    )
    critical_vulns = critical_vulns_result.scalar_one() or 0

    # Severity breakdown
    severity_stats = await db.execute(
        select(
            Finding.severity,
            func.count(Finding.id)
        ).group_by(Finding.severity)
    )
    severity_breakdown = {
        severity: count for severity, count in (severity_stats.all() or [])
    }

    # Recent scans (last 7 days)
    seven_days_ago = datetime.now() - timedelta(days=7)
    recent_scans_result = await db.execute(
        select(func.count()).select_from(Scan).where(
            Scan.created_at >= seven_days_ago
        )
    )
    recent_scans = recent_scans_result.scalar_one() or 0

    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "total_vulns": total_vulns,
        "critical_vulns": critical_vulns,
        "severity_breakdown": {
            "critical": severity_breakdown.get("critical", 0),
            "high": severity_breakdown.get("high", 0),
            "medium": severity_breakdown.get("medium", 0),
            "low": severity_breakdown.get("low", 0),
            "info": severity_breakdown.get("info", 0),
        },
        "recent_scans": recent_scans,
    }


@router.get("/stats/recent-activity")
async def get_recent_activity(
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(10, ge=1, le=50, description="Number of items to return"),
) -> dict:
    """
    Get recent scan activity for dashboard.

    Returns:
        List of recent scans with status and findings count
    """
    # Get recent scans
    result = await db.execute(
        select(Scan)
        .order_by(Scan.created_at.desc())
        .limit(limit)
    )
    scans = result.scalars().all()

    return {
        "items": [
            {
                "id": scan.id,
                "name": scan.name,
                "status": scan.status,
                "progress_percent": scan.progress_percent or 0,
                "findings_count": scan.findings_count or 0,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            }
            for scan in scans
        ],
    }


@router.get("/stats/vulnerability-trends")
async def get_vulnerability_trends(
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(30, ge=1, le=90, description="Number of days to analyze"),
) -> dict:
    """
    Get vulnerability trends over time.

    Returns:
        Daily vulnerability counts for the specified period
    """
    start_date = datetime.now() - timedelta(days=days)

    # Get findings created per day
    result = await db.execute(
        select(
            func.date(Finding.created_at).label('date'),
            Finding.severity,
            func.count(Finding.id).label('count')
        ).where(
            Finding.created_at >= start_date
        ).group_by(
            func.date(Finding.created_at),
            Finding.severity
        )
    )
    daily_data = result.all()

    # Organize by date
    trends = {}
    for date, severity, count in daily_data:
        date_str = date.isoformat() if date else None
        if date_str not in trends:
            trends[date_str] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }
        if severity:
            trends[date_str][severity] = count

    return {
        "period_days": days,
        "start_date": start_date.isoformat(),
        "end_date": datetime.now().isoformat(),
        "data": trends,
    }


@router.get("/stats/vulnerabilities")
async def get_vulnerabilities_list(
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: str | None = Query(None, description="Filter by severity"),
    status: str | None = Query(None, description="Filter by status"),
    search: str | None = Query(None, description="Search in vuln_type, file_path, description"),
) -> dict:
    """
    Get global vulnerabilities list across all scans.

    Returns:
        Paginated list of findings with scan information
    """
    # Build base query
    query = select(Finding).join(Scan).order_by(Finding.created_at.desc())

    # Apply filters
    conditions = []
    if severity:
        conditions.append(Finding.severity == severity)
    if status:
        conditions.append(Finding.status == status)
    if search:
        search_pattern = f"%{search}%"
        conditions.append(
            or_(
                Finding.vuln_type.ilike(search_pattern),
                Finding.file_path.ilike(search_pattern),
                Finding.description.ilike(search_pattern),
            )
        )

    if conditions:
        query = query.where(and_(*conditions))

    # Get total count
    count_query = select(func.count()).select_from(Finding)
    if conditions:
        count_query = count_query.where(and_(*conditions))
    count_result = await db.execute(count_query)
    total = count_result.scalar_one() or 0

    # Get paginated results
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    result = await db.execute(query)
    findings = result.scalars().all()

    # Get scan names for each finding
    scan_ids = [f.scan_id for f in findings]
    scans_result = await db.execute(
        select(Scan.id, Scan.name).where(Scan.id.in_(scan_ids))
    )
    scan_names = {scan_id: name for scan_id, name in scans_result.all()}

    return {
        "items": [
            {
                "id": f.id,
                "scan_id": f.scan_id,
                "scan_name": scan_names.get(f.scan_id, "Unknown"),
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "file_path": f.file_path,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "function_name": f.function_name,
                "title": f.title,
                "description": f.description,
                "engine": f.engine,
                "status": f.status,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in findings
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/stats/vulnerabilities/summary")
async def get_vulnerabilities_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """
    Get global vulnerabilities summary statistics.

    Returns:
        Summary with total, verified, false positive counts by severity
    """
    # Total count
    total_result = await db.execute(select(func.count()).select_from(Finding))
    total = total_result.scalar_one() or 0

    # By status
    status_result = await db.execute(
        select(Finding.status, func.count(Finding.id))
        .group_by(Finding.status)
    )
    by_status = {status: count for status, count in status_result.all() or []}

    # By severity
    severity_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
    )
    by_severity = {severity: count for severity, count in severity_result.all() or []}

    # Verified count
    verified_result = await db.execute(
        select(func.count()).select_from(Finding).where(Finding.status == "confirmed")
    )
    verified = verified_result.scalar_one() or 0

    # False positive count
    fp_result = await db.execute(
        select(func.count()).select_from(Finding).where(Finding.status == "false_positive")
    )
    false_positive = fp_result.scalar_one() or 0

    return {
        "total": total,
        "verified": verified,
        "false_positive": false_positive,
        "by_status": by_status,
        "by_severity": {
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "low": by_severity.get("low", 0),
            "info": by_severity.get("info", 0),
        },
    }
