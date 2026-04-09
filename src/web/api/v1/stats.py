"""Dashboard statistics API endpoints."""

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from src.web.api.deps import get_db
from src.web.api.v1.scans import router as scans_router
from src.web.models.scan import Scan, ScanStatus
from src.web.models.finding import Finding

router = APIRouter()


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
