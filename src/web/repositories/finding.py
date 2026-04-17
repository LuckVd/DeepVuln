"""Finding repository for database operations."""

from typing import Optional

from sqlalchemy import select, and_, case
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.models.finding import Finding
from src.web.models.schemas import FindingCreate, FindingUpdate
from src.web.repositories.base import AsyncRepository

# Severity weight mapping for proper numeric ordering
_SEVERITY_WEIGHT = case(
    (Finding.severity == "critical", 5),
    (Finding.severity == "high", 4),
    (Finding.severity == "medium", 3),
    (Finding.severity == "low", 2),
    (Finding.severity == "info", 1),
    else_=0,
)


class FindingRepository(
    AsyncRepository[Finding, FindingCreate, FindingUpdate]
):
    """Repository for Finding model."""

    def __init__(self):
        """Initialize repository with Finding model."""
        super().__init__(Finding)

    async def get_by_scan(
        self,
        db: AsyncSession,
        *,
        scan_id: int,
        skip: int = 0,
        limit: int = 100,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        engine: Optional[str] = None,
        sort_field: Optional[str] = None,
        sort_dir: Optional[str] = None,
    ) -> list[Finding]:
        """
        Get findings for a scan.

        Args:
            db: Database session
            scan_id: Scan ID
            skip: Number of records to skip
            limit: Maximum number of records to return
            severity: Optional severity filter
            status: Optional status filter
            engine: Optional engine filter
            sort_field: Sort field (severity, confidence, engine)
            sort_dir: Sort direction (asc, desc)

        Returns:
            List of findings
        """
        query = select(Finding).where(Finding.scan_id == scan_id)

        if severity:
            query = query.where(Finding.severity == severity)
        if status:
            query = query.where(Finding.status == status)
        if engine:
            query = query.where(Finding.engine == engine)

        # Build ORDER BY clauses
        order_clauses = []
        desc = sort_dir != "asc"

        if sort_field == "severity":
            order_clauses.append(_SEVERITY_WEIGHT.desc() if desc else _SEVERITY_WEIGHT.asc())
        elif sort_field == "confidence":
            order_clauses.append(Finding.confidence.desc() if desc else Finding.confidence.asc())
        elif sort_field == "engine":
            order_clauses.append(Finding.engine.desc() if desc else Finding.engine.asc())
        else:
            # Default: severity (numeric weight) desc, then line_start asc
            order_clauses.append(_SEVERITY_WEIGHT.desc())
            order_clauses.append(Finding.line_start.asc())

        query = query.order_by(*order_clauses).offset(skip).limit(limit)

        result = await db.execute(query)
        return list(result.scalars().all())

    async def get_by_file(
        self,
        db: AsyncSession,
        *,
        scan_id: int,
        file_path: str
    ) -> list[Finding]:
        """
        Get findings for a specific file in a scan.

        Args:
            db: Database session
            scan_id: Scan ID
            file_path: File path

        Returns:
            List of findings
        """
        result = await db.execute(
            select(Finding)
            .where(
                and_(
                    Finding.scan_id == scan_id,
                    Finding.file_path == file_path
                )
            )
            .order_by(Finding.line_start.asc())
        )
        return list(result.scalars().all())

    async def count_by_severity(
        self,
        db: AsyncSession,
        *,
        scan_id: int
    ) -> dict[str, int]:
        """
        Count findings by severity for a scan.

        Args:
            db: Database session
            scan_id: Scan ID

        Returns:
            Dictionary with severity counts
        """
        from sqlalchemy import func

        result = await db.execute(
            select(
                Finding.severity,
                func.count(Finding.id)
            )
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.severity)
        )

        counts = {row[0]: row[1] for row in result.all()}
        return {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "info": counts.get("info", 0),
        }

    async def get_summary(
        self,
        db: AsyncSession,
        *,
        scan_id: int
    ) -> dict:
        """
        Get finding summary for a scan.

        Args:
            db: Database session
            scan_id: Scan ID

        Returns:
            Summary dictionary
        """
        from sqlalchemy import func

        # Total count
        total_result = await db.execute(
            select(func.count(Finding.id)).where(Finding.scan_id == scan_id)
        )
        total = total_result.scalar_one() or 0

        # Verified count
        verified_result = await db.execute(
            select(func.count(Finding.id))
            .where(
                and_(
                    Finding.scan_id == scan_id,
                    Finding.status == "confirmed"
                )
            )
        )
        verified = verified_result.scalar_one() or 0

        # False positive count
        fp_result = await db.execute(
            select(func.count(Finding.id))
            .where(
                and_(
                    Finding.scan_id == scan_id,
                    Finding.status == "false_positive"
                )
            )
        )
        false_positive = fp_result.scalar_one() or 0

        # By severity
        severity_counts = await self.count_by_severity(db, scan_id=scan_id)

        return {
            "total": total,
            "verified": verified,
            "false_positive": false_positive,
            "by_severity": severity_counts,
        }
