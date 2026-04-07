"""Finding repository for database operations."""

from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.models.finding import Finding
from src.web.models.schemas import FindingCreate, FindingUpdate
from src.web.repositories.base import AsyncRepository


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
        status: Optional[str] = None
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

        Returns:
            List of findings
        """
        query = select(Finding).where(Finding.scan_id == scan_id)

        if severity:
            query = query.where(Finding.severity == severity)
        if status:
            query = query.where(Finding.status == status)

        query = query.order_by(
            Finding.severity.desc(),
            Finding.line_start.asc()
        ).offset(skip).limit(limit)

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
