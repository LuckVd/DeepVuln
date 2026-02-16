"""SQLite storage backend for threat intelligence data."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    PoCInfo,
    SeverityLevel,
)

logger = get_logger(__name__)


class ThreatIntelDatabase:
    """SQLite database for threat intelligence storage.

    Provides persistent storage for CVE and PoC data with
    full-text search capabilities.
    """

    def __init__(self, db_path: str = "./data/threat_intel.db") -> None:
        """Initialize database.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        """Connect to database and create tables."""
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row

        await self._create_tables()
        logger.info(f"Connected to database: {self.db_path}")

    async def close(self) -> None:
        """Close database connection."""
        if self._db:
            await self._db.close()
            self._db = None

    async def _create_tables(self) -> None:
        """Create database tables."""
        await self._db.executescript("""
            -- CVE table
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                description TEXT,
                description_zh TEXT,
                cvss_v2_score REAL,
                cvss_v3_score REAL,
                cvss_v2_vector TEXT,
                cvss_v3_vector TEXT,
                severity TEXT NOT NULL,
                cwe_ids TEXT,  -- JSON array
                affected_products TEXT,  -- JSON array
                affected_versions TEXT,  -- JSON array
                ref_links TEXT,  -- JSON array (renamed from 'references' - reserved keyword)
                patches TEXT,  -- JSON array
                has_poc INTEGER DEFAULT 0,
                kev INTEGER DEFAULT 0,
                ransomware_use INTEGER DEFAULT 0,
                tags TEXT,  -- JSON array
                published_date TEXT,
                modified_date TEXT,
                synced_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            -- PoC table
            CREATE TABLE IF NOT EXISTS pocs (
                poc_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                cve_ids TEXT,  -- JSON array
                title TEXT NOT NULL,
                description TEXT,
                poc_type TEXT,
                code_url TEXT,
                code_local_path TEXT,
                language TEXT,
                verified INTEGER DEFAULT 0,
                dangerous INTEGER DEFAULT 0,
                author TEXT,
                stars INTEGER DEFAULT 0,
                forks INTEGER DEFAULT 0,
                published_date TEXT,
                added_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            -- CVE-PoC junction table for many-to-many
            CREATE TABLE IF NOT EXISTS cve_poc_map (
                cve_id TEXT,
                poc_id TEXT,
                PRIMARY KEY (cve_id, poc_id),
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id),
                FOREIGN KEY (poc_id) REFERENCES pocs(poc_id)
            );

            -- Sync metadata table
            CREATE TABLE IF NOT EXISTS sync_meta (
                source TEXT PRIMARY KEY,
                last_sync TEXT,
                last_success TEXT,
                records_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending'
            );

            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
            CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev);
            CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date);
            CREATE INDEX IF NOT EXISTS idx_cves_synced ON cves(synced_at);
            CREATE INDEX IF NOT EXISTS idx_pocs_source ON pocs(source);
            CREATE INDEX IF NOT EXISTS idx_pocs_verified ON pocs(verified);

            -- Full-text search virtual table
            CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
                cve_id, description, description_zh,
                content='cves', content_rowid='rowid'
            );

            -- Triggers to keep FTS in sync
            CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
                INSERT INTO cves_fts(rowid, cve_id, description, description_zh)
                VALUES (new.rowid, new.cve_id, new.description, new.description_zh);
            END;

            CREATE TRIGGER IF NOT EXISTS cves_ad AFTER DELETE ON cves BEGIN
                INSERT INTO cves_fts(cves_fts, rowid, cve_id, description, description_zh)
                VALUES('delete', old.rowid, old.cve_id, old.description, old.description_zh);
            END;

            CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE ON cves BEGIN
                INSERT INTO cves_fts(cves_fts, rowid, cve_id, description, description_zh)
                VALUES('delete', old.rowid, old.cve_id, old.description, old.description_zh);
                INSERT INTO cves_fts(rowid, cve_id, description, description_zh)
                VALUES (new.rowid, new.cve_id, new.description, new.description_zh);
            END;
        """)

        await self._db.commit()

    async def save_cve(self, cve: CVEInfo) -> bool:
        """Save or update a CVE.

        Args:
            cve: CVEInfo to save.

        Returns:
            True if successful.
        """
        await self._db.execute("""
            INSERT INTO cves (
                cve_id, source, description, description_zh,
                cvss_v2_score, cvss_v3_score, cvss_v2_vector, cvss_v3_vector,
                severity, cwe_ids, affected_products, affected_versions,
                ref_links, patches, has_poc, kev, ransomware_use, tags,
                published_date, modified_date, synced_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                source = excluded.source,
                description = excluded.description,
                cvss_v3_score = excluded.cvss_v3_score,
                cvss_v3_vector = excluded.cvss_v3_vector,
                severity = excluded.severity,
                has_poc = excluded.has_poc,
                kev = excluded.kev,
                ransomware_use = excluded.ransomware_use,
                tags = excluded.tags,
                modified_date = excluded.modified_date,
                synced_at = excluded.synced_at
        """, (
            cve.cve_id,
            cve.source,
            cve.description,
            cve.description_zh,
            cve.cvss_v2_score,
            cve.cvss_v3_score,
            cve.cvss_v2_vector,
            cve.cvss_v3_vector,
            cve.severity.value,
            json.dumps(cve.cwe_ids),
            json.dumps(cve.affected_products),
            json.dumps(cve.affected_versions),
            json.dumps(cve.references),
            json.dumps(cve.patches),
            int(cve.has_poc),
            int(cve.kev),
            int(cve.ransomware_use),
            json.dumps(cve.tags),
            cve.published_date.isoformat() if cve.published_date else None,
            cve.modified_date.isoformat() if cve.modified_date else None,
            cve.synced_at.isoformat() if cve.synced_at else datetime.now().isoformat(),
        ))

        await self._db.commit()
        return True

    async def save_poc(self, poc: PoCInfo) -> bool:
        """Save or update a PoC.

        Args:
            poc: PoCInfo to save.

        Returns:
            True if successful.
        """
        await self._db.execute("""
            INSERT INTO pocs (
                poc_id, source, cve_ids, title, description, poc_type,
                code_url, code_local_path, language, verified, dangerous,
                author, stars, forks, published_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(poc_id) DO UPDATE SET
                cve_ids = excluded.cve_ids,
                title = excluded.title,
                verified = excluded.verified,
                stars = excluded.stars
        """, (
            poc.poc_id,
            poc.source,
            json.dumps(poc.cve_ids),
            poc.title,
            poc.description,
            poc.poc_type,
            poc.code_url,
            poc.code_local_path,
            poc.language,
            int(poc.verified),
            int(poc.dangerous),
            poc.author,
            poc.stars,
            poc.forks,
            poc.published_date.isoformat() if poc.published_date else None,
        ))

        # Update CVE-PoC mapping
        for cve_id in poc.cve_ids:
            await self._db.execute("""
                INSERT OR IGNORE INTO cve_poc_map (cve_id, poc_id)
                VALUES (?, ?)
            """, (cve_id, poc.poc_id))

            # Mark CVE as having PoC
            await self._db.execute("""
                UPDATE cves SET has_poc = 1 WHERE cve_id = ?
            """, (cve_id,))

        await self._db.commit()
        return True

    async def get_cve(self, cve_id: str) -> CVEInfo | None:
        """Get a CVE by ID.

        Args:
            cve_id: CVE identifier.

        Returns:
            CVEInfo or None.
        """
        async with self._db.execute(
            "SELECT * FROM cves WHERE cve_id = ?", (cve_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return self._row_to_cve(row) if row else None

    async def search_cves(
        self,
        query: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[CVEInfo]:
        """Search CVEs using full-text search.

        Args:
            query: Search query.
            limit: Maximum results.
            offset: Result offset.

        Returns:
            List of CVEInfo objects.
        """
        # Try FTS first, fall back to LIKE if FTS returns no results
        try:
            async with self._db.execute("""
                SELECT c.* FROM cves c
                WHERE c.rowid IN (
                    SELECT rowid FROM cves_fts WHERE cves_fts MATCH ?
                )
                ORDER BY c.kev DESC, c.cvss_v3_score DESC NULLS LAST
                LIMIT ? OFFSET ?
            """, (query, limit, offset)) as cursor:
                rows = await cursor.fetchall()
                if rows:
                    return [self._row_to_cve(row) for row in rows]
        except Exception:
            pass  # Fall through to LIKE search

        # Fallback to LIKE search
        async with self._db.execute("""
            SELECT * FROM cves
            WHERE description LIKE ? OR cve_id LIKE ?
            ORDER BY kev DESC, cvss_v3_score DESC NULLS LAST
            LIMIT ? OFFSET ?
        """, (f"%{query}%", f"%{query}%", limit, offset)) as cursor:
            rows = await cursor.fetchall()
            return [self._row_to_cve(row) for row in rows]

    async def get_cves_by_severity(
        self,
        severity: SeverityLevel,
        limit: int = 100,
    ) -> list[CVEInfo]:
        """Get CVEs by severity level.

        Args:
            severity: Severity level.
            limit: Maximum results.

        Returns:
            List of CVEInfo objects.
        """
        async with self._db.execute("""
            SELECT * FROM cves
            WHERE severity = ?
            ORDER BY cvss_v3_score DESC, published_date DESC
            LIMIT ?
        """, (severity.value, limit)) as cursor:
            rows = await cursor.fetchall()
            return [self._row_to_cve(row) for row in rows]

    async def get_kev_cves(self, limit: int = 100) -> list[CVEInfo]:
        """Get Known Exploited Vulnerabilities.

        Args:
            limit: Maximum results.

        Returns:
            List of CVEInfo objects.
        """
        async with self._db.execute("""
            SELECT * FROM cves
            WHERE kev = 1
            ORDER BY published_date DESC
            LIMIT ?
        """, (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [self._row_to_cve(row) for row in rows]

    async def get_pocs_for_cve(self, cve_id: str) -> list[PoCInfo]:
        """Get all PoCs for a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            List of PoCInfo objects.
        """
        async with self._db.execute("""
            SELECT p.* FROM pocs p
            JOIN cve_poc_map m ON p.poc_id = m.poc_id
            WHERE m.cve_id = ?
            ORDER BY p.verified DESC, p.stars DESC
        """, (cve_id,)) as cursor:
            rows = await cursor.fetchall()
            return [self._row_to_poc(row) for row in rows]

    async def get_recent_cves(
        self,
        days: int = 7,
        limit: int = 100,
    ) -> list[CVEInfo]:
        """Get recently published CVEs.

        Args:
            days: Days to look back.
            limit: Maximum results.

        Returns:
            List of CVEInfo objects.
        """
        async with self._db.execute("""
            SELECT * FROM cves
            WHERE date(published_date) >= date('now', ?)
            ORDER BY published_date DESC
            LIMIT ?
        """, (f"-{days} days", limit)) as cursor:
            rows = await cursor.fetchall()
            return [self._row_to_cve(row) for row in rows]

    async def update_sync_meta(
        self,
        source: str,
        records_count: int,
        status: str = "success",
    ) -> None:
        """Update sync metadata.

        Args:
            source: Source name.
            records_count: Number of records synced.
            status: Sync status.
        """
        now = datetime.now().isoformat()

        await self._db.execute("""
            INSERT INTO sync_meta (source, last_sync, last_success, records_count, status)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET
                last_sync = excluded.last_sync,
                last_success = CASE WHEN ? = 'success' THEN excluded.last_sync ELSE last_success END,
                records_count = excluded.records_count,
                status = excluded.status
        """, (source, now, now, records_count, status, status))

        await self._db.commit()

    async def get_sync_meta(self, source: str) -> dict[str, Any] | None:
        """Get sync metadata for a source.

        Args:
            source: Source name.

        Returns:
            Metadata dictionary or None.
        """
        async with self._db.execute(
            "SELECT * FROM sync_meta WHERE source = ?", (source,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_stats(self) -> dict[str, Any]:
        """Get database statistics.

        Returns:
            Statistics dictionary.
        """
        stats = {}

        # CVE counts
        async with self._db.execute(
            "SELECT COUNT(*) as count FROM cves"
        ) as cursor:
            row = await cursor.fetchone()
            stats["total_cves"] = row["count"] if row else 0

        async with self._db.execute(
            "SELECT COUNT(*) as count FROM cves WHERE kev = 1"
        ) as cursor:
            row = await cursor.fetchone()
            stats["kev_count"] = row["count"] if row else 0

        async with self._db.execute(
            "SELECT COUNT(*) as count FROM cves WHERE has_poc = 1"
        ) as cursor:
            row = await cursor.fetchone()
            stats["cves_with_poc"] = row["count"] if row else 0

        # PoC counts
        async with self._db.execute(
            "SELECT COUNT(*) as count FROM pocs"
        ) as cursor:
            row = await cursor.fetchone()
            stats["total_pocs"] = row["count"] if row else 0

        # Severity distribution
        async with self._db.execute("""
            SELECT severity, COUNT(*) as count
            FROM cves GROUP BY severity
        """) as cursor:
            rows = await cursor.fetchall()
            stats["severity_distribution"] = {row["severity"]: row["count"] for row in rows}

        return stats

    def _row_to_cve(self, row: aiosqlite.Row) -> CVEInfo:
        """Convert database row to CVEInfo.

        Args:
            row: Database row.

        Returns:
            CVEInfo object.
        """
        return CVEInfo(
            cve_id=row["cve_id"],
            source=row["source"],
            description=row["description"] or "",
            description_zh=row["description_zh"],
            cvss_v2_score=row["cvss_v2_score"],
            cvss_v3_score=row["cvss_v3_score"],
            cvss_v2_vector=row["cvss_v2_vector"],
            cvss_v3_vector=row["cvss_v3_vector"],
            severity=SeverityLevel(row["severity"]),
            cwe_ids=json.loads(row["cwe_ids"]) if row["cwe_ids"] else [],
            affected_products=json.loads(row["affected_products"]) if row["affected_products"] else [],
            affected_versions=json.loads(row["affected_versions"]) if row["affected_versions"] else [],
            references=json.loads(row["ref_links"]) if row["ref_links"] else [],
            patches=json.loads(row["patches"]) if row["patches"] else [],
            has_poc=bool(row["has_poc"]),
            kev=bool(row["kev"]),
            ransomware_use=bool(row["ransomware_use"]),
            tags=json.loads(row["tags"]) if row["tags"] else [],
            published_date=datetime.fromisoformat(row["published_date"]) if row["published_date"] else datetime.now(),
            modified_date=datetime.fromisoformat(row["modified_date"]) if row["modified_date"] else None,
            synced_at=datetime.fromisoformat(row["synced_at"]) if row["synced_at"] else None,
        )

    def _row_to_poc(self, row: aiosqlite.Row) -> PoCInfo:
        """Convert database row to PoCInfo.

        Args:
            row: Database row.

        Returns:
            PoCInfo object.
        """
        return PoCInfo(
            poc_id=row["poc_id"],
            source=row["source"],
            cve_ids=json.loads(row["cve_ids"]) if row["cve_ids"] else [],
            title=row["title"],
            description=row["description"],
            poc_type=row["poc_type"] or "poc",
            code_url=row["code_url"],
            code_local_path=row["code_local_path"],
            language=row["language"],
            verified=bool(row["verified"]),
            dangerous=bool(row["dangerous"]),
            author=row["author"],
            stars=row["stars"] or 0,
            forks=row["forks"] or 0,
            published_date=datetime.fromisoformat(row["published_date"]) if row["published_date"] else None,
        )

    async def __aenter__(self) -> "ThreatIntelDatabase":
        """Enter async context."""
        await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        await self.close()
