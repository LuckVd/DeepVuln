"""CISA Known Exploited Vulnerabilities (KEV) client."""

from datetime import datetime
from typing import Any

import aiohttp

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.core.data_models import CVEInfo

logger = get_logger(__name__)


class CISAKEVClient:
    """CISA Known Exploited Vulnerabilities catalog client.

    Fetches the KEV catalog from CISA and provides lookup/enrichment
    capabilities for CVE data.

    Catalog URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    JSON URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self) -> None:
        """Initialize CISA KEV client."""
        self._kev_cache: dict[str, dict[str, Any]] = {}
        self._last_sync: datetime | None = None

    async def sync(self) -> int:
        """Sync the KEV catalog from CISA.

        Returns:
            Number of KEV entries synced.
        """
        logger.info("Syncing CISA KEV catalog...")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.KEV_URL) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}")

                    data = await response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            self._kev_cache.clear()

            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID", "")
                if cve_id:
                    self._kev_cache[cve_id] = vuln

            self._last_sync = datetime.now()
            logger.info(f"Synced {len(self._kev_cache)} KEV entries")

            return len(self._kev_cache)

        except Exception as e:
            logger.error(f"Failed to sync KEV catalog: {e}")
            raise

    def is_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog.

        Args:
            cve_id: CVE identifier.

        Returns:
            True if CVE is known exploited.
        """
        return cve_id in self._kev_cache

    def get_kev_entry(self, cve_id: str) -> dict[str, Any] | None:
        """Get KEV entry for a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            KEV entry data or None.
        """
        return self._kev_cache.get(cve_id)

    def enrich_cve(self, cve: CVEInfo) -> CVEInfo:
        """Enrich CVE info with KEV data.

        Args:
            cve: CVEInfo to enrich.

        Returns:
            Enriched CVEInfo.
        """
        kev_entry = self._kev_cache.get(cve.cve_id)

        if kev_entry:
            cve.kev = True

            # Check for ransomware use
            if kev_entry.get("knownRansomwareCampaignUse") == "Known":
                cve.ransomware_use = True
                if "ransomware" not in cve.tags:
                    cve.tags.append("ransomware")

            # Add KEV tag
            if "known-exploited" not in cve.tags:
                cve.tags.append("known-exploited")

            # Add vendor/project info
            vendor = kev_entry.get("vendorProject", "")
            product = kev_entry.get("product", "")
            if vendor and product:
                product_str = f"{vendor}/{product}"
                if product_str not in cve.affected_products:
                    cve.affected_products.append(product_str)

            # Add required action if available
            action = kev_entry.get("requiredAction", "")
            if action and "action-required" not in cve.tags:
                cve.tags.append("action-required")

        return cve

    def get_all_kev_cves(self) -> list[str]:
        """Get all CVE IDs in the KEV catalog.

        Returns:
            List of CVE IDs.
        """
        return list(self._kev_cache.keys())

    def get_kev_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Get KEV entries added within a date range.

        Args:
            start_date: Start of date range.
            end_date: End of date range.

        Returns:
            List of KEV entries.
        """
        if end_date is None:
            end_date = datetime.now()

        results = []

        for _cve_id, entry in self._kev_cache.items():
            date_added_str = entry.get("dateAdded", "")
            if not date_added_str:
                continue

            try:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d")
                if start_date <= date_added <= end_date:
                    results.append(entry)
            except ValueError:
                continue

        return results

    def get_kev_by_vendor(self, vendor: str) -> list[dict[str, Any]]:
        """Get KEV entries for a specific vendor.

        Args:
            vendor: Vendor name (case-insensitive).

        Returns:
            List of KEV entries.
        """
        vendor_lower = vendor.lower()
        results = []

        for entry in self._kev_cache.values():
            entry_vendor = entry.get("vendorProject", "").lower()
            if vendor_lower in entry_vendor:
                results.append(entry)

        return results

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the KEV catalog.

        Returns:
            Dictionary of statistics.
        """
        if not self._kev_cache:
            return {
                "total": 0,
                "last_sync": None,
                "ransomware_count": 0,
            }

        ransomware_count = sum(
            1
            for entry in self._kev_cache.values()
            if entry.get("knownRansomwareCampaignUse") == "Known"
        )

        vendors: dict[str, int] = {}
        for entry in self._kev_cache.values():
            vendor = entry.get("vendorProject", "Unknown")
            vendors[vendor] = vendors.get(vendor, 0) + 1

        return {
            "total": len(self._kev_cache),
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "ransomware_count": ransomware_count,
            "top_vendors": sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10],
        }

    @property
    def cache_size(self) -> int:
        """Get number of cached KEV entries."""
        return len(self._kev_cache)

    @property
    def last_sync(self) -> datetime | None:
        """Get last sync timestamp."""
        return self._last_sync
