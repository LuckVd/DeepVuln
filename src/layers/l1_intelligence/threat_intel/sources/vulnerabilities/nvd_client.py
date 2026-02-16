"""NVD (National Vulnerability Database) API 2.0 client."""

import asyncio
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.core.base_client import BaseClient
from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    SeverityLevel,
)
from src.layers.l1_intelligence.threat_intel.core.rate_limiter import RateLimiter

logger = get_logger(__name__)


class NVDClient(BaseClient):
    """NVD API 2.0 client for CVE data.

    API Documentation: https://nvd.nist.gov/developers/vulnerabilities

    Rate Limits:
    - Without API Key: 5 requests per 30 seconds
    - With API Key: 50 requests per 30 seconds
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        api_key: str | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        """Initialize NVD client.

        Args:
            api_key: NVD API key (increases rate limit).
            rate_limiter: Custom rate limiter.
        """
        self.api_key = api_key

        # Create rate limiter based on API key presence
        if rate_limiter is None:
            requests_per_window = 50 if api_key else 5
            rate_limiter = RateLimiter.from_requests_per_window(
                requests_per_window, window_seconds=30.0
            )

        super().__init__(
            base_url=self.BASE_URL,
            rate_limiter=rate_limiter,
            timeout=60.0,  # NVD can be slow
        )

        self._api_key = api_key

    def _get_default_headers(self) -> dict[str, str]:
        """Get default headers including API key if available."""
        headers = super()._get_default_headers()
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    async def get_cve(self, cve_id: str) -> CVEInfo | None:
        """Get a single CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234).

        Returns:
            CVEInfo or None if not found.
        """
        params = {"cveId": cve_id}

        try:
            data = await self.get("", params=params)

            if isinstance(data, dict) and data.get("vulnerabilities"):
                cve_data = data["vulnerabilities"][0]["cve"]
                return self._parse_cve(cve_data)

        except Exception as e:
            logger.error(f"Failed to get CVE {cve_id}: {e}")

        return None

    async def get_cves_by_date(
        self,
        start_date: datetime,
        end_date: datetime | None = None,
        results_per_page: int = 100,
    ) -> AsyncIterator[CVEInfo]:
        """Get CVEs published within a date range.

        Args:
            start_date: Start of date range.
            end_date: End of date range (defaults to now).
            results_per_page: Results per page (max 100).

        Yields:
            CVEInfo objects.
        """
        if end_date is None:
            end_date = datetime.now()

        params = {
            "pubStartDate": self._format_date(start_date),
            "pubEndDate": self._format_date(end_date),
            "resultsPerPage": min(results_per_page, 100),
        }

        start_index = 0
        total_results = None

        while True:
            params["startIndex"] = start_index

            try:
                data = await self.get("", params=params)

                if not isinstance(data, dict):
                    break

                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    try:
                        yield self._parse_cve(vuln["cve"])
                    except Exception as e:
                        logger.warning(f"Failed to parse CVE: {e}")
                        continue

                if total_results is None:
                    total_results = data.get("totalResults", 0)

                start_index += len(vulnerabilities)

                if start_index >= (total_results or 0):
                    break

                # Small delay between pages
                await asyncio.sleep(0.5)

            except Exception as e:
                logger.error(f"Failed to fetch CVEs page: {e}")
                break

    async def get_cves_modified_since(
        self,
        since: datetime,
        results_per_page: int = 100,
    ) -> AsyncIterator[CVEInfo]:
        """Get CVEs modified since a given date.

        Args:
            since: Last modification date.
            results_per_page: Results per page.

        Yields:
            CVEInfo objects.
        """
        params = {
            "lastModStartDate": self._format_date(since),
            "lastModEndDate": self._format_date(datetime.now()),
            "resultsPerPage": min(results_per_page, 100),
        }

        start_index = 0
        total_results = None

        while True:
            params["startIndex"] = start_index

            try:
                data = await self.get("", params=params)

                if not isinstance(data, dict):
                    break

                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    try:
                        yield self._parse_cve(vuln["cve"])
                    except Exception as e:
                        logger.warning(f"Failed to parse CVE: {e}")
                        continue

                if total_results is None:
                    total_results = data.get("totalResults", 0)

                start_index += len(vulnerabilities)

                if start_index >= (total_results or 0):
                    break

                await asyncio.sleep(0.5)

            except Exception as e:
                logger.error(f"Failed to fetch modified CVEs: {e}")
                break

    async def search(
        self, query: str, results_per_page: int = 100, **kwargs: Any
    ) -> AsyncIterator[CVEInfo]:
        """Search CVEs by keyword.

        Args:
            query: Search keyword.
            results_per_page: Results per page.

        Yields:
            CVEInfo objects.
        """
        params = {
            "keywordSearch": query,
            "resultsPerPage": min(results_per_page, 100),
        }

        start_index = 0
        total_results = None

        while True:
            params["startIndex"] = start_index

            try:
                data = await self.get("", params=params)

                if not isinstance(data, dict):
                    break

                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    try:
                        yield self._parse_cve(vuln["cve"])
                    except Exception as e:
                        logger.warning(f"Failed to parse CVE: {e}")
                        continue

                if total_results is None:
                    total_results = data.get("totalResults", 0)

                start_index += len(vulnerabilities)

                if start_index >= (total_results or 0):
                    break

                await asyncio.sleep(0.5)

            except Exception as e:
                logger.error(f"Failed to search CVEs: {e}")
                break

    def _parse_cve(self, cve_data: dict[str, Any]) -> CVEInfo:
        """Parse NVD CVE data into CVEInfo.

        Args:
            cve_data: Raw CVE data from NVD API.

        Returns:
            CVEInfo object.
        """
        cve_id = cve_data["id"]

        # Extract description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        description_zh = None

        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
            elif desc.get("lang") in ("zh", "zh-CN", "zh-TW"):
                description_zh = desc.get("value", "")

        # Extract CVSS scores
        metrics = cve_data.get("metrics", {})
        cvss_v3_score = None
        cvss_v3_vector = None
        cvss_v2_score = None
        cvss_v2_vector = None

        # Try CVSS v3.1 first, then v3.0, then v2
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")

        if "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_v2_score = cvss_data.get("baseScore")
            cvss_v2_vector = cvss_data.get("vectorString")

        # Extract CWEs
        weaknesses = cve_data.get("weaknesses", [])
        cwe_ids: list[str] = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_id = desc.get("value", "")
                    if cwe_id and cwe_id not in cwe_ids:
                        cwe_ids.append(cwe_id)

        # Extract references
        references = [
            ref.get("url", "") for ref in cve_data.get("references", []) if ref.get("url")
        ]

        # Extract patches
        patches = [
            ref.get("url", "")
            for ref in cve_data.get("references", [])
            if ref.get("tags") and "Patch" in ref.get("tags", [])
        ]

        # Calculate severity
        score = cvss_v3_score if cvss_v3_score is not None else cvss_v2_score
        severity = self._score_to_severity(score)

        # Parse dates
        published_date = self._parse_nvd_date(cve_data.get("published", ""))
        modified_date = self._parse_nvd_date(cve_data.get("lastModified", ""))

        # Extract affected products (configurations)
        affected_products: list[str] = []
        configs = cve_data.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if criteria and criteria not in affected_products:
                        # Extract product name from CPE
                        parts = criteria.split(":")
                        if len(parts) >= 4:
                            affected_products.append(f"{parts[3]}:{parts[4] if len(parts) > 4 else ''}")

        return CVEInfo(
            cve_id=cve_id,
            source="nvd",
            description=description,
            description_zh=description_zh,
            cvss_v2_score=cvss_v2_score,
            cvss_v2_vector=cvss_v2_vector,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_vector=cvss_v3_vector,
            severity=severity,
            cwe_ids=cwe_ids,
            affected_products=list(set(affected_products))[:10],  # Limit to 10
            references=references,
            patches=patches,
            published_date=published_date,
            modified_date=modified_date,
            synced_at=datetime.now(),
        )

    def _score_to_severity(self, score: float | None) -> SeverityLevel:
        """Convert CVSS score to severity level.

        Args:
            score: CVSS score (0-10).

        Returns:
            SeverityLevel enum value.
        """
        if score is None:
            return SeverityLevel.INFO
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        if score >= 7.0:
            return SeverityLevel.HIGH
        if score >= 4.0:
            return SeverityLevel.MEDIUM
        if score > 0:
            return SeverityLevel.LOW
        return SeverityLevel.INFO

    def _format_date(self, dt: datetime) -> str:
        """Format datetime for NVD API.

        Args:
            dt: Datetime object.

        Returns:
            ISO formatted string.
        """
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _parse_nvd_date(self, date_str: str) -> datetime:
        """Parse NVD date string.

        Args:
            date_str: NVD date string.

        Returns:
            Datetime object.
        """
        if not date_str:
            return datetime.now()

        # Handle ISO format with Z suffix
        if date_str.endswith("Z"):
            date_str = date_str[:-1] + "+00:00"

        try:
            return datetime.fromisoformat(date_str)
        except ValueError:
            return datetime.now()
