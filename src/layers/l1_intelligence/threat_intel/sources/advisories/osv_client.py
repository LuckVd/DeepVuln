"""OSV (Open Source Vulnerabilities) API client.

OSV is a vulnerability database and infrastructure for open source projects.
API Documentation: https://google.github.io/osv.dev/api/
"""

from datetime import datetime
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    SeverityLevel,
)

logger = get_logger(__name__)


class OSVClient:
    """Client for OSV vulnerability database.

    OSV provides a free API to query vulnerabilities by package name and version.
    Supports many ecosystems including Maven, npm, Go, PyPI, etc.
    """

    API_URL = "https://api.osv.dev/v1"

    # Ecosystem mapping
    ECOSYSTEM_MAP = {
        "npm": "npm",
        "pip": "PyPI",
        "pypi": "PyPI",
        "go": "Go",
        "maven": "Maven",
        "cargo": "crates.io",
        "rust": "crates.io",
        "rubygems": "RubyGems",
        "nuget": "NuGet",
        "composer": "Packagist",
        "php": "Packagist",
    }

    def __init__(self) -> None:
        """Initialize OSV client."""
        self._session: Any = None

    async def _get_session(self) -> Any:
        """Get or create aiohttp session."""
        if self._session is None:
            import aiohttp
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def __aenter__(self) -> "OSVClient":
        """Enter async context."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        await self.close()

    def _map_ecosystem(self, ecosystem: str) -> str:
        """Map internal ecosystem name to OSV ecosystem name.

        Args:
            ecosystem: Internal ecosystem name.

        Returns:
            OSV ecosystem name.
        """
        return self.ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem)

    def _map_severity(self, severity: str | None, cvss_score: float | None) -> SeverityLevel:
        """Map severity to internal severity level.

        Args:
            severity: Severity string from OSV.
            cvss_score: CVSS score if available.

        Returns:
            SeverityLevel enum value.
        """
        # Use CVSS score if available
        if cvss_score is not None:
            if cvss_score >= 9.0:
                return SeverityLevel.CRITICAL
            elif cvss_score >= 7.0:
                return SeverityLevel.HIGH
            elif cvss_score >= 4.0:
                return SeverityLevel.MEDIUM
            elif cvss_score > 0:
                return SeverityLevel.LOW

        # Fall back to severity string
        if severity:
            severity_lower = severity.lower()
            if severity_lower == "critical":
                return SeverityLevel.CRITICAL
            elif severity_lower == "high":
                return SeverityLevel.HIGH
            elif severity_lower in ("moderate", "medium"):
                return SeverityLevel.MEDIUM
            elif severity_lower == "low":
                return SeverityLevel.LOW

        return SeverityLevel.INFO

    async def query_by_package(
        self,
        package_name: str,
        ecosystem: str,
        version: str | None = None,
    ) -> list[CVEInfo]:
        """Query vulnerabilities by package name.

        Args:
            package_name: Package name (e.g., "org.springframework:spring-core").
            ecosystem: Package ecosystem (e.g., "maven", "npm", "go").
            version: Optional version to filter affected vulnerabilities.

        Returns:
            List of CVEInfo objects.
        """
        session = await self._get_session()
        osv_ecosystem = self._map_ecosystem(ecosystem)

        url = f"{self.API_URL}/query"

        # Build query payload
        payload: dict[str, Any] = {
            "package": {
                "name": package_name,
                "ecosystem": osv_ecosystem,
            }
        }

        if version:
            payload["version"] = version

        try:
            async with session.post(url, json=payload) as response:
                if response.status == 404:
                    return []
                elif response.status == 429:
                    logger.warning("OSV API rate limit exceeded")
                    return []
                elif response.status != 200:
                    text = await response.text()
                    logger.warning(f"OSV API error {response.status}: {text}")
                    return []

                data = await response.json()
                vulns = data.get("vulns", [])

                results = []
                for vuln in vulns:
                    cve_info = self._parse_vulnerability(vuln, package_name)
                    if cve_info:
                        results.append(cve_info)

                return results

        except Exception as e:
            logger.warning(f"OSV API request failed: {e}")
            return []

    async def query_batch(
        self,
        queries: list[dict[str, Any]],
    ) -> list[list[CVEInfo]]:
        """Batch query multiple packages.

        Args:
            queries: List of query dicts with 'package', 'ecosystem', optional 'version'.

        Returns:
            List of CVEInfo lists, one per query.
        """
        session = await self._get_session()
        url = f"{self.API_URL}/querybatch"

        # Build batch payload
        batch_queries = []
        for q in queries:
            osv_ecosystem = self._map_ecosystem(q.get("ecosystem", ""))
            query: dict[str, Any] = {
                "package": {
                    "name": q["package"],
                    "ecosystem": osv_ecosystem,
                }
            }
            if q.get("version"):
                query["version"] = q["version"]
            batch_queries.append(query)

        payload = {"queries": batch_queries}

        try:
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    text = await response.text()
                    logger.warning(f"OSV batch API error {response.status}: {text}")
                    return [[] for _ in queries]

                data = await response.json()
                results_list = data.get("results", [])

                all_results = []
                for i, result in enumerate(results_list):
                    vulns = result.get("vulns", [])
                    package_name = queries[i]["package"] if i < len(queries) else ""
                    cves = []
                    for vuln in vulns:
                        cve_info = self._parse_vulnerability(vuln, package_name)
                        if cve_info:
                            cves.append(cve_info)
                    all_results.append(cves)

                return all_results

        except Exception as e:
            logger.warning(f"OSV batch API request failed: {e}")
            return [[] for _ in queries]

    def _parse_vulnerability(self, vuln: dict, package_name: str) -> CVEInfo | None:
        """Parse OSV vulnerability to CVEInfo.

        Args:
            vuln: OSV vulnerability dictionary.
            package_name: Package name being queried.

        Returns:
            CVEInfo object or None.
        """
        if not isinstance(vuln, dict):
            return None

        # Get vulnerability ID (OSV ID like GO-2024-xxx or GHSA-xxx)
        osv_id = vuln.get("id", "")
        if not osv_id:
            return None

        # Get CVE ID from aliases
        cve_id = osv_id
        aliases = vuln.get("aliases", [])
        if aliases:
            # Prefer CVE ID over GHSA/OSV ID
            for alias in aliases:
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

        # Parse severity
        cvss_score = None
        severity_str = None

        severity_data = vuln.get("severity", [])
        for sev in severity_data:
            if isinstance(sev, dict):
                if sev.get("type") == "CVSS_V3":
                    cvss_str = sev.get("score", "")
                    if cvss_str:
                        # CVSS vector string like "CVSS:3.1/AV:N/..."
                        # Extract numeric score if available
                        pass
                elif sev.get("type") == "CVSS_V3_SCORE":
                    try:
                        cvss_score = float(sev.get("score", 0))
                    except (ValueError, TypeError):
                        pass

        # Try database_specific for severity
        db_specific = vuln.get("database_specific", {})
        if isinstance(db_specific, dict):
            severity_str = db_specific.get("severity")

        severity = self._map_severity(severity_str, cvss_score)

        # Parse summary/description
        summary = vuln.get("summary", "")
        details = vuln.get("details", "")
        description = summary or details or ""

        # Parse affected versions
        affected_versions = []
        affected = vuln.get("affected", [])
        for aff in affected:
            if not isinstance(aff, dict):
                continue
            ranges = aff.get("ranges", [])
            for r in ranges:
                if isinstance(r, dict):
                    events = r.get("events", [])
                    for event in events:
                        if isinstance(event, dict):
                            if "introduced" in event:
                                affected_versions.append(f">={event['introduced']}")
                            elif "fixed" in event:
                                affected_versions.append(f"<{event['fixed']}")
                            elif "last_affected" in event:
                                affected_versions.append(f"<={event['last_affected']}")

        # Parse references
        references = []
        refs = vuln.get("references", [])
        for ref in refs:
            if isinstance(ref, dict):
                url = ref.get("url")
                if url:
                    references.append(url)

        # Parse CWE IDs
        cwe_ids = []
        if db_specific:
            cwes = db_specific.get("cwe_ids", [])
            if isinstance(cwes, list):
                cwe_ids = cwes

        # Parse dates
        published_date = None
        modified_date = None

        if vuln.get("published"):
            try:
                published_date = datetime.fromisoformat(
                    vuln["published"].replace("Z", "+00:00")
                )
            except Exception:
                pass

        if vuln.get("modified"):
            try:
                modified_date = datetime.fromisoformat(
                    vuln["modified"].replace("Z", "+00:00")
                )
            except Exception:
                pass

        # Check for KEV (Known Exploited Vulnerabilities)
        # OSV doesn't directly provide KEV info, but we can check tags
        kev = False
        tags = []
        ecosystem_specific = vuln.get("ecosystem_specific", {})
        if isinstance(ecosystem_specific, dict):
            if ecosystem_specific.get("known_exploited"):
                kev = True
                tags.append("kev")

        # Add source tag
        tags.append("osv")

        return CVEInfo(
            cve_id=cve_id,
            source="osv",
            description=description,
            cvss_v3_score=cvss_score,
            severity=severity,
            cwe_ids=cwe_ids,
            affected_products=[package_name],
            affected_versions=affected_versions,
            references=references,
            tags=tags,
            published_date=published_date or datetime.now(),
            modified_date=modified_date,
            kev=kev,
        )
