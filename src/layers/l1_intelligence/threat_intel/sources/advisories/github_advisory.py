"""GitHub Advisory Database client for vulnerability data.

Uses GitHub REST API to access the Advisory Database.
"""

from datetime import datetime
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    SeverityLevel,
)

logger = get_logger(__name__)


class GitHubAdvisoryClient:
    """Client for GitHub Advisory Database.

    GitHub Advisory Database contains security advisories for many ecosystems,
    including Go modules, npm packages, Python packages, etc.

    API Documentation: https://docs.github.com/en/rest/security-advisories
    """

    # REST API endpoints
    API_URL = "https://api.github.com"
    ADVISORIES_URL = f"{API_URL}/advisories"

    def __init__(self, token: str | None = None) -> None:
        """Initialize GitHub Advisory client.

        Args:
            token: GitHub Personal Access Token (optional but recommended).
        """
        self.token = token
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

    async def __aenter__(self) -> "GitHubAdvisoryClient":
        """Enter async context."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        await self.close()

    def _get_headers(self) -> dict[str, str]:
        """Get request headers."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _map_severity(self, severity: str) -> SeverityLevel:
        """Map GitHub severity to internal severity level.

        Args:
            severity: GitHub severity string.

        Returns:
            SeverityLevel enum value.
        """
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "moderate": SeverityLevel.MEDIUM,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
        }
        return severity_map.get(severity.lower(), SeverityLevel.INFO)

    def _map_ecosystem(self, ecosystem: str) -> str:
        """Map internal ecosystem to GitHub ecosystem.

        Args:
            ecosystem: Internal ecosystem name.

        Returns:
            GitHub ecosystem name.
        """
        ecosystem_map = {
            "npm": "npm",
            "pypi": "pip",
            "go": "go",
            "maven": "maven",
            "cargo": "rust",
            "rubygems": "rubygems",
            "nuget": "nuget",
            "composer": "composer",
        }
        return ecosystem_map.get(ecosystem.lower(), ecosystem.lower())

    async def search_by_package(
        self,
        package_name: str,
        ecosystem: str = "go",
        limit: int = 20,
    ) -> list[CVEInfo]:
        """Search advisories by package name using REST API.

        Args:
            package_name: Package name (e.g., "github.com/gin-gonic/gin").
            ecosystem: Package ecosystem (go, npm, pip, etc.).
            limit: Maximum results.

        Returns:
            List of CVEInfo objects.
        """
        session = await self._get_session()
        gh_ecosystem = self._map_ecosystem(ecosystem)

        params = {
            "ecosystem": gh_ecosystem,
            "per_page": min(limit, 100),
        }

        try:
            async with session.get(
                self.ADVISORIES_URL,
                params=params,
                headers=self._get_headers(),
            ) as response:
                if response.status == 401:
                    logger.warning("GitHub API authentication failed.")
                    return []
                elif response.status == 403:
                    logger.warning("GitHub API rate limit exceeded.")
                    return []
                elif response.status == 404:
                    logger.warning("GitHub Advisory API endpoint not found.")
                    return []

                response.raise_for_status()
                advisories = await response.json()

                # Handle case where API returns a string error
                if isinstance(advisories, str):
                    logger.warning(f"GitHub API returned string: {advisories}")
                    return []

                # Filter by package name
                results = []
                for adv in advisories:
                    if not isinstance(adv, dict):
                        continue

                    # Check if this advisory affects our package
                    for vuln in adv.get("vulnerabilities", []):
                        if not isinstance(vuln, dict):
                            continue
                        pkg = vuln.get("package", {})
                        if not isinstance(pkg, dict):
                            continue
                        pkg_name = pkg.get("name", "")
                        if pkg_name == package_name or package_name in pkg_name:
                            cve_info = self._parse_advisory(adv, package_name)
                            if cve_info:
                                results.append(cve_info)
                            break

                    if len(results) >= limit:
                        break

                return results

        except Exception as e:
            logger.warning(f"GitHub Advisory API request failed: {e}")
            return []

    async def get_advisory(self, ghsa_id: str) -> CVEInfo | None:
        """Get advisory by GHSA ID.

        Args:
            ghsa_id: GitHub Security Advisory ID (e.g., "GHSA-xxxx-xxxx").

        Returns:
            CVEInfo or None.
        """
        session = await self._get_session()
        url = f"{self.ADVISORIES_URL}/{ghsa_id}"

        try:
            async with session.get(url, headers=self._get_headers()) as response:
                if response.status == 404:
                    return None
                response.raise_for_status()
                advisory = await response.json()
                return self._parse_advisory(advisory)

        except Exception as e:
            logger.warning(f"Failed to get advisory {ghsa_id}: {e}")
            return None

    def _parse_advisory(self, advisory: dict, package_name: str | None = None) -> CVEInfo | None:
        """Parse GitHub advisory to CVEInfo.

        Args:
            advisory: GitHub advisory dictionary.
            package_name: Optional package name for affected versions.

        Returns:
            CVEInfo object or None.
        """
        if not isinstance(advisory, dict):
            return None

        ghsa_id = advisory.get("ghsa_id", "")
        if not ghsa_id:
            return None

        # Extract CVE ID from CVE IDs list
        cve_id = None
        cve_ids = advisory.get("cve_ids", [])
        if cve_ids and isinstance(cve_ids, list) and cve_ids:
            cve_id = cve_ids[0]
        else:
            cve_id = ghsa_id

        # Parse severity
        severity = self._map_severity(advisory.get("severity", "moderate"))

        # Parse CVSS score
        cvss_data = advisory.get("cvss")
        cvss_score = None
        if isinstance(cvss_data, dict):
            cvss_score = cvss_data.get("score")

        # Parse CWE IDs
        cwe_ids = advisory.get("cwe_ids", [])
        if not isinstance(cwe_ids, list):
            cwe_ids = []

        # Parse affected products
        affected_products = []
        affected_versions = []
        for vuln in advisory.get("vulnerabilities", []):
            if not isinstance(vuln, dict):
                continue
            pkg = vuln.get("package", {})
            if not isinstance(pkg, dict):
                continue
            pkg_name = pkg.get("name")
            if pkg_name:
                affected_products.append(pkg_name)

            # Get vulnerable version ranges
            version_range = vuln.get("vulnerable_version_range")
            if version_range:
                affected_versions.append(version_range)

        # Parse references
        references = []
        for ref in advisory.get("references", []):
            if not isinstance(ref, dict):
                continue
            url = ref.get("url")
            if url:
                references.append(url)

        # Parse dates
        published_date = None
        if advisory.get("published_at"):
            try:
                published_date = datetime.fromisoformat(
                    advisory["published_at"].replace("Z", "+00:00")
                )
            except Exception:
                pass

        modified_date = None
        if advisory.get("updated_at"):
            try:
                modified_date = datetime.fromisoformat(
                    advisory["updated_at"].replace("Z", "+00:00")
                )
            except Exception:
                pass

        description = advisory.get("description") or advisory.get("summary", "")

        return CVEInfo(
            cve_id=cve_id,
            source="github_advisory",
            description=description,
            cvss_v3_score=cvss_score,
            severity=severity,
            cwe_ids=cwe_ids,
            affected_products=affected_products,
            affected_versions=affected_versions,
            references=references,
            tags=["github-advisory"],
            published_date=published_date or datetime.now(),
            modified_date=modified_date,
        )

    async def search_go_module(self, module_path: str, limit: int = 20) -> list[CVEInfo]:
        """Search advisories for a Go module.

        This is a convenience method that handles Go module path formats.

        Args:
            module_path: Go module path (e.g., "github.com/gin-gonic/gin").
            limit: Maximum results.

        Returns:
            List of CVEInfo objects.
        """
        return await self.search_by_package(module_path, "go", limit)
