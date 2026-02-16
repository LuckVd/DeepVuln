"""Go Vulnerability Database client.

Go maintains an official vulnerability database at https://vuln.go.dev/
This module provides a client to query this database.
"""

import asyncio
from datetime import datetime
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    SeverityLevel,
)

logger = get_logger(__name__)


class GoVulnDBClient:
    """Client for Go Vulnerability Database.

    The Go vulnerability database is available at https://vuln.go.dev/
    It contains reports for vulnerabilities in Go packages.

    API Documentation: https://go.dev/security/vulndb
    """

    # Base URL for the vulnerability database
    BASE_URL = "https://vuln.go.dev"

    # Index URL for listing all vulnerabilities (correct path)
    INDEX_URL = f"{BASE_URL}/vulndb/index.json"

    # URL template for individual vulnerability reports
    VULN_URL_TEMPLATE = f"{BASE_URL}/vulndb/{{vuln_id}}.json"

    def __init__(self) -> None:
        """Initialize Go VulnDB client."""
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

    async def __aenter__(self) -> "GoVulnDBClient":
        """Enter async context."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        await self.close()

    async def get_vulnerability(self, vuln_id: str) -> dict | None:
        """Get a specific vulnerability by ID.

        Args:
            vuln_id: Vulnerability ID (e.g., "GO-2024-0001").

        Returns:
            Vulnerability data or None.
        """
        session = await self._get_session()
        url = self.VULN_URL_TEMPLATE.format(vuln_id=vuln_id)

        try:
            async with session.get(url) as response:
                if response.status == 404:
                    return None
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logger.warning(f"Failed to fetch Go vuln {vuln_id}: {e}")
            return None

    async def get_index(self) -> list[dict]:
        """Get the vulnerability index.

        Returns:
            List of vulnerability entries with IDs and timestamps.
        """
        session = await self._get_session()

        try:
            async with session.get(self.INDEX_URL) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logger.warning(f"Failed to fetch Go vuln index: {e}")
            return []

    async def search_by_module(self, module_path: str, limit: int = 20) -> list[CVEInfo]:
        """Search vulnerabilities affecting a specific Go module.

        Args:
            module_path: Go module path (e.g., "github.com/gin-gonic/gin").
            limit: Maximum results.

        Returns:
            List of CVEInfo objects.
        """
        # Get the index first
        index = await self.get_index()
        if not index:
            return []

        results: list[CVEInfo] = []

        # Fetch each vulnerability and check if it affects the module
        for entry in index[:limit * 3]:  # Check more entries to find matches
            if len(results) >= limit:
                break

            vuln_id = entry.get("id")
            if not vuln_id:
                continue

            vuln_data = await self.get_vulnerability(vuln_id)
            if not vuln_data:
                continue

            # Check if this vulnerability affects the module
            if self._affects_module(vuln_data, module_path):
                cve_info = self._parse_vulnerability(vuln_data)
                if cve_info:
                    results.append(cve_info)

        return results

    def _affects_module(self, vuln_data: dict, module_path: str) -> bool:
        """Check if vulnerability affects a specific module.

        Args:
            vuln_data: Vulnerability data.
            module_path: Module path to check.

        Returns:
            True if vulnerability affects the module.
        """
        # Check affected modules
        affected = vuln_data.get("affected", [])
        for affected_entry in affected:
            # Check module path
            affected_module = affected_entry.get("module", "")
            if affected_module == module_path:
                return True

            # Check if it's a subpath match
            if module_path.startswith(affected_module + "/"):
                return True

        # Also check package paths
        for affected_entry in affected:
            packages = affected_entry.get("package", "")
            if isinstance(packages, str):
                packages = [packages]

            for pkg in packages if isinstance(packages, list) else []:
                if pkg == module_path or module_path.startswith(pkg + "/"):
                    return True

        return False

    def _parse_vulnerability(self, vuln_data: dict) -> CVEInfo | None:
        """Parse Go vulnerability data to CVEInfo.

        Args:
            vuln_data: Go vulnerability data.

        Returns:
            CVEInfo or None.
        """
        vuln_id = vuln_data.get("id", "")
        if not vuln_id:
            return None

        # Extract CVE ID from aliases
        cve_id = vuln_id
        aliases = vuln_data.get("aliases", [])
        for alias in aliases:
            if isinstance(alias, str) and alias.startswith("CVE-"):
                cve_id = alias
                break

        # Parse description
        description = vuln_data.get("summary", "")
        details = vuln_data.get("details", "")
        if details:
            description = f"{description}\n\n{details}" if description else details

        # Parse severity
        severity = SeverityLevel.MEDIUM
        cvss_score = None

        # Check database_specific for severity info
        db_specific = vuln_data.get("database_specific", {})
        if db_specific:
            # Go vulndb uses "severity" field
            sev = db_specific.get("severity", "")
            if sev:
                severity_map = {
                    "critical": SeverityLevel.CRITICAL,
                    "high": SeverityLevel.HIGH,
                    "medium": SeverityLevel.MEDIUM,
                    "low": SeverityLevel.LOW,
                }
                severity = severity_map.get(sev.lower(), SeverityLevel.MEDIUM)

        # Parse affected modules
        affected_products = []
        for affected in vuln_data.get("affected", []):
            module = affected.get("module")
            if module and module not in affected_products:
                affected_products.append(module)

        # Parse references
        references = []
        for ref in vuln_data.get("references", []):
            url = ref.get("url")
            if url:
                references.append(url)

        # Parse CWE IDs
        cwe_ids = []
        for problem_type in vuln_data.get("credits", []):
            # Go vulndb may have CWE in different places
            pass

        # Parse dates
        published_date = None
        if vuln_data.get("published"):
            try:
                published_date = datetime.fromisoformat(
                    vuln_data["published"].replace("Z", "+00:00")
                )
            except Exception:
                pass

        modified_date = None
        if vuln_data.get("modified"):
            try:
                modified_date = datetime.fromisoformat(
                    vuln_data["modified"].replace("Z", "+00:00")
                )
            except Exception:
                pass

        return CVEInfo(
            cve_id=cve_id,
            source="go_vulndb",
            description=description,
            cvss_v3_score=cvss_score,
            severity=severity,
            cwe_ids=cwe_ids,
            affected_products=affected_products,
            references=references,
            tags=["go-vulndb"],
            published_date=published_date or datetime.now(),
            modified_date=modified_date,
        )

    async def lookup_cve(self, cve_id: str) -> CVEInfo | None:
        """Look up a CVE in the Go vulnerability database.

        Args:
            cve_id: CVE identifier.

        Returns:
            CVEInfo or None.
        """
        # Get the index
        index = await self.get_index()
        if not index:
            return None

        # Search for the CVE in aliases
        for entry in index:
            vuln_id = entry.get("id")
            if not vuln_id:
                continue

            vuln_data = await self.get_vulnerability(vuln_id)
            if not vuln_data:
                continue

            # Check aliases
            aliases = vuln_data.get("aliases", [])
            if cve_id in aliases:
                return self._parse_vulnerability(vuln_data)

        return None
