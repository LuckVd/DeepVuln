"""GitHub PoC searcher for finding exploit repositories."""

import re
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import aiohttp

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.core.data_models import PoCInfo

logger = get_logger(__name__)


class GitHubPoCSearcher:
    """GitHub PoC repository searcher.

    Searches GitHub for repositories related to CVEs and exploits.
    Supports authentication for higher rate limits.

    API Docs: https://docs.github.com/en/rest/search
    Rate Limits:
    - Anonymous: 10 requests/minute
    - Authenticated: 30 requests/minute
    """

    SEARCH_URL = "https://api.github.com/search/repositories"
    REPO_URL = "https://api.github.com/repos"

    # Known high-quality PoC sources
    TRUSTED_ORGS = [
        "rapid7",           # Metasploit
        "projectdiscovery", # Nuclei templates
        "poc-exploit",
        "cckuailong",
        "Exploitables",
        "horizon3ai",       # VCenter exploits
        "amba-cheat",       # Various PoCs
    ]

    # Keywords that indicate a PoC repository
    POC_KEYWORDS = [
        "poc", "exploit", "cve", "vulnerability",
        "rce", "xss", "sqli", "lfi", "rfi",
        "proof-of-concept", "vuln",
    ]

    def __init__(
        self,
        token: str | None = None,
        min_stars: int = 5,
    ) -> None:
        """Initialize GitHub searcher.

        Args:
            token: GitHub personal access token.
            min_stars: Minimum stars for a repo to be included.
        """
        self.token = token
        self.min_stars = min_stars
        self._headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        if token:
            self._headers["Authorization"] = f"token {token}"

    async def _search(
        self,
        query: str,
        sort: str = "stars",
        order: str = "desc",
        per_page: int = 30,
        page: int = 1,
    ) -> list[dict[str, Any]]:
        """Execute a GitHub search query.

        Args:
            query: Search query.
            sort: Sort field (stars, forks, updated).
            order: Sort order (asc, desc).
            per_page: Results per page (max 100).
            page: Page number.

        Returns:
            List of repository dictionaries.
        """
        params = {
            "q": query,
            "sort": sort,
            "order": order,
            "per_page": min(per_page, 100),
            "page": page,
        }

        async with aiohttp.ClientSession() as session:
            async with session.get(
                self.SEARCH_URL,
                params=params,
                headers=self._headers,
            ) as response:
                if response.status == 403:
                    logger.warning("GitHub API rate limit exceeded")
                    return []
                if response.status != 200:
                    logger.error(f"GitHub API error: {response.status}")
                    return []

                data = await response.json()
                return data.get("items", [])

    async def search_cve(self, cve_id: str, limit: int = 30) -> list[PoCInfo]:
        """Search for PoC repositories for a specific CVE.

        Args:
            cve_id: CVE identifier.
            limit: Maximum results.

        Returns:
            List of PoCInfo objects.
        """
        # Build search query
        query = f'"{cve_id}" poc OR exploit'

        results = []
        repos = await self._search(query, per_page=limit)

        for repo in repos:
            poc = self._parse_repo(repo, cve_id)
            if poc:
                results.append(poc)

        return results

    async def search_keyword(
        self,
        keyword: str,
        limit: int = 30,
    ) -> AsyncIterator[PoCInfo]:
        """Search for PoC repositories by keyword.

        Args:
            keyword: Search keyword.
            limit: Maximum results.

        Yields:
            PoCInfo objects.
        """
        query = f"{keyword} (poc OR exploit OR cve)"

        repos = await self._search(query, per_page=limit)

        for repo in repos:
            poc = self._parse_repo(repo)
            if poc:
                yield poc

    async def get_trusted_pocs(
        self,
        limit_per_org: int = 10,
    ) -> AsyncIterator[PoCInfo]:
        """Get PoCs from trusted organizations.

        Args:
            limit_per_org: Maximum repos per organization.

        Yields:
            PoCInfo objects.
        """
        for org in self.TRUSTED_ORGS:
            query = f"org:{org} (poc OR exploit OR cve)"

            try:
                repos = await self._search(query, per_page=limit_per_org)

                for repo in repos:
                    poc = self._parse_repo(repo)
                    if poc:
                        yield poc

            except Exception as e:
                logger.warning(f"Failed to search org {org}: {e}")
                continue

    async def get_recent_pocs(
        self,
        days: int = 30,
        limit: int = 50,
    ) -> AsyncIterator[PoCInfo]:
        """Get recently created PoC repositories.

        Args:
            days: Days to look back.
            limit: Maximum results.

        Yields:
            PoCInfo objects.
        """
        # GitHub search date format: YYYY-MM-DD
        from datetime import datetime, timedelta
        since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

        query = f"(poc OR exploit) created:>{since}"

        repos = await self._search(query, sort="updated", per_page=limit)

        for repo in repos:
            poc = self._parse_repo(repo)
            if poc:
                yield poc

    def _parse_repo(
        self,
        repo: dict[str, Any],
        cve_id: str | None = None,
    ) -> PoCInfo | None:
        """Parse a GitHub repository into PoCInfo.

        Args:
            repo: Repository dictionary from API.
            cve_id: Optional CVE ID to associate.

        Returns:
            PoCInfo or None if filtered out.
        """
        # Filter by minimum stars
        stars = repo.get("stargazers_count", 0)
        if stars < self.min_stars:
            return None

        full_name = repo.get("full_name", "")
        description = repo.get("description", "") or ""
        name = repo.get("name", "")

        # Extract CVE IDs from name/description
        cve_ids = []
        if cve_id:
            cve_ids.append(cve_id)

        # Find additional CVEs
        pattern = r"CVE-\d{4}-\d{4,7}"
        for text in [name, description, full_name]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                cve = match.upper()
                if cve not in cve_ids:
                    cve_ids.append(cve)

        # Determine if it's actually a PoC/exploit repo
        is_poc = any(kw in name.lower() or kw in description.lower()
                     for kw in self.POC_KEYWORDS)
        if not is_poc and not cve_ids:
            return None

        # Determine language
        language = repo.get("language")

        # Parse dates
        created_at = None
        if repo.get("created_at"):
            try:
                created_at = datetime.fromisoformat(
                    repo["created_at"].replace("Z", "+00:00")
                )
            except ValueError:
                pass

        # Check if from trusted source
        owner = repo.get("owner", {}).get("login", "")
        is_trusted = owner.lower() in self.TRUSTED_ORGS

        return PoCInfo(
            poc_id=f"GH-{repo.get('id', '')}",
            source="github",
            cve_ids=cve_ids,
            title=name,
            description=description[:500] if description else None,
            poc_type="poc",
            code_url=repo.get("html_url", ""),
            language=language,
            author=owner,
            published_date=created_at,
            verified=is_trusted or stars >= 100,
            stars=stars,
            forks=repo.get("forks_count", 0),
        )

    async def get_repo_readme(self, owner: str, repo: str) -> str | None:
        """Get README content for a repository.

        Args:
            owner: Repository owner.
            repo: Repository name.

        Returns:
            README content or None.
        """
        url = f"{self.REPO_URL}/{owner}/{repo}/readme"

        headers = self._headers.copy()
        headers["Accept"] = "application/vnd.github.v3.raw"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    return None
                return await response.text()

    async def check_rate_limit(self) -> dict[str, Any]:
        """Check GitHub API rate limit status.

        Returns:
            Rate limit info dictionary.
        """
        url = "https://api.github.com/rate_limit"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers) as response:
                if response.status != 200:
                    return {}
                data = await response.json()

        return {
            "limit": data.get("resources", {}).get("search", {}).get("limit", 0),
            "remaining": data.get("resources", {}).get("search", {}).get("remaining", 0),
            "reset": data.get("resources", {}).get("search", {}).get("reset", 0),
        }
