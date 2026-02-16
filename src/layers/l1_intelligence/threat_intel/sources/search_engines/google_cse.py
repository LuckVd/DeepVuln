"""Google Custom Search API client."""

from datetime import datetime
from typing import Any

import aiohttp

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.core.data_models import SearchResult
from src.layers.l1_intelligence.threat_intel.sources.search_engines.base_search import (
    BaseSearchEngine,
)

logger = get_logger(__name__)


class GoogleCSESearchEngine(BaseSearchEngine):
    """Google Custom Search Engine client.

    Uses Google's Custom Search JSON API to search the web.

    API Docs: https://developers.google.com/custom-search/v1/overview
    Rate Limit: 100 requests/day (free), 10,000/day (paid)

    Required:
    - API Key: https://console.cloud.google.com/apis/credentials
    - Custom Search Engine ID: https://cse.google.com/
    """

    SEARCH_URL = "https://www.googleapis.com/customsearch/v1"

    # Recommended sites for vulnerability research
    SECURITY_SITES = [
        "nvd.nist.gov",
        "cisa.gov",
        "exploit-db.com",
        "github.com",
        "seclists.org",
        "securityfocus.com",
        "packetstormsecurity.com",
        "thehackernews.com",
        "bleepingcomputer.com",
        "krebsonsecurity.com",
        "nakedsecurity.sophos.com",
        "threatpost.com",
    ]

    def __init__(
        self,
        api_key: str,
        cx: str,
        daily_limit: int = 100,
    ) -> None:
        """Initialize Google CSE client.

        Args:
            api_key: Google API key.
            cx: Custom Search Engine ID.
            daily_limit: Maximum requests per day.
        """
        super().__init__(daily_limit=daily_limit)
        self.api_key = api_key
        self.cx = cx

    @property
    def name(self) -> str:
        """Get engine name."""
        return "google_cse"

    async def search(
        self,
        query: str,
        limit: int = 10,
        start: int = 1,
        date_restrict: str | None = None,
        site_search: str | None = None,
        **kwargs: Any,
    ) -> list[SearchResult]:
        """Execute a Google Custom Search query.

        Args:
            query: Search query.
            limit: Maximum results (max 10 per request).
            start: Result offset (1-indexed).
            date_restrict: Date restriction (e.g., "d7" for last 7 days).
            site_search: Restrict to specific site.
            **kwargs: Additional parameters.

        Returns:
            List of SearchResult objects.
        """
        if not self._check_rate_limit():
            return []

        params = {
            "key": self.api_key,
            "cx": self.cx,
            "q": query,
            "num": min(limit, 10),  # Max 10 per request
            "start": start,
        }

        if date_restrict:
            params["dateRestrict"] = date_restrict

        if site_search:
            params["siteSearch"] = site_search

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.SEARCH_URL,
                    params=params,
                ) as response:
                    if response.status == 403:
                        logger.error("Google CSE: API quota exceeded")
                        return []

                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"Google CSE error: {response.status} - {error_text[:200]}")
                        return []

                    data = await response.json()

        except Exception as e:
            logger.error(f"Google CSE request failed: {e}")
            return []

        return self._parse_response(data, query)

    def _parse_response(
        self,
        data: dict[str, Any],
        query: str,
    ) -> list[SearchResult]:
        """Parse Google CSE API response.

        Args:
            data: API response data.
            query: Original query.

        Returns:
            List of SearchResult objects.
        """
        results = []
        items = data.get("items", [])

        for item in items:
            title = item.get("title", "")
            url = item.get("link", "")
            snippet = item.get("snippet", "")

            # Get metadata
            pagemap = item.get("pagemap", {})
            metatags = pagemap.get("metatags", [{}])
            meta = metatags[0] if metatags else {}

            # Try to get publication date
            published_date = None
            date_str = meta.get("article:published_time") or meta.get("date")
            if date_str:
                try:
                    published_date = datetime.fromisoformat(
                        date_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            result = self._parse_result(
                title=title,
                url=url,
                snippet=snippet,
                query=query,
                relevance_score=len(snippet) / 500 if snippet else 0,  # Rough heuristic
            )

            # Override with extracted date
            if published_date:
                result.published_date = published_date

            results.append(result)

        return results

    async def search_vulnerability_news(
        self,
        query: str,
        days: int = 30,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Search for vulnerability news.

        Restricts search to security-focused sites.

        Args:
            query: Search query.
            days: Days to look back.
            limit: Maximum results.

        Returns:
            List of SearchResult objects.
        """
        results = []

        # Search security sites
        for site in self.SECURITY_SITES[:5]:  # Limit to 5 sites
            if not self._check_rate_limit():
                break

            try:
                site_results = await self.search(
                    query,
                    limit=2,
                    date_restrict=f"d{days}",
                    site_search=site,
                )
                results.extend(site_results)
            except Exception as e:
                logger.warning(f"Search failed for {site}: {e}")
                continue

        # Deduplicate by URL
        seen_urls = set()
        unique_results = []
        for result in results:
            if result.url not in seen_urls:
                seen_urls.add(result.url)
                unique_results.append(result)

        return unique_results[:limit]

    async def search_cve_context(
        self,
        cve_id: str,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Search for context about a specific CVE.

        Args:
            cve_id: CVE identifier.
            limit: Maximum results.

        Returns:
            List of SearchResult objects.
        """
        # Build comprehensive query
        query = f'"{cve_id}" (exploit OR PoC OR vulnerability OR analysis)'

        return await self.search(
            query,
            limit=limit,
            date_restrict="d365",  # Last year
        )

    async def search_exploit_info(
        self,
        vendor: str,
        product: str,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Search for exploit information about a product.

        Args:
            vendor: Vendor name.
            product: Product name.
            limit: Maximum results.

        Returns:
            List of SearchResult objects.
        """
        query = f'{vendor} {product} (exploit OR vulnerability OR CVE OR RCE)'

        return await self.search_vulnerability_news(
            query,
            days=90,
            limit=limit,
        )

    def get_status(self) -> dict[str, Any]:
        """Get engine status.

        Returns:
            Status dictionary.
        """
        return {
            **self.get_usage_stats(),
            "api_key_configured": bool(self.api_key),
            "cx_configured": bool(self.cx),
        }
