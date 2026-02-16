"""Base class for search engine integrations."""

import re
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.core.data_models import SearchResult

logger = get_logger(__name__)


class BaseSearchEngine(ABC):
    """Abstract base class for search engine integrations.

    Provides common functionality for searching and parsing results.
    """

    # Pattern for extracting CVE IDs from text
    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    # Pattern for extracting CWE IDs from text
    CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)

    def __init__(
        self,
        daily_limit: int = 100,
    ) -> None:
        """Initialize search engine.

        Args:
            daily_limit: Maximum requests per day.
        """
        self.daily_limit = daily_limit
        self._request_count = 0
        self._last_reset: datetime | None = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the search engine name."""
        pass

    @abstractmethod
    async def search(
        self,
        query: str,
        limit: int = 10,
        **kwargs: Any,
    ) -> list[SearchResult]:
        """Execute a search query.

        Args:
            query: Search query.
            limit: Maximum results.
            **kwargs: Engine-specific parameters.

        Returns:
            List of SearchResult objects.
        """
        pass

    async def iter_search(
        self,
        query: str,
        limit: int = 10,
        **kwargs: Any,
    ) -> AsyncIterator[SearchResult]:
        """Iterate over search results.

        Args:
            query: Search query.
            limit: Maximum results.
            **kwargs: Engine-specific parameters.

        Yields:
            SearchResult objects.
        """
        results = await self.search(query, limit=limit, **kwargs)
        for result in results:
            yield result

    async def search_vulnerabilities(
        self,
        query: str,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Search for vulnerability-related content.

        Automatically adds vulnerability-related keywords.

        Args:
            query: Search query.
            limit: Maximum results.

        Returns:
            List of SearchResult objects.
        """
        # Add vulnerability context to query
        vuln_query = f"{query} (vulnerability OR CVE OR exploit OR security OR PoC)"
        return await self.search(vuln_query, limit=limit)

    def _check_rate_limit(self) -> bool:
        """Check if rate limit allows a request.

        Returns:
            True if request is allowed.
        """
        now = datetime.now()

        # Reset counter if new day
        if self._last_reset is None or self._last_reset.date() != now.date():
            self._request_count = 0
            self._last_reset = now

        if self._request_count >= self.daily_limit:
            logger.warning(f"{self.name}: Daily rate limit reached ({self.daily_limit})")
            return False

        self._request_count += 1
        return True

    def _extract_cves(self, text: str) -> list[str]:
        """Extract CVE IDs from text.

        Args:
            text: Text to search.

        Returns:
            List of CVE IDs (uppercase).
        """
        matches = self.CVE_PATTERN.findall(text)
        return list({m.upper() for m in matches})

    def _extract_cwes(self, text: str) -> list[str]:
        """Extract CWE IDs from text.

        Args:
            text: Text to search.

        Returns:
            List of CWE IDs (uppercase).
        """
        matches = self.CWE_PATTERN.findall(text)
        return list({m.upper() for m in matches})

    def _parse_result(
        self,
        title: str,
        url: str,
        snippet: str | None,
        query: str,
        **extra: Any,
    ) -> SearchResult:
        """Parse a search result.

        Args:
            title: Result title.
            url: Result URL.
            snippet: Result snippet/description.
            query: Original query.
            **extra: Extra fields.

        Returns:
            SearchResult object.
        """
        # Combine text for entity extraction
        combined_text = f"{title} {snippet or ''}"

        return SearchResult(
            query=query,
            source=self.name,
            title=title,
            url=url,
            snippet=snippet,
            related_cves=self._extract_cves(combined_text),
            related_cwes=self._extract_cwes(combined_text),
            **extra,
        )

    def get_usage_stats(self) -> dict[str, Any]:
        """Get usage statistics.

        Returns:
            Usage statistics dictionary.
        """
        return {
            "engine": self.name,
            "daily_limit": self.daily_limit,
            "requests_today": self._request_count,
            "remaining": max(0, self.daily_limit - self._request_count),
            "last_reset": self._last_reset.isoformat() if self._last_reset else None,
        }


class SearchEngineRegistry:
    """Registry for multiple search engines."""

    def __init__(self) -> None:
        """Initialize registry."""
        self._engines: dict[str, BaseSearchEngine] = {}

    def register(self, engine: BaseSearchEngine) -> None:
        """Register a search engine.

        Args:
            engine: Search engine instance.
        """
        self._engines[engine.name] = engine
        logger.info(f"Registered search engine: {engine.name}")

    def get(self, name: str) -> BaseSearchEngine | None:
        """Get a search engine by name.

        Args:
            name: Engine name.

        Returns:
            Search engine or None.
        """
        return self._engines.get(name)

    def list_engines(self) -> list[str]:
        """List registered engine names.

        Returns:
            List of engine names.
        """
        return list(self._engines.keys())

    async def search_all(
        self,
        query: str,
        limit_per_engine: int = 5,
    ) -> list[SearchResult]:
        """Search across all registered engines.

        Args:
            query: Search query.
            limit_per_engine: Results per engine.

        Returns:
            Combined list of results.
        """
        results = []

        for engine in self._engines.values():
            try:
                engine_results = await engine.search(query, limit=limit_per_engine)
                results.extend(engine_results)
            except Exception as e:
                logger.warning(f"Search failed for {engine.name}: {e}")

        # Sort by relevance score if available
        results.sort(
            key=lambda r: r.relevance_score or 0,
            reverse=True,
        )

        return results
