"""Base client for threat intelligence data sources."""

import asyncio
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any

from aiohttp import ClientError, ClientResponse, ClientSession, ClientTimeout

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.core.rate_limiter import RateLimiter

logger = get_logger(__name__)


class BaseClient(ABC):
    """Base class for threat intelligence API clients.

    Provides common functionality for HTTP requests, rate limiting,
    error handling, and retries.
    """

    def __init__(
        self,
        base_url: str | None = None,
        rate_limiter: RateLimiter | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> None:
        """Initialize the base client.

        Args:
            base_url: Base URL for API requests.
            rate_limiter: Rate limiter instance. Created if not provided.
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retry attempts.
            retry_delay: Base delay between retries (exponential backoff).
        """
        self.base_url = base_url
        self.rate_limiter = rate_limiter or RateLimiter()
        self.timeout = ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "BaseClient":
        """Enter async context manager."""
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit async context manager."""
        await self.close()

    async def _ensure_session(self) -> ClientSession:
        """Ensure aiohttp session exists.

        Returns:
            ClientSession instance.
        """
        if self._session is None or self._session.closed:
            self._session = ClientSession(
                timeout=self.timeout,
                headers=self._get_default_headers(),
            )
        return self._session

    def _get_default_headers(self) -> dict[str, str]:
        """Get default headers for requests.

        Returns:
            Dictionary of headers.
        """
        return {
            "Accept": "application/json",
            "User-Agent": "DeepVuln/0.1.0 (Threat Intelligence Collector)",
        }

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def _request(
        self,
        url: str,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json_data: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | str:
        """Make an HTTP request with rate limiting and retries.

        Args:
            url: Request URL.
            method: HTTP method.
            params: Query parameters.
            headers: Additional headers.
            json_data: JSON body data.
            **kwargs: Additional arguments for aiohttp.

        Returns:
            Response data (JSON dict or string).

        Raises:
            ClientError: If request fails after all retries.
        """
        session = await self._ensure_session()

        # Apply rate limiting
        await self.rate_limiter.acquire()

        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                # Merge headers
                request_headers = self._get_default_headers()
                if headers:
                    request_headers.update(headers)

                # Build full URL
                full_url = url
                if self.base_url and not url.startswith("http"):
                    full_url = f"{self.base_url.rstrip('/')}/{url.lstrip('/')}"

                logger.debug(f"Request: {method} {full_url} (attempt {attempt})")

                async with session.request(
                    method,
                    full_url,
                    params=params,
                    headers=request_headers,
                    json=json_data,
                    **kwargs,
                ) as response:
                    return await self._handle_response(response)

            except (ClientError, asyncio.TimeoutError) as e:
                last_error = e
                logger.warning(
                    f"Request failed (attempt {attempt}/{self.max_retries}): {e}"
                )

                if attempt < self.max_retries:
                    delay = self.retry_delay * (2 ** (attempt - 1))
                    logger.info(f"Retrying in {delay:.1f}s...")
                    await asyncio.sleep(delay)

        raise ClientError(
            f"Request failed after {self.max_retries} attempts: {last_error}"
        )

    async def _handle_response(self, response: ClientResponse) -> dict[str, Any] | str:
        """Handle HTTP response.

        Args:
            response: aiohttp response object.

        Returns:
            Parsed response data.

        Raises:
            ClientError: On HTTP errors.
        """
        content_type = response.headers.get("Content-Type", "")

        if response.status >= 400:
            error_body = await response.text()
            logger.error(f"HTTP {response.status}: {error_body[:500]}")
            raise ClientError(f"HTTP {response.status}: {response.reason}")

        if "application/json" in content_type:
            return await response.json()
        else:
            return await response.text()

    async def get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | str:
        """Make a GET request.

        Args:
            url: Request URL.
            params: Query parameters.
            headers: Additional headers.
            **kwargs: Additional arguments.

        Returns:
            Response data.
        """
        return await self._request(url, "GET", params=params, headers=headers, **kwargs)

    async def post(
        self,
        url: str,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | str:
        """Make a POST request.

        Args:
            url: Request URL.
            json_data: JSON body.
            headers: Additional headers.
            **kwargs: Additional arguments.

        Returns:
            Response data.
        """
        return await self._request(
            url, "POST", json_data=json_data, headers=headers, **kwargs
        )

    @abstractmethod
    async def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Get a single CVE by ID.

        Args:
            cve_id: CVE identifier.

        Returns:
            CVE data or None if not found.
        """
        pass

    @abstractmethod
    async def search(self, query: str, **kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        """Search for vulnerabilities.

        Args:
            query: Search query.
            **kwargs: Additional search parameters.

        Yields:
            Search results.
        """
        pass

    async def health_check(self) -> bool:
        """Check if the data source is accessible.

        Returns:
            True if healthy, False otherwise.
        """
        try:
            await self._request(self.base_url or "")
            return True
        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False
