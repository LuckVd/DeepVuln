"""File-based cache for threat intelligence data."""

import asyncio
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class FileCache:
    """File-based cache for threat intelligence data.

    Provides a simple file-based caching mechanism to reduce
    API calls and improve performance.
    """

    def __init__(
        self,
        cache_dir: str = "./data/threat_intel/cache",
        default_ttl: int = 3600,  # 1 hour
    ) -> None:
        """Initialize file cache.

        Args:
            cache_dir: Directory for cache files.
            default_ttl: Default time-to-live in seconds.
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl

        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path for a key.

        Args:
            key: Cache key.

        Returns:
            Path to cache file.
        """
        # Use hash for filename to handle special characters
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self.cache_dir / f"{key_hash}.json"

    def _get_metadata_path(self, key: str) -> Path:
        """Get metadata file path for a key.

        Args:
            key: Cache key.

        Returns:
            Path to metadata file.
        """
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self.cache_dir / f"{key_hash}.meta.json"

    async def get(self, key: str) -> Any | None:
        """Get a value from cache.

        Args:
            key: Cache key.

        Returns:
            Cached value or None if not found/expired.
        """
        cache_path = self._get_cache_path(key)
        meta_path = self._get_metadata_path(key)

        async with self._lock:
            if not cache_path.exists() or not meta_path.exists():
                return None

            try:
                # Check expiration
                with open(meta_path, encoding="utf-8") as f:
                    meta = json.load(f)

                expires_at = datetime.fromisoformat(meta.get("expires_at", ""))
                if datetime.now() > expires_at:
                    logger.debug(f"Cache expired for key: {key[:50]}...")
                    return None

                # Read cached data
                with open(cache_path, encoding="utf-8") as f:
                    data = json.load(f)

                logger.debug(f"Cache hit for key: {key[:50]}...")
                return data

            except Exception as e:
                logger.warning(f"Cache read error: {e}")
                return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: int | None = None,
    ) -> bool:
        """Set a value in cache.

        Args:
            key: Cache key.
            value: Value to cache.
            ttl: Time-to-live in seconds (uses default if None).

        Returns:
            True if successful.
        """
        cache_path = self._get_cache_path(key)
        meta_path = self._get_metadata_path(key)

        ttl = ttl or self.default_ttl
        expires_at = datetime.now() + timedelta(seconds=ttl)

        async with self._lock:
            try:
                # Write data
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(value, f, default=str, indent=2)

                # Write metadata
                meta = {
                    "key": key[:100],  # Truncate for storage
                    "created_at": datetime.now().isoformat(),
                    "expires_at": expires_at.isoformat(),
                    "ttl": ttl,
                }
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2)

                logger.debug(f"Cached key: {key[:50]}... (TTL: {ttl}s)")
                return True

            except Exception as e:
                logger.error(f"Cache write error: {e}")
                return False

    async def delete(self, key: str) -> bool:
        """Delete a value from cache.

        Args:
            key: Cache key.

        Returns:
            True if deleted.
        """
        cache_path = self._get_cache_path(key)
        meta_path = self._get_metadata_path(key)

        async with self._lock:
            try:
                if cache_path.exists():
                    cache_path.unlink()
                if meta_path.exists():
                    meta_path.unlink()
                return True
            except Exception as e:
                logger.warning(f"Cache delete error: {e}")
                return False

    async def clear(self) -> int:
        """Clear all cached data.

        Returns:
            Number of cache entries cleared.
        """
        count = 0

        async with self._lock:
            try:
                for file in self.cache_dir.glob("*.json"):
                    file.unlink()
                    count += 1
            except Exception as e:
                logger.error(f"Cache clear error: {e}")

        logger.info(f"Cleared {count} cache entries")
        return count

    async def cleanup_expired(self) -> int:
        """Remove expired cache entries.

        Returns:
            Number of entries removed.
        """
        count = 0
        now = datetime.now()

        async with self._lock:
            for meta_path in self.cache_dir.glob("*.meta.json"):
                try:
                    with open(meta_path, encoding="utf-8") as f:
                        meta = json.load(f)

                    expires_at = datetime.fromisoformat(meta.get("expires_at", ""))
                    if now > expires_at:
                        # Delete both files
                        cache_path = self.cache_dir / meta_path.name.replace(
                            ".meta.json", ".json"
                        )
                        if cache_path.exists():
                            cache_path.unlink()
                        meta_path.unlink()
                        count += 1

                except Exception as e:
                    logger.warning(f"Cache cleanup error for {meta_path}: {e}")

        if count > 0:
            logger.info(f"Cleaned up {count} expired cache entries")

        return count

    async def get_or_set(
        self,
        key: str,
        factory: Any,
        ttl: int | None = None,
    ) -> Any:
        """Get from cache or compute and cache.

        Args:
            key: Cache key.
            factory: Async function to compute value if not cached.
            ttl: Time-to-live in seconds.

        Returns:
            Cached or computed value.
        """
        # Try to get from cache
        value = await self.get(key)
        if value is not None:
            return value

        # Compute value
        if asyncio.iscoroutinefunction(factory):
            value = await factory()
        else:
            value = factory()

        # Cache the value
        await self.set(key, value, ttl=ttl)

        return value

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics.

        Returns:
            Statistics dictionary.
        """
        total_files = len(list(self.cache_dir.glob("*.json")))
        total_size = sum(
            f.stat().st_size for f in self.cache_dir.glob("*.json") if f.exists()
        )

        return {
            "cache_dir": str(self.cache_dir),
            "total_entries": total_files // 2,  # Each entry has data + meta
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "default_ttl": self.default_ttl,
        }

    async def get_keys(self) -> list[str]:
        """Get all cache keys.

        Returns:
            List of cache keys.
        """
        keys = []

        async with self._lock:
            for meta_path in self.cache_dir.glob("*.meta.json"):
                try:
                    with open(meta_path, encoding="utf-8") as f:
                        meta = json.load(f)
                    keys.append(meta.get("key", ""))
                except Exception:
                    continue

        return [k for k in keys if k]


class CVECache(FileCache):
    """Specialized cache for CVE data."""

    def __init__(self, cache_dir: str = "./data/threat_intel/cache/cve") -> None:
        """Initialize CVE cache with 24-hour TTL."""
        super().__init__(cache_dir=cache_dir, default_ttl=86400)

    async def get_cve(self, cve_id: str) -> dict | None:
        """Get cached CVE data.

        Args:
            cve_id: CVE identifier.

        Returns:
            Cached CVE data or None.
        """
        return await self.get(f"cve:{cve_id}")

    async def set_cve(self, cve_id: str, data: dict) -> bool:
        """Cache CVE data.

        Args:
            cve_id: CVE identifier.
            data: CVE data.

        Returns:
            True if successful.
        """
        return await self.set(f"cve:{cve_id}", data)


class SearchCache(FileCache):
    """Specialized cache for search results."""

    def __init__(self, cache_dir: str = "./data/threat_intel/cache/search") -> None:
        """Initialize search cache with 1-hour TTL."""
        super().__init__(cache_dir=cache_dir, default_ttl=3600)

    async def get_search_results(self, query: str) -> list | None:
        """Get cached search results.

        Args:
            query: Search query.

        Returns:
            Cached results or None.
        """
        return await self.get(f"search:{query}")

    async def set_search_results(
        self,
        query: str,
        results: list,
        ttl: int = 3600,
    ) -> bool:
        """Cache search results.

        Args:
            query: Search query.
            results: Search results.
            ttl: Time-to-live.

        Returns:
            True if successful.
        """
        return await self.set(f"search:{query}", results, ttl=ttl)
