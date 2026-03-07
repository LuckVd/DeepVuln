"""Analysis cache for dependency scanning and tech stack detection results.

This module provides caching to speed up repeated scans of the same project.
"""

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class CacheKeyBuilder:
    """Builder for cache keys based on file signatures."""

    @staticmethod
    def _get_file_signature(file_path: Path) -> str:
        """Get a signature for a single file.

        Args:
            file_path: Path to the file.

        Returns:
            Signature string (name:mtime:size).
        """
        try:
            stat = file_path.stat()
            return f"{file_path.name}:{stat.st_mtime}:{stat.st_size}"
        except OSError:
            return f"{file_path.name}:error"

    @staticmethod
    def _get_files_signature(files: list[Path]) -> str:
        """Get a combined signature for multiple files.

        Args:
            files: List of file paths.

        Returns:
            Combined signature hash.
        """
        signatures = []
        for f in sorted(files, key=lambda x: str(x)):
            signatures.append(CacheKeyBuilder._get_file_signature(f))

        combined = "|".join(signatures)
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    @staticmethod
    def build_dependency_cache_key(source_path: Path, dep_files: list[Path]) -> str:
        """Build cache key for dependency scanning.

        Args:
            source_path: Project source path.
            dep_files: List of dependency files found.

        Returns:
            Cache key string.
        """
        source_hash = hashlib.sha256(str(source_path).encode()).hexdigest()[:16]
        files_sig = CacheKeyBuilder._get_files_signature(dep_files)
        return f"deps:{source_hash}:{files_sig}"

    @staticmethod
    def build_tech_stack_cache_key(source_path: Path, significant_files: list[Path] | None) -> str:
        """Build cache key for tech stack detection.

        Args:
            source_path: Project source path.
            significant_files: List of significant project files (config, source).

        Returns:
            Cache key string.
        """
        source_hash = hashlib.sha256(str(source_path).encode()).hexdigest()[:16]

        if significant_files:
            files_sig = CacheKeyBuilder._get_files_signature(significant_files)
            return f"tech:{source_hash}:{files_sig}"

        return f"tech:{source_hash}:project"


class AnalysisCache:
    """File-based cache for analysis results.

    Provides caching for dependency scanning and tech stack detection
    to speed up repeated scans.
    """

    def __init__(
        self,
        cache_dir: str = "./data/analysis_cache",
        default_ttl: int = 86400,  # 24 hours
    ) -> None:
        """Initialize analysis cache.

        Args:
            cache_dir: Directory for cache files.
            default_ttl: Default time-to-live in seconds.
        """
        self.cache_dir = Path(cache_dir)
        self.default_ttl = default_ttl

        # Create subdirectories
        self.deps_cache_dir = self.cache_dir / "dependencies"
        self.tech_cache_dir = self.cache_dir / "tech_stack"

        self.deps_cache_dir.mkdir(parents=True, exist_ok=True)
        self.tech_cache_dir.mkdir(parents=True, exist_ok=True)

        # Statistics
        self._hits = 0
        self._misses = 0

    def _get_cache_path(self, key: str, cache_type: str) -> Path:
        """Get cache file path.

        Args:
            key: Cache key.
            cache_type: Type of cache (dependencies/tech_stack).

        Returns:
            Path to cache file.
        """
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        base_dir = self.deps_cache_dir if cache_type == "deps" else self.tech_cache_dir
        return base_dir / f"{key_hash}.json"

    def _get_metadata_path(self, key: str, cache_type: str) -> Path:
        """Get metadata file path.

        Args:
            key: Cache key.
            cache_type: Type of cache.

        Returns:
            Path to metadata file.
        """
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        base_dir = self.deps_cache_dir if cache_type == "deps" else self.tech_cache_dir
        return base_dir / f"{key_hash}.meta.json"

    def get_dependencies(self, source_path: Path, dep_files: list[Path]) -> dict | None:
        """Get cached dependency scan result.

        Args:
            source_path: Project source path.
            dep_files: List of dependency files found.

        Returns:
            Cached dependency data or None if not found/expired.
        """
        key = CacheKeyBuilder.build_dependency_cache_key(source_path, dep_files)
        return self._get(key, "deps")

    def set_dependencies(
        self,
        source_path: Path,
        dep_files: list[Path],
        data: dict,
        ttl: int | None = None,
    ) -> bool:
        """Cache dependency scan result.

        Args:
            source_path: Project source path.
            dep_files: List of dependency files found.
            data: Dependency data to cache.
            ttl: Time-to-live in seconds.

        Returns:
            True if successful.
        """
        key = CacheKeyBuilder.build_dependency_cache_key(source_path, dep_files)
        return self._set(key, data, "deps", ttl)

    def get_tech_stack(self, source_path: Path, significant_files: list[Path] | None) -> dict | None:
        """Get cached tech stack detection result.

        Args:
            source_path: Project source path.
            significant_files: List of significant project files.

        Returns:
            Cached tech stack data or None if not found/expired.
        """
        key = CacheKeyBuilder.build_tech_stack_cache_key(source_path, significant_files)
        return self._get(key, "tech")

    def set_tech_stack(
        self,
        source_path: Path,
        significant_files: list[Path] | None,
        data: dict,
        ttl: int | None = None,
    ) -> bool:
        """Cache tech stack detection result.

        Args:
            source_path: Project source path.
            significant_files: List of significant project files.
            data: Tech stack data to cache.
            ttl: Time-to-live in seconds.

        Returns:
            True if successful.
        """
        key = CacheKeyBuilder.build_tech_stack_cache_key(source_path, significant_files)
        return self._set(key, data, "tech", ttl)

    def _get(self, key: str, cache_type: str) -> dict | None:
        """Get a value from cache.

        Args:
            key: Cache key.
            cache_type: Type of cache.

        Returns:
            Cached data or None if not found/expired.
        """
        cache_path = self._get_cache_path(key, cache_type)
        meta_path = self._get_metadata_path(key, cache_type)

        if not cache_path.exists() or not meta_path.exists():
            self._misses += 1
            return None

        try:
            # Check expiration
            with open(meta_path, encoding="utf-8") as f:
                meta = json.load(f)

            expires_at = datetime.fromisoformat(meta.get("expires_at", ""))
            if datetime.now() > expires_at:
                logger.debug(f"Cache expired for {cache_type}: {key[:50]}...")
                self._misses += 1
                return None

            # Read cached data
            with open(cache_path, encoding="utf-8") as f:
                data = json.load(f)

            self._hits += 1
            logger.debug(f"Cache hit for {cache_type}: {key[:50]}...")
            return data

        except Exception as e:
            logger.warning(f"Cache read error: {e}")
            self._misses += 1
            return None

    def _set(
        self,
        key: str,
        value: dict,
        cache_type: str,
        ttl: int | None = None,
    ) -> bool:
        """Set a value in cache.

        Args:
            key: Cache key.
            value: Value to cache.
            cache_type: Type of cache.
            ttl: Time-to-live in seconds.

        Returns:
            True if successful.
        """
        cache_path = self._get_cache_path(key, cache_type)
        meta_path = self._get_metadata_path(key, cache_type)

        effective_ttl = ttl or self.default_ttl

        try:
            # Write data
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(value, f, indent=2)

            # Write metadata
            now = datetime.now()
            expires_at = now + timedelta(seconds=effective_ttl)
            meta = {
                "created_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "ttl": effective_ttl,
            }
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)

            logger.debug(f"Cached {cache_type}: {key[:50]}...")
            return True

        except Exception as e:
            logger.error(f"Cache write error: {e}")
            return False

    def invalidate(self, source_path: Path) -> int:
        """Invalidate all cache entries for a source path.

        Args:
            source_path: Project source path.

        Returns:
            Number of entries invalidated.
        """
        source_hash = hashlib.sha256(str(source_path).encode()).hexdigest()[:16]
        count = 0

        # Invalidate dependency cache
        for cache_file in self.deps_cache_dir.glob(f"*.json"):
            try:
                with open(cache_file, encoding="utf-8") as f:
                    data = json.load(f)
                if source_hash in str(data):
                    cache_file.unlink()
                    count += 1
            except Exception:
                pass

        # Invalidate tech stack cache
        for cache_file in self.tech_cache_dir.glob(f"*.json"):
            try:
                with open(cache_file, encoding="utf-8") as f:
                    data = json.load(f)
                if source_hash in str(data):
                    cache_file.unlink()
                    count += 1
            except Exception:
                pass

        logger.info(f"Invalidated {count} cache entries for {source_path}")
        return count

    def get_stats(self) -> dict:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics.
        """
        deps_count = len(list(self.deps_cache_dir.glob("*.json"))) // 2  # meta files
        tech_count = len(list(self.tech_cache_dir.glob("*.json"))) // 2

        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0,
            "deps_entries": deps_count,
            "tech_entries": tech_count,
            "cache_dir": str(self.cache_dir),
        }

    def clear_all(self) -> int:
        """Clear all cache entries.

        Returns:
            Number of entries cleared.
        """
        count = 0

        for cache_file in self.deps_cache_dir.glob("*.json"):
            cache_file.unlink()
            count += 1

        for cache_file in self.tech_cache_dir.glob("*.json"):
            cache_file.unlink()
            count += 1

        logger.info(f"Cleared {count} cache entries")
        return count


# Global cache instance
_cache_instance: AnalysisCache | None = None


def get_analysis_cache() -> AnalysisCache:
    """Get the global analysis cache instance.

    Returns:
        Global AnalysisCache instance.
    """
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = AnalysisCache()
    return _cache_instance
