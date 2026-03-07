"""Scoped cache wrappers for dependency scanning and tech stack detection."""

from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.cache.analysis_cache import AnalysisCache, get_analysis_cache
from src.layers.l1_intelligence.depend_scanner.base_scanner import Dependency, ScanResult

from src.layers.l1_intelligence.tech_stack_detector.detector import TechStack

logger = get_logger(__name__)


class ScopedDependencyCache:
    """Cache wrapper for dependency scanning results.

    Provides transparent caching with automatic invalidation.
    """

    def __init__(self, cache: AnalysisCache | None = None) -> None:
        self.cache = cache or get_analysis_cache()
        self._source_path: Path | None
        self._last_files: list[Path] = []
        self._last_signature: str | ""

    async def get(
        self,
        source_path: Path,
    ) -> ScanResult | None:
        """Get cached dependency scan result.

        Args:
            source_path: Project source path.

        Returns:
            Cached ScanResult or None if not found/expired.
        """
        if not self.cache:
            return None

        cache_key = CacheKeyBuilder.build_dependency_cache_key(
            source_path, self._last_files
        )
        cached_data = await self.cache.get(cache_key)
        if cached_data is None:
            return None

        # Deserialize ScanResult
        return ScanResult.model_validate(cached_data)

    async def set(
        self,
        source_path: Path,
        result: ScanResult,
        dep_files: list[Path],
    ) -> bool:
        """Cache dependency scan result.

        Args:
            source_path: Project source path.
            result: ScanResult to cache.
            dep_files: List of dependency files that were scanned.

        Returns:
            True if successful.
        """
        if not self.cache:
            return False

        # Update last files for invalidation check
        self._last_files = dep_files
        self._last_signature = CacheKeyBuilder._get_files_signature(dep_files)

        cache_key = CacheKeyBuilder.build_dependency_cache_key(
            source_path, self._last_files
        )
        return await self.cache.set(cache_key, result.model_dump())

    def is_valid(self, source_path: Path, dep_files: list[Path]) -> bool:
        """Check if cache is valid for given source path.

        Args:
            source_path: Project source path.
            dep_files: List of dependency files.

        Returns:
            True if cache is valid, """
        if not self._last_files:
            return False

        # Check if files changed
        current_files = list(source_path.rglob("package*.json")) + \
            list(source_path.rglob("requirements*.txt")) + \
            list(source_path.rglob("go.mod"))

        if not current_files:
            return False

        current_sig = CacheKeyBuilder._get_files_signature(current_files)
        return current_sig != self._last_signature


class ScopedTechStackCache:
    """Cache wrapper for tech stack detection results.

    Provides transparent caching with automatic invalidation.
    """

    def __init__(self, cache: AnalysisCache | None = None) -> None:
        self.cache = cache or get_analysis_cache()
        self._source_path: Path | None
        self._last_signature: str = ""
        self._significant_extensions = [
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".java",
            ".go",
            ".rs",
            ".rb",
            ".php",
            ".json",
            ".yaml",
            ".yml",
            ".toml",
            ".xml",
            ".gradle",
        ]

    async def get(
        self,
        source_path: Path,
    ) -> TechStack | None:
        """Get cached tech stack detection result.

        Args:
            source_path: Project source path.

        Returns:
            Cached TechStack or None if not found/expired.
        """
        if not self.cache:
            return None

        # Get significant files for cache key
        significant_files = self._get_significant_files(source_path)
        cache_key = CacheKeyBuilder.build_tech_stack_cache_key(
            source_path, significant_files
        )

        cached_data = await self.cache.get(cache_key)
        if cached_data is None:
            return None

        # Deserialize TechStack
        return TechStack.model_validate(cached_data)

    async def set(
        self,
        source_path: Path,
        result: TechStack,
    ) -> bool:
        """Cache tech stack detection result.

        Args:
            source_path: Project source path.
            result: TechStack to cache.

        Returns:
            True if successful.
        """
        if not self.cache:
            return False

        # Get significant files for cache key
        significant_files = self._get_significant_files(source_path)
        self._last_signature = CacheKeyBuilder._get_files_signature(significant_files)

        cache_key = CacheKeyBuilder.build_tech_stack_cache_key(
            source_path, significant_files
        )
        return await self.cache.set(cache_key, result.model_dump())

    def _get_significant_files(self, source_path: Path) -> list[Path]:
        """Get significant project files for cache key.

        Args:
            source_path: Project source path.

        Returns:
            List of significant file paths.
        """
        significant_files = []
        for ext in self._significant_extensions:
            significant_files.extend(source_path.rglob(f"*{ext}"))
        return significant_files[:50]  # Limit to avoid huge signatures

