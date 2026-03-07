"""Analysis cache for dependency scanning and tech stack detection results."""

from pathlib import Path

from src.layers.l1_intelligence.cache.analysis_cache import (
    AnalysisCache,
    CacheKeyBuilder,
    get_analysis_cache,
)
from src.layers.l1_intelligence.cache.scoped_cache import (
    ScopedDependencyCache,
    ScopedTechStackCache,
)

__all__ = [
    "AnalysisCache",
    "CacheKeyBuilder",
    "get_analysis_cache",
    "ScopedDependencyCache",
    "ScopedTechStackCache",
]
