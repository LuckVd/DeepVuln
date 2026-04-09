"""Data models for attack surface detection.

P15: Models moved to src.core.models.attack_surface to resolve circular dependencies.
This file now re-exports the models from core for backward compatibility.
"""

# Re-export from core to maintain backward compatibility
from src.core.models.attack_surface import (
    EntryPoint,
    EntryPointType,
    DetectionSource,
    HTTPMethod,
    AttackSurfaceReport,
)

__all__ = [
    "EntryPoint",
    "EntryPointType",
    "DetectionSource",
    "HTTPMethod",
    "AttackSurfaceReport",
]
