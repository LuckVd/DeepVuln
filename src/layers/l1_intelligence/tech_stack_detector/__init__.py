"""Tech stack detector module for identifying project technologies."""

from src.layers.l1_intelligence.tech_stack_detector.detector import (
    TechStackDetector,
)
from src.layers.l1_intelligence.tech_stack_detector.models import (
    Database,
    Framework,
    Language,
    LanguageInfo,
    Middleware,
    ProjectType,
    TechStack,
)

__all__ = [
    # Main detector
    "TechStackDetector",
    # Data models
    "TechStack",
    "Language",
    "LanguageInfo",
    "Framework",
    "Database",
    "Middleware",
    "ProjectType",
]
