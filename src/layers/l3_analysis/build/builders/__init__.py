"""
Language-specific builders for CodeQL database creation.

This package provides builder classes for each supported language
that analyze projects and generate appropriate build strategies.
"""

from .base import (
    BuildResult,
    BuilderOutput,
    BuilderRegistry,
    FailureCategory,
    FailureDiagnosis,
    LanguageBuilder,
)
from .go import GoBuilder
from .java import JavaBuilder

__all__ = [
    "BuildResult",
    "BuilderOutput",
    "BuilderRegistry",
    "FailureCategory",
    "FailureDiagnosis",
    "LanguageBuilder",
    "GoBuilder",
    "JavaBuilder",
]
