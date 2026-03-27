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
from .cpp import CppBuilder
from .go import GoBuilder
from .java import JavaBuilder
from .javascript import JavaScriptBuilder
from .python import PythonBuilder

__all__ = [
    "BuildResult",
    "BuilderOutput",
    "BuilderRegistry",
    "FailureCategory",
    "FailureDiagnosis",
    "LanguageBuilder",
    "CppBuilder",
    "GoBuilder",
    "JavaBuilder",
    "JavaScriptBuilder",
    "PythonBuilder",
]
