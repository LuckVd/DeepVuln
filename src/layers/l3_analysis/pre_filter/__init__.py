"""
Pre-Filter Module - Frontline defense against false positives.

This module implements filtering mechanisms that operate BEFORE analysis begins,
reducing resource waste on files that won't yield meaningful findings.

Core Principle: Filter early, filter often, save resources.

Components:
- FilePreFilter: File-level filtering before scan (P8-08a)
- StreamingValidator: Real-time finding validation (P8-08c)
- CodeQLPreFilter: CodeQL rule adjustment (P8-08d)
- InMemoryDeduplicator: In-memory deduplication (P8-08e)
"""

from src.layers.l3_analysis.pre_filter.file_pre_filter import FilePreFilter
from src.layers.l3_analysis.pre_filter.streaming_validator import StreamingValidator
from src.layers.l3_analysis.pre_filter.codeql_pre_filter import CodeQLPreFilter
from src.layers.l3_analysis.pre_filter.in_memory_deduplicator import InMemoryDeduplicator

__all__ = [
    "FilePreFilter",
    "StreamingValidator",
    "CodeQLPreFilter",
    "InMemoryDeduplicator",
]
