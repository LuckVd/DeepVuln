"""
L3 Analysis Layer - Static Code Analysis

This layer provides multi-engine static analysis capabilities:
- Semgrep: Fast pattern matching for known vulnerability patterns
- CodeQL: Deep dataflow analysis
- OpenCode Agent: AI-powered deep audit (future)

Core components:
- Finding: Unified vulnerability finding model
- BaseEngine: Abstract base class for analysis engines
- SemgrepEngine: Semgrep integration
- CodeQLEngine: CodeQL integration
- SmartScanner: Intelligent scanner with auto rule selection
"""

from src.layers.l3_analysis.models import (
    Finding,
    FindingType,
    SeverityLevel,
    CodeLocation,
    ScanResult,
)
from src.layers.l3_analysis.engines.base import BaseEngine, EngineRegistry
from src.layers.l3_analysis.engines.codeql import CodeQLEngine
from src.layers.l3_analysis.engines.semgrep import SemgrepEngine
from src.layers.l3_analysis.smart_scanner import SmartScanner, create_smart_scanner

__all__ = [
    # Models
    "Finding",
    "FindingType",
    "SeverityLevel",
    "CodeLocation",
    "ScanResult",
    # Engines
    "BaseEngine",
    "EngineRegistry",
    "SemgrepEngine",
    "CodeQLEngine",
    # Scanner
    "SmartScanner",
    "create_smart_scanner",
]
