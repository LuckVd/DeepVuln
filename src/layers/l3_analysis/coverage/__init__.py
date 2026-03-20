"""
P6-08: Coverage Matrix Module

This module provides data structures for tracking audit coverage
across languages, engines, and security dimensions (D1-D10).

Coverage Matrix: language x engine x dimension x status

Dimension Types:
- Sink-driven (D1, D4, D5, D6): Search dangerous functions → trace data flow
- Control-driven (D3, D9): Enumerate endpoints → verify controls exist
- Config-driven (D2, D7, D8, D10): Search config → compare against baseline
"""

from src.layers.l3_analysis.coverage.matrix import (
    CoverageStatus,
    DimensionType,
    DimensionCoverage,
    LanguageEngineCoverage,
    CoverageMatrix,
    CORE_LANGUAGES,
    ALL_ENGINES,
    ALL_DIMENSIONS,
)
from src.layers.l3_analysis.coverage.evaluator import (
    CoverageEvaluator,
    evaluate_sink_driven_coverage,
    evaluate_control_driven_coverage,
    evaluate_config_driven_coverage,
)

__all__ = [
    # Enums
    "CoverageStatus",
    "DimensionType",
    # Models
    "DimensionCoverage",
    "LanguageEngineCoverage",
    "CoverageMatrix",
    # Constants
    "CORE_LANGUAGES",
    "ALL_ENGINES",
    "ALL_DIMENSIONS",
    # Evaluators
    "CoverageEvaluator",
    "evaluate_sink_driven_coverage",
    "evaluate_control_driven_coverage",
    "evaluate_config_driven_coverage",
]
