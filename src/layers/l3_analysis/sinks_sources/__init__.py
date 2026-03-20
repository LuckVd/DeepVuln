"""
P6-05: Sink and Source Definitions Module

Integrated from code-audit/references/core/sinks_sources.md.
Provides comprehensive definitions for taint sources and dangerous sinks
across multiple programming languages.

P6-06b: Extended with BusinessLogicCategory for D9 dimension.

This module is used by:
- TaintTracker for backward taint analysis
- Semgrep/CodeQL engines for pattern matching
- LLM Agent for vulnerability verification
"""

from enum import Enum

from src.layers.l3_analysis.sinks_sources.models import (
    SinkCategory,
    SinkDefinition,
    SourceCategory,
    SourceDefinition,
    SinkLibrary,
    SourceLibrary,
)
from src.layers.l3_analysis.sinks_sources.registry import (
    SinkRegistry,
    SourceRegistry,
    get_sink_registry,
    get_source_registry,
)


class BusinessLogicCategory(str, Enum):
    """
    P6-06b: Categories of business logic vulnerabilities (D9 dimension).

    Business logic vulnerabilities are "missing security controls" rather than
    "dangerous code patterns". They require Control-driven audit methodology.

    See: methodology/business_logic.md for detailed detection patterns.
    """

    IDOR = "idor"
    """Insecure Direct Object Reference - High severity"""

    MASS_ASSIGNMENT = "mass_assignment"
    """Mass Assignment - High severity"""

    STATE_MACHINE = "state_machine"
    """State Machine Integrity - High severity"""

    RACE_CONDITION = "race_condition"
    """Race Condition (TOCTOU, Lost Update) - High severity"""

    DATA_EXPORT = "data_export"
    """Data Export / Bulk Operations - Medium severity"""

    MULTI_TENANT = "multi_tenant"
    """Multi-tenant Isolation - High severity"""


__all__ = [
    # Models
    "SinkCategory",
    "SinkDefinition",
    "SourceCategory",
    "SourceDefinition",
    "SinkLibrary",
    "SourceLibrary",
    # Registry
    "SinkRegistry",
    "SourceRegistry",
    "get_sink_registry",
    "get_source_registry",
    # P6-06b: Business Logic
    "BusinessLogicCategory",
]
