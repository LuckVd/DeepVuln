"""
CodeQL Dataflow Analysis Tools.

This module provides tools for generating and executing CodeQL dataflow queries
to trace taint propagation from sources to sinks.

Components:
- QueryGenerator: Generate CodeQL queries from vulnerability candidates
- CodeQLDataflowExecutor: Execute CodeQL dataflow queries and get results
- SARIFParser: Parse SARIF output with codeFlows for complete path extraction
- SanitizerDetector: Identify and evaluate sanitizers in data flow paths
"""

from src.layers.l3_analysis.codeql.query_generator import (
    QueryGenerator,
    QueryTemplate,
    SourceDefinition,
    SinkDefinition,
    TaintTrackingConfig,
    VulnerabilityCategory,
    generate_taint_tracking_query,
)
from src.layers.l3_analysis.codeql.executor import (
    CodeQLDataflowExecutor,
    DataflowResult,
    DataflowAnalysisConfig,
)
from src.layers.l3_analysis.codeql.sarif_parser import (
    SARIFParser,
    ParsedDataflowPath,
    PathLocation,
)
from src.layers.l3_analysis.codeql.sanitizer_detector import (
    SanitizerDetector,
    SanitizerMatch,
    SanitizerEffectiveness,
)

__all__ = [
    # Query Generator
    "QueryGenerator",
    "QueryTemplate",
    "SourceDefinition",
    "SinkDefinition",
    "TaintTrackingConfig",
    "VulnerabilityCategory",
    "generate_taint_tracking_query",
    # Executor
    "CodeQLDataflowExecutor",
    "DataflowResult",
    "DataflowAnalysisConfig",
    # SARIF Parser
    "SARIFParser",
    "ParsedDataflowPath",
    "PathLocation",
    # Sanitizer Detector
    "SanitizerDetector",
    "SanitizerMatch",
    "SanitizerEffectiveness",
]
