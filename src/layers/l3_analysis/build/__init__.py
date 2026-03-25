"""Build system detection and execution for CodeQL scanning.

This module provides:
- Build system detection (Go, Java, Node.js, Python)
- Automatic build execution
- LLM-assisted build diagnostics
- Module discovery for monorepo support
"""

from src.layers.l3_analysis.build.detector import (
    BuildConfig,
    BuildSystem,
    BuildSystemDetector,
    detect_build_system,
)
from src.layers.l3_analysis.build.diagnostic import (
    BuildDiagnostic,
    BuildDiagnostician,
    diagnose_build_failure,
)
from src.layers.l3_analysis.build.executor import (
    BuildExecutor,
    BuildResult,
    execute_build,
)
from src.layers.l3_analysis.build.module_discovery import (
    ModuleDiscovery,
    MonorepoInfo,
    MonorepoType,
    discover_modules,
)

__all__ = [
    "BuildSystem",
    "BuildSystemDetector",
    "BuildConfig",
    "detect_build_system",
    "BuildExecutor",
    "BuildResult",
    "execute_build",
    "BuildDiagnostician",
    "BuildDiagnostic",
    "diagnose_build_failure",
    "ModuleDiscovery",
    "MonorepoInfo",
    "MonorepoType",
    "discover_modules",
]
