"""Build system detection and execution for CodeQL scanning.

This module provides:
- Build system detection (Go, Java, Node.js, Python)
- Automatic build execution
- LLM-assisted build diagnostics
- Module discovery for monorepo support
- Build target extraction and recommendation
- Runtime version detection
- Tool resolution and compatibility checking
- Build plan generation and execution orchestration
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
from src.layers.l3_analysis.build.target_extractor import (
    BuildRecommendation,
    BuildStrategy,
    BuildTarget,
    BuildTargetExtractor,
    EntryPoint,
    EntryPointType,
    extract_build_targets,
)
from src.layers.l3_analysis.build.version_detector import (
    RuntimeType,
    VersionDetector,
    VersionInfo,
    VersionRequirement,
    detect_versions,
)
from src.layers.l3_analysis.build.tool_resolver import (
    CompatibilityChecker,
    CompatibilityResult,
    CompatibilityStatus,
    ProvisionPolicy,
    ReadinessReport,
    ToolInfo,
    ToolResolver,
    ToolSource,
    ToolType,
    check_tool_compatibility,
    generate_readiness_report,
    resolve_tool,
    version_matches,
)
from src.layers.l3_analysis.build.build_plan import (
    BuildCache,
    BuildExecutionResult,
    BuildOrchestrator,
    BuildPlan,
    BuildPlanGenerator,
    BuildPlanStatus,
    BuildStep,
    BuildSummary,
    CacheEntry,
    FallbackStrategy,
    RiskLevel,
    create_build_cache,
    generate_build_plan,
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
    "BuildTarget",
    "EntryPoint",
    "BuildRecommendation",
    "BuildStrategy",
    "EntryPointType",
    "BuildTargetExtractor",
    "extract_build_targets",
    "RuntimeType",
    "VersionDetector",
    "VersionInfo",
    "VersionRequirement",
    "detect_versions",
    # Tool resolver
    "ToolType",
    "ToolSource",
    "ToolInfo",
    "ToolResolver",
    "CompatibilityChecker",
    "CompatibilityResult",
    "CompatibilityStatus",
    "ProvisionPolicy",
    "ReadinessReport",
    "resolve_tool",
    "check_tool_compatibility",
    "generate_readiness_report",
    "version_matches",
    # Build plan
    "BuildPlan",
    "BuildStep",
    "BuildPlanGenerator",
    "BuildOrchestrator",
    "BuildCache",
    "CacheEntry",
    "BuildExecutionResult",
    "BuildSummary",
    "RiskLevel",
    "FallbackStrategy",
    "BuildPlanStatus",
    "generate_build_plan",
    "create_build_cache",
]

# Runtime version management (lazy import to avoid circular dependencies)
def get_runtime_manager(*args, **kwargs):
    """Get RuntimeVersionManager instance."""
    from .runtime import RuntimeVersionManager
    return RuntimeVersionManager(*args, **kwargs)
