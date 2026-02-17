"""L1 Intelligence Layer - Source code acquisition and workspace management."""

from src.layers.l1_intelligence.code_structure import (
    CallEdge,
    CallGraph,
    ClassDef,
    CodeStructureParser,
    FunctionDef,
    ModuleInfo,
    ParseOptions,
    ProjectStructure,
    parse_file,
    parse_project,
)
from src.layers.l1_intelligence.fetcher import AssetFetcher
from src.layers.l1_intelligence.git_operations import GitOperations
from src.layers.l1_intelligence.security_analyzer import SecurityAnalyzer, SecurityReport
from src.layers.l1_intelligence.tech_stack_detector import TechStack, TechStackDetector
from src.layers.l1_intelligence.workflow import AutoSecurityScanner, ScanConfig, ScanResult
from src.layers.l1_intelligence.workspace import WorkspaceManager

__all__ = [
    # Core components
    "AssetFetcher",
    "GitOperations",
    "WorkspaceManager",
    # Security analysis
    "SecurityAnalyzer",
    "SecurityReport",
    # Tech stack detection
    "TechStack",
    "TechStackDetector",
    # Code structure parsing
    "CallEdge",
    "CallGraph",
    "ClassDef",
    "CodeStructureParser",
    "FunctionDef",
    "ModuleInfo",
    "ParseOptions",
    "ProjectStructure",
    "parse_file",
    "parse_project",
    # Auto security workflow
    "AutoSecurityScanner",
    "ScanConfig",
    "ScanResult",
    # Build config security analysis (lazy import)
    # Use: from src.layers.l1_intelligence.build_config import BuildConfigAnalyzer
]
