"""Code structure parsing module.

This module provides functionality to parse source code and extract
structural information like classes, functions, imports, and call graphs.

Example usage:
    from src.layers.l1_intelligence.code_structure import parse_file, parse_project

    # Parse a single file
    module = parse_file("path/to/file.java")
    print(f"Classes: {len(module.classes)}")
    print(f"Functions: {len(module.functions)}")

    # Parse an entire project
    project = parse_project("path/to/project")
    print(f"Total classes: {len(project.all_classes)}")
    print(f"Call graph edges: {len(project.global_call_graph.edges)}")
"""

from .base import CodeStructureParser, LanguageParser, TreeSitterParser
from .models import (
    CallEdge,
    CallGraph,
    ClassDef,
    ClassType,
    FieldDef,
    FunctionDef,
    ImportDef,
    ModuleInfo,
    Parameter,
    ParseOptions,
    ProjectStructure,
    Visibility,
)
from .parser import CodeStructureParser as _CodeStructureParser
from .parser import parse_file, parse_project

__all__ = [
    # Data models
    "CallEdge",
    "CallGraph",
    "ClassDef",
    "ClassType",
    "FieldDef",
    "FunctionDef",
    "ImportDef",
    "ModuleInfo",
    "Parameter",
    "ParseOptions",
    "ProjectStructure",
    "Visibility",
    # Parsers
    "CodeStructureParser",
    "LanguageParser",
    "TreeSitterParser",
    # Convenience functions
    "parse_file",
    "parse_project",
]
