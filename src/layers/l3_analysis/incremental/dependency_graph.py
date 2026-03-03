"""
Dependency Graph - Build and query file dependency relationships.

Constructs a graph of file dependencies to enable impact analysis
by tracking how changes in one file can affect others.
"""

import asyncio
import ast
import hashlib
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class DependencyType(str, Enum):
    """Type of dependency relationship."""

    # Import dependencies
    IMPORT = "import"  # Direct import (import x)
    FROM_IMPORT = "from_import"  # From import (from x import y)
    DYNAMIC_IMPORT = "dynamic_import"  # Dynamic import (__import__, importlib)

    # Code dependencies
    FUNCTION_CALL = "function_call"  # Function call
    CLASS_INHERITANCE = "inheritance"  # Class inheritance
    CLASS_COMPOSITION = "composition"  # Class composition/usage

    # Resource dependencies
    CONFIG_INCLUDE = "config_include"  # Config file inclusion
    TEMPLATE_EXTENDS = "template_extends"  # Template inheritance
    TEMPLATE_INCLUDE = "template_include"  # Template inclusion

    # File system
    FILE_READ = "file_read"  # File read operation
    FILE_REFERENCE = "file_reference"  # File path reference


@dataclass
class DependencyEdge:
    """An edge in the dependency graph."""

    source: str  # Source file path
    target: str  # Target file path
    dependency_type: DependencyType
    weight: float = 1.0  # Edge weight for impact scoring
    details: dict[str, Any] = field(default_factory=dict)  # Additional details

    # Location information
    line_number: int | None = None
    symbol_name: str | None = None  # Function/class/import name

    @property
    def edge_key(self) -> tuple[str, str, str]:
        """Get unique key for this edge."""
        return (self.source, self.target, self.dependency_type.value)


@dataclass
class DependencyNode:
    """A node in the dependency graph."""

    path: str  # File path
    language: str | None = None
    is_entry_point: bool = False  # Is this an entry point (main, handler, etc.)
    exports: list[str] = field(default_factory=list)  # Exported symbols
    imports: list[str] = field(default_factory=list)  # Imported modules

    # Metrics
    in_degree: int = 0  # Number of incoming edges
    out_degree: int = 0  # Number of outgoing edges
    centrality_score: float = 0.0  # Centrality in the graph

    # Hash for change detection
    content_hash: str | None = None


class DependencyGraph:
    """
    Builds and queries file dependency relationships.

    Supports multiple languages through pluggable parsers and
    provides efficient graph queries for impact analysis.
    """

    # Language detection by extension
    LANGUAGE_EXTENSIONS = {
        ".py": "python",
        ".pyw": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".rb": "ruby",
        ".php": "php",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
    }

    # Entry point patterns by language
    ENTRY_POINT_PATTERNS = {
        "python": [
            r"^(main|app|run|server|wsgi|asgi)\.py$",
            r"__main__\.py$",
            r"manage\.py$",
        ],
        "javascript": [
            r"^(index|main|app|server)\.(js|ts)$",
            r"^app\.(js|ts)$",
        ],
        "java": [
            r".*Application\.java$",
            r".*Main\.java$",
        ],
        "go": [
            r"^main\.go$",
            r"^cmd/.*/main\.go$",
        ],
    }

    def __init__(
        self,
        project_path: str | Path,
        exclude_patterns: list[str] | None = None,
        include_tests: bool = False,
        max_depth: int = 10,
    ):
        """
        Initialize the dependency graph.

        Args:
            project_path: Path to the project root.
            exclude_patterns: Patterns to exclude from analysis.
            include_tests: Whether to include test files.
            max_depth: Maximum depth for dependency traversal.
        """
        self.project_path = Path(project_path).resolve()
        self.exclude_patterns = exclude_patterns or [
            "node_modules",
            ".venv",
            "venv",
            "__pycache__",
            ".git",
            "build",
            "dist",
            "target",
        ]
        self.include_tests = include_tests
        self.max_depth = max_depth

        # Graph storage
        self.nodes: dict[str, DependencyNode] = {}
        self.edges: dict[str, list[DependencyEdge]] = defaultdict(list)  # source -> edges
        self.reverse_edges: dict[str, list[DependencyEdge]] = defaultdict(list)  # target -> edges

        # Symbol index for fast lookup
        self.symbol_to_files: dict[str, list[str]] = defaultdict(list)

        # Cache
        self._built = False
        self._build_time: datetime | None = None

    def _should_exclude(self, path: str) -> bool:
        """Check if a path should be excluded."""
        path_lower = path.lower()

        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if pattern.lower() in path_lower:
                return True

        # Exclude test files unless included
        if not self.include_tests:
            test_patterns = ["_test.", ".test.", "_spec.", ".spec.", "tests/", "test/"]
            for pattern in test_patterns:
                if pattern in path_lower:
                    return True

        return False

    def _detect_language(self, file_path: str) -> str | None:
        """Detect language from file extension."""
        ext = Path(file_path).suffix.lower()
        return self.LANGUAGE_EXTENSIONS.get(ext)

    def _is_entry_point(self, file_path: str, language: str) -> bool:
        """Check if a file is an entry point."""
        patterns = self.ENTRY_POINT_PATTERNS.get(language, [])
        for pattern in patterns:
            if re.search(pattern, file_path):
                return True
        return False

    def _resolve_import_path(
        self,
        import_name: str,
        source_file: str,
        language: str,
    ) -> str | None:
        """
        Resolve an import to a file path.

        Args:
            import_name: The import name (e.g., 'src.utils.helpers').
            source_file: The file containing the import.
            language: The source file language.

        Returns:
            Resolved file path or None if not found.
        """
        # Convert module name to potential file paths
        parts = import_name.split(".")

        if language == "python":
            # Try direct file
            py_path = "/".join(parts) + ".py"
            # Try package __init__.py
            init_path = "/".join(parts) + "/__init__.py"

            for candidate in [py_path, init_path]:
                full_path = self.project_path / candidate
                if full_path.exists():
                    return candidate

            # Try relative import
            source_dir = str(Path(source_file).parent)
            for candidate in [py_path, init_path]:
                rel_path = source_dir + "/" + candidate
                full_path = self.project_path / rel_path
                if full_path.exists():
                    return rel_path.lstrip("/")

        elif language in ("javascript", "typescript"):
            # Try various extensions
            extensions = [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", "/index.js", "/index.ts"]

            for ext in extensions:
                js_path = "/".join(parts) + ext
                full_path = self.project_path / js_path
                if full_path.exists():
                    return js_path

        elif language == "java":
            # Convert package to path
            java_path = "/".join(parts) + ".java"
            full_path = self.project_path / "src/main/java" / java_path
            if full_path.exists():
                return "src/main/java/" + java_path
            full_path = self.project_path / "src/test/java" / java_path
            if full_path.exists():
                return "src/test/java/" + java_path

        elif language == "go":
            # Go imports are usually full package paths
            go_path = "/".join(parts) + ".go"
            full_path = self.project_path / go_path
            if full_path.exists():
                return go_path

        return None

    async def _parse_python_file(self, file_path: str) -> tuple[list[str], list[str], list[DependencyEdge]]:
        """
        Parse a Python file for imports and exports.

        Returns:
            Tuple of (imports, exports, edges).
        """
        full_path = self.project_path / file_path
        imports = []
        exports = []
        edges = []

        try:
            content = await asyncio.to_thread(full_path.read_text, encoding="utf-8", errors="ignore")
            tree = ast.parse(content, filename=str(full_path))

            for node in ast.walk(tree):
                # Import statements
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                        resolved = self._resolve_import_path(alias.name, file_path, "python")
                        if resolved:
                            edges.append(DependencyEdge(
                                source=file_path,
                                target=resolved,
                                dependency_type=DependencyType.IMPORT,
                                line_number=node.lineno,
                                symbol_name=alias.name,
                            ))

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
                        resolved = self._resolve_import_path(node.module, file_path, "python")
                        if resolved:
                            edges.append(DependencyEdge(
                                source=file_path,
                                target=resolved,
                                dependency_type=DependencyType.FROM_IMPORT,
                                line_number=node.lineno,
                                symbol_name=node.module,
                                details={"names": [n.name for n in node.names]},
                            ))

                # Function and class definitions (exports)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    exports.append(node.name)
                elif isinstance(node, ast.ClassDef):
                    exports.append(node.name)

        except SyntaxError as e:
            logger.debug(f"Syntax error in {file_path}: {e}")
        except Exception as e:
            logger.debug(f"Error parsing Python file {file_path}: {e}")

        return imports, exports, edges

    async def _parse_javascript_file(self, file_path: str) -> tuple[list[str], list[str], list[DependencyEdge]]:
        """
        Parse a JavaScript/TypeScript file for imports and exports.

        Uses regex-based parsing for speed.
        """
        full_path = self.project_path / file_path
        imports = []
        exports = []
        edges = []

        try:
            content = await asyncio.to_thread(full_path.read_text, encoding="utf-8", errors="ignore")
            language = "typescript" if file_path.endswith((".ts", ".tsx")) else "javascript"

            # ES6 imports: import x from 'y'
            import_patterns = [
                r"import\s+(?:\{[^}]*\}|\*\s+as\s+\w+|\w+)\s+from\s+['\"]([^'\"]+)['\"]",
                r"import\s+['\"]([^'\"]+)['\"]",
                r"require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
                r"import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",  # Dynamic import
            ]

            for pattern in import_patterns:
                for match in re.finditer(pattern, content):
                    import_name = match.group(1)
                    imports.append(import_name)

                    # Skip external packages (node_modules)
                    if not import_name.startswith(".") and not import_name.startswith("/"):
                        continue

                    resolved = self._resolve_import_path(import_name, file_path, language)
                    if resolved:
                        dep_type = DependencyType.DYNAMIC_IMPORT if "import(" in match.group(0) else DependencyType.IMPORT
                        edges.append(DependencyEdge(
                            source=file_path,
                            target=resolved,
                            dependency_type=dep_type,
                            symbol_name=import_name,
                        ))

            # ES6 exports
            export_patterns = [
                r"export\s+(?:default\s+)?(?:function|class|const|let|var)\s+(\w+)",
                r"export\s+\{\s*([^}]+)\s*\}",
            ]

            for pattern in export_patterns:
                for match in re.finditer(pattern, content):
                    if match.lastindex:
                        names = match.group(1)
                        for name in names.split(","):
                            name = name.strip().split(" as ")[0].strip()
                            if name:
                                exports.append(name)

        except Exception as e:
            logger.debug(f"Error parsing JS/TS file {file_path}: {e}")

        return imports, exports, edges

    async def _parse_java_file(self, file_path: str) -> tuple[list[str], list[str], list[DependencyEdge]]:
        """
        Parse a Java file for imports and exports.
        """
        full_path = self.project_path / file_path
        imports = []
        exports = []
        edges = []

        try:
            content = await asyncio.to_thread(full_path.read_text, encoding="utf-8", errors="ignore")

            # Import statements
            import_pattern = r"import\s+([\w.]+)\s*;"
            for match in re.finditer(import_pattern, content):
                import_name = match.group(1)
                imports.append(import_name)

                # Skip java.* and javax.* packages
                if import_name.startswith("java.") or import_name.startswith("javax."):
                    continue

                resolved = self._resolve_import_path(import_name, file_path, "java")
                if resolved:
                    edges.append(DependencyEdge(
                        source=file_path,
                        target=resolved,
                        dependency_type=DependencyType.IMPORT,
                        symbol_name=import_name,
                    ))

            # Class and interface definitions
            class_pattern = r"(?:public|private|protected)?\s*(?:abstract|final)?\s*(?:class|interface|enum)\s+(\w+)"
            for match in re.finditer(class_pattern, content):
                exports.append(match.group(1))

        except Exception as e:
            logger.debug(f"Error parsing Java file {file_path}: {e}")

        return imports, exports, edges

    async def _parse_go_file(self, file_path: str) -> tuple[list[str], list[str], list[DependencyEdge]]:
        """
        Parse a Go file for imports and exports.
        """
        full_path = self.project_path / file_path
        imports = []
        exports = []
        edges = []

        try:
            content = await asyncio.to_thread(full_path.read_text, encoding="utf-8", errors="ignore")

            # Import statements
            import_patterns = [
                r"import\s+[\(]?\s*\"([^\"]+)\"",
                r"import\s+(\w+)\s+\"([^\"]+)\"",  # Aliased import
            ]

            for pattern in import_patterns:
                for match in re.finditer(pattern, content):
                    import_name = match.group(1) if match.lastindex == 1 else match.group(2)
                    imports.append(import_name)

            # Function and type definitions (capitalized = exported)
            export_patterns = [
                r"func\s+([A-Z]\w+)",  # Exported functions
                r"type\s+([A-Z]\w+)",  # Exported types
            ]

            for pattern in export_patterns:
                for match in re.finditer(pattern, content):
                    exports.append(match.group(1))

        except Exception as e:
            logger.debug(f"Error parsing Go file {file_path}: {e}")

        return imports, exports, edges

    async def _parse_file(self, file_path: str) -> tuple[list[str], list[str], list[DependencyEdge]]:
        """
        Parse a file for dependencies based on its language.

        Returns:
            Tuple of (imports, exports, edges).
        """
        language = self._detect_language(file_path)
        if not language:
            return [], [], []

        if language == "python":
            return await self._parse_python_file(file_path)
        elif language in ("javascript", "typescript"):
            return await self._parse_javascript_file(file_path)
        elif language == "java":
            return await self._parse_java_file(file_path)
        elif language == "go":
            return await self._parse_go_file(file_path)

        return [], [], []

    async def build(self) -> None:
        """
        Build the dependency graph by parsing all files in the project.
        """
        start_time = datetime.now(UTC)
        logger.info(f"Building dependency graph for {self.project_path}")

        # Collect all source files
        source_files = []
        for ext in self.LANGUAGE_EXTENSIONS.keys():
            for file_path in self.project_path.rglob(f"*{ext}"):
                rel_path = str(file_path.relative_to(self.project_path))
                if not self._should_exclude(rel_path):
                    source_files.append(rel_path)

        logger.info(f"Found {len(source_files)} source files to analyze")

        # Parse files in parallel
        tasks = [self._parse_file(f) for f in source_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Build nodes and edges
        for file_path, result in zip(source_files, results):
            if isinstance(result, Exception):
                logger.debug(f"Failed to parse {file_path}: {result}")
                continue

            imports, exports, edges = result
            language = self._detect_language(file_path)

            # Create node
            node = DependencyNode(
                path=file_path,
                language=language,
                is_entry_point=self._is_entry_point(file_path, language or ""),
                exports=exports,
                imports=imports,
            )
            self.nodes[file_path] = node

            # Add edges
            for edge in edges:
                self.edges[edge.source].append(edge)
                self.reverse_edges[edge.target].append(edge)

            # Update symbol index
            for export in exports:
                self.symbol_to_files[export].append(file_path)

        # Calculate node degrees
        for path, node in self.nodes.items():
            node.out_degree = len(self.edges.get(path, []))
            node.in_degree = len(self.reverse_edges.get(path, []))

        # Calculate centrality scores
        self._calculate_centrality()

        self._built = True
        self._build_time = datetime.now(UTC)

        duration = (datetime.now(UTC) - start_time).total_seconds()
        logger.info(
            f"Dependency graph built: {len(self.nodes)} nodes, "
            f"{sum(len(e) for e in self.edges.values())} edges in {duration:.2f}s"
        )

    def _calculate_centrality(self) -> None:
        """Calculate centrality scores for nodes."""
        if not self.nodes:
            return

        # Simple degree centrality
        max_degree = max(n.in_degree + n.out_degree for n in self.nodes.values())
        if max_degree == 0:
            return

        for node in self.nodes.values():
            node.centrality_score = (node.in_degree + node.out_degree) / max_degree

    def get_dependents(self, file_path: str, max_depth: int | None = None) -> set[str]:
        """
        Get all files that depend on the given file.

        Args:
            file_path: The file to find dependents for.
            max_depth: Maximum traversal depth.

        Returns:
            Set of file paths that depend on the given file.
        """
        if max_depth is None:
            max_depth = self.max_depth

        visited = set()
        to_visit = [(file_path, 0)]

        while to_visit:
            current, depth = to_visit.pop(0)

            if current in visited or depth > max_depth:
                continue

            visited.add(current)

            # Find files that import this file
            for edge in self.reverse_edges.get(current, []):
                if edge.source not in visited:
                    to_visit.append((edge.source, depth + 1))

        # Remove the original file
        visited.discard(file_path)
        return visited

    def get_dependencies(self, file_path: str, max_depth: int | None = None) -> set[str]:
        """
        Get all files that the given file depends on.

        Args:
            file_path: The file to find dependencies for.
            max_depth: Maximum traversal depth.

        Returns:
            Set of file paths that the given file depends on.
        """
        if max_depth is None:
            max_depth = self.max_depth

        visited = set()
        to_visit = [(file_path, 0)]

        while to_visit:
            current, depth = to_visit.pop(0)

            if current in visited or depth > max_depth:
                continue

            visited.add(current)

            # Find files that this file imports
            for edge in self.edges.get(current, []):
                if edge.target not in visited:
                    to_visit.append((edge.target, depth + 1))

        # Remove the original file
        visited.discard(file_path)
        return visited

    def get_impact_set(self, changed_files: list[str]) -> dict[str, float]:
        """
        Get all files affected by changes to the given files.

        Args:
            changed_files: List of files that have changed.

        Returns:
            Dictionary mapping affected file paths to impact scores.
        """
        if not self._built:
            logger.warning("Dependency graph not built, call build() first")
            return {}

        impact_scores: dict[str, float] = defaultdict(float)

        for changed_file in changed_files:
            if changed_file not in self.nodes:
                continue

            # Get all dependents (files that might be affected)
            dependents = self.get_dependents(changed_file)

            for dependent in dependents:
                # Calculate impact score based on distance and edge weights
                distance = self._get_shortest_path_length(dependent, changed_file)
                if distance > 0:
                    # Score decreases with distance
                    score = 1.0 / distance
                    impact_scores[dependent] = max(impact_scores[dependent], score)

            # The changed file itself has maximum impact
            impact_scores[changed_file] = 1.0

        return dict(impact_scores)

    def _get_shortest_path_length(self, source: str, target: str) -> int:
        """Get shortest path length between two nodes using BFS."""
        if source == target:
            return 0

        visited = {source}
        queue = [(source, 0)]

        while queue:
            current, distance = queue.pop(0)

            for edge in self.reverse_edges.get(current, []):
                if edge.source == target:
                    return distance + 1

                if edge.source not in visited:
                    visited.add(edge.source)
                    queue.append((edge.source, distance + 1))

        return float("inf")

    def get_high_centrality_files(self, threshold: float = 0.5) -> list[str]:
        """
        Get files with high centrality scores.

        Args:
            threshold: Centrality threshold (0-1).

        Returns:
            List of high centrality file paths.
        """
        return [
            path for path, node in self.nodes.items()
            if node.centrality_score >= threshold
        ]

    def get_entry_points(self) -> list[str]:
        """Get all entry point files."""
        return [path for path, node in self.nodes.items() if node.is_entry_point]

    def get_statistics(self) -> dict[str, Any]:
        """Get graph statistics."""
        if not self._built:
            return {"built": False}

        total_edges = sum(len(e) for e in self.edges.values())

        return {
            "built": True,
            "build_time": self._build_time.isoformat() if self._build_time else None,
            "total_nodes": len(self.nodes),
            "total_edges": total_edges,
            "entry_points": len(self.get_entry_points()),
            "high_centrality_files": len(self.get_high_centrality_files()),
            "avg_out_degree": total_edges / len(self.nodes) if self.nodes else 0,
            "languages": dict(self._count_by_language()),
        }

    def _count_by_language(self) -> dict[str, int]:
        """Count nodes by language."""
        counts: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            if node.language:
                counts[node.language] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Export graph to dictionary for serialization."""
        return {
            "nodes": {
                path: {
                    "language": node.language,
                    "is_entry_point": node.is_entry_point,
                    "exports": node.exports,
                    "imports": node.imports,
                    "in_degree": node.in_degree,
                    "out_degree": node.out_degree,
                    "centrality_score": node.centrality_score,
                }
                for path, node in self.nodes.items()
            },
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "type": edge.dependency_type.value,
                    "weight": edge.weight,
                    "line": edge.line_number,
                    "symbol": edge.symbol_name,
                }
                for edges in self.edges.values()
                for edge in edges
            ],
            "statistics": self.get_statistics(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], project_path: Path) -> "DependencyGraph":
        """Reconstruct graph from dictionary."""
        graph = cls(project_path)

        for path, node_data in data.get("nodes", {}).items():
            graph.nodes[path] = DependencyNode(
                path=path,
                language=node_data.get("language"),
                is_entry_point=node_data.get("is_entry_point", False),
                exports=node_data.get("exports", []),
                imports=node_data.get("imports", []),
                in_degree=node_data.get("in_degree", 0),
                out_degree=node_data.get("out_degree", 0),
                centrality_score=node_data.get("centrality_score", 0.0),
            )

        for edge_data in data.get("edges", []):
            edge = DependencyEdge(
                source=edge_data["source"],
                target=edge_data["target"],
                dependency_type=DependencyType(edge_data["type"]),
                weight=edge_data.get("weight", 1.0),
                line_number=edge_data.get("line"),
                symbol_name=edge_data.get("symbol"),
            )
            graph.edges[edge.source].append(edge)
            graph.reverse_edges[edge.target].append(edge)

        graph._built = True
        return graph
