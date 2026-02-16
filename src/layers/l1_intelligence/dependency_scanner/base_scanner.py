"""Base dependency scanner and data models."""

from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class Ecosystem(str, Enum):
    """Package ecosystem types."""

    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    GO = "go"
    CARGO = "cargo"
    COMPOSER = "composer"
    GEM = "gem"
    NUGET = "nuget"


class DependencyFile(BaseModel):
    """Represents a dependency file."""

    path: Path
    ecosystem: Ecosystem
    exists: bool = False
    parse_error: str | None = None

    class Config:
        arbitrary_types_allowed = True


class Dependency(BaseModel):
    """Represents a project dependency."""

    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    ecosystem: Ecosystem = Field(..., description="Package ecosystem")
    source_file: str = Field(..., description="Source file path")
    is_direct: bool = Field(default=True, description="Is direct dependency")
    is_dev: bool = Field(default=False, description="Is dev dependency")
    is_optional: bool = Field(default=False, description="Is optional dependency")

    # Additional metadata
    license: str | None = Field(default=None, description="License type")
    description: str | None = Field(default=None, description="Package description")
    homepage: str | None = Field(default=None, description="Homepage URL")
    repository: str | None = Field(default=None, description="Repository URL")

    def to_search_query(self) -> str:
        """Generate search query for CVE lookup.

        Returns:
            Search query string.
        """
        # Clean version string (remove prefixes like ^, ~, >=, etc.)
        clean_version = self.version.lstrip("^~>=")
        return f"{self.name} {clean_version}"

    def __hash__(self) -> int:
        return hash((self.name, self.version, self.ecosystem))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Dependency):
            return False
        return (
            self.name == other.name
            and self.version == other.version
            and self.ecosystem == other.ecosystem
        )


class ScanResult(BaseModel):
    """Result of dependency scanning."""

    source_path: str = Field(..., description="Scanned source path")
    dependencies: list[Dependency] = Field(default_factory=list)
    files_scanned: list[str] = Field(default_factory=list)
    files_skipped: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    # Statistics
    total_dependencies: int = Field(default=0, description="Total dependencies found")
    direct_dependencies: int = Field(default=0, description="Direct dependencies")
    dev_dependencies: int = Field(default=0, description="Dev dependencies")

    def add_dependency(self, dep: Dependency) -> None:
        """Add a dependency to the result."""
        self.dependencies.append(dep)
        self.total_dependencies += 1
        if dep.is_direct and not dep.is_dev:
            self.direct_dependencies += 1
        if dep.is_dev:
            self.dev_dependencies += 1

    def get_dependencies_by_ecosystem(self, ecosystem: Ecosystem) -> list[Dependency]:
        """Get dependencies filtered by ecosystem.

        Args:
            ecosystem: Ecosystem to filter by.

        Returns:
            List of dependencies in the ecosystem.
        """
        return [d for d in self.dependencies if d.ecosystem == ecosystem]

    def get_unique_packages(self) -> list[Dependency]:
        """Get unique packages (by name, ignoring version).

        Returns:
            List of unique packages.
        """
        seen: set[str] = set()
        unique: list[Dependency] = []
        for dep in self.dependencies:
            key = f"{dep.ecosystem}:{dep.name}"
            if key not in seen:
                seen.add(key)
                unique.append(dep)
        return unique


class BaseDependencyScanner(ABC):
    """Base class for dependency scanners."""

    # Files this scanner can handle
    supported_files: list[str] = []
    ecosystem: Ecosystem

    def __init__(self) -> None:
        """Initialize the scanner."""
        self.logger = get_logger(self.__class__.__name__)

    def can_scan(self, file_path: Path) -> bool:
        """Check if this scanner can handle the file.

        Args:
            file_path: Path to the file.

        Returns:
            True if this scanner can handle the file.
        """
        return file_path.name in self.supported_files

    @abstractmethod
    def scan(self, source_path: Path) -> list[Dependency]:
        """Scan for dependencies.

        Args:
            source_path: Path to the source code.

        Returns:
            List of found dependencies.
        """
        pass

    def find_files(self, source_path: Path) -> list[Path]:
        """Find supported dependency files in the source path.

        Args:
            source_path: Path to the source code.

        Returns:
            List of found dependency files.
        """
        found: list[Path] = []
        for pattern in self.supported_files:
            # Check root level first
            root_file = source_path / pattern
            if root_file.exists():
                found.append(root_file)

            # Also check subdirectories (limit depth to avoid deep scans)
            for f in source_path.rglob(pattern):
                # Skip node_modules, venv, etc.
                if self._should_skip_path(f):
                    continue
                if f not in found:
                    found.append(f)

        return found

    def _should_skip_path(self, path: Path) -> bool:
        """Check if path should be skipped.

        Args:
            path: Path to check.

        Returns:
            True if path should be skipped.
        """
        skip_dirs = {
            "node_modules",
            "venv",
            ".venv",
            "env",
            ".env",
            "__pycache__",
            ".git",
            "dist",
            "build",
            "target",
            "vendor",
        }
        for part in path.parts:
            if part in skip_dirs:
                return True
        return False

    def _safe_read_file(self, file_path: Path) -> str | None:
        """Safely read file contents.

        Args:
            file_path: Path to the file.

        Returns:
            File contents or None on error.
        """
        try:
            return file_path.read_text(encoding="utf-8")
        except Exception as e:
            self.logger.warning(f"Failed to read {file_path}: {e}")
            return None

    def _safe_read_json(self, file_path: Path) -> dict[str, Any] | None:
        """Safely read JSON file.

        Args:
            file_path: Path to the JSON file.

        Returns:
            Parsed JSON or None on error.
        """
        import json

        content = self._safe_read_file(file_path)
        if content is None:
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse JSON {file_path}: {e}")
            return None


class CompositeScanner:
    """Composite scanner that runs multiple scanners."""

    def __init__(self) -> None:
        """Initialize composite scanner with all available scanners."""
        from src.layers.l1_intelligence.dependency_scanner.go_scanner import GoScanner
        from src.layers.l1_intelligence.dependency_scanner.npm_scanner import NpmScanner
        from src.layers.l1_intelligence.dependency_scanner.python_scanner import (
            PythonScanner,
        )

        self.scanners: list[BaseDependencyScanner] = [
            NpmScanner(),
            PythonScanner(),
            GoScanner(),
        ]
        self.logger = get_logger(__name__)

    def scan(self, source_path: Path) -> ScanResult:
        """Scan source path with all available scanners.

        Args:
            source_path: Path to the source code.

        Returns:
            Combined scan result.
        """
        result = ScanResult(source_path=str(source_path))

        self.logger.info(f"Scanning dependencies in {source_path}")

        for scanner in self.scanners:
            try:
                files = scanner.find_files(source_path)
                if files:
                    self.logger.debug(f"{scanner.__class__.__name__} found {len(files)} files")

                    for file_path in files:
                        result.files_scanned.append(str(file_path))

                    deps = scanner.scan(source_path)
                    for dep in deps:
                        result.add_dependency(dep)

            except Exception as e:
                self.logger.error(f"Scanner {scanner.__class__.__name__} failed: {e}")
                result.errors.append(f"{scanner.__class__.__name__}: {e}")

        self.logger.info(
            f"Scan complete: {result.total_dependencies} dependencies from "
            f"{len(result.files_scanned)} files"
        )

        return result
