"""Go dependency scanner for go.mod and go.sum files."""

import re
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.dependency_scanner.base_scanner import (
    BaseDependencyScanner,
    Dependency,
    Ecosystem,
)


class GoScanner(BaseDependencyScanner):
    """Scanner for Go dependency files (go.mod, go.sum)."""

    supported_files = ["go.mod", "go.sum"]
    ecosystem = Ecosystem.GO

    # Pattern for parsing require lines in go.mod
    # Format: package/path v1.2.3 // optional comment
    REQUIRE_PATTERN = re.compile(
        r"^\s*(?P<path>[^\s]+)\s+(?P<version>v[^\s]+)(?:\s+//\s*(?P<comment>.*))?$"
    )

    # Pattern for go.sum lines
    # Format: package/path v1.2.3 h1:hash...
    # Or: package/path v1.2.3/go.mod h1:hash...
    GOSUM_PATTERN = re.compile(
        r"^(?P<path>[^\s]+)\s+(?P<version>v[^\s]+)(?:/go\.mod)?\s+h1:[^\s]+$"
    )

    def __init__(self) -> None:
        """Initialize Go scanner."""
        super().__init__()
        self.logger = get_logger(__name__)

    def scan(self, source_path: Path) -> list[Dependency]:
        """Scan for Go dependencies.

        Args:
            source_path: Path to the source code.

        Returns:
            List of Go dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[str] = set()

        # First, parse go.sum for exact versions (if available)
        go_sum_versions: dict[str, str] = {}
        for go_sum_file in source_path.rglob("go.sum"):
            if self._should_skip_path(go_sum_file):
                continue
            go_sum_versions.update(self._parse_go_sum(go_sum_file))

        # Parse go.mod files
        for go_mod_file in source_path.rglob("go.mod"):
            if self._should_skip_path(go_mod_file):
                continue

            deps = self._parse_go_mod(go_mod_file, go_sum_versions)
            for dep in deps:
                # Use path as unique key
                if dep.name not in seen:
                    seen.add(dep.name)
                    dependencies.append(dep)

        self.logger.info(f"Found {len(dependencies)} Go dependencies")
        return dependencies

    def _parse_go_mod(
        self, file_path: Path, go_sum_versions: dict[str, str]
    ) -> list[Dependency]:
        """Parse go.mod file.

        Args:
            file_path: Path to go.mod.
            go_sum_versions: Version map from go.sum.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []

        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError as e:
            self.logger.warning(f"Failed to read {file_path}: {e}")
            return dependencies

        source_file = str(file_path)

        # Remove comments and normalize
        lines = self._normalize_go_mod(content)

        # Track if we're in a require block
        in_require_block = False
        require_block_is_indirect = False

        for line in lines:
            stripped = line.strip()

            # Skip empty lines
            if not stripped:
                continue

            # Check for require block start
            if stripped.startswith("require ("):
                in_require_block = True
                require_block_is_indirect = False
                continue

            # Check for require block end
            if in_require_block and stripped == ")":
                in_require_block = False
                require_block_is_indirect = False
                continue

            # Check for single-line require
            if stripped.startswith("require "):
                # Single line require: require package v1.0.0
                dep = self._parse_require_line(
                    stripped[8:].strip(),  # Remove "require "
                    source_file,
                    go_sum_versions,
                    is_indirect=False,
                )
                if dep:
                    dependencies.append(dep)
                continue

            # Parse require block lines
            if in_require_block:
                dep = self._parse_require_line(
                    stripped,
                    source_file,
                    go_sum_versions,
                    is_indirect="// indirect" in stripped,
                )
                if dep:
                    dependencies.append(dep)

        return dependencies

    def _normalize_go_mod(self, content: str) -> list[str]:
        """Normalize go.mod content by removing comments.

        Args:
            content: Raw go.mod content.

        Returns:
            List of normalized lines.
        """
        lines: list[str] = []
        for line in content.splitlines():
            # Remove inline comments but preserve // indirect marker
            if "//" in line:
                # Check if this is an indirect marker
                if "// indirect" in line:
                    # Keep the line with indirect marker
                    line = line.split("// indirect")[0] + "// indirect"
                else:
                    # Remove regular comment
                    line = line.split("//")[0]
            lines.append(line)
        return lines

    def _parse_require_line(
        self,
        line: str,
        source_file: str,
        go_sum_versions: dict[str, str],
        is_indirect: bool = False,
    ) -> Dependency | None:
        """Parse a require line from go.mod.

        Args:
            line: Require line.
            source_file: Source file path.
            go_sum_versions: Version map from go.sum.
            is_indirect: Whether this is an indirect dependency.

        Returns:
            Dependency or None.
        """
        # Clean up the line
        line = line.strip()
        if not line:
            return None

        # Check for indirect marker in line
        if "// indirect" in line:
            is_indirect = True
            line = line.split("//")[0].strip()

        # Parse package path and version
        match = self.REQUIRE_PATTERN.match(line)
        if not match:
            # Try simple split
            parts = line.split()
            if len(parts) >= 2:
                package_path = parts[0]
                version = parts[1]
            else:
                return None
        else:
            package_path = match.group("path")
            version = match.group("version")

        # Skip local replacements and special packages
        if package_path.startswith(".") or package_path.startswith("./"):
            return None

        # Use go.sum version if available (more precise)
        precise_version = go_sum_versions.get(package_path)
        if precise_version:
            version = precise_version

        # Clean version (remove 'v' prefix for consistency in search)
        clean_version = version.lstrip("v") if version else "*"

        return Dependency(
            name=package_path,
            version=clean_version,
            ecosystem=Ecosystem.GO,
            source_file=source_file,
            is_direct=not is_indirect,
            is_dev=False,
            is_optional=False,
        )

    def _parse_go_sum(self, file_path: Path) -> dict[str, str]:
        """Parse go.sum file for exact versions.

        Args:
            file_path: Path to go.sum.

        Returns:
            Dict mapping package path to version.
        """
        versions: dict[str, str] = {}

        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError as e:
            self.logger.warning(f"Failed to read {file_path}: {e}")
            return versions

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            match = self.GOSUM_PATTERN.match(line)
            if match:
                package_path = match.group("path")
                version = match.group("version")

                # Skip /go.mod entries, prefer main entry
                if "/go.mod" in line:
                    continue

                # Only keep first occurrence (prefer main version over /go.mod)
                if package_path not in versions:
                    versions[package_path] = version

        return versions

    def get_go_version(self, source_path: Path) -> str | None:
        """Get the Go version from go.mod.

        Args:
            source_path: Path to source code.

        Returns:
            Go version string or None.
        """
        go_mod = source_path / "go.mod"
        if not go_mod.exists():
            # Try to find any go.mod
            for go_mod in source_path.rglob("go.mod"):
                if not self._should_skip_path(go_mod):
                    break
            else:
                return None

        try:
            content = go_mod.read_text(encoding="utf-8")
        except OSError:
            return None

        # Look for go directive
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("go "):
                return line.split()[1]

        return None

    def get_module_name(self, source_path: Path) -> str | None:
        """Get the module name from go.mod.

        Args:
            source_path: Path to source code.

        Returns:
            Module name or None.
        """
        go_mod = source_path / "go.mod"
        if not go_mod.exists():
            for go_mod in source_path.rglob("go.mod"):
                if not self._should_skip_path(go_mod):
                    break
            else:
                return None

        try:
            content = go_mod.read_text(encoding="utf-8")
        except OSError:
            return None

        # Look for module directive
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("module "):
                return line.split()[1]

        return None
