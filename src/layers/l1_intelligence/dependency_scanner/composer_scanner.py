"""PHP Composer dependency scanner for composer.json and composer.lock files."""

import json
import re
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.dependency_scanner.base_scanner import (
    BaseDependencyScanner,
    Dependency,
    Ecosystem,
    VersionSource,
)

logger = get_logger(__name__)


class ComposerScanner(BaseDependencyScanner):
    """Scanner for PHP Composer dependency files (composer.json, composer.lock)."""

    supported_files = ["composer.json", "composer.lock"]
    ecosystem = Ecosystem.COMPOSER

    # Version constraint patterns
    # Composer supports: ^1.2.3, ~1.2, >=1.0 <2.0, 1.*, *, @dev, etc.
    VERSION_CONSTRAINT_PATTERN = re.compile(
        r"^(?P<operator>[~^>=<!*]*)"  # optional operator prefix
        r"(?P<version>[\d]+(?:\.[\d*x]+)*(?:\.[\d*x]+)*)"  # version number
        r"(?:-(?P<stability>alpha|beta|rc|dev|patch|stable)[\d]*)?"  # optional stability
        r"(?:@(?P<alias>dev|alpha|beta|rc|stable))?$"  # optional alias
    )

    def __init__(self) -> None:
        """Initialize Composer scanner."""
        super().__init__()
        self.logger = get_logger(__name__)

    def scan(self, source_path: Path) -> list[Dependency]:
        """Scan for PHP Composer dependencies.

        Args:
            source_path: Path to the source code.

        Returns:
            List of Composer dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[str] = set()

        # First, parse composer.lock for exact resolved versions
        lock_versions: dict[str, str] = {}
        for lock_file in source_path.rglob("composer.lock"):
            if self._should_skip_path(lock_file):
                continue
            lock_versions.update(self._parse_composer_lock(lock_file))

        # Parse composer.json files
        for composer_json in source_path.rglob("composer.json"):
            if self._should_skip_path(composer_json):
                continue

            deps = self._parse_composer_json(composer_json, lock_versions)
            for dep in deps:
                if dep.name not in seen:
                    seen.add(dep.name)
                    dependencies.append(dep)

        # Add transitive deps from lock file that were not in composer.json
        for lock_file in source_path.rglob("composer.lock"):
            if self._should_skip_path(lock_file):
                continue

            lock_deps = self._parse_composer_lock_deps(lock_file, seen)
            for dep in lock_deps:
                seen.add(dep.name)
                dependencies.append(dep)

        self.logger.info(f"Found {len(dependencies)} Composer dependencies")
        return dependencies

    def _parse_composer_json(
        self, file_path: Path, lock_versions: dict[str, str]
    ) -> list[Dependency]:
        """Parse composer.json file.

        Args:
            file_path: Path to composer.json.
            lock_versions: Resolved versions from composer.lock.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []
        source_file = str(file_path)

        data = self._safe_read_json(file_path)
        if data is None:
            return dependencies

        # Parse "require" section (production dependencies)
        require = data.get("require", {})
        for name, version_constraint in require.items():
            # Skip platform requirements (php, ext-*, lib-*)
            if self._is_platform_requirement(name):
                continue

            dep = self._make_dependency(
                name=name,
                version_constraint=version_constraint,
                source_file=source_file,
                lock_versions=lock_versions,
                is_dev=False,
            )
            if dep:
                dependencies.append(dep)

        # Parse "require-dev" section (development dependencies)
        require_dev = data.get("require-dev", {})
        for name, version_constraint in require_dev.items():
            if self._is_platform_requirement(name):
                continue

            dep = self._make_dependency(
                name=name,
                version_constraint=version_constraint,
                source_file=source_file,
                lock_versions=lock_versions,
                is_dev=True,
            )
            if dep:
                dependencies.append(dep)

        return dependencies

    def _parse_composer_lock(self, file_path: Path) -> dict[str, str]:
        """Parse composer.lock for resolved versions.

        Args:
            file_path: Path to composer.lock.

        Returns:
            Dict mapping package name to resolved version.
        """
        versions: dict[str, str] = {}

        data = self._safe_read_json(file_path)
        if data is None:
            return versions

        # Parse "packages" (production)
        for pkg in data.get("packages", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version:
                # Composer lock includes vendor prefix: "vendor/package"
                versions[name] = self._strip_v_prefix(version)

        # Parse "packages-dev" (development)
        for pkg in data.get("packages-dev", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version:
                versions[name] = self._strip_v_prefix(version)

        return versions

    def _parse_composer_lock_deps(
        self, file_path: Path, seen: set[str]
    ) -> list[Dependency]:
        """Parse composer.lock for transitive dependencies not in composer.json.

        Args:
            file_path: Path to composer.lock.
            seen: Set of already-seen package names.

        Returns:
            List of transitive dependencies.
        """
        dependencies: list[Dependency] = []
        source_file = str(file_path)

        data = self._safe_read_json(file_path)
        if data is None:
            return dependencies

        # Parse "packages" (production transitive)
        for pkg in data.get("packages", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version and name not in seen:
                dep = Dependency(
                    name=name,
                    version=self._strip_v_prefix(version),
                    ecosystem=Ecosystem.COMPOSER,
                    source_file=source_file,
                    is_direct=False,
                    is_dev=False,
                    version_source=VersionSource.EXPLICIT,
                    version_confidence=1.0,
                )
                dependencies.append(dep)

        # Parse "packages-dev" (development transitive)
        for pkg in data.get("packages-dev", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version and name not in seen:
                dep = Dependency(
                    name=name,
                    version=self._strip_v_prefix(version),
                    ecosystem=Ecosystem.COMPOSER,
                    source_file=source_file,
                    is_direct=False,
                    is_dev=True,
                    version_source=VersionSource.EXPLICIT,
                    version_confidence=1.0,
                )
                dependencies.append(dep)

        return dependencies

    def _make_dependency(
        self,
        name: str,
        version_constraint: str,
        source_file: str,
        lock_versions: dict[str, str],
        is_dev: bool = False,
    ) -> Dependency | None:
        """Create a Dependency from a composer.json entry.

        Args:
            name: Package name (vendor/package format).
            version_constraint: Version constraint string.
            source_file: Source file path.
            lock_versions: Resolved versions from composer.lock.
            is_dev: Whether this is a dev dependency.

        Returns:
            Dependency or None.
        """
        # Validate package name format: vendor/package
        if not re.match(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", name):
            return None

        # Clean the version constraint
        clean_version = self._clean_version_constraint(version_constraint)

        # Use lock file version if available
        resolved_version = lock_versions.get(name)
        if resolved_version:
            final_version = resolved_version
            version_source = VersionSource.EXPLICIT
            version_confidence = 1.0
        else:
            final_version = clean_version
            version_source = VersionSource.EXPLICIT
            version_confidence = 0.8 if clean_version and clean_version != "*" else 0.3

        return Dependency(
            name=name,
            version=final_version,
            ecosystem=Ecosystem.COMPOSER,
            source_file=source_file,
            is_direct=True,
            is_dev=is_dev,
            raw_version=version_constraint,
            version_source=version_source,
            version_confidence=version_confidence,
        )

    def _clean_version_constraint(self, constraint: str) -> str:
        """Clean a Composer version constraint to an approximate version.

        Supports: ^1.2.3, ~1.2, >=1.0, >1.0, <2.0, <=2.0, !=1.0,
                  1.2.*, *, @dev, || operator, space-separated ranges.

        Args:
            constraint: Raw version constraint string.

        Returns:
            Cleaned version string.
        """
        if not constraint:
            return "*"

        constraint = constraint.strip()

        # Handle "*" or "any"
        if constraint in ("*", "any"):
            return "*"

        # Handle @stability suffix (e.g., "1.0@dev")
        constraint = re.sub(r"@(dev|alpha|beta|rc|stable)$", "", constraint)

        # Handle || (OR) constraints: take first version
        if "||" in constraint:
            parts = constraint.split("||")
            return self._clean_version_constraint(parts[0].strip())

        # Handle space-separated range (e.g., ">=1.0 <2.0")
        parts = constraint.split()
        if len(parts) > 1:
            # Try to find the lower bound version
            for part in parts:
                part = part.strip()
                if part.startswith(">=") or part.startswith("=="):
                    return part.lstrip(">= !")
                if part.startswith(">") and not part.startswith(">="):
                    continue
                if part.startswith("<") or part.startswith("!"):
                    continue
            # If no lower bound found, use first part
            return self._clean_version_constraint(parts[0])

        # Single constraint
        single = constraint.strip()

        # Handle ^ (caret): ^1.2.3 -> 1.2.3
        if single.startswith("^"):
            return single[1:]

        # Handle ~ (tilde): ~1.2 -> 1.2
        if single.startswith("~"):
            return single[1:]

        # Handle >=, ==, <=
        for prefix in (">=", "==", "<="):
            if single.startswith(prefix):
                return single[len(prefix):]

        # Handle >, <, !=
        for prefix in (">", "<", "!="):
            if single.startswith(prefix):
                return single[len(prefix):]

        # Handle wildcard: 1.2.* -> 1.2.0
        if "*" in single:
            return single.replace("*", "0")

        # Handle v-prefix: v1.2.3 -> 1.2.3
        if single.startswith("v"):
            return single[1:]

        # Return as-is
        return single

    def _is_platform_requirement(self, name: str) -> bool:
        """Check if a requirement is a platform requirement.

        Platform requirements like php, ext-json, lib-pcre are not packages.

        Args:
            name: Requirement name.

        Returns:
            True if it is a platform requirement.
        """
        if name == "php":
            return True
        if name.startswith("ext-"):
            return True
        if name.startswith("lib-"):
            return True
        if name.startswith("php-"):
            return True
        return False

    def _strip_v_prefix(self, version: str) -> str:
        """Strip the 'v' prefix from version strings.

        Args:
            version: Version string (e.g., "v1.2.3").

        Returns:
            Version without 'v' prefix (e.g., "1.2.3").
        """
        if version.startswith("v"):
            return version[1:]
        return version
