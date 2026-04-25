"""Rust Cargo dependency scanner for Cargo.toml and Cargo.lock files."""

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


class CargoScanner(BaseDependencyScanner):
    """Scanner for Rust Cargo dependency files (Cargo.toml, Cargo.lock)."""

    supported_files = ["Cargo.toml", "Cargo.lock"]
    ecosystem = Ecosystem.CARGO

    # Regex patterns for Cargo.toml parsing (fallback when toml library unavailable)
    # Matches: [dependencies], [dev-dependencies], [build-dependencies]
    SECTION_HEADER_PATTERN = re.compile(
        r"^\s*\[(?P<section>[^\]]+)\]\s*$"
    )
    # Matches: name = "version" or name = { version = "x", ... }
    SIMPLE_DEP_PATTERN = re.compile(
        r'^\s*(?P<name>[a-zA-Z0-9_-]+)\s*=\s*"(?P<version>[^"]*)"'
    )
    DETAILED_DEP_PATTERN = re.compile(
        r'^\s*(?P<name>[a-zA-Z0-9_-]+)\s*=\s*\{(?P<props>.+)\}'
    )
    VERSION_IN_PROPS_PATTERN = re.compile(
        r'version\s*=\s*"(?P<version>[^"]*)"'
    )
    GIT_IN_PROPS_PATTERN = re.compile(
        r'git\s*=\s*"(?P<url>[^"]*)"'
    )
    PATH_IN_PROPS_PATTERN = re.compile(
        r'path\s*=\s*"(?P<path>[^"]*)"'
    )
    FEATURES_IN_PROPS_PATTERN = re.compile(
        r'features\s*=\s*\[(?P<features>[^\]]*)\]'
    )
    OPTIONAL_IN_PROPS_PATTERN = re.compile(
        r'optional\s*=\s*(?P<optional>true|false)'
    )

    # Cargo.lock patterns
    # [[package]]
    # name = "serde"
    # version = "1.0.130"
    # source = "registry+https://github.com/..."
    LOCK_PACKAGE_PATTERN = re.compile(
        r'^name\s*=\s*"(?P<name>[^"]*)"'
    )
    LOCK_VERSION_PATTERN = re.compile(
        r'^version\s*=\s*"(?P<version>[^"]*)"'
    )
    LOCK_SOURCE_PATTERN = re.compile(
        r'^source\s*=\s*"(?P<source>[^"]*)"'
    )

    def __init__(self) -> None:
        """Initialize Cargo scanner."""
        super().__init__()
        self.logger = get_logger(__name__)

    def scan(self, source_path: Path) -> list[Dependency]:
        """Scan for Rust Cargo dependencies.

        Args:
            source_path: Path to the source code.

        Returns:
            List of Cargo dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[str] = set()

        # First, parse Cargo.lock for exact resolved versions
        lock_versions: dict[str, str] = {}
        for lock_file in source_path.rglob("Cargo.lock"):
            if self._should_skip_path(lock_file):
                continue
            lock_versions.update(self._parse_cargo_lock(lock_file))

        # Parse Cargo.toml files
        for cargo_toml in source_path.rglob("Cargo.toml"):
            if self._should_skip_path(cargo_toml):
                continue

            deps = self._parse_cargo_toml(cargo_toml, lock_versions)
            for dep in deps:
                if dep.name not in seen:
                    seen.add(dep.name)
                    dependencies.append(dep)

        self.logger.info(f"Found {len(dependencies)} Cargo dependencies")
        return dependencies

    def _parse_cargo_toml(
        self, file_path: Path, lock_versions: dict[str, str]
    ) -> list[Dependency]:
        """Parse Cargo.toml file.

        Args:
            file_path: Path to Cargo.toml.
            lock_versions: Resolved versions from Cargo.lock.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []

        # Try toml library first, fall back to regex parsing
        data = self._try_parse_toml(file_path)
        if data is not None:
            dependencies = self._parse_toml_data(data, file_path, lock_versions)
        else:
            dependencies = self._parse_cargo_toml_regex(file_path, lock_versions)

        return dependencies

    def _try_parse_toml(self, file_path: Path) -> dict | None:
        """Try to parse TOML file using available library.

        Args:
            file_path: Path to TOML file.

        Returns:
            Parsed TOML data or None.
        """
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                return None

        try:
            content = file_path.read_text(encoding="utf-8")
            return tomllib.loads(content)
        except Exception as e:
            self.logger.warning(f"Failed to parse TOML {file_path}: {e}")
            return None

    def _parse_toml_data(
        self,
        data: dict,
        file_path: Path,
        lock_versions: dict[str, str],
    ) -> list[Dependency]:
        """Parse TOML data from Cargo.toml.

        Args:
            data: Parsed TOML data.
            file_path: Source file path.
            lock_versions: Resolved versions from Cargo.lock.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []
        source_file = str(file_path)

        # Parse [dependencies] (direct, production)
        deps_section = data.get("dependencies", {})
        for name, spec in deps_section.items():
            dep = self._toml_dep_to_dependency(
                name, spec, source_file, lock_versions,
                is_dev=False,
            )
            if dep:
                dependencies.append(dep)

        # Parse [dev-dependencies] (development)
        dev_deps_section = data.get("dev-dependencies", {})
        for name, spec in dev_deps_section.items():
            dep = self._toml_dep_to_dependency(
                name, spec, source_file, lock_versions,
                is_dev=True,
            )
            if dep:
                dependencies.append(dep)

        # Parse [build-dependencies] (build)
        build_deps_section = data.get("build-dependencies", {})
        for name, spec in build_deps_section.items():
            dep = self._toml_dep_to_dependency(
                name, spec, source_file, lock_versions,
                is_dev=False,
            )
            if dep:
                dependencies.append(dep)

        # Parse [target.'cfg(...)'.dependencies] (target-specific)
        target_section = data.get("target", {})
        if isinstance(target_section, dict):
            for _target_cfg, target_deps in target_section.items():
                if not isinstance(target_deps, dict):
                    continue
                for section_key in ("dependencies", "dev-dependencies", "build-dependencies"):
                    target_sub_deps = target_deps.get(section_key, {})
                    if not isinstance(target_sub_deps, dict):
                        continue
                    is_dev = section_key == "dev-dependencies"
                    for name, spec in target_sub_deps.items():
                        dep = self._toml_dep_to_dependency(
                            name, spec, source_file, lock_versions,
                            is_dev=is_dev,
                        )
                        if dep:
                            dependencies.append(dep)

        return dependencies

    def _toml_dep_to_dependency(
        self,
        name: str,
        spec: str | dict,
        source_file: str,
        lock_versions: dict[str, str],
        is_dev: bool = False,
    ) -> Dependency | None:
        """Convert a TOML dependency spec to a Dependency object.

        Args:
            name: Dependency name.
            spec: Version string or detail dict.
            source_file: Source file path.
            lock_versions: Resolved versions from Cargo.lock.
            is_dev: Whether this is a dev dependency.

        Returns:
            Dependency or None.
        """
        version: str | None = None
        is_optional = False
        is_git = False

        if isinstance(spec, str):
            # Simple version spec: name = "1.0"
            version = spec
        elif isinstance(spec, dict):
            # Detailed spec: name = { version = "1.0", optional = true }
            version = spec.get("version")
            is_optional = spec.get("optional", False)
            if "git" in spec:
                is_git = True
            if "path" in spec and not version:
                # Path-only dependency without version, skip
                return None
        else:
            return None

        if is_git and not version:
            # Git dependency without explicit version -- represent via git ref
            git_url = spec.get("git", "") if isinstance(spec, dict) else ""
            git_rev = spec.get("branch", spec.get("tag", spec.get("rev", ""))) if isinstance(spec, dict) else ""
            if git_rev:
                version = f"git:{git_rev}"
            elif git_url:
                version = f"git:{git_url}"
            else:
                return None

        if not version:
            return None

        # Use lock file version if available (more precise)
        resolved_version = lock_versions.get(name)
        if resolved_version:
            version = resolved_version
            version_source = VersionSource.EXPLICIT
            version_confidence = 1.0
        else:
            version_source = VersionSource.EXPLICIT
            version_confidence = 0.8 if version and version != "*" else 0.3

        return Dependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.CARGO,
            source_file=source_file,
            is_direct=True,
            is_dev=is_dev,
            is_optional=is_optional,
            raw_version=spec if isinstance(spec, str) else str(spec),
            version_source=version_source,
            version_confidence=version_confidence,
        )

    def _parse_cargo_toml_regex(
        self, file_path: Path, lock_versions: dict[str, str]
    ) -> list[Dependency]:
        """Parse Cargo.toml using regex (fallback when toml library unavailable).

        Args:
            file_path: Path to Cargo.toml.
            lock_versions: Resolved versions from Cargo.lock.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []
        source_file = str(file_path)

        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError as e:
            self.logger.warning(f"Failed to read {file_path}: {e}")
            return dependencies

        current_section = ""
        for line in content.splitlines():
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Check for section headers
            section_match = self.SECTION_HEADER_PATTERN.match(stripped)
            if section_match:
                current_section = section_match.group("section")
                continue

            # Only parse dependency sections
            dep_type = self._classify_section(current_section)
            if dep_type is None:
                continue

            is_dev = dep_type == "dev"

            # Try simple pattern: name = "version"
            simple_match = self.SIMPLE_DEP_PATTERN.match(stripped)
            if simple_match:
                name = simple_match.group("name")
                version = simple_match.group("version")
                dep = self._make_dependency(
                    name, version, source_file, lock_versions, is_dev=is_dev
                )
                if dep:
                    dependencies.append(dep)
                continue

            # Try detailed pattern: name = { version = "x", ... }
            detailed_match = self.DETAILED_DEP_PATTERN.match(stripped)
            if detailed_match:
                name = detailed_match.group("name")
                props = detailed_match.group("props")

                # Extract version from props
                version_match = self.VERSION_IN_PROPS_PATTERN.search(props)
                if version_match:
                    version = version_match.group("version")
                else:
                    # Check for git dependency
                    git_match = self.GIT_IN_PROPS_PATTERN.search(props)
                    if git_match:
                        version = f"git:{git_match.group('url')}"
                    else:
                        # Path-only dependency, skip
                        path_match = self.PATH_IN_PROPS_PATTERN.search(props)
                        if path_match and not version_match:
                            continue
                        version = "*"

                is_optional = False
                optional_match = self.OPTIONAL_IN_PROPS_PATTERN.search(props)
                if optional_match:
                    is_optional = optional_match.group("optional") == "true"

                dep = self._make_dependency(
                    name, version, source_file, lock_versions,
                    is_dev=is_dev, is_optional=is_optional,
                )
                if dep:
                    dependencies.append(dep)
                continue

        return dependencies

    def _classify_section(self, section: str) -> str | None:
        """Classify a TOML section as dependency type.

        Args:
            section: Section name (e.g. "dependencies", "dev-dependencies").

        Returns:
            "prod", "dev", "build", or None if not a dependency section.
        """
        # Normalize: strip target prefix like target.'cfg(unix)'.dependencies
        base = section.split(".")[-1] if "." in section else section

        if base == "dependencies":
            return "prod"
        elif base == "dev-dependencies":
            return "dev"
        elif base == "build-dependencies":
            return "build"
        return None

    def _make_dependency(
        self,
        name: str,
        version: str,
        source_file: str,
        lock_versions: dict[str, str],
        is_dev: bool = False,
        is_optional: bool = False,
    ) -> Dependency | None:
        """Create a Dependency object from extracted fields.

        Args:
            name: Package name.
            version: Version string.
            source_file: Source file path.
            lock_versions: Resolved versions from Cargo.lock.
            is_dev: Whether this is a dev dependency.
            is_optional: Whether this is an optional dependency.

        Returns:
            Dependency or None.
        """
        if not name or not re.match(r"^[a-zA-Z0-9_-]+$", name):
            return None

        resolved_version = lock_versions.get(name)
        if resolved_version:
            final_version = resolved_version
            version_source = VersionSource.EXPLICIT
            version_confidence = 1.0
        else:
            final_version = version
            version_source = VersionSource.EXPLICIT
            version_confidence = 0.8 if version and version != "*" else 0.3

        return Dependency(
            name=name,
            version=final_version,
            ecosystem=Ecosystem.CARGO,
            source_file=source_file,
            is_direct=True,
            is_dev=is_dev,
            is_optional=is_optional,
            raw_version=version,
            version_source=version_source,
            version_confidence=version_confidence,
        )

    def _parse_cargo_lock(self, file_path: Path) -> dict[str, str]:
        """Parse Cargo.lock file for resolved versions.

        Args:
            file_path: Path to Cargo.lock.

        Returns:
            Dict mapping package name to resolved version.
        """
        versions: dict[str, str] = {}

        # Try TOML parsing first
        data = self._try_parse_toml(file_path)
        if data is not None:
            packages = data.get("package", [])
            for pkg in packages:
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                if name and version:
                    versions[name] = version
            return versions

        # Fallback to regex parsing
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError as e:
            self.logger.warning(f"Failed to read {file_path}: {e}")
            return versions

        current_name: str | None = None
        for line in content.splitlines():
            stripped = line.strip()

            name_match = self.LOCK_PACKAGE_PATTERN.match(stripped)
            if name_match:
                current_name = name_match.group("name")
                continue

            version_match = self.LOCK_VERSION_PATTERN.match(stripped)
            if version_match and current_name:
                versions[current_name] = version_match.group("version")
                current_name = None
                continue

        return versions
