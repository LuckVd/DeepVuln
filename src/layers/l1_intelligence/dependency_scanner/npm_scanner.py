"""NPM dependency scanner for package.json files."""

import json
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.dependency_scanner.base_scanner import (
    BaseDependencyScanner,
    Dependency,
    Ecosystem,
)


class NpmScanner(BaseDependencyScanner):
    """Scanner for npm package.json files."""

    supported_files = ["package.json", "package-lock.json", "yarn.lock"]
    ecosystem = Ecosystem.NPM

    def __init__(self) -> None:
        """Initialize npm scanner."""
        super().__init__()
        self.logger = get_logger(__name__)

    def scan(self, source_path: Path) -> list[Dependency]:
        """Scan for npm dependencies.

        Args:
            source_path: Path to the source code.

        Returns:
            List of npm dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[tuple[str, str]] = set()

        # Find and parse package.json files
        package_json_files = list(source_path.rglob("package.json"))

        for package_json_path in package_json_files:
            if self._should_skip_path(package_json_path):
                continue

            deps = self._parse_package_json(package_json_path)
            for dep in deps:
                key = (dep.name, dep.version)
                if key not in seen:
                    seen.add(key)
                    dependencies.append(dep)

        # If we have package-lock.json, use it for more accurate versions
        lock_files = list(source_path.rglob("package-lock.json"))
        for lock_path in lock_files:
            if self._should_skip_path(lock_path):
                continue

            lock_deps = self._parse_package_lock(lock_path)
            # Merge lock file versions (more accurate)
            for dep in lock_deps:
                key = (dep.name, dep.version)
                if key not in seen:
                    seen.add(key)
                    dependencies.append(dep)

        self.logger.info(f"Found {len(dependencies)} npm dependencies")
        return dependencies

    def _parse_package_json(self, file_path: Path) -> list[Dependency]:
        """Parse package.json file.

        Args:
            file_path: Path to package.json.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []

        try:
            content = file_path.read_text(encoding="utf-8")
            data = json.loads(content)
        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning(f"Failed to parse {file_path}: {e}")
            return dependencies

        source_file = str(file_path)

        # Parse dependencies
        for dep_type, is_dev in [("dependencies", False), ("devDependencies", True)]:
            deps = data.get(dep_type, {})
            for name, version in deps.items():
                # Skip local/workspace packages
                if self._is_local_package(version):
                    continue

                dep = Dependency(
                    name=name,
                    version=self._clean_version(version),
                    ecosystem=Ecosystem.NPM,
                    source_file=source_file,
                    is_direct=True,
                    is_dev=is_dev,
                )
                dependencies.append(dep)

        # Parse optionalDependencies
        for name, version in data.get("optionalDependencies", {}).items():
            if self._is_local_package(version):
                continue
            dep = Dependency(
                name=name,
                version=self._clean_version(version),
                ecosystem=Ecosystem.NPM,
                source_file=source_file,
                is_direct=True,
                is_optional=True,
            )
            dependencies.append(dep)

        # Parse peerDependencies
        for name, version in data.get("peerDependencies", {}).items():
            if self._is_local_package(version):
                continue
            dep = Dependency(
                name=name,
                version=self._clean_version(version),
                ecosystem=Ecosystem.NPM,
                source_file=source_file,
                is_direct=True,
            )
            dependencies.append(dep)

        return dependencies

    def _parse_package_lock(self, file_path: Path) -> list[Dependency]:
        """Parse package-lock.json file.

        Args:
            file_path: Path to package-lock.json.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []

        try:
            content = file_path.read_text(encoding="utf-8")
            data = json.loads(content)
        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning(f"Failed to parse {file_path}: {e}")
            return dependencies

        source_file = str(file_path)
        lock_version = data.get("lockfileVersion", 1)

        if lock_version >= 2:
            # New format (npm 7+)
            packages = data.get("packages", {})
            for pkg_path, pkg_info in packages.items():
                if pkg_path == "":  # Root package
                    continue

                # Extract name from path
                name = pkg_path.replace("node_modules/", "")
                if "node_modules/" in name:
                    # Nested dependency, get the last part
                    name = name.split("node_modules/")[-1]

                version = pkg_info.get("version", "")
                if not version:
                    continue

                is_dev = pkg_info.get("dev", False)
                is_optional = pkg_info.get("optional", False)

                dep = Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    source_file=source_file,
                    is_direct=False,  # Lock file deps are transitive
                    is_dev=is_dev,
                    is_optional=is_optional,
                )
                dependencies.append(dep)
        else:
            # Old format (npm 6 and below)
            all_deps = data.get("dependencies", {})

            def walk_deps(deps: dict, is_dev: bool = False) -> None:
                for name, info in deps.items():
                    version = info.get("version", "")
                    if version:
                        dep = Dependency(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.NPM,
                            source_file=source_file,
                            is_direct=False,
                            is_dev=is_dev,
                        )
                        dependencies.append(dep)

                    # Walk nested requires
                    requires = info.get("requires", {})
                    for req_name, req_version in requires.items():
                        dep = Dependency(
                            name=req_name,
                            version=req_version,
                            ecosystem=Ecosystem.NPM,
                            source_file=source_file,
                            is_direct=False,
                            is_dev=is_dev,
                        )
                        dependencies.append(dep)

            walk_deps(all_deps)

        return dependencies

    def _clean_version(self, version: str) -> str:
        """Clean version string.

        Args:
            version: Raw version string.

        Returns:
            Cleaned version string.
        """
        # Remove common prefixes
        prefixes = ["^", "~", ">=", "<=", ">", "<", "="]
        cleaned = version
        for prefix in prefixes:
            cleaned = cleaned.lstrip(prefix)

        # Handle complex version ranges
        if " " in cleaned:
            # Take the first version in range
            cleaned = cleaned.split()[0]

        # Handle || (OR) conditions
        if "||" in cleaned:
            cleaned = cleaned.split("||")[0].strip()

        # Handle x ranges (1.x.x)
        if "x" in cleaned.lower():
            cleaned = cleaned.replace("x", "0").replace("X", "0")

        return cleaned

    def _is_local_package(self, version: str) -> bool:
        """Check if package is local/workspace package.

        Args:
            version: Version string.

        Returns:
            True if local package.
        """
        local_prefixes = [
            "file:",
            "link:",
            "workspace:",
            "git+file:",
            "./",
            "../",
        ]
        return any(version.startswith(prefix) for prefix in local_prefixes)
