"""Python dependency scanner for requirements.txt, Pipfile, pyproject.toml."""

import re
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.dependency_scanner.base_scanner import (
    BaseDependencyScanner,
    Dependency,
    Ecosystem,
)


class PythonScanner(BaseDependencyScanner):
    """Scanner for Python dependency files."""

    supported_files = ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py"]
    ecosystem = Ecosystem.PYPI

    # Pattern for parsing requirements.txt lines
    REQUIREMENT_PATTERN = re.compile(
        r"^(?P<name>[a-zA-Z0-9_-]+)"
        r"(?P<extras>\[[^\]]+\])?"
        r"(?P<version>[<>=!~\[\]].+)?"
        r"(?P<env_marker>;\s*.+)?$"
    )

    def __init__(self) -> None:
        """Initialize Python scanner."""
        super().__init__()
        self.logger = get_logger(__name__)

    def scan(self, source_path: Path) -> list[Dependency]:
        """Scan for Python dependencies.

        Args:
            source_path: Path to the source code.

        Returns:
            List of Python dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[tuple[str, str]] = set()

        # Scan requirements.txt files
        for req_file in source_path.rglob("requirements*.txt"):
            if self._should_skip_path(req_file):
                continue

            deps = self._parse_requirements_txt(req_file)
            for dep in deps:
                key = (dep.name, dep.version)
                if key not in seen:
                    seen.add(key)
                    dependencies.append(dep)

        # Scan pyproject.toml
        for pyproject_file in source_path.rglob("pyproject.toml"):
            if self._should_skip_path(pyproject_file):
                continue

            deps = self._parse_pyproject_toml(pyproject_file)
            for dep in deps:
                key = (dep.name, dep.version)
                if key not in seen:
                    seen.add(key)
                    dependencies.append(dep)

        # Scan setup.py
        for setup_file in source_path.rglob("setup.py"):
            if self._should_skip_path(setup_file):
                continue

            deps = self._parse_setup_py(setup_file)
            for dep in deps:
                key = (dep.name, dep.version)
                if key not in seen:
                    seen.add(key)
                    dependencies.append(dep)

        # Scan Pipfile
        for pipfile in source_path.rglob("Pipfile"):
            if self._should_skip_path(pipfile):
                continue

            deps = self._parse_pipfile(pipfile)
            for dep in deps:
                key = (dep.name, dep.version)
                if key not in seen:
                    seen.add(key)
                    dependencies.append(dep)

        self.logger.info(f"Found {len(dependencies)} Python dependencies")
        return dependencies

    def _parse_requirements_txt(self, file_path: Path) -> list[Dependency]:
        """Parse requirements.txt file.

        Args:
            file_path: Path to requirements.txt.

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

        for line in content.splitlines():
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Skip -r, -e, --index-url, etc.
            if line.startswith(("-", "--")):
                continue

            # Skip bare URLs
            if line.startswith("http://") or line.startswith("https://"):
                continue

            # Parse requirement
            parsed = self._parse_requirement_line(line)
            if parsed:
                dep = Dependency(
                    name=parsed["name"],
                    version=parsed["version"],
                    ecosystem=Ecosystem.PYPI,
                    source_file=source_file,
                    is_direct=True,
                )
                dependencies.append(dep)

        return dependencies

    def _parse_requirement_line(self, line: str) -> dict | None:
        """Parse a single requirement line.

        Args:
            line: Requirement line.

        Returns:
            Parsed requirement dict or None.
        """
        # Handle environment markers (e.g., "package; python_version < '3.8'")
        if ";" in line:
            line = line.split(";")[0].strip()

        # Handle extras (e.g., "package[extra1,extra2]")
        extras_match = re.search(r"\[([^\]]+)\]", line)
        extras = extras_match.group(1) if extras_match else None
        line_without_extras = re.sub(r"\[[^\]]+\]", "", line)

        # Parse name and version
        # Patterns: package==1.0, package>=1.0, package~=1.0, package!=1.0
        version_operators = ["==", ">=", "<=", "~=", "!=", ">", "<"]

        name = line_without_extras
        version = "*"

        for op in version_operators:
            if op in line_without_extras:
                parts = line_without_extras.split(op, 1)
                name = parts[0].strip()
                version = op + parts[1].strip() if len(parts) > 1 else "*"
                break

        # Handle @ (URL-based requirements)
        if "@" in name:
            return None  # Skip URL-based requirements

        # Validate name
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", name):
            return None

        return {
            "name": name.lower().replace("_", "-"),
            "version": self._clean_version(version),
            "extras": extras,
        }

    def _parse_pyproject_toml(self, file_path: Path) -> list[Dependency]:
        """Parse pyproject.toml file.

        Args:
            file_path: Path to pyproject.toml.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []

        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        try:
            content = file_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception as e:
            self.logger.warning(f"Failed to parse {file_path}: {e}")
            return dependencies

        source_file = str(file_path)

        # Parse project.dependencies (PEP 621)
        project_deps = data.get("project", {}).get("dependencies", [])
        for dep_str in project_deps:
            parsed = self._parse_requirement_line(dep_str)
            if parsed:
                dep = Dependency(
                    name=parsed["name"],
                    version=parsed["version"],
                    ecosystem=Ecosystem.PYPI,
                    source_file=source_file,
                    is_direct=True,
                )
                dependencies.append(dep)

        # Parse project.optional-dependencies
        optional_deps = data.get("project", {}).get("optional-dependencies", {})
        for _group, deps_list in optional_deps.items():
            for dep_str in deps_list:
                parsed = self._parse_requirement_line(dep_str)
                if parsed:
                    dep = Dependency(
                        name=parsed["name"],
                        version=parsed["version"],
                        ecosystem=Ecosystem.PYPI,
                        source_file=source_file,
                        is_direct=True,
                        is_optional=True,
                    )
                    dependencies.append(dep)

        # Parse tool.poetry.dependencies
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for name, version in poetry_deps.items():
            if name.lower() == "python":
                continue

            version_str = self._poetry_version_to_string(version)
            if version_str:
                dep = Dependency(
                    name=name.lower().replace("_", "-"),
                    version=version_str,
                    ecosystem=Ecosystem.PYPI,
                    source_file=source_file,
                    is_direct=True,
                )
                dependencies.append(dep)

        # Parse tool.poetry.dev-dependencies
        poetry_dev_deps = data.get("tool", {}).get("poetry", {}).get("dev-dependencies", {})
        for name, version in poetry_dev_deps.items():
            version_str = self._poetry_version_to_string(version)
            if version_str:
                dep = Dependency(
                    name=name.lower().replace("_", "-"),
                    version=version_str,
                    ecosystem=Ecosystem.PYPI,
                    source_file=source_file,
                    is_direct=True,
                    is_dev=True,
                )
                dependencies.append(dep)

        # Parse tool.poetry.group.*.dependencies (Poetry 1.2+)
        poetry_groups = data.get("tool", {}).get("poetry", {}).get("group", {})
        for group_name, group_data in poetry_groups.items():
            group_deps = group_data.get("dependencies", {})
            is_dev = group_name in ("dev", "test", "development")
            for name, version in group_deps.items():
                if name.lower() == "python":
                    continue
                version_str = self._poetry_version_to_string(version)
                if version_str:
                    dep = Dependency(
                        name=name.lower().replace("_", "-"),
                        version=version_str,
                        ecosystem=Ecosystem.PYPI,
                        source_file=source_file,
                        is_direct=True,
                        is_dev=is_dev,
                    )
                    dependencies.append(dep)

        return dependencies

    def _poetry_version_to_string(self, version: str | dict | None) -> str | None:
        """Convert Poetry version format to standard format.

        Args:
            version: Poetry version (string or dict).

        Returns:
            Standard version string.
        """
        if version is None:
            return "*"

        if isinstance(version, str):
            # Handle caret (^) and tilde (~) versions
            if version.startswith("^"):
                return f">={version[1:]},<{self._next_major(version[1:])}"
            elif version.startswith("~"):
                return f">={version[1:]},<{self._next_minor(version[1:])}"
            return version

        if isinstance(version, dict):
            # Handle dict format like {version = "^1.0"}
            return self._poetry_version_to_string(version.get("version"))

        return None

    def _next_major(self, version: str) -> str:
        """Get next major version.

        Args:
            version: Version string.

        Returns:
            Next major version.
        """
        parts = version.split(".")
        if parts:
            major = int(parts[0]) + 1
            return f"{major}.0.0"
        return version

    def _next_minor(self, version: str) -> str:
        """Get next minor version.

        Args:
            version: Version string.

        Returns:
            Next minor version.
        """
        parts = version.split(".")
        if len(parts) >= 2:
            minor = int(parts[1]) + 1
            return f"{parts[0]}.{minor}.0"
        return version

    def _parse_setup_py(self, file_path: Path) -> list[Dependency]:
        """Parse setup.py file (basic extraction).

        Args:
            file_path: Path to setup.py.

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

        # Simple regex-based extraction of install_requires
        # This is a basic approach; full parsing would require AST
        patterns = [
            # install_requires=['package>=1.0', ...]
            r"install_requires\s*=\s*\[(.*?)\]",
            # requires=['package>=1.0', ...]
            r"requires\s*=\s*\[(.*?)\]",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.DOTALL)
            for match in matches:
                # Extract quoted strings
                dep_strings = re.findall(r"['\"]([^'\"]+)['\"]", match)
                for dep_str in dep_strings:
                    parsed = self._parse_requirement_line(dep_str)
                    if parsed:
                        dep = Dependency(
                            name=parsed["name"],
                            version=parsed["version"],
                            ecosystem=Ecosystem.PYPI,
                            source_file=source_file,
                            is_direct=True,
                        )
                        dependencies.append(dep)

        return dependencies

    def _parse_pipfile(self, file_path: Path) -> list[Dependency]:
        """Parse Pipfile.

        Args:
            file_path: Path to Pipfile.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []

        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        try:
            content = file_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception as e:
            self.logger.warning(f"Failed to parse {file_path}: {e}")
            return dependencies

        source_file = str(file_path)

        # Parse [packages]
        packages = data.get("packages", {})
        for name, version in packages.items():
            version_str = self._pipfile_version_to_string(version)
            if version_str:
                dep = Dependency(
                    name=name.lower().replace("_", "-"),
                    version=version_str,
                    ecosystem=Ecosystem.PYPI,
                    source_file=source_file,
                    is_direct=True,
                )
                dependencies.append(dep)

        # Parse [dev-packages]
        dev_packages = data.get("dev-packages", {})
        for name, version in dev_packages.items():
            version_str = self._pipfile_version_to_string(version)
            if version_str:
                dep = Dependency(
                    name=name.lower().replace("_", "-"),
                    version=version_str,
                    ecosystem=Ecosystem.PYPI,
                    source_file=source_file,
                    is_direct=True,
                    is_dev=True,
                )
                dependencies.append(dep)

        return dependencies

    def _pipfile_version_to_string(self, version: str | dict | None) -> str | None:
        """Convert Pipfile version format to standard format.

        Args:
            version: Pipfile version.

        Returns:
            Standard version string.
        """
        if version is None or version == "*":
            return "*"

        if isinstance(version, str):
            if version == "*":
                return "*"
            return version

        if isinstance(version, dict):
            return version.get("version", "*")

        return None

    def _clean_version(self, version: str) -> str:
        """Clean version string.

        Args:
            version: Raw version string.

        Returns:
            Cleaned version string.
        """
        if not version or version == "*":
            return "*"

        # Remove common prefixes
        version = version.lstrip("=<>!~")

        # Handle complex version ranges
        if "," in version:
            # Take the minimum version from range
            parts = version.split(",")
            for part in parts:
                part = part.strip()
                if part.startswith(">=") or part.startswith("=="):
                    return part.lstrip("=<>!~")

        return version
