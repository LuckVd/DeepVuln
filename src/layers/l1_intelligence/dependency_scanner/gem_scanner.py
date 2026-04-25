"""Ruby Gem dependency scanner for Gemfile and Gemfile.lock files."""

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


class GemScanner(BaseDependencyScanner):
    """Scanner for Ruby Gem dependency files (Gemfile, Gemfile.lock)."""

    supported_files = ["Gemfile", "Gemfile.lock"]
    ecosystem = Ecosystem.GEM

    # Gemfile patterns
    # gem 'name', 'version', option1: value1, option2: value2
    GEM_DECLARATION_PATTERN = re.compile(
        r"^\s*gem\s+"
        r"['\"](?P<name>[^'\"]+)['\"]"          # gem name
        r"(?:\s*,\s*['\"](?P<version>[^'\"]+)['\"])?"
        r"(?P<options>.*)$"                      # remaining options
    )
    # Options patterns
    GROUP_PATTERN = re.compile(r"group:\s*(?::[\w]+|['\"][^'\"]+['\"])")
    REQUIRE_PATTERN = re.compile(r"require:\s*(?::[\w]+|['\"][^'\"]+['\"]|false|nil)")
    GIT_PATTERN = re.compile(r"git:\s*['\"](?P<url>[^'\"]+)['\"]")
    PATH_PATTERN = re.compile(r"path:\s*['\"](?P<path>[^'\"]+)['\"]")
    PLATFORM_PATTERN = re.compile(r"platform:\s*[:\w]+")
    BRANCH_PATTERN = re.compile(r"branch:\s*['\"](?P<branch>[^'\"]+)['\"]")
    TAG_PATTERN = re.compile(r"tag:\s*['\"](?P<tag>[^'\"]+)['\"]")
    REF_PATTERN = re.compile(r"ref:\s*['\"](?P<ref>[^'\"]+)['\"]")

    # Group block pattern
    GROUP_BLOCK_PATTERN = re.compile(
        r"^\s*group\s+(?P<groups>.+)\s+do\s*$"
    )

    # source block pattern
    SOURCE_BLOCK_PATTERN = re.compile(
        r"^\s*source\s+['\"](?P<url>[^'\"]+)['\"]\s+do\s*$"
    )

    # Gemfile.lock SPECIFICATIONS section patterns
    SPEC_SECTION_PATTERN = re.compile(
        r"^\s*SPECIFICATIONS\s*$"
    )
    SPEC_ENTRY_PATTERN = re.compile(
        r"^\s{4,6}(?P<name>[a-zA-Z0-9_.-]+)\s+\((?P<version>[^)]+)\)\s*$"
    )
    # Also match indented spec entries (under platforms)
    SPEC_DEP_PATTERN = re.compile(
        r"^\s{6,}(?P<name>[a-zA-Z0-9_.-]+)\s+\((?P<version>[^)]+)\)\s*$"
    )

    # Section markers in Gemfile.lock
    GIT_SECTION_PATTERN = re.compile(r"^\s*GIT\s*$")
    PATH_SECTION_PATTERN = re.compile(r"^\s*PATH\s*$")
    SPECS_INNER_PATTERN = re.compile(r"^\s{2}specs:\s*$")

    def __init__(self) -> None:
        """Initialize Gem scanner."""
        super().__init__()
        self.logger = get_logger(__name__)

    def scan(self, source_path: Path) -> list[Dependency]:
        """Scan for Ruby Gem dependencies.

        Args:
            source_path: Path to the source code.

        Returns:
            List of Gem dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[str] = set()

        # First, parse Gemfile.lock for resolved versions
        lock_versions: dict[str, str] = {}
        lock_dev_names: set[str] = set()
        for lock_file in source_path.rglob("Gemfile.lock"):
            if self._should_skip_path(lock_file):
                continue
            parsed = self._parse_gemfile_lock(lock_file)
            lock_versions = parsed["versions"]
            lock_dev_names = parsed["dev_names"]

        # Parse Gemfile files
        for gemfile in source_path.rglob("Gemfile"):
            if self._should_skip_path(gemfile):
                continue

            deps = self._parse_gemfile(gemfile, lock_versions, lock_dev_names)
            for dep in deps:
                if dep.name not in seen:
                    seen.add(dep.name)
                    dependencies.append(dep)

        # Add transitive deps from lock file not declared in Gemfile
        for lock_file in source_path.rglob("Gemfile.lock"):
            if self._should_skip_path(lock_file):
                continue
            lock_deps = self._get_lock_transitive_deps(
                lock_file, seen, lock_dev_names
            )
            for dep in lock_deps:
                seen.add(dep.name)
                dependencies.append(dep)

        self.logger.info(f"Found {len(dependencies)} Gem dependencies")
        return dependencies

    def _parse_gemfile(
        self,
        file_path: Path,
        lock_versions: dict[str, str],
        dev_group_names: set[str],
    ) -> list[Dependency]:
        """Parse Gemfile for gem declarations.

        Args:
            file_path: Path to Gemfile.
            lock_versions: Resolved versions from Gemfile.lock.
            dev_group_names: Names in dev groups from lock.

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

        # Track group context for dev classification
        current_groups: list[str] = []
        in_source_block = False

        for line in content.splitlines():
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Check for group block start: group :development, :test do
            group_match = self.GROUP_BLOCK_PATTERN.match(stripped)
            if group_match:
                groups_str = group_match.group("groups")
                current_groups = self._parse_group_list(groups_str)
                continue

            # Check for group block end
            if stripped == "end":
                if current_groups:
                    current_groups = []
                elif in_source_block:
                    in_source_block = False
                continue

            # Check for source block start: source "https://..." do
            source_match = self.SOURCE_BLOCK_PATTERN.match(stripped)
            if source_match:
                in_source_block = True
                continue

            # Parse gem declarations
            gem_match = self.GEM_DECLARATION_PATTERN.match(stripped)
            if gem_match:
                name = gem_match.group("name")
                version = gem_match.group("version")
                options = gem_match.group("options") or ""

                # Determine if it's a dev dependency
                is_dev = self._is_dev_dependency(current_groups, name, dev_group_names)

                # Check for git/path dependency markers
                is_git = bool(self.GIT_PATTERN.search(options))
                is_path = bool(self.PATH_PATTERN.search(options))

                # Determine version
                if is_git and not version:
                    git_match = self.GIT_PATTERN.search(options)
                    if git_match:
                        ref_match = self.REF_PATTERN.search(options)
                        tag_match = self.TAG_PATTERN.search(options)
                        branch_match = self.BRANCH_PATTERN.search(options)
                        if ref_match:
                            version = f"git:{ref_match.group('ref')}"
                        elif tag_match:
                            version = f"git:{tag_match.group('tag')}"
                        elif branch_match:
                            version = f"git:{branch_match.group('branch')}"
                        else:
                            version = f"git:{git_match.group('url')}"
                elif is_path and not version:
                    path_match = self.PATH_PATTERN.search(options)
                    if path_match:
                        version = f"path:{path_match.group('path')}"
                    else:
                        version = "*"
                elif not version:
                    version = "*"

                # Resolve from lock file
                resolved = lock_versions.get(name)
                if resolved:
                    final_version = resolved
                    version_source = VersionSource.EXPLICIT
                    version_confidence = 1.0
                else:
                    final_version = self._clean_gem_version(version)
                    version_source = VersionSource.EXPLICIT
                    version_confidence = 0.8 if final_version != "*" else 0.3

                dep = Dependency(
                    name=name,
                    version=final_version,
                    ecosystem=Ecosystem.GEM,
                    source_file=source_file,
                    is_direct=True,
                    is_dev=is_dev,
                    raw_version=version,
                    version_source=version_source,
                    version_confidence=version_confidence,
                )
                dependencies.append(dep)

        return dependencies

    def _parse_gemfile_lock(self, file_path: Path) -> dict:
        """Parse Gemfile.lock for resolved versions.

        Args:
            file_path: Path to Gemfile.lock.

        Returns:
            Dict with "versions" (name->version) and "dev_names" (set).
        """
        versions: dict[str, str] = {}
        dev_names: set[str] = set()

        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError as e:
            self.logger.warning(f"Failed to read {file_path}: {e}")
            return {"versions": versions, "dev_names": dev_names}

        lines = content.splitlines()

        # Parse sections. Gemfile.lock structure:
        #   GEM
        #     specs:
        #       rake (13.0.6)
        #   GIT
        #     ...
        #   PATH
        #     ...
        #   GEM
        #     remote: ...
        #     specs:
        #       ...
        #   PLATFORMS
        #     ...
        #   DEPENDENCIES
        #     rake
        #     rspec (~> 3.0)
        #   BUNDLED WITH
        #     2.4.6

        # Track which section we're in
        in_specs = False
        in_dependencies = False
        spec_indent = 0

        i = 0
        while i < len(lines):
            line = lines[i]

            # Detect specs: line under GEM/GIT/PATH sections
            if self.SPECS_INNER_PATTERN.match(line):
                in_specs = True
                in_dependencies = False
                i += 1
                continue

            # Detect SPECIFICATIONS section (alternative format)
            if self.SPEC_SECTION_PATTERN.match(line):
                in_specs = True
                in_dependencies = False
                i += 1
                continue

            # Detect DEPENDENCIES section
            if re.match(r"^\s*DEPENDENCIES\s*$", line):
                in_specs = False
                in_dependencies = True
                i += 1
                continue

            # Detect section headers (all caps, non-indented)
            if re.match(r"^[A-Z]", line) and not re.match(r"^\s", line):
                section_name = line.strip()
                if section_name not in ("DEPENDENCIES", "BUNDLED WITH", "PLATFORMS"):
                    # Entering a new spec-bearing section (GEM, GIT, PATH)
                    in_specs = False
                    in_dependencies = False
                elif section_name == "PLATFORMS":
                    in_specs = False
                    in_dependencies = False
                elif section_name == "BUNDLED WITH":
                    in_specs = False
                    in_dependencies = False
                i += 1
                continue

            # Parse specs
            if in_specs:
                spec_match = self.SPEC_ENTRY_PATTERN.match(line)
                if not spec_match:
                    spec_match = self.SPEC_DEP_PATTERN.match(line)
                if spec_match:
                    name = spec_match.group("name")
                    version = spec_match.group("version")
                    if name and version:
                        versions[name] = version
                    i += 1
                    continue

                # If we hit a non-spec, non-blank line that is less indented,
                # we're no longer in specs
                if line.strip() and not line.startswith(" " * 4):
                    in_specs = False

            # Parse DEPENDENCIES section for dev group detection
            if in_dependencies:
                dep_line = line.strip()
                if dep_line and not dep_line.startswith("#"):
                    # Lines like: "rspec (~> 3.0)" or just "rake"
                    dep_name = re.split(r"[\s(~>!=<>=]", dep_line)[0].strip()
                    if dep_name and re.match(r"^[a-zA-Z0-9_.-]+$", dep_name):
                        # These are direct deps listed in lock
                        pass

            i += 1

        return {"versions": versions, "dev_names": dev_names}

    def _get_lock_transitive_deps(
        self,
        file_path: Path,
        seen: set[str],
        dev_group_names: set[str],
    ) -> list[Dependency]:
        """Get transitive dependencies from lock not already captured.

        Args:
            file_path: Path to Gemfile.lock.
            seen: Already seen package names.
            dev_group_names: Names in dev groups.

        Returns:
            List of transitive dependencies.
        """
        dependencies: list[Dependency] = []
        source_file = str(file_path)

        parsed = self._parse_gemfile_lock(file_path)
        versions = parsed["versions"]

        for name, version in versions.items():
            if name not in seen:
                dep = Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.GEM,
                    source_file=source_file,
                    is_direct=False,
                    is_dev=name in dev_group_names,
                    version_source=VersionSource.EXPLICIT,
                    version_confidence=1.0,
                )
                dependencies.append(dep)

        return dependencies

    def _parse_group_list(self, groups_str: str) -> list[str]:
        """Parse group list from group declaration.

        Args:
            groups_str: Group list string (e.g., ":development, :test").

        Returns:
            List of group names.
        """
        groups: list[str] = []
        for part in groups_str.split(","):
            part = part.strip().rstrip(":").lstrip(":")
            part = part.strip("\"'")
            if part:
                groups.append(part.lower())
        return groups

    def _is_dev_dependency(
        self,
        current_groups: list[str],
        name: str,
        dev_group_names: set[str],
    ) -> bool:
        """Determine if a dependency is a development dependency.

        Args:
            current_groups: Current group context.
            name: Package name.
            dev_group_names: Known dev group names from lock.

        Returns:
            True if this is a dev dependency.
        """
        dev_groups = {"development", "test", "dev", "docs", "doc", "benchmark"}
        if any(g in dev_groups for g in current_groups):
            return True
        if name in dev_group_names:
            return True
        return False

    def _clean_gem_version(self, version: str) -> str:
        """Clean a Gem version string.

        Args:
            version: Raw version string.

        Returns:
            Cleaned version string.
        """
        if not version or version == "*":
            return "*"

        # Handle ~> (pessimistic): ~> 1.2 -> 1.2
        if version.startswith("~>"):
            return version[2:].strip()

        # Handle >=, <=, ==, !=, >, <
        for prefix in (">=", "<=", "==", "!=", "~>", ">", "<", "="):
            if version.startswith(prefix):
                return version[len(prefix):].strip()

        # Handle v-prefix
        if version.startswith("v"):
            return version[1:]

        return version.strip()
