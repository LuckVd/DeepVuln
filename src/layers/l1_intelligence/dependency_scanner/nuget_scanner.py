""".NET NuGet dependency scanner for .csproj, packages.config, and Directory.Packages.props files."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.dependency_scanner.base_scanner import (
    BaseDependencyScanner,
    Dependency,
    Ecosystem,
    VersionSource,
)

logger = get_logger(__name__)


class NuGetScanner(BaseDependencyScanner):
    """Scanner for .NET NuGet dependency files (.csproj, packages.config, Directory.Packages.props)."""

    supported_files = [
        "*.csproj",
        "packages.config",
        "Directory.Packages.props",
        "Directory.Build.props",
    ]
    ecosystem = Ecosystem.NUGET

    # Namespace prefixes common in csproj files
    MSBUILD_NAMESPACES = [
        "http://schemas.microsoft.com/developer/msbuild/2003",
    ]

    # Pattern for PackageReference in non-XML contexts (e.g., in props files with ItemGroup)
    PACKAGE_REF_PATTERN = re.compile(
        r'<PackageReference\s+'
        r'(?:Include|Update)\s*=\s*["\'](?P<name>[^"\']+)["\']'
        r'(?:\s+Version\s*=\s*["\'](?P<version>[^"\']+)["\'])?'
        r'',
        re.IGNORECASE,
    )

    # Pattern for PackageVersion in Directory.Packages.props
    PACKAGE_VERSION_PATTERN = re.compile(
        r'<PackageVersion\s+'
        r'(?:Include|Update)\s*=\s*["\'](?P<name>[^"\']+)["\']'
        r'(?:\s+Version\s*=\s*["\'](?P<version>[^"\']+)["\'])?'
        r'',
        re.IGNORECASE,
    )

    # Pattern for HintPath in legacy packages
    HINT_PATH_PATTERN = re.compile(
        r"packages[/\\](?P<name>[^/\\]+)\.(?P<version>\d+[^/\\]*)[/\\]"
    )

    def __init__(self) -> None:
        """Initialize NuGet scanner."""
        super().__init__()
        self.logger = get_logger(__name__)

    def scan(self, source_path: Path) -> list[Dependency]:
        """Scan for .NET NuGet dependencies.

        Args:
            source_path: Path to the source code.

        Returns:
            List of NuGet dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[str] = set()

        # Collect version map from lock file if available
        lock_versions = self._parse_lock_file(source_path)

        # Collect version map from Directory.Packages.props (central package management)
        central_versions = self._parse_central_package_management(source_path)
        # Merge: central versions override lock versions as they are authoritative
        all_versions = {**lock_versions, **central_versions}

        # Scan .csproj files
        for csproj_file in source_path.rglob("*.csproj"):
            if self._should_skip_path(csproj_file):
                continue

            deps = self._parse_csproj(csproj_file, all_versions)
            for dep in deps:
                if dep.name.lower() not in seen:
                    seen.add(dep.name.lower())
                    dependencies.append(dep)

        # Scan packages.config (legacy format)
        for packages_config in source_path.rglob("packages.config"):
            if self._should_skip_path(packages_config):
                continue

            deps = self._parse_packages_config(packages_config, all_versions)
            for dep in deps:
                if dep.name.lower() not in seen:
                    seen.add(dep.name.lower())
                    dependencies.append(dep)

        # Scan Directory.Packages.props (central package management)
        for props_file in source_path.rglob("Directory.Packages.props"):
            if self._should_skip_path(props_file):
                continue

            deps = self._parse_directory_packages_props(props_file)
            for dep in deps:
                if dep.name.lower() not in seen:
                    seen.add(dep.name.lower())
                    dependencies.append(dep)

        # Scan Directory.Build.props (may contain PackageReference)
        for build_props in source_path.rglob("Directory.Build.props"):
            if self._should_skip_path(build_props):
                continue

            deps = self._parse_csproj(build_props, all_versions)
            for dep in deps:
                if dep.name.lower() not in seen:
                    seen.add(dep.name.lower())
                    dependencies.append(dep)

        # Scan vbproj and fsproj files as well (same MSBuild format)
        for ext in ("*.vbproj", "*.fsproj"):
            for proj_file in source_path.rglob(ext):
                if self._should_skip_path(proj_file):
                    continue

                deps = self._parse_csproj(proj_file, all_versions)
                for dep in deps:
                    if dep.name.lower() not in seen:
                        seen.add(dep.name.lower())
                        dependencies.append(dep)

        self.logger.info(f"Found {len(dependencies)} NuGet dependencies")
        return dependencies

    def _parse_csproj(
        self, file_path: Path, version_map: dict[str, str]
    ) -> list[Dependency]:
        """Parse a .csproj (MSBuild) file for PackageReference elements.

        Handles both SDK-style csproj (without namespace) and legacy csproj
        (with MSBuild namespace).

        Args:
            file_path: Path to the .csproj file.
            version_map: Resolved versions from lock/central management.

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

        # Try XML parsing first
        deps = self._parse_csproj_xml(content, source_file, version_map)
        if deps:
            dependencies.extend(deps)
            return dependencies

        # Fallback to regex parsing for malformed XML
        deps = self._parse_csproj_regex(content, source_file, version_map)
        dependencies.extend(deps)
        return dependencies

    def _parse_csproj_xml(
        self,
        content: str,
        source_file: str,
        version_map: dict[str, str],
    ) -> list[Dependency]:
        """Parse csproj content using XML parser.

        Args:
            content: File content string.
            source_file: Source file path string.
            version_map: Resolved versions.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []

        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return dependencies

        # Handle namespace
        ns_prefix = self._detect_namespace(root)

        # Find all PackageReference elements
        # These can be under ItemGroup at various levels
        xpath_queries = [
            f".//{ns_prefix}PackageReference",
            f".//{ns_prefix}PackageVersion",
        ]

        for xpath in xpath_queries:
            try:
                for elem in root.iterfind(xpath):
                    dep = self._parse_package_reference_element(
                        elem, source_file, version_map
                    )
                    if dep and dep.name.lower() not in {d.name.lower() for d in dependencies}:
                        dependencies.append(dep)
            except SyntaxError:
                # Invalid xpath, try without namespace
                continue

        # If namespace-based search yielded nothing, try a broader search
        if not dependencies:
            for elem in root.iter():
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if tag in ("PackageReference", "PackageVersion"):
                    dep = self._parse_package_reference_element(
                        elem, source_file, version_map
                    )
                    if dep:
                        dependencies.append(dep)

        return dependencies

    def _detect_namespace(self, root: ET.Element) -> str:
        """Detect MSBuild namespace prefix for xpath queries.

        Args:
            root: XML root element.

        Returns:
            Namespace prefix string for xpath (e.g., "{ns}" or "").
        """
        tag = root.tag
        if tag.startswith("{"):
            ns = tag[1:tag.index("}")]
            return f"{{{ns}}}"
        return ""

    def _parse_package_reference_element(
        self,
        elem: ET.Element,
        source_file: str,
        version_map: dict[str, str],
    ) -> Dependency | None:
        """Parse a PackageReference XML element.

        Handles these formats:
          <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
          <PackageReference Include="Serilog">
            <Version>2.10.0</Version>
          </PackageReference>
          <PackageReference Update="Polly" Version="7.2.3" />
          <PackageReference Include=" coverlet.collector">
            <PrivateAssets>all</PrivateAssets>
            <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
          </PackageReference>

        Args:
            elem: PackageReference XML element.
            source_file: Source file path.
            version_map: Resolved versions.

        Returns:
            Dependency or None.
        """
        # Get package name from Include or Update attribute
        name = elem.get("Include", "").strip()
        if not name:
            name = elem.get("Update", "").strip()
        if not name:
            return None

        # Get version from Version attribute
        version = elem.get("Version", "").strip()

        # If no Version attribute, check child Version element
        if not version:
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            version_elem = elem.find(f"{'{'+elem.tag.split('}')[0][1:]+'}' if '}' in elem.tag else ''}Version")
            if version_elem is not None and version_elem.text:
                version = version_elem.text.strip()
            else:
                # Try without namespace
                for child in elem:
                    child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if child_tag == "Version" and child.text:
                        version = child.text.strip()
                        break

        # Determine if dev dependency (test/analyzers/build tools)
        is_dev = self._is_dev_package(name, elem)

        # Handle version variable references like $(SomeVersion)
        raw_version = version
        if version and version.startswith("$(") and version.endswith(")"):
            # Variable reference, try to resolve from version map
            resolved = version_map.get(name)
            if resolved:
                version = resolved
            else:
                # Cannot resolve variable, use as-is with low confidence
                version = version

        # Resolve from version map if no version or version is a variable
        if not version:
            resolved = version_map.get(name)
            if resolved:
                version = resolved

        if not version:
            version = "*"

        # Clean version
        version = self._clean_nuget_version(version)

        version_source = VersionSource.EXPLICIT
        version_confidence = 1.0 if version != "*" and not version.startswith("$(") else 0.3

        return Dependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.NUGET,
            source_file=source_file,
            is_direct=True,
            is_dev=is_dev,
            raw_version=raw_version if raw_version != version else None,
            version_source=version_source,
            version_confidence=version_confidence,
        )

    def _parse_csproj_regex(
        self,
        content: str,
        source_file: str,
        version_map: dict[str, str],
    ) -> list[Dependency]:
        """Parse csproj content using regex (fallback for malformed XML).

        Args:
            content: File content.
            source_file: Source file path.
            version_map: Resolved versions.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[str] = set()

        # Find PackageReference elements
        for match in self.PACKAGE_REF_PATTERN.finditer(content):
            name = match.group("name").strip()
            version = match.group("version")

            if not name or name.lower() in seen:
                continue

            seen.add(name.lower())

            if not version:
                version = version_map.get(name, "*")

            version = self._clean_nuget_version(version) if version else "*"
            version_confidence = 1.0 if version and version != "*" else 0.3

            is_dev = self._is_dev_package_name(name)

            dep = Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.NUGET,
                source_file=source_file,
                is_direct=True,
                is_dev=is_dev,
                version_source=VersionSource.EXPLICIT,
                version_confidence=version_confidence,
            )
            dependencies.append(dep)

        # Find PackageVersion elements
        for match in self.PACKAGE_VERSION_PATTERN.finditer(content):
            name = match.group("name").strip()
            version = match.group("version")

            if not name or name.lower() in seen:
                continue

            seen.add(name.lower())

            version = self._clean_nuget_version(version) if version else "*"
            version_confidence = 1.0 if version and version != "*" else 0.3

            dep = Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.NUGET,
                source_file=source_file,
                is_direct=True,
                version_source=VersionSource.EXPLICIT,
                version_confidence=version_confidence,
            )
            dependencies.append(dep)

        return dependencies

    def _parse_packages_config(
        self, file_path: Path, version_map: dict[str, str]
    ) -> list[Dependency]:
        """Parse legacy packages.config file.

        Format:
          <?xml version="1.0" encoding="utf-8"?>
          <packages>
            <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net45" />
            <package id=" NUnit" version="3.13.2" targetFramework="net45" developmentDependency="true" />
          </packages>

        Args:
            file_path: Path to packages.config.
            version_map: Resolved versions.

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

        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            # Fallback to regex
            return self._parse_packages_config_regex(content, source_file)

        for package_elem in root.iter("package"):
            name = package_elem.get("id", "").strip()
            version = package_elem.get("version", "").strip()
            target_framework = package_elem.get("targetFramework", "")
            dev_dependency = package_elem.get("developmentDependency", "false")

            if not name:
                continue

            if not version:
                version = version_map.get(name, "*")

            version = self._clean_nuget_version(version) if version else "*"

            is_dev = dev_dependency.lower() == "true" or self._is_dev_package_name(name)

            version_confidence = 1.0 if version != "*" else 0.3

            dep = Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.NUGET,
                source_file=source_file,
                is_direct=True,
                is_dev=is_dev,
                version_source=VersionSource.EXPLICIT,
                version_confidence=version_confidence,
            )
            dependencies.append(dep)

        return dependencies

    def _parse_packages_config_regex(
        self, content: str, source_file: str
    ) -> list[Dependency]:
        """Parse packages.config using regex (fallback).

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[str] = set()

        pattern = re.compile(
            r'<package\s+'
            r'id\s*=\s*["\'](?P<id>[^"\']+)["\']'
            r'(?:\s+version\s*=\s*["\'](?P<version>[^"\']+)["\'])?'
            r'(?:\s+targetFramework\s*=\s*["\'](?P<framework>[^"\']+)["\'])?'
            r'(?:\s+developmentDependency\s*=\s*["\'](?P<dev>[^"\']+)["\'])?'
            r'',
            re.IGNORECASE,
        )

        for match in pattern.finditer(content):
            name = match.group("id").strip()
            if not name or name.lower() in seen:
                continue

            seen.add(name.lower())
            version = match.group("version")
            dev_flag = match.group("dev")

            version = self._clean_nuget_version(version) if version else "*"
            is_dev = (dev_flag or "").lower() == "true" or self._is_dev_package_name(name)

            version_confidence = 1.0 if version != "*" else 0.3

            dep = Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.NUGET,
                source_file=source_file,
                is_direct=True,
                is_dev=is_dev,
                version_source=VersionSource.EXPLICIT,
                version_confidence=version_confidence,
            )
            dependencies.append(dep)

        return dependencies

    def _parse_directory_packages_props(
        self, file_path: Path
    ) -> list[Dependency]:
        """Parse Directory.Packages.props for central package management.

        This file declares package versions centrally:
          <Project>
            <ItemGroup>
              <PackageVersion Include="Serilog" Version="2.10.0" />
              <PackageVersion Include="Polly" Version="7.2.3" />
            </ItemGroup>
          </Project>

        Args:
            file_path: Path to Directory.Packages.props.

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

        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            # Regex fallback
            for match in self.PACKAGE_VERSION_PATTERN.finditer(content):
                name = match.group("name").strip()
                version = match.group("version")
                if name and version:
                    version = self._clean_nuget_version(version)
                    dep = Dependency(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.NUGET,
                        source_file=source_file,
                        is_direct=True,
                        version_source=VersionSource.EXPLICIT,
                        version_confidence=1.0,
                    )
                    dependencies.append(dep)
            return dependencies

        # XML parsing
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag == "PackageVersion":
                name = elem.get("Include", "").strip()
                if not name:
                    name = elem.get("Update", "").strip()
                if not name:
                    continue

                version = elem.get("Version", "").strip()
                if not version:
                    # Check child element
                    for child in elem:
                        child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        if child_tag == "Version" and child.text:
                            version = child.text.strip()
                            break

                if version:
                    version = self._clean_nuget_version(version)

                if not version:
                    version = "*"

                version_confidence = 1.0 if version != "*" else 0.3

                dep = Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NUGET,
                    source_file=source_file,
                    is_direct=True,
                    version_source=VersionSource.EXPLICIT,
                    version_confidence=version_confidence,
                )
                dependencies.append(dep)

        return dependencies

    def _parse_central_package_management(
        self, source_path: Path
    ) -> dict[str, str]:
        """Parse Directory.Packages.props for version resolution map.

        Args:
            source_path: Path to source code.

        Returns:
            Dict mapping package name to version from central management.
        """
        versions: dict[str, str] = {}

        for props_file in source_path.rglob("Directory.Packages.props"):
            if self._should_skip_path(props_file):
                continue

            try:
                content = props_file.read_text(encoding="utf-8")
            except OSError:
                continue

            try:
                root = ET.fromstring(content)
            except ET.ParseError:
                # Regex fallback
                for match in self.PACKAGE_VERSION_PATTERN.finditer(content):
                    name = match.group("name").strip()
                    version = match.group("version")
                    if name and version:
                        versions[name] = self._clean_nuget_version(version)
                continue

            for elem in root.iter():
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if tag == "PackageVersion":
                    name = elem.get("Include", "").strip()
                    if not name:
                        name = elem.get("Update", "").strip()
                    version = elem.get("Version", "").strip()
                    if name and version:
                        versions[name] = self._clean_nuget_version(version)

        return versions

    def _parse_lock_file(self, source_path: Path) -> dict[str, str]:
        """Parse packages.lock.json for resolved versions if available.

        Args:
            source_path: Path to source code.

        Returns:
            Dict mapping package name to resolved version.
        """
        versions: dict[str, str] = {}

        for lock_file in source_path.rglob("packages.lock.json"):
            if self._should_skip_path(lock_file):
                continue

            import json

            try:
                content = lock_file.read_text(encoding="utf-8")
                data = json.loads(content)
            except (json.JSONDecodeError, OSError) as e:
                self.logger.warning(f"Failed to parse {lock_file}: {e}")
                continue

            # Format: { "version": 1, "dependencies": { "tfm": { "pkg": { "resolved": "x.y.z" } } } }
            dependencies = data.get("dependencies", {})
            for _tfm, packages in dependencies.items():
                if not isinstance(packages, dict):
                    continue
                for name, info in packages.items():
                    if isinstance(info, dict):
                        version = info.get("resolved", "")
                        if version:
                            versions[name] = version
                    elif isinstance(info, str):
                        versions[name] = info

        return versions

    def _is_dev_package(
        self, name: str, elem: ET.Element | None = None
    ) -> bool:
        """Check if a package is a development/test dependency.

        Args:
            name: Package name.
            elem: XML element (to check PrivateAssets).

        Returns:
            True if this is a dev dependency.
        """
        # Check element attributes
        if elem is not None:
            private_assets = elem.get("PrivateAssets", "")
            include_assets = elem.get("IncludeAssets", "")
            if "all" in private_assets.lower():
                if "analyzers" in include_assets.lower() or "build" in include_assets.lower():
                    return True
            # Check child PrivateAssets element
            for child in elem:
                child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child_tag == "PrivateAssets" and child.text and "all" in child.text.lower():
                    return True

        return self._is_dev_package_name(name)

    def _is_dev_package_name(self, name: str) -> bool:
        """Check if a package name suggests a dev/test dependency.

        Args:
            name: Package name.

        Returns:
            True if likely a dev dependency.
        """
        name_lower = name.lower()
        dev_indicators = [
            "test",
            "nunit",
            "xunit",
            "mstest",
            "coverlet",
            "moq",
            "nspec",
            "specflow",
            "fluentassertions",
            "shouldly",
            "benchmarks",
            "benchmarkdotnet",
            "roslyn",
            "analyzer",
            ".analyzers",
            ".testing",
            ".test",
            "fsharp.compiler.tools",
            "microsoft.codecoverage",
            "microsoft.net.test.sdk",
        ]
        for indicator in dev_indicators:
            if indicator in name_lower:
                return True
        return False

    def _clean_nuget_version(self, version: str) -> str:
        """Clean a NuGet version string.

        Handles version ranges like [1.0,2.0), (1.0,), [, etc.

        Args:
            version: Raw version string.

        Returns:
            Cleaned version string.
        """
        if not version:
            return "*"

        version = version.strip()

        # Handle NuGet version range syntax: [1.0, 2.0), (1.0,), [1.0]
        if version.startswith("[") or version.startswith("("):
            return self._extract_version_from_range(version)

        # Handle v-prefix
        if version.startswith("v"):
            version = version[1:]

        # Handle variable references $(Version) -- keep as-is
        if version.startswith("$("):
            return version

        return version

    def _extract_version_from_range(self, version_range: str) -> str:
        """Extract a concrete version from NuGet version range syntax.

        NuGet ranges: [1.0, 2.0) means >= 1.0 and < 2.0
                      (1.0,) means > 1.0
                      [1.0] means exactly 1.0

        Args:
            version_range: Version range string.

        Returns:
            Approximate version string.
        """
        # Remove brackets
        inner = version_range.strip("[]()")

        if not inner:
            return "*"

        # Split on comma
        parts = [p.strip() for p in inner.split(",")]

        if len(parts) == 1:
            # [1.0] exact version
            return parts[0]

        if len(parts) >= 2:
            # [1.0, 2.0) or (1.0, 2.0]
            lower = parts[0].strip()
            # Use lower bound as approximate version
            if lower:
                return lower
            # If no lower bound, use upper bound
            upper = parts[1].strip()
            if upper:
                return upper

        return "*"
