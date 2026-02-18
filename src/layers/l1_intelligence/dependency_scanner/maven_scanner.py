"""Maven/Gradle dependency scanner for Java projects."""

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


class MavenScanner(BaseDependencyScanner):
    """Scanner for Java dependency files (pom.xml, build.gradle, build.gradle.kts)."""

    supported_files = ["pom.xml", "build.gradle", "build.gradle.kts"]
    ecosystem = Ecosystem.MAVEN

    # Gradle dependency pattern for string notation
    GRADLE_STRING_PATTERN = re.compile(
        r"""['"](?P<group>[^:'"]+):(?P<artifact>[^:'"]+):(?P<version>[^'"]+)['"]"""
    )

    # Dev/optional configurations in Gradle
    GRADLE_DEV_CONFIGS = {
        "testImplementation",
        "testCompileOnly",
        "testRuntimeOnly",
        "androidTestImplementation",
        "androidTestCompile",
        "testCompile",
    }

    GRADLE_OPTIONAL_CONFIGS = {
        "compileOnly",
        "providedCompile",
        "optional",
    }

    def __init__(self) -> None:
        """Initialize Maven scanner."""
        super().__init__()
        self.logger = get_logger(__name__)

    def scan(self, source_path: Path) -> list[Dependency]:
        """Scan for Java/Maven dependencies.

        Args:
            source_path: Path to the source code.

        Returns:
            List of Maven dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[str] = set()

        # Parse pom.xml files
        for pom_file in source_path.rglob("pom.xml"):
            if self._should_skip_path(pom_file):
                continue

            deps = self._parse_pom_xml(pom_file)
            for dep in deps:
                key = f"{dep.name}@{dep.version}"
                if key not in seen:
                    seen.add(key)
                    dependencies.append(dep)

        # Parse build.gradle files
        for gradle_file in source_path.rglob("build.gradle"):
            if self._should_skip_path(gradle_file):
                continue

            deps = self._parse_build_gradle(gradle_file)
            for dep in deps:
                key = f"{dep.name}@{dep.version}"
                if key not in seen:
                    seen.add(key)
                    dependencies.append(dep)

        # Parse build.gradle.kts files (Kotlin DSL)
        for kts_file in source_path.rglob("build.gradle.kts"):
            if self._should_skip_path(kts_file):
                continue

            deps = self._parse_build_gradle_kts(kts_file)
            for dep in deps:
                key = f"{dep.name}@{dep.version}"
                if key not in seen:
                    seen.add(key)
                    dependencies.append(dep)

        self.logger.info(f"Found {len(dependencies)} Maven/Gradle dependencies")
        return dependencies

    def _parse_pom_xml(self, file_path: Path) -> list[Dependency]:
        """Parse pom.xml file.

        Args:
            file_path: Path to pom.xml.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []

        try:
            content = file_path.read_text(encoding="utf-8")
            # Remove XML declaration and comments for parsing
            content = re.sub(r"<\?xml[^>]*\?>", "", content)
            content = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)
            root = ET.fromstring(content)
        except ET.ParseError as e:
            self.logger.warning(f"Failed to parse {file_path}: {e}")
            return dependencies
        except OSError as e:
            self.logger.warning(f"Failed to read {file_path}: {e}")
            return dependencies

        source_file = str(file_path)

        # Extract properties for variable substitution
        properties = self._extract_properties(root)

        # Extract BOM (dependencyManagement) versions
        bom_versions = self._extract_bom_versions(root)

        # Find dependency elements NOT in dependencyManagement
        dep_elements = self._find_direct_dependencies(root)

        for dep_elem in dep_elements:
            dep = self._parse_dependency_element(dep_elem, source_file, properties, bom_versions)
            if dep:
                dependencies.append(dep)

        return dependencies

    def _find_direct_dependencies(self, root: ET.Element) -> list[ET.Element]:
        """Find dependency elements that are NOT in dependencyManagement.

        Args:
            root: POM root element.

        Returns:
            List of dependency elements outside dependencyManagement.
        """
        dependencies: list[ET.Element] = []

        def traverse(elem: ET.Element, in_dep_mgmt: bool = False) -> None:
            """Traverse tree and collect dependencies outside dependencyManagement."""
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

            # Track if we're entering dependencyManagement
            if tag == "dependencyManagement":
                in_dep_mgmt = True

            # Collect dependencies not in dependencyManagement
            if tag == "dependency" and not in_dep_mgmt:
                dependencies.append(elem)

            # Recurse into children
            for child in elem:
                traverse(child, in_dep_mgmt)

        traverse(root)
        return dependencies

    def _extract_properties(self, root: ET.Element) -> dict[str, str]:
        """Extract properties from POM for variable substitution.

        Args:
            root: POM root element.

        Returns:
            Dict of property name to value.
        """
        properties: dict[str, str] = {}

        # Find properties element - handle namespace
        props_elem = None
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag == "properties":
                props_elem = elem
                break

        if props_elem is not None:
            for child in props_elem:
                # Remove namespace prefix if present
                tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child.text:
                    properties[tag] = child.text.strip()

        # Also extract version from parent if present - handle namespace
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag == "parent":
                for child in elem:
                    child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if child.text:
                        properties[f"parent.{child_tag}"] = child.text.strip()
                break

        return properties

    def _extract_bom_versions(self, root: ET.Element) -> dict[str, str]:
        """Extract BOM (Bill of Materials) versions from dependencyManagement.

        BOM allows centralizing dependency versions. When a dependency has no
        version specified, it can inherit from the BOM.

        Example:
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-dependencies</artifactId>
                        <version>2.7.0</version>
                        <type>pom</type>
                        <scope>import</scope>
                    </dependency>
                </dependencies>
            </dependencyManagement>

        Or inline version management:
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>org.apache.dubbo</groupId>
                        <artifactId>dubbo</artifactId>
                        <version>${dubbo.version}</version>
                    </dependency>
                </dependencies>
            </dependencyManagement>

        Args:
            root: POM root element.

        Returns:
            Dict of "groupId:artifactId" -> version.
        """
        bom_versions: dict[str, str] = {}

        # Find dependencyManagement element
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag == "dependencyManagement":
                # Find dependencies within dependencyManagement
                for child in elem:
                    child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if child_tag == "dependencies":
                        # Extract versions from each dependency
                        for dep in child:
                            dep_tag = dep.tag.split("}")[-1] if "}" in dep.tag else dep.tag
                            if dep_tag == "dependency":
                                group_id = ""
                                artifact_id = ""
                                version = ""

                                for field in dep:
                                    field_tag = field.tag.split("}")[-1] if "}" in field.tag else field.tag
                                    text = (field.text or "").strip()
                                    if field_tag == "groupId":
                                        group_id = text
                                    elif field_tag == "artifactId":
                                        artifact_id = text
                                    elif field_tag == "version":
                                        version = text

                                # Skip BOM imports (type=pom, scope=import)
                                # These are external BOMs we can't resolve without Maven
                                if group_id and artifact_id and version:
                                    key = f"{group_id}:{artifact_id}"
                                    bom_versions[key] = version
                                    self.logger.debug(f"BOM version: {key} -> {version}")

                break  # Only process first dependencyManagement

        return bom_versions

    def _substitute_version(self, version: str, properties: dict[str, str]) -> str:
        """Substitute version variables.

        Args:
            version: Version string (may contain ${var}).
            properties: Properties dict for substitution.

        Returns:
            Resolved version string.
        """
        if not version:
            return ""

        # Pattern for ${variable}
        pattern = r"\$\{([^}]+)\}"

        def replacer(match: re.Match) -> str:
            var_name = match.group(1)
            # Try direct lookup
            if var_name in properties:
                return properties[var_name]
            # Try with project. prefix
            if var_name.startswith("project."):
                alt_name = var_name[8:]  # Remove 'project.'
                if alt_name in properties:
                    return properties[alt_name]
            # Return original if not found
            return match.group(0)

        return re.sub(pattern, replacer, version)

    def _parse_dependency_element(
        self,
        dep_elem: ET.Element,
        source_file: str,
        properties: dict[str, str],
        bom_versions: dict[str, str] | None = None,
    ) -> Dependency | None:
        """Parse a single dependency element.

        Args:
            dep_elem: Dependency XML element.
            source_file: Source file path.
            properties: Properties for variable substitution.
            bom_versions: BOM version mappings (groupId:artifactId -> version).

        Returns:
            Dependency or None.
        """
        bom_versions = bom_versions or {}
        group_id = ""
        artifact_id = ""
        raw_version = ""
        version = ""
        scope = ""
        optional = False

        for child in dep_elem:
            # Remove namespace prefix if present
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            text = (child.text or "").strip()

            if tag == "groupId":
                group_id = text
            elif tag == "artifactId":
                artifact_id = text
            elif tag == "version":
                raw_version = text
                version = self._substitute_version(text, properties)
            elif tag == "scope":
                scope = text
            elif tag == "optional":
                optional = text.lower() in ("true", "yes", "1")

        # Skip if missing required fields
        if not group_id or not artifact_id:
            return None

        # Package name format: groupId:artifactId
        name = f"{group_id}:{artifact_id}"

        # Track if version came from BOM (no version in dependency element)
        version_from_bom = False

        # If no version in dependency, try BOM
        if not raw_version and name in bom_versions:
            raw_version = bom_versions[name]
            version = self._substitute_version(raw_version, properties)
            version_from_bom = True
            self.logger.debug(f"Version for {name} from BOM: {version}")

        # Determine version source and confidence
        version_source, version_confidence, final_version = self._determine_version_info(
            raw_version, version, properties, version_from_bom
        )

        # Determine if dev or optional
        is_dev = scope == "test"
        is_optional = optional or scope == "provided"

        return Dependency(
            name=name,
            version=final_version,
            ecosystem=Ecosystem.MAVEN,
            source_file=source_file,
            is_direct=True,
            is_dev=is_dev,
            is_optional=is_optional,
            raw_version=raw_version if raw_version else None,
            version_source=version_source,
            version_confidence=version_confidence,
        )

    def _determine_version_info(
        self,
        raw_version: str,
        resolved_version: str,
        properties: dict[str, str],
        version_from_bom: bool = False,
    ) -> tuple[VersionSource, float, str | None]:
        """Determine version source, confidence, and final version.

        Args:
            raw_version: Original version string.
            resolved_version: Version after property substitution.
            properties: Properties dict used for resolution.
            version_from_bom: Whether version was obtained from BOM.

        Returns:
            Tuple of (version_source, confidence, final_version).
            final_version is None if version cannot be reliably determined.
        """
        # No version specified at all
        if not raw_version:
            return VersionSource.UNKNOWN, 0.0, None

        # Version came from BOM (dependency had no version element)
        if version_from_bom:
            # Check if BOM version itself is resolved
            if resolved_version and "${" not in resolved_version:
                return VersionSource.BOM, 0.8, resolved_version
            else:
                self.logger.debug(f"BOM version unresolved: {raw_version}")
                return VersionSource.BOM, 0.4, None

        # Check if version is a property reference
        is_property_ref = "${" in raw_version

        # Version is still unresolved (property not found)
        if is_property_ref and "${" in resolved_version:
            self.logger.debug(f"Unresolved version property: {raw_version}")
            return VersionSource.UNKNOWN, 0.0, None

        # Version was successfully resolved from property
        if is_property_ref and resolved_version and "${" not in resolved_version:
            # Check where the property was defined
            prop_name = raw_version.replace("${", "").replace("}", "")

            # Property from current POM's <properties>
            if prop_name in properties and not prop_name.startswith("parent."):
                return VersionSource.PROPERTY, 0.9, resolved_version

            # Property from parent POM
            if prop_name.startswith("parent.") or f"parent.{prop_name}" in properties:
                return VersionSource.PARENT, 0.7, resolved_version

            # Unknown property source but resolved
            return VersionSource.PROPERTY, 0.6, resolved_version

        # Explicit version (no property reference)
        if not is_property_ref and resolved_version:
            return VersionSource.EXPLICIT, 1.0, resolved_version

        # Fallback - shouldn't reach here normally
        return VersionSource.UNKNOWN, 0.0, None

    def _parse_build_gradle(self, file_path: Path) -> list[Dependency]:
        """Parse build.gradle file (Groovy DSL).

        Args:
            file_path: Path to build.gradle.

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

        # Remove comments
        content = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
        content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)

        # Extract ext properties for variable substitution
        properties = self._extract_gradle_properties(content)

        # Find dependencies block
        deps_match = re.search(r"dependencies\s*\{(.*?)\}", content, re.DOTALL)
        if not deps_match:
            return dependencies

        deps_block = deps_match.group(1)

        # Parse each line
        for line in deps_block.splitlines():
            line = line.strip()
            if not line:
                continue

            dep = self._parse_gradle_line(line, source_file, properties)
            if dep:
                dependencies.append(dep)

        return dependencies

    def _extract_gradle_properties(self, content: str) -> dict[str, str]:
        """Extract ext properties from Gradle file.

        Args:
            content: Gradle file content.

        Returns:
            Dict of property name to value.
        """
        properties: dict[str, str] = {}

        # Find ext block
        ext_match = re.search(r"ext\s*\{(.*?)\}", content, re.DOTALL)
        if ext_match:
            ext_block = ext_match.group(1)
            # Match property definitions like: propName = 'value' or propName = "value"
            for match in re.finditer(r"(\w+)\s*=\s*['\"]([^'\"]+)['\"]", ext_block):
                properties[match.group(1)] = match.group(2)

        # Also look for single-line ext definitions: ext.propName = 'value'
        for match in re.finditer(r"ext\.(\w+)\s*=\s*['\"]([^'\"]+)['\"]", content):
            properties[match.group(1)] = match.group(2)

        return properties

    def _parse_build_gradle_kts(self, file_path: Path) -> list[Dependency]:
        """Parse build.gradle.kts file (Kotlin DSL).

        Args:
            file_path: Path to build.gradle.kts.

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

        # Remove comments
        content = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
        content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)

        # Extract extra properties for variable substitution
        properties = self._extract_gradle_kts_properties(content)

        # Find dependencies block
        deps_match = re.search(r"dependencies\s*\{(.*?)\}", content, re.DOTALL)
        if not deps_match:
            return dependencies

        deps_block = deps_match.group(1)

        # Parse each line - Kotlin DSL uses parentheses
        for line in deps_block.splitlines():
            line = line.strip()
            if not line:
                continue

            dep = self._parse_kotlin_gradle_line(line, source_file, properties)
            if dep:
                dependencies.append(dep)

        return dependencies

    def _extract_gradle_kts_properties(self, content: str) -> dict[str, str]:
        """Extract extra properties from Kotlin DSL Gradle file.

        Args:
            content: Gradle.kts file content.

        Returns:
            Dict of property name to value.
        """
        properties: dict[str, str] = {}

        # Find extra block: extra["propName"] = "value" or extra.set("propName", "value")
        for match in re.finditer(r'extra\["(\w+)"\]\s*=\s*["\']([^"\']+)["\']', content):
            properties[match.group(1)] = match.group(2)

        for match in re.finditer(r'extra\.set\(["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']', content):
            properties[match.group(1)] = match.group(2)

        return properties

    def _parse_gradle_line(
        self, line: str, source_file: str, properties: dict[str, str]
    ) -> Dependency | None:
        """Parse a single Gradle dependency line.

        Args:
            line: Dependency line.
            source_file: Source file path.
            properties: Properties for variable substitution.

        Returns:
            Dependency or None.
        """
        # Match string notation: configuration 'group:artifact:version'
        match = self.GRADLE_STRING_PATTERN.search(line)
        if not match:
            return None

        group_id = match.group("group")
        artifact_id = match.group("artifact")
        raw_version = match.group("version")

        # Resolve version if it's a property reference
        version = self._resolve_gradle_version(raw_version, properties)

        # Determine version source and confidence
        version_source, version_confidence, final_version = self._determine_gradle_version_info(
            raw_version, version
        )

        # Extract configuration (before the string)
        config_part = line[: match.start()].strip()
        config = config_part.split()[-1] if config_part else ""

        # Determine if dev or optional
        is_dev = config in self.GRADLE_DEV_CONFIGS
        is_optional = config in self.GRADLE_OPTIONAL_CONFIGS

        # Package name format: groupId:artifactId
        name = f"{group_id}:{artifact_id}"

        return Dependency(
            name=name,
            version=final_version,
            ecosystem=Ecosystem.MAVEN,
            source_file=source_file,
            is_direct=True,
            is_dev=is_dev,
            is_optional=is_optional,
            raw_version=raw_version if raw_version != final_version else None,
            version_source=version_source,
            version_confidence=version_confidence,
        )

    def _resolve_gradle_version(self, version: str, properties: dict[str, str]) -> str:
        """Resolve Gradle version with property substitution.

        Args:
            version: Version string (may contain $property or ${property}).
            properties: Properties dict for substitution.

        Returns:
            Resolved version string.
        """
        if not version:
            return version

        # Pattern for ${property} or $property
        def replacer(match: re.Match) -> str:
            prop_name = match.group(1) or match.group(2)
            if prop_name in properties:
                return properties[prop_name]
            return match.group(0)  # Return original if not found

        # Try ${property} format
        result = re.sub(r"\$\{(\w+)\}", replacer, version)
        # Try $property format (without braces)
        result = re.sub(r"\$(\w+)(?!\w)", replacer, result)

        return result

    def _determine_gradle_version_info(
        self, raw_version: str, resolved_version: str
    ) -> tuple[VersionSource, float, str | None]:
        """Determine version info for Gradle dependency.

        Args:
            raw_version: Original version string.
            resolved_version: Version after property substitution.

        Returns:
            Tuple of (version_source, confidence, final_version).
        """
        if not raw_version:
            return VersionSource.UNKNOWN, 0.0, None

        # Check if version is a variable reference
        is_variable = raw_version.startswith("$")

        # Version is still unresolved
        if is_variable and resolved_version.startswith("$"):
            self.logger.debug(f"Unresolved Gradle version variable: {raw_version}")
            return VersionSource.UNKNOWN, 0.0, None

        # Version was resolved from property
        if is_variable and not resolved_version.startswith("$"):
            return VersionSource.PROPERTY, 0.9, resolved_version

        # Explicit version
        if not is_variable and resolved_version:
            return VersionSource.EXPLICIT, 1.0, resolved_version

        return VersionSource.UNKNOWN, 0.0, None

    def _parse_kotlin_gradle_line(
        self, line: str, source_file: str, properties: dict[str, str]
    ) -> Dependency | None:
        """Parse a single Kotlin DSL Gradle dependency line.

        Args:
            line: Dependency line.
            source_file: Source file path.
            properties: Properties for variable substitution.

        Returns:
            Dependency or None.
        """
        # Kotlin DSL format: configuration("group:artifact:version")
        # or: configuration(group = "group", name = "artifact", version = "version")

        # Try simple string format first
        pattern = r'(\w+)\s*\(\s*["\']([^"\']+)["\']\s*\)'
        match = re.search(pattern, line)

        if match:
            config = match.group(1)
            dep_string = match.group(2)

            # Parse group:artifact:version
            parts = dep_string.split(":")
            if len(parts) >= 3:
                name = f"{parts[0]}:{parts[1]}"
                raw_version = parts[2]

                # Resolve version
                version = self._resolve_gradle_version(raw_version, properties)
                version_source, version_confidence, final_version = self._determine_gradle_version_info(
                    raw_version, version
                )

                is_dev = config in self.GRADLE_DEV_CONFIGS
                is_optional = config in self.GRADLE_OPTIONAL_CONFIGS

                return Dependency(
                    name=name,
                    version=final_version,
                    ecosystem=Ecosystem.MAVEN,
                    source_file=source_file,
                    is_direct=True,
                    is_dev=is_dev,
                    is_optional=is_optional,
                    raw_version=raw_version if raw_version != version else None,
                    version_source=version_source,
                    version_confidence=version_confidence,
                )

        # Try named parameter format: configuration(group = "...", name = "...", version = "...")
        named_pattern = r'(\w+)\s*\(\s*group\s*=\s*["\']([^"\']+)["\']\s*,\s*name\s*=\s*["\']([^"\']+)["\']\s*,\s*version\s*=\s*["\']([^"\']+)["\']'
        named_match = re.search(named_pattern, line)

        if named_match:
            config = named_match.group(1)
            group_id = named_match.group(2)
            artifact_id = named_match.group(3)
            raw_version = named_match.group(4)

            # Resolve version
            version = self._resolve_gradle_version(raw_version, properties)
            version_source, version_confidence, final_version = self._determine_gradle_version_info(
                raw_version, version
            )

            name = f"{group_id}:{artifact_id}"

            is_dev = config in self.GRADLE_DEV_CONFIGS
            is_optional = config in self.GRADLE_OPTIONAL_CONFIGS

            return Dependency(
                name=name,
                version=final_version,
                ecosystem=Ecosystem.MAVEN,
                source_file=source_file,
                is_direct=True,
                is_dev=is_dev,
                is_optional=is_optional,
                raw_version=raw_version if raw_version != version else None,
                version_source=version_source,
                version_confidence=version_confidence,
            )

        return None
