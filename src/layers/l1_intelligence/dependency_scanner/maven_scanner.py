"""Maven/Gradle dependency scanner for Java projects."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.dependency_scanner.base_scanner import (
    BaseDependencyScanner,
    Dependency,
    Ecosystem,
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

        # Find all dependencies - handle both namespaced and non-namespaced XML
        # Check if there's a namespace in the root tag
        namespace = ""
        if "}" in root.tag:
            namespace = root.tag.split("}")[0] + "}"

        # Find dependencies using namespace-aware search
        dep_elements = root.iter(f"{namespace}dependency") if namespace else root.iter("dependency")

        # Also try without namespace if nothing found (for non-namespaced XML)
        if not list(dep_elements):
            dep_elements = root.iter("dependency")

        # Reset iterator
        dep_elements = root.iter()

        for dep_elem in dep_elements:
            # Check if this is a dependency element (with or without namespace)
            tag = dep_elem.tag.split("}")[-1] if "}" in dep_elem.tag else dep_elem.tag
            if tag == "dependency":
                dep = self._parse_dependency_element(dep_elem, source_file, properties)
                if dep:
                    dependencies.append(dep)

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
        self, dep_elem: ET.Element, source_file: str, properties: dict[str, str]
    ) -> Dependency | None:
        """Parse a single dependency element.

        Args:
            dep_elem: Dependency XML element.
            source_file: Source file path.
            properties: Properties for variable substitution.

        Returns:
            Dependency or None.
        """
        group_id = ""
        artifact_id = ""
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
                version = self._substitute_version(text, properties)
            elif tag == "scope":
                scope = text
            elif tag == "optional":
                optional = text.lower() in ("true", "yes", "1")

        # Skip if missing required fields
        if not group_id or not artifact_id:
            return None

        # Skip if version is still unresolved (contains ${})
        if not version or "${" in version:
            # Log but still include with unresolved version
            self.logger.debug(
                f"Unresolved version for {group_id}:{artifact_id}: {version}"
            )
            if not version:
                version = "*"

        # Determine if dev or optional
        is_dev = scope == "test"
        is_optional = optional or scope == "provided"

        # Package name format: groupId:artifactId
        name = f"{group_id}:{artifact_id}"

        return Dependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.MAVEN,
            source_file=source_file,
            is_direct=True,
            is_dev=is_dev,
            is_optional=is_optional,
        )

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

            dep = self._parse_gradle_line(line, source_file)
            if dep:
                dependencies.append(dep)

        return dependencies

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

            dep = self._parse_kotlin_gradle_line(line, source_file)
            if dep:
                dependencies.append(dep)

        return dependencies

    def _parse_gradle_line(self, line: str, source_file: str) -> Dependency | None:
        """Parse a single Gradle dependency line.

        Args:
            line: Dependency line.
            source_file: Source file path.

        Returns:
            Dependency or None.
        """
        # Match string notation: configuration 'group:artifact:version'
        match = self.GRADLE_STRING_PATTERN.search(line)
        if not match:
            return None

        group_id = match.group("group")
        artifact_id = match.group("artifact")
        version = match.group("version")

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
            version=version,
            ecosystem=Ecosystem.MAVEN,
            source_file=source_file,
            is_direct=True,
            is_dev=is_dev,
            is_optional=is_optional,
        )

    def _parse_kotlin_gradle_line(self, line: str, source_file: str) -> Dependency | None:
        """Parse a single Kotlin DSL Gradle dependency line.

        Args:
            line: Dependency line.
            source_file: Source file path.

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
                version = parts[2]

                is_dev = config in self.GRADLE_DEV_CONFIGS
                is_optional = config in self.GRADLE_OPTIONAL_CONFIGS

                return Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.MAVEN,
                    source_file=source_file,
                    is_direct=True,
                    is_dev=is_dev,
                    is_optional=is_optional,
                )

        # Try named parameter format: configuration(group = "...", name = "...", version = "...")
        named_pattern = r'(\w+)\s*\(\s*group\s*=\s*["\']([^"\']+)["\']\s*,\s*name\s*=\s*["\']([^"\']+)["\']\s*,\s*version\s*=\s*["\']([^"\']+)["\']'
        named_match = re.search(named_pattern, line)

        if named_match:
            config = named_match.group(1)
            group_id = named_match.group(2)
            artifact_id = named_match.group(3)
            version = named_match.group(4)

            name = f"{group_id}:{artifact_id}"

            is_dev = config in self.GRADLE_DEV_CONFIGS
            is_optional = config in self.GRADLE_OPTIONAL_CONFIGS

            return Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.MAVEN,
                source_file=source_file,
                is_direct=True,
                is_dev=is_dev,
                is_optional=is_optional,
            )

        return None
