"""Maven pom.xml security configuration analyzer."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from src.layers.l1_intelligence.build_config.base import BaseConfigAnalyzer
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    FindingCategory,
    MavenModuleInfo,
    MavenPluginInfo,
    MavenProfileInfo,
    SecurityFinding,
    SecurityRisk,
)


class MavenAnalyzer(BaseConfigAnalyzer):
    """Analyzer for Maven pom.xml security configurations."""

    supported_files = ["pom.xml"]
    category_name = "maven_config"

    # Security-sensitive plugins
    SECURITY_PLUGINS = {
        # Compiler plugins with security settings
        "maven-compiler-plugin": {
            "category": "build",
            "security_configs": ["compilerArgs", "fork", "executable"],
        },
        # Security scanning plugins
        "dependency-check-maven": {"category": "security", "security_configs": []},
        "spotbugs-maven-plugin": {"category": "security", "security_configs": []},
        "maven-checkstyle-plugin": {"category": "security", "security_configs": []},
        # Deployment plugins that might expose secrets
        "maven-deploy-plugin": {"category": "deployment", "security_configs": ["repositoryId", "url"]},
        "maven-release-plugin": {"category": "deployment", "security_configs": []},
        # Container/plugins that might have insecure defaults
        "spring-boot-maven-plugin": {"category": "build", "security_configs": []},
        "docker-maven-plugin": {"category": "container", "security_configs": []},
        "jib-maven-plugin": {"category": "container", "security_configs": []},
    }

    # Properties that often contain sensitive data
    SENSITIVE_PROPERTY_PATTERNS = [
        r"password",
        r"secret",
        r"token",
        r"api[_-]?key",
        r"access[_-]?key",
        r"private[_-]?key",
        r"credential",
        r"auth",
        r"keystore",
        r"truststore",
        r"jdbc",
        r"database",
        r"smtp",
        r"mail",
    ]

    def __init__(self) -> None:
        """Initialize Maven analyzer."""
        super().__init__()

    def analyze(self, source_path: Path, report: BuildConfigReport) -> list[SecurityFinding]:
        """Analyze Maven pom.xml files for security issues.

        Args:
            source_path: Path to the source code.
            report: Report to add findings to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        pom_files = self.find_files(source_path)
        if not pom_files:
            return findings

        for pom_file in pom_files:
            report.scanned_files.append(str(pom_file))
            file_findings = self._analyze_pom(pom_file, report)
            findings.extend(file_findings)

        return findings

    def _analyze_pom(self, pom_file: Path, report: BuildConfigReport) -> list[SecurityFinding]:
        """Analyze a single pom.xml file.

        Args:
            pom_file: Path to pom.xml.
            report: Report to add findings to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        content = self._safe_read_file(pom_file)
        if not content:
            return findings

        try:
            # Clean content for parsing
            content = self._clean_xml(content)
            root = ET.fromstring(content)
        except ET.ParseError as e:
            self.logger.warning(f"Failed to parse {pom_file}: {e}")
            report.scan_errors.append(f"Failed to parse {pom_file}: {e}")
            return findings

        source_file = str(pom_file)

        # Handle namespace
        self.namespace = self._extract_namespace(root)

        # Analyze different aspects
        findings.extend(self._analyze_plugins(root, source_file, report))
        findings.extend(self._analyze_properties(root, source_file))
        findings.extend(self._analyze_profiles(root, source_file, report))
        findings.extend(self._analyze_modules(root, source_file, report))

        return findings

    def _clean_xml(self, content: str) -> str:
        """Clean XML content for parsing.

        Args:
            content: Raw XML content.

        Returns:
            Cleaned XML content.
        """
        # Remove XML declaration
        content = re.sub(r"<\?xml[^>]*\?>", "", content)
        # Remove comments
        content = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)
        return content.strip()

    def _extract_namespace(self, root: ET.Element) -> str:
        """Extract XML namespace from root element.

        Args:
            root: Root XML element.

        Returns:
            Namespace string (with trailing brace) or empty string.
        """
        if "}" in root.tag:
            return root.tag.split("}")[0] + "}"
        return ""

    def _get_element(self, parent: ET.Element, tag: str) -> ET.Element | None:
        """Get child element, handling namespace.

        Args:
            parent: Parent element.
            tag: Tag name (without namespace).

        Returns:
            Child element or None.
        """
        # Try with namespace first
        elem = parent.find(f"{self.namespace}{tag}")
        if elem is not None:
            return elem
        # Try without namespace
        return parent.find(tag)

    def _get_elements(self, parent: ET.Element, tag: str) -> list[ET.Element]:
        """Get all child elements with tag, handling namespace.

        Args:
            parent: Parent element.
            tag: Tag name (without namespace).

        Returns:
            List of child elements.
        """
        # Try with namespace first
        elems = parent.findall(f".//{self.namespace}{tag}")
        if elems:
            return elems
        # Try without namespace
        return parent.findall(f".//{tag}")

    def _analyze_plugins(
        self, root: ET.Element, source_file: str, report: BuildConfigReport
    ) -> list[SecurityFinding]:
        """Analyze Maven plugins for security configurations.

        Args:
            root: POM root element.
            source_file: Source file path.
            report: Report to add plugin info to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Find build/plugins section
        build = self._get_element(root, "build")
        if build is None:
            return findings

        plugins = self._get_element(build, "plugins")
        if plugins is None:
            return findings

        for plugin_elem in plugins:
            # Get plugin info
            plugin_info = self._parse_plugin(plugin_elem, source_file)
            if plugin_info:
                report.maven_plugins.append(plugin_info)

                # Check for security issues
                plugin_findings = self._check_plugin_security(plugin_info)
                findings.extend(plugin_findings)

        return findings

    def _parse_plugin(self, plugin_elem: ET.Element, source_file: str) -> MavenPluginInfo | None:
        """Parse a plugin element.

        Args:
            plugin_elem: Plugin XML element.
            source_file: Source file path.

        Returns:
            MavenPluginInfo or None.
        """
        group_id = ""
        artifact_id = ""
        version = None

        for child in plugin_elem:
            tag = self._get_local_tag(child.tag)
            text = (child.text or "").strip()

            if tag == "groupId":
                group_id = text
            elif tag == "artifactId":
                artifact_id = text
            elif tag == "version":
                version = text

        if not artifact_id:
            return None

        if not group_id:
            group_id = "org.apache.maven.plugins"  # Default group

        # Parse configuration
        configuration = {}
        config_elem = self._get_element(plugin_elem, "configuration")
        if config_elem is not None:
            configuration = self._parse_configuration(config_elem)

        # Parse executions
        executions = []
        executions_elem = self._get_element(plugin_elem, "executions")
        if executions_elem is not None:
            for exec_elem in executions_elem:
                if self._get_local_tag(exec_elem.tag) == "execution":
                    executions.append(self._parse_execution(exec_elem))

        return MavenPluginInfo(
            group_id=group_id,
            artifact_id=artifact_id,
            version=version,
            configuration=configuration,
            executions=executions,
            source_file=source_file,
        )

    def _parse_configuration(self, config_elem: ET.Element) -> dict[str, str | list]:
        """Parse plugin configuration element.

        Args:
            config_elem: Configuration XML element.

        Returns:
            Configuration dictionary.
        """
        config: dict[str, str | list] = {}

        for child in config_elem:
            tag = self._get_local_tag(child.tag)
            text = (child.text or "").strip()

            # Handle nested elements
            if len(child) > 0:
                nested: list[str] = []
                for nested_child in child:
                    nested_text = (nested_child.text or "").strip()
                    if nested_text:
                        nested.append(nested_text)
                config[tag] = nested
            elif text:
                config[tag] = text

        return config

    def _parse_execution(self, exec_elem: ET.Element) -> dict[str, str | list]:
        """Parse plugin execution element.

        Args:
            exec_elem: Execution XML element.

        Returns:
            Execution dictionary.
        """
        execution: dict[str, str | list] = {}

        for child in exec_elem:
            tag = self._get_local_tag(child.tag)
            text = (child.text or "").strip()

            if tag == "goals" and len(child) > 0:
                goals = []
                for goal_elem in child:
                    goal_text = (goal_elem.text or "").strip()
                    if goal_text:
                        goals.append(goal_text)
                execution["goals"] = goals
            elif text:
                execution[tag] = text

        return execution

    def _check_plugin_security(self, plugin: MavenPluginInfo) -> list[SecurityFinding]:
        """Check plugin for security issues.

        Args:
            plugin: Plugin information.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        plugin_key = plugin.artifact_id
        plugin_info = self.SECURITY_PLUGINS.get(plugin_key)

        if plugin_info:
            # Check for sensitive configuration values
            for config_key, config_value in plugin.configuration.items():
                if isinstance(config_value, str) and self._is_sensitive_value(config_value):
                    findings.append(
                        SecurityFinding(
                            category=FindingCategory.MAVEN_CONFIG,
                            risk_level=SecurityRisk.MEDIUM,
                            title=f"Sensitive configuration in {plugin_key}",
                            description=f"Plugin {plugin_key} has configuration '{config_key}' that may contain sensitive data",
                            file_path=plugin.source_file or "",
                            evidence=f"{config_key}={config_value[:50]}..." if len(config_value) > 50 else f"{config_key}={config_value}",
                            recommendation="Move sensitive values to environment variables or external configuration",
                            references=["https://maven.apache.org/guides/introduction/introduction-to-the-pom.html"],
                            cwe="CWE-798",
                        )
                    )

        # Check for missing security plugins in production builds
        has_dependency_check = any(
            "dependency-check" in p.artifact_id for p in [plugin] if plugin
        )
        if not has_dependency_check:
            # This is informational, not a hard finding
            pass  # Could add INFO-level finding

        return findings

    def _analyze_properties(
        self, root: ET.Element, source_file: str
    ) -> list[SecurityFinding]:
        """Analyze Maven properties for sensitive data.

        Args:
            root: POM root element.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        props_elem = self._get_element(root, "properties")
        if props_elem is None:
            return findings

        for child in props_elem:
            prop_name = self._get_local_tag(child.tag)
            prop_value = (child.text or "").strip()

            if not prop_value:
                continue

            # Check if property name suggests sensitive data
            is_sensitive_name = self._is_sensitive_property(prop_name)
            is_sensitive_val = self._is_sensitive_value(prop_value)

            if is_sensitive_name and prop_value and not self._is_placeholder(prop_value):
                risk = SecurityRisk.HIGH if is_sensitive_val else SecurityRisk.MEDIUM
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.SECRETS,
                        risk_level=risk,
                        title=f"Potentially sensitive property: {prop_name}",
                        description=f"Property '{prop_name}' may contain sensitive configuration or credentials",
                        file_path=source_file,
                        evidence=f"<{prop_name}>{prop_value[:50]}</{prop_name}>",
                        recommendation="Use environment variables or encrypted property files for sensitive values",
                        references=[
                            "https://maven.apache.org/guides/introduction/introduction-to-the-pom.html#properties"
                        ],
                        cwe="CWE-798",
                    )
                )

        return findings

    def _analyze_profiles(
        self, root: ET.Element, source_file: str, report: BuildConfigReport
    ) -> list[SecurityFinding]:
        """Analyze Maven profiles for security issues.

        Args:
            root: POM root element.
            source_file: Source file path.
            report: Report to add profile info to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        profiles_elem = self._get_element(root, "profiles")
        if profiles_elem is None:
            return findings

        for profile_elem in profiles_elem:
            if self._get_local_tag(profile_elem.tag) != "profile":
                continue

            profile_info = self._parse_profile(profile_elem, source_file)
            if profile_info:
                report.maven_profiles.append(profile_info)

                # Check profile properties for sensitive data
                for prop_name, prop_value in profile_info.properties.items():
                    if self._is_sensitive_property(prop_name) and not self._is_placeholder(
                        prop_value
                    ):
                        findings.append(
                            SecurityFinding(
                                category=FindingCategory.SECRETS,
                                risk_level=SecurityRisk.MEDIUM,
                                title=f"Sensitive property in profile '{profile_info.id}'",
                                description=f"Profile '{profile_info.id}' has property '{prop_name}' that may contain sensitive data",
                                file_path=source_file,
                                evidence=f"<{prop_name}>{prop_value[:50]}</{prop_name}>",
                                recommendation="Use environment-specific property files or secret management",
                                references=[
                                    "https://maven.apache.org/guides/introduction/introduction-to-profiles.html"
                                ],
                                cwe="CWE-798",
                            )
                        )

        return findings

    def _parse_profile(self, profile_elem: ET.Element, source_file: str) -> MavenProfileInfo | None:
        """Parse a profile element.

        Args:
            profile_elem: Profile XML element.
            source_file: Source file path.

        Returns:
            MavenProfileInfo or None.
        """
        profile_id = ""
        activation = None
        properties: dict[str, str] = {}
        plugins: list[MavenPluginInfo] = []
        dependencies: list[dict[str, Any]] = []

        for child in profile_elem:
            tag = self._get_local_tag(child.tag)

            if tag == "id":
                profile_id = (child.text or "").strip()
            elif tag == "activation":
                activation = self._parse_activation(child)
            elif tag == "properties":
                for prop_child in child:
                    prop_name = self._get_local_tag(prop_child.tag)
                    prop_value = (prop_child.text or "").strip()
                    if prop_name and prop_value:
                        properties[prop_name] = prop_value
            elif tag == "build":
                build_plugins = self._get_element(child, "plugins")
                if build_plugins is not None:
                    for plugin_elem in build_plugins:
                        plugin_info = self._parse_plugin(plugin_elem, source_file)
                        if plugin_info:
                            plugins.append(plugin_info)
            elif tag == "dependencies":
                for dep_elem in child:
                    if self._get_local_tag(dep_elem.tag) == "dependency":
                        dep = self._parse_dependency(dep_elem)
                        if dep:
                            dependencies.append(dep)

        if not profile_id:
            return None

        return MavenProfileInfo(
            id=profile_id,
            activation=activation,
            properties=properties,
            plugins=plugins,
            dependencies=dependencies,
            source_file=source_file,
        )

    def _parse_activation(self, activation_elem: ET.Element) -> dict[str, Any]:
        """Parse profile activation element.

        Args:
            activation_elem: Activation XML element.

        Returns:
            Activation dictionary.
        """
        activation: dict[str, Any] = {}

        for child in activation_elem:
            tag = self._get_local_tag(child.tag)
            text = (child.text or "").strip()

            if tag == "activeByDefault":
                activation["active_by_default"] = text.lower() == "true"
            elif tag == "jdk":
                activation["jdk"] = text
            elif tag == "property":
                prop_name = ""
                prop_value = ""
                for prop_child in child:
                    prop_tag = self._get_local_tag(prop_child.tag)
                    if prop_tag == "name":
                        prop_name = (prop_child.text or "").strip()
                    elif prop_tag == "value":
                        prop_value = (prop_child.text or "").strip()
                if prop_name:
                    activation["property"] = {"name": prop_name, "value": prop_value}
            elif tag == "file":
                file_info = {}
                for file_child in child:
                    file_tag = self._get_local_tag(file_child.tag)
                    file_text = (file_child.text or "").strip()
                    if file_text:
                        file_info[file_tag] = file_text
                if file_info:
                    activation["file"] = file_info

        return activation

    def _parse_dependency(self, dep_elem: ET.Element) -> dict[str, str] | None:
        """Parse a dependency element.

        Args:
            dep_elem: Dependency XML element.

        Returns:
            Dependency dictionary or None.
        """
        dep: dict[str, str] = {}

        for child in dep_elem:
            tag = self._get_local_tag(child.tag)
            text = (child.text or "").strip()
            if text:
                dep[tag] = text

        if not dep.get("groupId") or not dep.get("artifactId"):
            return None

        return dep

    def _analyze_modules(
        self, root: ET.Element, source_file: str, report: BuildConfigReport
    ) -> list[SecurityFinding]:
        """Analyze multi-module Maven project structure.

        Args:
            root: POM root element.
            source_file: Source file path.
            report: Report to add module info to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        modules_elem = self._get_element(root, "modules")
        if modules_elem is None:
            return findings

        parent_pom = Path(source_file)
        modules: list[MavenModuleInfo] = []

        for child in modules_elem:
            tag = self._get_local_tag(child.tag)
            if tag == "module":
                module_name = (child.text or "").strip()
                if module_name:
                    module_path = str(parent_pom.parent / module_name)
                    modules.append(
                        MavenModuleInfo(
                            name=module_name,
                            path=module_path,
                            source_file=source_file,
                        )
                    )

        report.maven_modules.extend(modules)

        # Check for modules with potential security implications
        sensitive_modules = []
        for module in modules:
            module_lower = module.name.lower()
            if any(
                kw in module_lower
                for kw in ["auth", "security", "admin", "api", "gateway", "login"]
            ):
                sensitive_modules.append(module.name)

        if sensitive_modules:
            findings.append(
                SecurityFinding(
                    category=FindingCategory.MAVEN_CONFIG,
                    risk_level=SecurityRisk.INFO,
                    title="Security-sensitive modules detected",
                    description=f"Found modules that may contain security-sensitive code: {', '.join(sensitive_modules)}",
                    file_path=source_file,
                    evidence=f"Modules: {sensitive_modules}",
                    recommendation="Ensure these modules receive extra security review",
                    references=[],
                )
            )

        return findings

    def _get_local_tag(self, tag: str) -> str:
        """Get local tag name without namespace.

        Args:
            tag: Full tag name.

        Returns:
            Local tag name.
        """
        if "}" in tag:
            return tag.split("}")[1]
        return tag

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a Maven placeholder.

        Args:
            value: Value to check.

        Returns:
            True if value is a placeholder.
        """
        return value.startswith("${") or value.startswith("@")
