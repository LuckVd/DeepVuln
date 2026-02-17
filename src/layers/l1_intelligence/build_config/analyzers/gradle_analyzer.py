"""Gradle build.gradle security configuration analyzer."""

import re
from pathlib import Path

from src.layers.l1_intelligence.build_config.base import BaseConfigAnalyzer
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    FindingCategory,
    GradleBuildType,
    GradleSigningConfig,
    SecurityFinding,
    SecurityRisk,
)


class GradleAnalyzer(BaseConfigAnalyzer):
    """Analyzer for Gradle build.gradle security configurations."""

    supported_files = ["build.gradle", "build.gradle.kts"]
    category_name = "gradle_config"

    # Sensitive configuration keys
    SENSITIVE_KEYS = {
        "password", "secret", "token", "apikey", "api_key",
        "credential", "private_key", "access_key", "auth"
    }

    def __init__(self) -> None:
        """Initialize Gradle analyzer."""
        super().__init__()

    def analyze(self, source_path: Path, report: BuildConfigReport) -> list[SecurityFinding]:
        """Analyze Gradle build files for security issues.

        Args:
            source_path: Path to the source code.
            report: Report to add findings to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        gradle_files = self.find_files(source_path)
        if not gradle_files:
            return findings

        for gradle_file in gradle_files:
            report.scanned_files.append(str(gradle_file))
            file_findings = self._analyze_gradle_file(gradle_file, report)
            findings.extend(file_findings)

        return findings

    def _analyze_gradle_file(
        self, gradle_file: Path, report: BuildConfigReport
    ) -> list[SecurityFinding]:
        """Analyze a single Gradle file.

        Args:
            gradle_file: Path to build.gradle or build.gradle.kts.
            report: Report to add findings to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        content = self._safe_read_file(gradle_file)
        if not content:
            return findings

        source_file = str(gradle_file)
        is_kotlin = gradle_file.suffix == ".kts"

        # Remove comments
        content = self._remove_comments(content)

        # Analyze different aspects
        findings.extend(self._analyze_signing_configs(content, source_file, report))
        findings.extend(self._analyze_build_types(content, source_file, report, is_kotlin))
        findings.extend(self._analyze_custom_tasks(content, source_file))
        findings.extend(self._analyze_hardcoded_secrets(content, source_file))

        return findings

    def _remove_comments(self, content: str) -> str:
        """Remove comments from Gradle file.

        Args:
            content: File content.

        Returns:
            Content with comments removed.
        """
        # Remove single-line comments
        content = re.sub(r"//.*$", "", content, flags=re.MULTILINE)

        # Remove multi-line comments
        content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)

        return content

    def _extract_block(self, content: str, block_name: str) -> str | None:
        """Extract a named block from Gradle content.

        Args:
            content: File content.
            block_name: Name of the block (e.g., "signingConfigs").

        Returns:
            Block content or None.
        """
        # Find the block start
        pattern = rf"\b{block_name}\s*\{{"
        match = re.search(pattern, content)
        if not match:
            return None

        start = match.end()

        # Find matching closing brace
        brace_count = 1
        pos = start
        while pos < len(content) and brace_count > 0:
            if content[pos] == "{":
                brace_count += 1
            elif content[pos] == "}":
                brace_count -= 1
            pos += 1

        return content[start:pos - 1]

    def _extract_sub_blocks(self, block_content: str) -> list[tuple[str, str]]:
        """Extract named sub-blocks from a block.

        Args:
            block_content: Content of the parent block.

        Returns:
            List of (name, content) tuples.
        """
        sub_blocks = []

        # Pattern to find named blocks like "release { ... }"
        pattern = r"(\w+)\s*\{"

        for match in re.finditer(pattern, block_content):
            name = match.group(1)
            start = match.end()

            # Find matching closing brace
            brace_count = 1
            pos = start
            while pos < len(block_content) and brace_count > 0:
                if block_content[pos] == "{":
                    brace_count += 1
                elif block_content[pos] == "}":
                    brace_count -= 1
                pos += 1

            content = block_content[start:pos - 1]
            sub_blocks.append((name, content))

        return sub_blocks

    def _analyze_signing_configs(
        self, content: str, source_file: str, report: BuildConfigReport
    ) -> list[SecurityFinding]:
        """Analyze signing configurations for hardcoded secrets.

        Args:
            content: File content.
            source_file: Source file path.
            report: Report to add configs to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Find signingConfigs block
        signing_block = self._extract_block(content, "signingConfigs")
        if not signing_block:
            return findings

        # Parse individual signing configs
        for config_name, config_body in self._extract_sub_blocks(signing_block):
            signing_config = self._parse_signing_config(config_name, config_body, source_file)
            report.gradle_signing_configs.append(signing_config)

            # Check for hardcoded passwords
            if signing_config.has_hardcoded_passwords:
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.GRADLE_CONFIG,
                        risk_level=SecurityRisk.HIGH,
                        title=f"Hardcoded signing credentials in '{config_name}'",
                        description=f"Signing config '{config_name}' contains hardcoded password(s). "
                        "This can lead to credential exposure in version control.",
                        file_path=source_file,
                        evidence=self._get_evidence(config_body, ["storePassword", "keyPassword"]),
                        recommendation="Use environment variables or a dedicated secrets manager "
                        "for signing credentials. Consider using gradle.properties with local.properties "
                        "excluded from version control.",
                        references=[
                            "https://developer.android.com/studio/publish/app-signing#secure-shared-keystore"
                        ],
                        cwe="CWE-798",
                    )
                )

        return findings

    def _parse_signing_config(
        self, name: str, body: str, source_file: str
    ) -> GradleSigningConfig:
        """Parse a signing configuration.

        Args:
            name: Config name.
            body: Config body content.
            source_file: Source file path.

        Returns:
            GradleSigningConfig.
        """
        store_file = None
        store_password = None
        key_alias = None
        key_password = None
        has_hardcoded = False

        # Extract store file
        store_match = re.search(r"storeFile\s*(?:=|\s)?\s*(?:file\s*\()?[\"']([^\"']+)[\"']", body)
        if store_match:
            store_file = store_match.group(1)

        # Extract passwords - check for hardcoded values
        store_pw_match = re.search(r"storePassword\s*(?:=|\s)?\s*[\"']([^\"']+)[\"']", body)
        if store_pw_match:
            store_password = store_pw_match.group(1)
            if not self._is_placeholder(store_password):
                has_hardcoded = True

        key_pw_match = re.search(r"keyPassword\s*(?:=|\s)?\s*[\"']([^\"']+)[\"']", body)
        if key_pw_match:
            key_password = key_pw_match.group(1)
            if not self._is_placeholder(key_password):
                has_hardcoded = True

        # Extract key alias
        alias_match = re.search(r"keyAlias\s*(?:=|\s)?\s*[\"']([^\"']+)[\"']", body)
        if alias_match:
            key_alias = alias_match.group(1)

        return GradleSigningConfig(
            name=name,
            store_file=store_file,
            store_password=store_password if not has_hardcoded else "***",
            key_alias=key_alias,
            key_password=key_password if not has_hardcoded else "***",
            has_hardcoded_passwords=has_hardcoded,
            source_file=source_file,
        )

    def _analyze_build_types(
        self, content: str, source_file: str, report: BuildConfigReport, is_kotlin: bool = False
    ) -> list[SecurityFinding]:
        """Analyze build types for security configurations.

        Args:
            content: File content.
            source_file: Source file path.
            report: Report to add build types to.
            is_kotlin: Whether this is Kotlin DSL.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Find buildTypes block
        build_types_block = self._extract_block(content, "buildTypes")
        if not build_types_block:
            return findings

        # Parse individual build types
        for type_name, type_body in self._extract_sub_blocks(build_types_block):
            build_type = self._parse_build_type(type_name, type_body, source_file, is_kotlin)
            report.gradle_build_types.append(build_type)

            # Check for debuggable release builds
            if type_name.lower() == "release" and build_type.is_debuggable:
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.GRADLE_CONFIG,
                        risk_level=SecurityRisk.HIGH,
                        title="Debuggable release build",
                        description="Release build type has debuggable=true. "
                        "This allows debugging of the production app.",
                        file_path=source_file,
                        evidence=f"buildTypes -> {type_name} {{ debuggable true }}",
                        recommendation="Set debuggable=false for release builds, or remove the explicit "
                        "setting (defaults to false).",
                        references=[
                            "https://developer.android.com/topic/security/risks/debuggable-app"
                        ],
                        cwe="CWE-489",
                    )
                )

            # Check for missing minification in release
            if type_name.lower() == "release" and not build_type.minify_enabled:
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.GRADLE_CONFIG,
                        risk_level=SecurityRisk.LOW,
                        title="Release build without code minification",
                        description="Release build type has minifyEnabled=false. "
                        "This makes reverse engineering easier.",
                        file_path=source_file,
                        evidence=f"buildTypes -> {type_name} {{ minifyEnabled false }}",
                        recommendation="Enable minification with minifyEnabled=true for release builds.",
                        references=[
                            "https://developer.android.com/build/shrink-code"
                        ],
                    )
                )

        return findings

    def _parse_build_type(
        self, name: str, body: str, source_file: str, is_kotlin: bool = False
    ) -> GradleBuildType:
        """Parse a build type configuration.

        Args:
            name: Build type name.
            body: Build type body content.
            source_file: Source file path.
            is_kotlin: Whether this is Kotlin DSL.

        Returns:
            GradleBuildType.
        """
        is_debuggable = False
        minify_enabled = False
        shrink_resources = False
        proguard_files: list[str] = []

        # Extract debuggable (both Groovy and Kotlin DSL)
        debug_match = re.search(r"(?:is)?Debuggable\s*(?:=|\s)?\s*(true|false)", body, re.IGNORECASE)
        if debug_match:
            is_debuggable = debug_match.group(1).lower() == "true"

        # Extract minify
        minify_match = re.search(r"(?:is)?MinifyEnabled\s*(?:=|\s)?\s*(true|false)", body, re.IGNORECASE)
        if minify_match:
            minify_enabled = minify_match.group(1).lower() == "true"

        # Extract shrink resources
        shrink_match = re.search(r"(?:is)?ShrinkResources\s*(?:=|\s)?\s*(true|false)", body, re.IGNORECASE)
        if shrink_match:
            shrink_resources = shrink_match.group(1).lower() == "true"

        # Extract proguard files
        for proguard_match in re.finditer(r"proguardFiles?\s*[=+]?\s*[\"']([^\"']+)[\"']", body):
            proguard_files.append(proguard_match.group(1))

        return GradleBuildType(
            name=name,
            is_debuggable=is_debuggable,
            minify_enabled=minify_enabled,
            shrink_resources=shrink_resources,
            proguard_files=proguard_files,
            source_file=source_file,
        )

    def _analyze_custom_tasks(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Analyze custom tasks for potential security issues.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Find task definitions
        task_pattern = re.compile(r"task\s+(\w+)\s*(?:\([^)]*\))?\s*\{", re.DOTALL)
        for match in task_pattern.finditer(content):
            task_name = match.group(1)
            start = match.end()

            # Extract task body
            brace_count = 1
            pos = start
            while pos < len(content) and brace_count > 0:
                if content[pos] == "{":
                    brace_count += 1
                elif content[pos] == "}":
                    brace_count -= 1
                pos += 1
            task_body = content[start:pos - 1]

            # Check for hardcoded secrets in task
            secret_pattern = re.compile(
                r"(?:password|secret|token|key|credential)\s*[=:]\s*[\"']([^\"']{8,})[\"']",
                re.IGNORECASE
            )
            for secret_match in secret_pattern.finditer(task_body):
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.GRADLE_CONFIG,
                        risk_level=SecurityRisk.HIGH,
                        title=f"Hardcoded secret in task '{task_name}'",
                        description=f"Custom task '{task_name}' contains hardcoded sensitive value.",
                        file_path=source_file,
                        evidence=f"task {task_name} {{ ... {secret_match.group(0)[:50]} ... }}",
                        recommendation="Move sensitive values to gradle.properties or environment variables.",
                        references=[],
                        cwe="CWE-798",
                    )
                )

            # Check for environment variable access that might be logged
            env_pattern = re.compile(r"(?:System\.getenv|environment)\s*[\[(]?['\"](\w+)['\"]", re.IGNORECASE)
            for env_match in env_pattern.finditer(task_body):
                env_name = env_match.group(1)
                if any(sk in env_name.lower() for sk in self.SENSITIVE_KEYS):
                    findings.append(
                        SecurityFinding(
                            category=FindingCategory.GRADLE_CONFIG,
                            risk_level=SecurityRisk.MEDIUM,
                            title=f"Sensitive environment variable in task '{task_name}'",
                            description=f"Task '{task_name}' accesses sensitive environment variable '{env_name}'. "
                            "Ensure this is not logged or exposed.",
                            file_path=source_file,
                            evidence=f"System.getenv('{env_name}')",
                            recommendation="Ensure sensitive environment variables are not logged or exposed "
                            "in build output.",
                            references=[],
                        )
                    )

        return findings

    def _analyze_hardcoded_secrets(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Analyze for hardcoded secrets outside of known blocks.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Look for ext properties with secrets
        ext_block = self._extract_block(content, "ext")
        if ext_block:
            secret_pattern = re.compile(
                r"(?:password|secret|token|key|credential)\s*[=:]\s*[\"']([^\"']{8,})[\"']",
                re.IGNORECASE
            )
            for match in secret_pattern.finditer(ext_block):
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.SECRETS,
                        risk_level=SecurityRisk.HIGH,
                        title="Hardcoded secret in ext properties",
                        description="Extra extension properties contain hardcoded sensitive value.",
                        file_path=source_file,
                        evidence=match.group(0)[:80],
                        recommendation="Move sensitive values to local.properties (excluded from VCS) "
                        "or environment variables.",
                        references=[],
                        cwe="CWE-798",
                    )
                )

        return findings

    def _get_evidence(self, body: str, keywords: list[str]) -> str:
        """Extract evidence lines containing keywords.

        Args:
            body: Content to search.
            keywords: Keywords to look for.

        Returns:
            Evidence string.
        """
        evidence_lines = []
        for line in body.splitlines():
            line = line.strip()
            if any(kw.lower() in line.lower() for kw in keywords):
                # Mask the actual password
                masked = re.sub(
                    r"['\"][^'\"]{8,}['\"]",
                    "'***'",
                    line
                )
                evidence_lines.append(masked)
        return "\n".join(evidence_lines[:3])  # Max 3 lines

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder or variable reference.

        Args:
            value: Value to check.

        Returns:
            True if value is a placeholder.
        """
        if not value:
            return True
        placeholders = ["${", "project.", "rootProject.", "properties[", "findProperty", "System.getenv"]
        return any(ph in value for ph in placeholders)
