"""
Version Detector for runtime version detection.

Detects required runtime versions (Java, Go, Node) from project
configuration files to inform CodeQL build environment setup.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class RuntimeType(str, Enum):
    """Supported runtime types."""

    JAVA = "java"
    GO = "go"
    NODE = "node"
    PYTHON = "python"


@dataclass
class VersionInfo:
    """Detected version information for a runtime."""

    runtime: RuntimeType
    version: str | None = None
    source: str = ""  # Config file where version was found
    confidence: float = 1.0  # How confident the detection is
    raw_value: str = ""  # Raw value from config

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime": self.runtime.value,
            "version": self.version,
            "source": self.source,
            "confidence": self.confidence,
            "raw_value": self.raw_value,
        }


@dataclass
class VersionRequirement:
    """Version requirements for a module."""

    module_path: Path
    versions: dict[RuntimeType, VersionInfo] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_path": str(self.module_path),
            "versions": {k.value: v.to_dict() for k, v in self.versions.items()},
        }

    @property
    def java_version(self) -> str | None:
        """Get detected Java version."""
        info = self.versions.get(RuntimeType.JAVA)
        return info.version if info else None

    @property
    def go_version(self) -> str | None:
        """Get detected Go version."""
        info = self.versions.get(RuntimeType.GO)
        return info.version if info else None

    @property
    def node_version(self) -> str | None:
        """Get detected Node version."""
        info = self.versions.get(RuntimeType.NODE)
        return info.version if info else None


class VersionDetector:
    """
    Detects runtime version requirements from project configuration.

    Supports detection from:
    - Java: pom.xml (maven.compiler.source/release), build.gradle (sourceCompatibility/toolchain)
    - Go: go.mod (go directive)
    - Node: .nvmrc, package.json (engines)
    """

    # Default versions when not specified
    DEFAULT_VERSIONS = {
        RuntimeType.JAVA: "11",
        RuntimeType.GO: "1.21",
        RuntimeType.NODE: "18",
    }

    def __init__(self, repo_path: Path):
        """
        Initialize the version detector.

        Args:
            repo_path: Root path of the repository.
        """
        self.repo_path = Path(repo_path)

    def detect(self, module_path: Path | None = None) -> VersionRequirement:
        """
        Detect version requirements for a module.

        Args:
            module_path: Path to the module (defaults to repo root).

        Returns:
            VersionRequirement with detected versions.
        """
        target_path = module_path or self.repo_path
        versions: dict[RuntimeType, VersionInfo] = {}

        # Detect Java version
        java_info = self._detect_java_version(target_path)
        if java_info:
            versions[RuntimeType.JAVA] = java_info

        # Detect Go version
        go_info = self._detect_go_version(target_path)
        if go_info:
            versions[RuntimeType.GO] = go_info

        # Detect Node version
        node_info = self._detect_node_version(target_path)
        if node_info:
            versions[RuntimeType.NODE] = node_info

        return VersionRequirement(module_path=target_path, versions=versions)

    # =========================================================================
    # Java Version Detection
    # =========================================================================

    def _detect_java_version(self, module_path: Path) -> VersionInfo | None:
        """Detect Java version from Maven or Gradle config."""
        # Try Maven first
        pom_info = self._detect_java_from_pom(module_path)
        if pom_info:
            return pom_info

        # Try Gradle
        gradle_info = self._detect_java_from_gradle(module_path)
        if gradle_info:
            return gradle_info

        return None

    def _detect_java_from_pom(self, module_path: Path) -> VersionInfo | None:
        """Detect Java version from pom.xml."""
        pom_file = module_path / "pom.xml"
        if not pom_file.exists():
            return None

        try:
            content = pom_file.read_text()

            # Priority 1: maven.compiler.release (Java 9+)
            release_match = re.search(
                r"<maven\.compiler\.release>([^<]+)</maven\.compiler\.release>",
                content,
            )
            if release_match:
                version = self._normalize_java_version(release_match.group(1).strip())
                return VersionInfo(
                    runtime=RuntimeType.JAVA,
                    version=version,
                    source="pom.xml:maven.compiler.release",
                    confidence=1.0,
                    raw_value=release_match.group(1).strip(),
                )

            # Priority 2: release in properties
            props_release = re.search(
                r"<release>([^<]+)</release>",
                content,
            )
            if props_release:
                version = self._normalize_java_version(props_release.group(1).strip())
                return VersionInfo(
                    runtime=RuntimeType.JAVA,
                    version=version,
                    source="pom.xml:release",
                    confidence=1.0,
                    raw_value=props_release.group(1).strip(),
                )

            # Priority 3: maven.compiler.source
            source_match = re.search(
                r"<maven\.compiler\.source>([^<]+)</maven\.compiler\.source>",
                content,
            )
            if source_match:
                version = self._normalize_java_version(source_match.group(1).strip())
                return VersionInfo(
                    runtime=RuntimeType.JAVA,
                    version=version,
                    source="pom.xml:maven.compiler.source",
                    confidence=0.9,
                    raw_value=source_match.group(1).strip(),
                )

            # Priority 4: java.version property
            java_version_match = re.search(
                r"<java\.version>([^<]+)</java\.version>",
                content,
            )
            if java_version_match:
                version = self._normalize_java_version(java_version_match.group(1).strip())
                return VersionInfo(
                    runtime=RuntimeType.JAVA,
                    version=version,
                    source="pom.xml:java.version",
                    confidence=0.8,
                    raw_value=java_version_match.group(1).strip(),
                )

        except Exception as e:
            logger.warning(f"Failed to parse pom.xml: {e}")

        return None

    def _detect_java_from_gradle(self, module_path: Path) -> VersionInfo | None:
        """Detect Java version from build.gradle."""
        gradle_file = module_path / "build.gradle"
        gradle_kts = module_path / "build.gradle.kts"

        # Try .gradle first, then .kts
        for gradle_path in [gradle_file, gradle_kts]:
            if gradle_path.exists():
                info = self._parse_gradle_file(gradle_path)
                if info:
                    return info

        return None

    def _parse_gradle_file(self, gradle_path: Path) -> VersionInfo | None:
        """Parse Gradle file for Java version."""
        try:
            content = gradle_path.read_text()

            # Priority 1: Java toolchain (most specific)
            toolchain_match = re.search(
                r"languageVersion\s*=\s*JavaLanguageVersion\.of\((\d+)\)",
                content,
            )
            if toolchain_match:
                version = toolchain_match.group(1)
                return VersionInfo(
                    runtime=RuntimeType.JAVA,
                    version=version,
                    source=f"{gradle_path.name}:toolchain",
                    confidence=1.0,
                    raw_value=f"JavaLanguageVersion.of({version})",
                )

            # Priority 2: sourceCompatibility
            source_match = re.search(
                r"sourceCompatibility\s*=\s*['\"]?(\d+(?:\.\d+)?)['\"]?",
                content,
            )
            if source_match:
                version = self._normalize_java_version(source_match.group(1))
                return VersionInfo(
                    runtime=RuntimeType.JAVA,
                    version=version,
                    source=f"{gradle_path.name}:sourceCompatibility",
                    confidence=0.9,
                    raw_value=source_match.group(0),
                )

            # Priority 3: targetCompatibility
            target_match = re.search(
                r"targetCompatibility\s*=\s*['\"]?(\d+(?:\.\d+)?)['\"]?",
                content,
            )
            if target_match:
                version = self._normalize_java_version(target_match.group(1))
                return VersionInfo(
                    runtime=RuntimeType.JAVA,
                    version=version,
                    source=f"{gradle_path.name}:targetCompatibility",
                    confidence=0.8,
                    raw_value=target_match.group(0),
                )

            # Priority 4: Java version in toolchain block
            toolchain_version = re.search(
                r"java\s*\{[^}]*version\s*=\s*['\"]?(\d+(?:\.\d+)?)['\"]?",
                content,
                re.DOTALL,
            )
            if toolchain_version:
                version = self._normalize_java_version(toolchain_version.group(1))
                return VersionInfo(
                    runtime=RuntimeType.JAVA,
                    version=version,
                    source=f"{gradle_path.name}:java.version",
                    confidence=0.9,
                    raw_value=toolchain_version.group(0),
                )

        except Exception as e:
            logger.warning(f"Failed to parse {gradle_path}: {e}")

        return None

    def _normalize_java_version(self, version: str) -> str:
        """Normalize Java version string."""
        # Handle "1.8" -> "8"
        if version.startswith("1."):
            return version[2:]

        # Handle "11.0" -> "11"
        if "." in version:
            major = version.split(".")[0]
            return major

        return version

    # =========================================================================
    # Go Version Detection
    # =========================================================================

    def _detect_go_version(self, module_path: Path) -> VersionInfo | None:
        """Detect Go version from go.mod."""
        go_mod = module_path / "go.mod"
        if not go_mod.exists():
            return None

        try:
            content = go_mod.read_text()

            # Find go directive: "go 1.21" or "go 1.21.0"
            go_match = re.search(r"^go\s+(\d+(?:\.\d+)*)", content, re.MULTILINE)
            if go_match:
                version = go_match.group(1)
                return VersionInfo(
                    runtime=RuntimeType.GO,
                    version=version,
                    source="go.mod",
                    confidence=1.0,
                    raw_value=f"go {version}",
                )

        except Exception as e:
            logger.warning(f"Failed to parse go.mod: {e}")

        return None

    # =========================================================================
    # Node Version Detection
    # =========================================================================

    def _detect_node_version(self, module_path: Path) -> VersionInfo | None:
        """Detect Node version from .nvmrc or package.json."""
        # Priority 1: .nvmrc (most specific)
        nvmrc_info = self._detect_node_from_nvmrc(module_path)
        if nvmrc_info:
            return nvmrc_info

        # Priority 2: package.json engines
        engines_info = self._detect_node_from_package_json(module_path)
        if engines_info:
            return engines_info

        return None

    def _detect_node_from_nvmrc(self, module_path: Path) -> VersionInfo | None:
        """Detect Node version from .nvmrc."""
        nvmrc = module_path / ".nvmrc"
        if not nvmrc.exists():
            # Check repo root as fallback
            nvmrc = self.repo_path / ".nvmrc"
            if not nvmrc.exists():
                return None

        try:
            content = nvmrc.read_text().strip()

            # Handle various formats: "18", "18.17.0", "v18.17.0", "lts/*"
            if content.startswith("v"):
                content = content[1:]

            # Skip lts/* or other non-version formats
            if not content[0].isdigit():
                return None

            # Extract version number
            version_match = re.match(r"(\d+(?:\.\d+)*)", content)
            if version_match:
                version = version_match.group(1)
                return VersionInfo(
                    runtime=RuntimeType.NODE,
                    version=version,
                    source=".nvmrc",
                    confidence=1.0,
                    raw_value=content,
                )

        except Exception as e:
            logger.warning(f"Failed to parse .nvmrc: {e}")

        return None

    def _detect_node_from_package_json(self, module_path: Path) -> VersionInfo | None:
        """Detect Node version from package.json engines."""
        package_json = module_path / "package.json"
        if not package_json.exists():
            return None

        try:
            content = json.loads(package_json.read_text())

            engines = content.get("engines", {})
            node_engine = engines.get("node", "")

            if not node_engine:
                return None

            # Parse version range: ">=18.0.0", "^18.0.0", "18.x", etc.
            version = self._parse_node_engine_version(node_engine)
            if version:
                return VersionInfo(
                    runtime=RuntimeType.NODE,
                    version=version,
                    source="package.json:engines.node",
                    confidence=0.9,
                    raw_value=node_engine,
                )

        except Exception as e:
            logger.warning(f"Failed to parse package.json: {e}")

        return None

    def _parse_node_engine_version(self, engine: str) -> str | None:
        """Parse Node version from engines field."""
        # Handle: ">=18.0.0", "^18.0.0", "~18.0.0", "18.x", "18", "18.0.0"
        # First strip all whitespace
        engine = engine.strip()

        # Remove operators (allow whitespace after operators)
        cleaned = re.sub(r"^[>=<~^]+\s*", "", engine)

        # Handle "18.x" -> "18"
        cleaned = cleaned.replace(".x", "")

        # Handle "18 || 20" -> take first
        if "||" in cleaned:
            cleaned = cleaned.split("||")[0].strip()

        # Extract version number
        version_match = re.match(r"(\d+(?:\.\d+)*)", cleaned)
        if version_match:
            return version_match.group(1)

        return None


def detect_versions(repo_path: Path, module_path: Path | None = None) -> VersionRequirement:
    """
    Convenience function to detect versions.

    Args:
        repo_path: Root path of the repository.
        module_path: Path to the module (defaults to repo root).

    Returns:
        VersionRequirement with detected versions.
    """
    detector = VersionDetector(repo_path)
    return detector.detect(module_path)
