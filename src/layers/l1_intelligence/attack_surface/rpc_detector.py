"""RPC entry point detection for various frameworks."""

import re
from abc import ABC, abstractmethod
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.models import (
    EntryPoint,
    EntryPointType,
)

logger = get_logger(__name__)


class RPCDetector(ABC):
    """Base class for RPC entry point detectors."""

    framework_name: str = "unknown"
    file_patterns: list[str] = []

    @abstractmethod
    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect RPC entry points in source code."""
        pass


class DubboDetector(RPCDetector):
    """Detector for Apache Dubbo RPC services."""

    framework_name = "dubbo"
    file_patterns = ["*.java"]

    # Pattern for @DubboService or @Service (Alibaba Dubbo)
    DUBBO_SERVICE_PATTERN = re.compile(
        r"""@
        (?:DubboService|Service|org\.apache\.dubbo\.config\.annotation\.Service)
        \s*\(
        ([^)]*)
        \)
        [^{]*
        (?:public|private)?\s*
        (?:class|interface)\s+
        (\w+)
        """,
        re.VERBOSE | re.MULTILINE | re.DOTALL,
    )

    # Pattern for @DubboReference or @Reference
    DUBBO_REFERENCE_PATTERN = re.compile(
        r"""@
        (?:DubboReference|Reference|org\.apache\.dubbo\.config\.annotation\.Reference)
        \s*\(
        ([^)]*)
        \)
        [^;]*
        (?:private|protected|public)?\s*
        \w+(?:<[^>]+>)?\s+
        (\w+)\s*[;=]
        """,
        re.VERBOSE | re.MULTILINE | re.DOTALL,
    )

    # Pattern for interface class declaration
    INTERFACE_PATTERN = re.compile(
        r"""public\s+interface\s+(\w+)\s*\{""",
        re.VERBOSE,
    )

    # Extract service interface from annotation
    INTERFACE_ATTR_PATTERN = re.compile(
        r"""interfaceClass\s*=\s*(\w+)\.class""",
        re.VERBOSE,
    )

    # Extract version from annotation
    VERSION_ATTR_PATTERN = re.compile(
        r"""version\s*=\s*["']([^"']+)["']""",
        re.VERBOSE,
    )

    # Extract group from annotation
    GROUP_ATTR_PATTERN = re.compile(
        r"""group\s*=\s*["']([^"']+)["']""",
        re.VERBOSE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect Dubbo RPC services."""
        entry_points = []

        # Find @DubboService / @Service annotations
        for match in self.DUBBO_SERVICE_PATTERN.finditer(content):
            annotation_attrs = match.group(1)
            class_name = match.group(2)

            # Extract attributes
            interface_name = self._extract_interface(annotation_attrs, class_name)
            version = self._extract_version(annotation_attrs)
            group = self._extract_group(annotation_attrs)

            # Build service path
            service_path = interface_name
            if group:
                service_path = f"{group}/{service_path}"
            if version:
                service_path = f"{service_path}:{version}"

            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.RPC,
                path=service_path,
                handler=class_name,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
                metadata={
                    "interface": interface_name,
                    "version": version,
                    "group": group,
                    "protocol": "dubbo",
                },
            )
            entry_points.append(entry)

        return entry_points

    def _extract_interface(self, attrs: str, default: str) -> str:
        """Extract interface name from annotation attributes."""
        match = self.INTERFACE_ATTR_PATTERN.search(attrs)
        if match:
            return match.group(1)
        return default

    def _extract_version(self, attrs: str) -> str | None:
        """Extract version from annotation attributes."""
        match = self.VERSION_ATTR_PATTERN.search(attrs)
        if match:
            return match.group(1)
        return None

    def _extract_group(self, attrs: str) -> str | None:
        """Extract group from annotation attributes."""
        match = self.GROUP_ATTR_PATTERN.search(attrs)
        if match:
            return match.group(1)
        return None


class GrpcDetector(RPCDetector):
    """Detector for gRPC services."""

    framework_name = "grpc"
    file_patterns = ["*.proto"]

    # Pattern for service definition
    SERVICE_PATTERN = re.compile(
        r"""service\s+(\w+)\s*\{""",
        re.VERBOSE,
    )

    # Pattern for rpc method
    RPC_PATTERN = re.compile(
        r"""rpc\s+(\w+)\s*\(\s*(?:stream\s+)?(\w+)\s*\)\s*
        returns\s*\(\s*(?:stream\s+)?(\w+)\s*\)""",
        re.VERBOSE | re.MULTILINE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect gRPC services from .proto files."""
        entry_points = []

        # Find service definitions
        for service_match in self.SERVICE_PATTERN.finditer(content):
            service_name = service_match.group(1)

            # Find methods within this service
            service_block_start = service_match.end()
            # Find the closing brace
            brace_count = 1
            pos = service_block_start
            while pos < len(content) and brace_count > 0:
                if content[pos] == "{":
                    brace_count += 1
                elif content[pos] == "}":
                    brace_count -= 1
                pos += 1

            service_block = content[service_block_start:pos]

            for rpc_match in self.RPC_PATTERN.finditer(service_block):
                method_name = rpc_match.group(1)
                request_type = rpc_match.group(2)
                # response_type = rpc_match.group(3)  # Not used currently

                line_num = content[: service_match.start()].count("\n") + 1

                entry = EntryPoint(
                    type=EntryPointType.GRPC,
                    path=f"/{service_name}/{method_name}",
                    handler=f"{service_name}Impl.{method_name}",
                    file=str(file_path),
                    line=line_num,
                    framework=self.framework_name,
                    metadata={
                        "service": service_name,
                        "method": method_name,
                        "request_type": request_type,
                        "protocol": "grpc",
                    },
                )
                entry_points.append(entry)

        return entry_points


class ThriftDetector(RPCDetector):
    """Detector for Apache Thrift services."""

    framework_name = "thrift"
    file_patterns = ["*.thrift"]

    # Pattern for service definition
    SERVICE_PATTERN = re.compile(
        r"""service\s+(\w+)\s*\{""",
        re.VERBOSE,
    )

    # Pattern for method definition
    METHOD_PATTERN = re.compile(
        r"""(\w+(?:<[^>]+>)?)\s+(\w+)\s*\(([^)]*)\)""",
        re.VERBOSE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect Thrift services from .thrift files."""
        entry_points = []

        for service_match in self.SERVICE_PATTERN.finditer(content):
            service_name = service_match.group(1)

            # Find methods within this service
            service_block_start = service_match.end()
            brace_count = 1
            pos = service_block_start
            while pos < len(content) and brace_count > 0:
                if content[pos] == "{":
                    brace_count += 1
                elif content[pos] == "}":
                    brace_count -= 1
                pos += 1

            service_block = content[service_block_start:pos]

            for method_match in self.METHOD_PATTERN.finditer(service_block):
                return_type = method_match.group(1)
                method_name = method_match.group(2)
                params = method_match.group(3)

                line_num = content[: service_match.start()].count("\n") + 1

                # Parse parameter names
                param_names = []
                for param in params.split(","):
                    param = param.strip()
                    if param:
                        parts = param.split()
                        if len(parts) >= 2:
                            param_names.append(parts[-1])

                entry = EntryPoint(
                    type=EntryPointType.RPC,
                    path=f"{service_name}.{method_name}",
                    handler=f"{service_name}Handler.{method_name}",
                    file=str(file_path),
                    line=line_num,
                    framework=self.framework_name,
                    params=param_names,
                    metadata={
                        "service": service_name,
                        "method": method_name,
                        "return_type": return_type,
                        "protocol": "thrift",
                    },
                )
                entry_points.append(entry)

        return entry_points


# Registry of all RPC detectors
RPC_DETECTORS: list[type[RPCDetector]] = [
    DubboDetector,
    GrpcDetector,
    ThriftDetector,
]


def get_rpc_detector_for_framework(framework: str) -> RPCDetector | None:
    """Get RPC detector for a specific framework."""
    framework_lower = framework.lower()
    for detector_cls in RPC_DETECTORS:
        if detector_cls.framework_name == framework_lower:
            return detector_cls()
    return None


def get_rpc_detector_for_file(file_path: Path) -> list[RPCDetector]:
    """Get applicable RPC detectors for a file."""
    detectors = []
    suffix = file_path.suffix

    for detector_cls in RPC_DETECTORS:
        for pattern in detector_cls.file_patterns:
            if pattern.startswith("*."):
                if suffix == pattern[1:]:
                    detectors.append(detector_cls())
                    break
            elif file_path.match(pattern):
                detectors.append(detector_cls())
                break

    return detectors
