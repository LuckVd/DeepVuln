"""HTTP entry point detection for various frameworks."""

import re
from abc import ABC, abstractmethod
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.models import (
    EntryPoint,
    EntryPointType,
    HTTPMethod,
)

logger = get_logger(__name__)


class HTTPDetector(ABC):
    """Base class for HTTP entry point detectors."""

    # Override in subclasses
    framework_name: str = "unknown"
    file_patterns: list[str] = []

    @abstractmethod
    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect HTTP entry points in source code.

        Args:
            content: Source code content.
            file_path: Path to the source file.

        Returns:
            List of detected entry points.
        """
        pass

    def _should_skip_path(self, path: Path) -> bool:
        """Check if path should be skipped.

        Args:
            path: Path to check.

        Returns:
            True if path should be skipped.
        """
        skip_dirs = {
            "node_modules",
            "venv",
            ".venv",
            "env",
            ".env",
            "__pycache__",
            ".git",
            "dist",
            "build",
            "target",
            "vendor",
            "test",
            "tests",
            "__tests__",
        }
        for part in path.parts:
            if part.lower() in skip_dirs:
                return True
        return False


class GinDetector(HTTPDetector):
    """Detector for Gin framework (Go)."""

    framework_name = "gin"
    file_patterns = ["*.go"]

    # Pattern for gin routes: r.GET("/path", handler) or router.POST("/path", handler)
    ROUTE_PATTERN = re.compile(
        r"""(?:\w+\.)?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*(\w+)""",
        re.VERBOSE,
    )

    # Pattern for group routes: r.Group("/api")
    GROUP_PATTERN = re.compile(r"""(\w+)\s*=\s*\w+\.Group\s*\(\s*['"`]([^'"`]+)['"`]""")

    # Pattern for middleware
    MIDDLEWARE_PATTERN = re.compile(r"""\.Use\s*\(\s*(\w+)""")

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect Gin routes."""
        entry_points = []

        # Track groups for path prefix
        groups: dict[str, str] = {}
        for match in self.GROUP_PATTERN.finditer(content):
            var_name = match.group(1)
            prefix = match.group(2)
            groups[var_name] = prefix

        # Find routes
        for match in self.ROUTE_PATTERN.finditer(content):
            method_str = match.group(1)
            path = match.group(2)
            handler = match.group(3)

            # Convert method
            try:
                method = HTTPMethod[method_str]
            except KeyError:
                method = HTTPMethod.GET

            # Normalize path (convert :param to {param})
            normalized_path = self._normalize_path(path)

            # Find line number
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.HTTP,
                method=method,
                path=normalized_path,
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
            )
            entry_points.append(entry)

        return entry_points

    def _normalize_path(self, path: str) -> str:
        """Normalize Gin path to standard format.

        :param -> {param}
        """
        # Convert :param to {param}
        path = re.sub(r":(\w+)", r"{\1}", path)
        return path


class EchoDetector(HTTPDetector):
    """Detector for Echo framework (Go)."""

    framework_name = "echo"
    file_patterns = ["*.go"]

    # Pattern: e.GET("/path", handler)
    ROUTE_PATTERN = re.compile(
        r"""(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*(\w+)""",
        re.VERBOSE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect Echo routes."""
        entry_points = []

        for match in self.ROUTE_PATTERN.finditer(content):
            _router_var = match.group(1)  # e.g., 'e' or 'echo'
            method_str = match.group(2)
            path = match.group(3)
            handler = match.group(4)

            try:
                method = HTTPMethod[method_str]
            except KeyError:
                method = HTTPMethod.GET

            normalized_path = self._normalize_path(path)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.HTTP,
                method=method,
                path=normalized_path,
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
            )
            entry_points.append(entry)

        return entry_points

    def _normalize_path(self, path: str) -> str:
        """Normalize Echo path to standard format.

        :param -> {param}
        """
        path = re.sub(r":(\w+)", r"{\1}", path)
        return path


class SpringDetector(HTTPDetector):
    """Detector for Spring Boot framework (Java)."""

    framework_name = "spring"
    file_patterns = ["*.java"]

    # Pattern for @GetMapping, @PostMapping, etc. (single line)
    MAPPING_PATTERN = re.compile(
        r"""@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']""",
        re.VERBOSE,
    )

    # Pattern for multi-line @RequestMapping with value and method
    MULTILINE_REQUEST_MAPPING = re.compile(
        r"""@RequestMapping\s*\(
        [^)]*?
        value\s*=\s*["']([^"']+)["']
        [^)]*?
        (?:method\s*=\s*RequestMethod\.(GET|POST|PUT|DELETE|PATCH))?
        [^)]*?
        \)""",
        re.VERBOSE | re.DOTALL,
    )

    # Pattern for @RequestMapping with method first
    MULTILINE_REQUEST_MAPPING_METHOD_FIRST = re.compile(
        r"""@RequestMapping\s*\(
        [^)]*?
        (?:method\s*=\s*RequestMethod\.(GET|POST|PUT|DELETE|PATCH))?
        [^)]*?
        value\s*=\s*["']([^"']+)["']
        [^)]*?
        \)""",
        re.VERBOSE | re.DOTALL,
    )

    # Pattern for @RequestMapping on class (simple format)
    CLASS_MAPPING_PATTERN = re.compile(
        r"""@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']""",
        re.VERBOSE,
    )

    # Pattern for @RestController or @Controller on class
    CONTROLLER_PATTERN = re.compile(
        r"""@(RestController|Controller)"""
    )

    # Pattern for method handler
    HANDLER_PATTERN = re.compile(
        r"""(?:public|private|protected)?\s*\w+(?:<[^>]+>)?\s+(\w+)\s*\([^)]*\)""",
        re.VERBOSE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect Spring routes."""
        entry_points = []

        # Find class-level mapping
        class_prefix = ""
        class_match = self.CLASS_MAPPING_PATTERN.search(content)
        if class_match:
            class_prefix = class_match.group(1)

        # Normalize content for multi-line matching (but keep track of original lines)
        lines = content.split("\n")

        # Find all @XxxMapping annotations (both single and multi-line)
        # Use a combined approach

        # 1. Find single-line @GetMapping, @PostMapping, etc.
        for match in self.MAPPING_PATTERN.finditer(content):
            mapping_type = match.group(1)
            path = match.group(2)

            method = self._get_method_from_mapping_type(mapping_type)
            handler = self._find_handler_name(content, match.end())
            line_num = content[: match.start()].count("\n") + 1

            full_path = class_prefix + path if class_prefix else path

            entry = EntryPoint(
                type=EntryPointType.HTTP,
                method=method,
                path=full_path,
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
            )
            entry_points.append(entry)

        # 2. Find multi-line @RequestMapping with value
        for match in self.MULTILINE_REQUEST_MAPPING.finditer(content):
            path = match.group(1)
            method_str = match.group(2) if match.group(2) else None

            method = self._get_method_from_string(method_str) if method_str else HTTPMethod.ALL
            handler = self._find_handler_name(content, match.end())
            line_num = content[: match.start()].count("\n") + 1

            full_path = class_prefix + path if class_prefix else path

            entry = EntryPoint(
                type=EntryPointType.HTTP,
                method=method,
                path=full_path,
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
            )
            entry_points.append(entry)

        return entry_points

    def _get_method_from_mapping_type(self, mapping_type: str) -> HTTPMethod:
        """Get HTTP method from mapping type."""
        method_map = {
            "Get": HTTPMethod.GET,
            "Post": HTTPMethod.POST,
            "Put": HTTPMethod.PUT,
            "Delete": HTTPMethod.DELETE,
            "Patch": HTTPMethod.PATCH,
            "Request": HTTPMethod.ALL,
        }
        return method_map.get(mapping_type, HTTPMethod.GET)

    def _get_method_from_string(self, method_str: str | None) -> HTTPMethod:
        """Get HTTP method from string."""
        if not method_str:
            return HTTPMethod.ALL
        method_map = {
            "GET": HTTPMethod.GET,
            "POST": HTTPMethod.POST,
            "PUT": HTTPMethod.PUT,
            "DELETE": HTTPMethod.DELETE,
            "PATCH": HTTPMethod.PATCH,
        }
        return method_map.get(method_str.upper(), HTTPMethod.ALL)

    def _find_handler_name(self, content: str, start_pos: int) -> str:
        """Find handler method name from annotation position."""
        # Look for method signature after the annotation
        # Find the next method definition
        search_content = content[start_pos : start_pos + 500]

        # Look for: public ReturnType methodName(
        match = self.HANDLER_PATTERN.search(search_content)
        if match:
            name = match.group(1)
            # Skip common keywords
            if name not in ("public", "private", "protected", "static", "final", "class", "interface", "void"):
                return name

        return "unknown"


class FlaskDetector(HTTPDetector):
    """Detector for Flask framework (Python)."""

    framework_name = "flask"
    file_patterns = ["*.py"]

    # Pattern for @app.route('/path', methods=['GET', 'POST'])
    ROUTE_PATTERN = re.compile(
        r"""@(\w+)\.route\s*\(\s*['"`]([^'"`]+)['"`](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?""",
        re.VERBOSE,
    )

    # Pattern for @app.get('/path'), @app.post('/path')
    METHOD_ROUTE_PATTERN = re.compile(
        r"""@(\w+)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""",
        re.VERBOSE,
    )

    # Pattern for function definition
    FUNC_PATTERN = re.compile(r"def\s+(\w+)\s*\(")

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect Flask routes."""
        entry_points = []

        lines = content.split("\n")

        for i, line in enumerate(lines):
            # Check for @app.route
            match = self.ROUTE_PATTERN.search(line)
            if match:
                _app_var = match.group(1)
                path = match.group(2)
                methods_str = match.group(3) or "'GET'"

                # Parse methods
                methods = self._parse_methods(methods_str)

                # Find handler function name (next def)
                handler = self._find_next_function(lines, i)

                for method in methods:
                    entry = EntryPoint(
                        type=EntryPointType.HTTP,
                        method=method,
                        path=self._normalize_path(path),
                        handler=handler,
                        file=str(file_path),
                        line=i + 1,
                        framework=self.framework_name,
                    )
                    entry_points.append(entry)
                continue

            # Check for @app.get, @app.post, etc.
            match = self.METHOD_ROUTE_PATTERN.search(line)
            if match:
                _app_var = match.group(1)
                method_str = match.group(2)
                path = match.group(3)

                try:
                    method = HTTPMethod[method_str.upper()]
                except KeyError:
                    method = HTTPMethod.GET

                handler = self._find_next_function(lines, i)

                entry = EntryPoint(
                    type=EntryPointType.HTTP,
                    method=method,
                    path=self._normalize_path(path),
                    handler=handler,
                    file=str(file_path),
                    line=i + 1,
                    framework=self.framework_name,
                )
                entry_points.append(entry)

        return entry_points

    def _parse_methods(self, methods_str: str) -> list[HTTPMethod]:
        """Parse methods string like "['GET', 'POST']"."""
        methods = []
        for m in re.findall(r"['\"](\w+)['\"]", methods_str):
            try:
                methods.append(HTTPMethod[m.upper()])
            except KeyError:
                pass
        return methods if methods else [HTTPMethod.GET]

    def _find_next_function(self, lines: list[str], start_idx: int) -> str:
        """Find next function definition."""
        for i in range(start_idx, min(start_idx + 5, len(lines))):
            match = self.FUNC_PATTERN.search(lines[i])
            if match:
                return match.group(1)
        return "unknown"

    def _normalize_path(self, path: str) -> str:
        """Normalize Flask path to standard format.

        <int:id> -> {id}
        <string:name> -> {name}
        """
        # Convert <type:name> to {name}
        path = re.sub(r"<[^>]+:([^>]+)>", r"{\1}", path)
        # Convert <name> to {name}
        path = re.sub(r"<([^>]+)>", r"{\1}", path)
        return path


class FastAPIDetector(HTTPDetector):
    """Detector for FastAPI framework (Python)."""

    framework_name = "fastapi"
    file_patterns = ["*.py"]

    # Pattern for @app.get("/path"), @router.post("/path")
    ROUTE_PATTERN = re.compile(
        r"""@(\w+)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""",
        re.VERBOSE,
    )

    # Pattern for function definition
    FUNC_PATTERN = re.compile(r"(?:async\s+)?def\s+(\w+)\s*\(")

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect FastAPI routes."""
        entry_points = []

        lines = content.split("\n")

        for i, line in enumerate(lines):
            match = self.ROUTE_PATTERN.search(line)
            if match:
                _router_var = match.group(1)
                method_str = match.group(2)
                path = match.group(3)

                try:
                    method = HTTPMethod[method_str.upper()]
                except KeyError:
                    method = HTTPMethod.GET

                handler = self._find_next_function(lines, i)

                entry = EntryPoint(
                    type=EntryPointType.HTTP,
                    method=method,
                    path=path,
                    handler=handler,
                    file=str(file_path),
                    line=i + 1,
                    framework=self.framework_name,
                )
                entry_points.append(entry)

        return entry_points

    def _find_next_function(self, lines: list[str], start_idx: int) -> str:
        """Find next function definition."""
        for i in range(start_idx, min(start_idx + 5, len(lines))):
            match = self.FUNC_PATTERN.search(lines[i])
            if match:
                return match.group(1)
        return "unknown"


# Registry of all HTTP detectors
HTTP_DETECTORS: list[type[HTTPDetector]] = [
    GinDetector,
    EchoDetector,
    SpringDetector,
    FlaskDetector,
    FastAPIDetector,
]


def get_detector_for_framework(framework: str) -> HTTPDetector | None:
    """Get detector for a specific framework.

    Args:
        framework: Framework name (case-insensitive).

    Returns:
        Detector instance or None.
    """
    framework_lower = framework.lower()
    for detector_cls in HTTP_DETECTORS:
        if detector_cls.framework_name == framework_lower:
            return detector_cls()
    return None


def get_detector_for_file(file_path: Path) -> list[HTTPDetector]:
    """Get applicable detectors for a file.

    Args:
        file_path: Path to source file.

    Returns:
        List of applicable detectors.
    """
    detectors = []
    suffix = file_path.suffix

    for detector_cls in HTTP_DETECTORS:
        # Check if file matches any pattern
        for pattern in detector_cls.file_patterns:
            if pattern.startswith("*."):
                if suffix == pattern[1:]:
                    detectors.append(detector_cls())
                    break
            elif file_path.match(pattern):
                detectors.append(detector_cls())
                break

    return detectors
