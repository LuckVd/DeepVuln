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


class GoStdlibDetector(HTTPDetector):
    """Detector for Go net/http standard library."""

    framework_name = "go-stdlib"
    file_patterns = ["*.go"]

    # Pattern: http.HandleFunc("/path", handler)
    HANDLE_FUNC_PATTERN = re.compile(
        r"""http\.HandleFunc\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*(\w+)""",
        re.VERBOSE,
    )

    # Pattern: http.Handle("/path", handler) - can be &Handler{} or handler
    HANDLE_PATTERN = re.compile(
        r"""http\.Handle\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*&?(\w+)""",
        re.VERBOSE,
    )

    # Pattern: mux.HandleFunc("/path", handler)
    MUX_HANDLE_FUNC_PATTERN = re.compile(
        r"""(\w+)\.HandleFunc\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*(\w+)""",
        re.VERBOSE,
    )

    # Pattern: http.ListenAndServe(":8080", nil)
    LISTEN_PATTERN = re.compile(r"""http\.ListenAndServe\s*\(""")

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect Go net/http routes."""
        entry_points = []

        # Find http.HandleFunc
        for match in self.HANDLE_FUNC_PATTERN.finditer(content):
            path = match.group(1)
            handler = match.group(2)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.HTTP,
                method=HTTPMethod.ALL,
                path=path,
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
            )
            entry_points.append(entry)

        # Find http.Handle
        for match in self.HANDLE_PATTERN.finditer(content):
            path = match.group(1)
            handler = match.group(2)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.HTTP,
                method=HTTPMethod.ALL,
                path=path,
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
            )
            entry_points.append(entry)

        # Find mux.HandleFunc
        for match in self.MUX_HANDLE_FUNC_PATTERN.finditer(content):
            _mux_var = match.group(1)
            path = match.group(2)
            handler = match.group(3)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.HTTP,
                method=HTTPMethod.ALL,
                path=path,
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
            )
            entry_points.append(entry)

        return entry_points


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


class JavaStdlibDetector(HTTPDetector):
    """Detector for Java com.sun.net.httpserver standard library."""

    framework_name = "java-stdlib"
    file_patterns = ["*.java"]

    # Pattern: httpServer.createContext("/path", handler)
    CREATE_CONTEXT_PATTERN = re.compile(
        r"""\.createContext\s*\(\s*["']([^"']+)["']\s*,\s*(\w+)""",
        re.VERBOSE,
    )

    # Pattern: implements HttpHandler
    HTTP_HANDLER_PATTERN = re.compile(
        r"""implements\s+HttpHandler""",
        re.VERBOSE,
    )

    # Pattern: class Name implements HttpHandler
    HANDLER_CLASS_PATTERN = re.compile(
        r"""class\s+(\w+)\s+implements\s+HttpHandler""",
        re.VERBOSE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect Java HttpServer routes."""
        entry_points = []

        # Find createContext calls
        for match in self.CREATE_CONTEXT_PATTERN.finditer(content):
            path = match.group(1)
            handler = match.group(2)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.HTTP,
                method=HTTPMethod.ALL,
                path=path,
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
            )
            entry_points.append(entry)

        # Find HttpHandler implementations
        for match in self.HANDLER_CLASS_PATTERN.finditer(content):
            class_name = match.group(1)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.HTTP,
                method=HTTPMethod.ALL,
                path="/",  # Unknown path
                handler=class_name,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
                metadata={"handler_type": "class"},
            )
            entry_points.append(entry)

        return entry_points


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


class PythonStdlibHTTPDetector(HTTPDetector):
    """Detector for Python http.server standard library.

    Detects BaseHTTPRequestHandler and http.server.HTTPServer patterns.
    """

    framework_name = "python-stdlib"
    file_patterns = ["*.py"]

    # Pattern: class Handler(BaseHTTPRequestHandler)
    HANDLER_CLASS_PATTERN = re.compile(
        r"""class\s+(\w+)\s*\(\s*(?:http\.server\.)?BaseHTTPRequestHandler\s*\)""",
        re.VERBOSE,
    )

    # Pattern: def do_GET(self), def do_POST(self), etc.
    DO_METHOD_PATTERN = re.compile(
        r"""def\s+(do_GET|do_POST|do_PUT|do_DELETE|do_HEAD|do_OPTIONS|do_PATCH)\s*\(\s*self\s*\)""",
        re.VERBOSE,
    )

    # Pattern: http.server.HTTPServer or HTTPServer
    HTTP_SERVER_PATTERN = re.compile(
        r"""(?:http\.server\.)?HTTPServer\s*\(\s*\(""",
        re.VERBOSE,
    )

    # Pattern: socketserver.TCPServer
    TCPSERVER_PATTERN = re.compile(
        r"""socketserver\.TCPServer\s*\(\s*\(""",
        re.VERBOSE,
    )

    # Pattern: self.path or self.send_response
    REQUEST_HANDLING_PATTERN = re.compile(
        r"""self\.(?:path|send_response|send_header|end_headers)""",
        re.VERBOSE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect Python http.server handlers."""
        entry_points = []

        # Find handler classes
        handler_classes: dict[str, int] = {}
        for match in self.HANDLER_CLASS_PATTERN.finditer(content):
            class_name = match.group(1)
            line_num = content[: match.start()].count("\n") + 1
            handler_classes[class_name] = line_num

        # Find do_* methods within handler classes
        for match in self.DO_METHOD_PATTERN.finditer(content):
            method_name = match.group(1)
            line_num = content[: match.start()].count("\n") + 1

            # Convert do_GET -> GET
            http_method_str = method_name.replace("do_", "")
            try:
                http_method = HTTPMethod[http_method_str]
            except KeyError:
                http_method = HTTPMethod.ALL

            # Find the class this method belongs to
            handler_class = self._find_enclosing_class(content, match.start())
            path = "/"  # BaseHTTPRequestHandler uses self.path for routing

            entry = EntryPoint(
                type=EntryPointType.HTTP,
                method=http_method,
                path=path,
                handler=f"{handler_class}.{method_name}" if handler_class else method_name,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
                metadata={"handler_type": "do_method"},
            )
            entry_points.append(entry)

        return entry_points

    def _find_enclosing_class(self, content: str, pos: int) -> str | None:
        """Find the class that encloses the given position."""
        # Look backwards for class definition
        before_content = content[:pos]
        lines = before_content.split("\n")

        for i in range(len(lines) - 1, -1, -1):
            match = re.search(r"class\s+(\w+)\s*[:\(]", lines[i])
            if match:
                return match.group(1)

        return None


class CustomHTTPServerDetector(HTTPDetector):
    """Detector for custom HTTP server implementations.

    Detects common patterns in custom HTTP servers like copyparty:
    - Classes with run() method handling HTTP
    - Classes with handle_request() or handle() methods
    - Socket-based HTTP processing
    """

    framework_name = "custom"
    file_patterns = ["*.py"]

    # Pattern: class HttpCli, class HttpSrv, etc.
    HTTP_CLASS_PATTERN = re.compile(
        r"""class\s+(\w*(?:[Hh]ttp|[Ss]rv|[Ss]erver|[Cc]li)\w*)\s*[\(:]""",
        re.VERBOSE,
    )

    # Pattern: def run(self) handling HTTP
    RUN_METHOD_PATTERN = re.compile(
        r"""def\s+run\s*\(\s*self\s*(?:,\s*\w+)*\s*\)\s*(?:->\s*\w+)?\s*:""",
        re.VERBOSE,
    )

    # Pattern: self.mode, self.req, self.path in HTTP context
    HTTP_STATE_PATTERN = re.compile(
        r"""self\.(?:mode|req|path|method)\s*=\s*["']?(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)""",
        re.VERBOSE,
    )

    # Pattern: header parsing (read_header, parse headers)
    HEADER_PARSE_PATTERN = re.compile(
        r"""(?:read_header|parse.*header|header.*parse)""",
        re.VERBOSE | re.IGNORECASE,
    )

    # Pattern: socket recv/send with HTTP
    SOCKET_HTTP_PATTERN = re.compile(
        r"""(?:socket\.socket|\.recv\(|\.send\(|\.sendall\()""",
        re.VERBOSE,
    )

    # Pattern: HTTP response codes
    HTTP_RESPONSE_PATTERN = re.compile(
        r"""["']?HTTP/1\.[01]["']?\s*["']?(\d{3})""",
        re.VERBOSE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect custom HTTP server implementations."""
        entry_points = []

        # Check if this file looks like a custom HTTP implementation
        if not self._is_http_server_file(content):
            return entry_points

        # Find HTTP-related classes
        for match in self.HTTP_CLASS_PATTERN.finditer(content):
            class_name = match.group(1)
            line_num = content[: match.start()].count("\n") + 1

            # Check if this class has HTTP handling methods
            class_content = self._extract_class_content(content, match.start())
            if class_content and self._has_http_handling(class_content):
                entry = EntryPoint(
                    type=EntryPointType.HTTP,
                    method=HTTPMethod.ALL,
                    path="/",  # Generic path
                    handler=class_name,
                    file=str(file_path),
                    line=line_num,
                    framework=self.framework_name,
                    metadata={"handler_type": "custom_http_class"},
                )
                entry_points.append(entry)

        # Find run() methods that handle HTTP
        for match in self.RUN_METHOD_PATTERN.finditer(content):
            line_num = content[: match.start()].count("\n") + 1

            # Check if this method handles HTTP
            method_content = self._extract_method_content(content, match.start())
            if method_content and self._is_http_handler_method(method_content):
                enclosing_class = self._find_enclosing_class(content, match.start())
                handler_name = f"{enclosing_class}.run" if enclosing_class else "run"

                entry = EntryPoint(
                    type=EntryPointType.HTTP,
                    method=HTTPMethod.ALL,
                    path="/",
                    handler=handler_name,
                    file=str(file_path),
                    line=line_num,
                    framework=self.framework_name,
                    metadata={"handler_type": "run_method"},
                )
                entry_points.append(entry)

        return entry_points

    def _is_http_server_file(self, content: str) -> bool:
        """Check if file looks like an HTTP server implementation."""
        http_indicators = [
            r"http\.server",
            r"socket",
            r"HTTP/1\.[01]",
            r"handle.*request",
            r"process.*request",
            r"def run\s*\(",
            r"class.*Http\w*",
            r"class.*[Ss]rv\w*",
            r"self\.headers",
            r"headerlines",
            r"keepalive",
        ]

        count = 0
        for pattern in http_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                count += 1

        # Lower threshold for files with HTTP-related class names
        if re.search(r"class\s+\w*(?:Http|[Ss]rv|[Ss]erver|[Cc]li)\w*", content):
            return count >= 1

        return count >= 2

    def _has_http_handling(self, class_content: str) -> bool:
        """Check if class has HTTP handling logic."""
        indicators = [
            r"self\.mode\s*=",
            r"self\.req\s*=",
            r"self\.path\s*=",
            r"HTTP/1\.",
            r"header",
            r"GET|POST|PUT|DELETE",
            r"self\.headers",
            r"socket",
            r"keepalive",
            r"def run\s*\(",
            r"def handle",
        ]

        count = 0
        for pattern in indicators:
            if re.search(pattern, class_content, re.IGNORECASE):
                count += 1

        return count >= 1

    def _is_http_handler_method(self, method_content: str) -> bool:
        """Check if method handles HTTP requests."""
        indicators = [
            r"self\.mode",
            r"self\.req",
            r"self\.path",
            r"headers",
            r"HTTP/1\.",
            r"GET|POST|PUT|DELETE",
            r"read_header",
        ]

        count = 0
        for pattern in indicators:
            if re.search(pattern, method_content, re.IGNORECASE):
                count += 1

        return count >= 2

    def _extract_class_content(self, content: str, class_start: int) -> str | None:
        """Extract content of a class definition."""
        # Find next class or end of file
        next_class = content.find("\nclass ", class_start + 1)
        if next_class == -1:
            return content[class_start:]
        return content[class_start:next_class]

    def _extract_method_content(self, content: str, method_start: int) -> str | None:
        """Extract content of a method (until next def at same or lower indentation)."""
        lines = content[method_start:].split("\n")
        if not lines:
            return None

        result = [lines[0]]
        for i in range(1, len(lines)):
            line = lines[i]
            # Check if this is a new def at same or lower indentation
            if re.match(r"\S", line) or (line.startswith("    ") and re.match(r"    def ", line)):
                break
            result.append(line)

        return "\n".join(result)

    def _find_enclosing_class(self, content: str, pos: int) -> str | None:
        """Find the class that encloses the given position."""
        before_content = content[:pos]
        lines = before_content.split("\n")

        for i in range(len(lines) - 1, -1, -1):
            match = re.search(r"class\s+(\w+)\s*[:\(]", lines[i])
            if match:
                return match.group(1)

        return None


# Registry of all HTTP detectors
HTTP_DETECTORS: list[type[HTTPDetector]] = [
    # Framework-specific detectors
    GinDetector,
    EchoDetector,
    SpringDetector,
    FlaskDetector,
    FastAPIDetector,
    # Standard library detectors
    GoStdlibDetector,
    JavaStdlibDetector,
    PythonStdlibHTTPDetector,
    # Custom HTTP server detector
    CustomHTTPServerDetector,
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
