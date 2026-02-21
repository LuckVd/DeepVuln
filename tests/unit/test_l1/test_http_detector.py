"""Tests for HTTP entry point detection."""

import pytest

from src.layers.l1_intelligence.attack_surface.http_detector import (
    CustomHTTPServerDetector,
    GoStdlibDetector,
    JavaStdlibDetector,
    PythonStdlibHTTPDetector,
    get_detector_for_file,
    get_detector_for_framework,
)
from src.layers.l1_intelligence.attack_surface.models import (
    EntryPoint,
    EntryPointType,
    HTTPMethod,
)
from pathlib import Path


class TestPythonStdlibHTTPDetector:
    """Tests for Python http.server detection."""

    @pytest.fixture
    def detector(self):
        return PythonStdlibHTTPDetector()

    def test_detect_base_http_request_handler_class(self, detector):
        """Test detection of BaseHTTPRequestHandler subclass."""
        code = '''
from http.server import BaseHTTPRequestHandler, HTTPServer

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Hello")
'''
        entry_points = detector.detect(code, Path("/test/server.py"))
        assert len(entry_points) >= 1
        assert any(ep.handler == "MyHandler.do_GET" for ep in entry_points)
        assert any(ep.method == HTTPMethod.GET for ep in entry_points)
        assert any(ep.framework == "python-stdlib" for ep in entry_points)

    def test_detect_do_post_method(self, detector):
        """Test detection of do_POST method."""
        code = '''
from http.server import BaseHTTPRequestHandler

class APIHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        self.send_response(201)
'''
        entry_points = detector.detect(code, Path("/test/api.py"))
        assert len(entry_points) >= 1
        assert any(ep.handler == "APIHandler.do_POST" for ep in entry_points)
        assert any(ep.method == HTTPMethod.POST for ep in entry_points)

    def test_detect_multiple_do_methods(self, detector):
        """Test detection of multiple do_* methods."""
        code = '''
from http.server import BaseHTTPRequestHandler

class RESTHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        pass

    def do_POST(self):
        pass

    def do_PUT(self):
        pass

    def do_DELETE(self):
        pass
'''
        entry_points = detector.detect(code, Path("/test/rest.py"))
        methods = {ep.method for ep in entry_points}
        assert HTTPMethod.GET in methods
        assert HTTPMethod.POST in methods
        assert HTTPMethod.PUT in methods
        assert HTTPMethod.DELETE in methods
        assert len(entry_points) >= 4

    def test_detect_http_server_with_explicit_import(self, detector):
        """Test detection with explicit http.server import."""
        code = '''
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
'''
        entry_points = detector.detect(code, Path("/test/server.py"))
        assert len(entry_points) >= 1


class TestGoStdlibDetector:
    """Tests for Go net/http detection."""

    @pytest.fixture
    def detector(self):
        return GoStdlibDetector()

    def test_detect_http_handle_func(self, detector):
        """Test detection of http.HandleFunc."""
        code = '''
package main

import (
    "net/http"
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello"))
}

func main() {
    http.HandleFunc("/", homeHandler)
    http.ListenAndServe(":8080", nil)
}
'''
        entry_points = detector.detect(code, Path("/test/main.go"))
        assert len(entry_points) >= 1
        assert any(ep.handler == "homeHandler" for ep in entry_points)
        assert any(ep.path == "/" for ep in entry_points)
        assert any(ep.framework == "go-stdlib" for ep in entry_points)

    def test_detect_http_handle(self, detector):
        """Test detection of http.Handle."""
        code = '''
package main

import "net/http"

type apiHandler struct{}

func (h *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

func main() {
    http.Handle("/api", &apiHandler{})
}
'''
        entry_points = detector.detect(code, Path("/test/main.go"))
        assert len(entry_points) >= 1
        assert any(ep.path == "/api" for ep in entry_points)

    def test_detect_mux_handle_func(self, detector):
        """Test detection of mux.HandleFunc."""
        code = '''
package main

import "net/http"

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/users", usersHandler)
    mux.HandleFunc("/posts", postsHandler)
}
'''
        entry_points = detector.detect(code, Path("/test/main.go"))
        assert len(entry_points) >= 2
        paths = {ep.path for ep in entry_points}
        assert "/users" in paths
        assert "/posts" in paths


class TestJavaStdlibDetector:
    """Tests for Java com.sun.net.httpserver detection."""

    @pytest.fixture
    def detector(self):
        return JavaStdlibDetector()

    def test_detect_create_context(self, detector):
        """Test detection of createContext."""
        code = '''
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;

public class Server {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/api", new ApiHandler());
        server.createContext("/health", new HealthHandler());
        server.start();
    }
}
'''
        entry_points = detector.detect(code, Path("/test/Server.java"))
        assert len(entry_points) >= 2
        paths = {ep.path for ep in entry_points}
        assert "/api" in paths
        assert "/health" in paths
        assert all(ep.framework == "java-stdlib" for ep in entry_points)

    def test_detect_http_handler_implementation(self, detector):
        """Test detection of HttpHandler implementations."""
        code = '''
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

public class ApiHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // Handle request
    }
}
'''
        entry_points = detector.detect(code, Path("/test/ApiHandler.java"))
        assert len(entry_points) >= 1
        assert any(ep.handler == "ApiHandler" for ep in entry_points)


class TestCustomHTTPServerDetector:
    """Tests for custom HTTP server detection."""

    @pytest.fixture
    def detector(self):
        return CustomHTTPServerDetector()

    def test_detect_copyparty_httpcli(self, detector):
        """Test detection of copyparty-style HTTP handler class."""
        code = '''
class HttpCli(object):
    """Spawned by HttpConn to process one http transaction"""

    def __init__(self, conn):
        self.mode = " "
        self.req = " "
        self.headers = {}

    def run(self) -> bool:
        """returns true if connection can be reused"""
        headerlines = read_header(self.sr, self.args.s_thead)
        self.mode, self.req, self.http_ver = headerlines[0].split(" ")
        return True
'''
        entry_points = detector.detect(code, Path("/test/httpcli.py"))
        assert len(entry_points) >= 1
        # Should detect HttpCli class and/or run method
        handlers = {ep.handler for ep in entry_points}
        assert "HttpCli" in handlers or "HttpCli.run" in handlers

    def test_detect_copyparty_httpsrv(self, detector):
        """Test detection of copyparty-style HTTP server class."""
        code = '''
class HttpSrv(object):
    """handles incoming connections using HttpConn to process http"""

    def __init__(self, broker):
        self.clients = set()

    def run(self):
        socket.setdefaulttimeout(120)
        # HTTP server logic
        pass
'''
        entry_points = detector.detect(code, Path("/test/httpsrv.py"))
        # Should detect HttpSrv as HTTP handler
        assert len(entry_points) >= 1

    def test_detect_socket_based_http(self, detector):
        """Test detection of socket-based HTTP implementation."""
        code = '''
import socket

class MyServer:
    def handle_request(self):
        data = self.socket.recv(4096)
        if data.startswith(b"GET"):
            self.handle_get(data)
        elif data.startswith(b"POST"):
            self.handle_post(data)

    def run(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("0.0.0.0", 8080))
        self.socket.listen(5)
        while True:
            self.handle_request()
'''
        entry_points = detector.detect(code, Path("/test/server.py"))
        # Should detect as custom HTTP implementation
        assert len(entry_points) >= 1
        assert all(ep.framework == "custom" for ep in entry_points)

    def test_skip_non_http_files(self, detector):
        """Test that non-HTTP files are skipped."""
        code = '''
class Calculator:
    def add(self, a, b):
        return a + b

    def run(self):
        return self.add(1, 2)
'''
        entry_points = detector.detect(code, Path("/test/calc.py"))
        assert len(entry_points) == 0


class TestDetectorRegistry:
    """Tests for detector registry functions."""

    def test_get_detector_for_framework_python_stdlib(self):
        """Test getting Python stdlib detector by name."""
        detector = get_detector_for_framework("python-stdlib")
        assert detector is not None
        assert isinstance(detector, PythonStdlibHTTPDetector)

    def test_get_detector_for_framework_go_stdlib(self):
        """Test getting Go stdlib detector by name."""
        detector = get_detector_for_framework("go-stdlib")
        assert detector is not None
        assert isinstance(detector, GoStdlibDetector)

    def test_get_detector_for_framework_java_stdlib(self):
        """Test getting Java stdlib detector by name."""
        detector = get_detector_for_framework("java-stdlib")
        assert detector is not None
        assert isinstance(detector, JavaStdlibDetector)

    def test_get_detector_for_framework_custom(self):
        """Test getting custom detector by name."""
        detector = get_detector_for_framework("custom")
        assert detector is not None
        assert isinstance(detector, CustomHTTPServerDetector)

    def test_get_detector_for_framework_unknown(self):
        """Test getting detector for unknown framework."""
        detector = get_detector_for_framework("unknown-framework")
        assert detector is None

    def test_get_detector_for_file_python(self):
        """Test getting detectors for Python file."""
        detectors = get_detector_for_file(Path("/test/server.py"))
        detector_types = {type(d).__name__ for d in detectors}
        assert "PythonStdlibHTTPDetector" in detector_types
        assert "CustomHTTPServerDetector" in detector_types

    def test_get_detector_for_file_go(self):
        """Test getting detectors for Go file."""
        detectors = get_detector_for_file(Path("/test/main.go"))
        detector_types = {type(d).__name__ for d in detectors}
        assert "GoStdlibDetector" in detector_types

    def test_get_detector_for_file_java(self):
        """Test getting detectors for Java file."""
        detectors = get_detector_for_file(Path("/test/Server.java"))
        detector_types = {type(d).__name__ for d in detectors}
        assert "JavaStdlibDetector" in detector_types


class TestCopypartyDetection:
    """Tests for copyparty-style HTTP detection (real-world case)."""

    @pytest.fixture
    def detector(self):
        return CustomHTTPServerDetector()

    def test_detect_httpconn_class(self, detector):
        """Test detection of copyparty HttpConn class."""
        code = '''
class HttpConn(object):
    """
    spawned by HttpSrv to handle an incoming client connection,
    creates an HttpCli for each request (Connection: Keep-Alive)
    """

    def __init__(self, sck, addr, hsrv):
        self.s = sck
        self.addr = addr
        self.hsrv = hsrv

    def run(self):
        self.s.settimeout(10)
        is_https = self._detect_https()
        if is_https:
            self.s = ctx.wrap_socket(self.s, server_side=True)
'''
        entry_points = detector.detect(code, Path("/test/httpconn.py"))
        assert len(entry_points) >= 1

    def test_detect_full_copyparty_pattern(self, detector):
        """Test detection of full copyparty HTTP pattern."""
        # This is a simplified version of copyparty's httpcli.py
        code = '''
class HttpCli(object):
    """Spawned by HttpConn to process one http transaction"""

    def __init__(self, conn):
        self.conn = conn
        self.headers = {}
        self.mode = " "  # http verb
        self.req = " "

    def run(self) -> bool:
        """returns true if connection can be reused"""
        try:
            headerlines = read_header(self.sr, self.args.s_thead)
            self.mode, self.req, self.http_ver = headerlines[0].split(" ")
            for header_line in headerlines[1:]:
                k, zs = header_line.split(":", 1)
                self.headers[k.lower()] = zs.strip()
        except Pebkac as ex:
            self.mode = "GET"
            self.req = "[junk]"
        return self.keepalive
'''
        entry_points = detector.detect(code, Path("/test/httpcli.py"))
        assert len(entry_points) >= 1
        # Should detect HttpCli class and/or run method
        handlers = {ep.handler for ep in entry_points}
        assert "HttpCli" in handlers or "HttpCli.run" in handlers


class TestEntryPointModel:
    """Tests for EntryPoint model with new frameworks."""

    def test_python_stdlib_entry_point_display(self):
        """Test display string for Python stdlib entry point."""
        entry = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.GET,
            path="/",
            handler="MyHandler.do_GET",
            file="/test/server.py",
            line=10,
            framework="python-stdlib",
        )
        display = entry.to_display()
        assert "GET" in display
        assert "/" in display
        assert "MyHandler.do_GET" in display

    def test_custom_entry_point_with_metadata(self):
        """Test entry point with custom metadata."""
        entry = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.ALL,
            path="/",
            handler="HttpCli.run",
            file="/test/httpcli.py",
            line=330,
            framework="custom",
            metadata={"handler_type": "run_method"},
        )
        assert entry.metadata["handler_type"] == "run_method"
        assert entry.framework == "custom"
