"""Python AST-based attack surface detector using Tree-sitter."""

from pathlib import Path
from typing import Any

import tree_sitter_python as tspython

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.ast.base import (
    ASTDetector,
    register_ast_detector,
)
from src.layers.l1_intelligence.attack_surface.models import (
    EntryPoint,
    EntryPointType,
    HTTPMethod,
)


@register_ast_detector
class PythonASTDetector(ASTDetector):
    """AST-based detector for Python frameworks (Flask, FastAPI, etc.)."""

    language_module = tspython
    language_name = "python"
    file_extensions = [".py"]

    # Tree-sitter query for Flask/FastAPI routes
    FLASK_ROUTE_QUERY = """
    (decorated_definition
        (decorator
            (call
                function: (attribute
                    object: (identifier) @app_var
                    attribute: (identifier) @method
                )
                arguments: (argument_list
                    (string) @path
                )
            )
        )
        definition: (function_definition
            name: (identifier) @func_name
        )
    )
    """

    # Tree-sitter query for @app.route with methods parameter
    FLASK_ROUTE_METHODS_QUERY = """
    (decorated_definition
        (decorator
            (call
                function: (attribute
                    object: (identifier) @app_var
                    attribute: (identifier) @route_method
                    (#eq? @route_method "route")
                )
                arguments: (argument_list
                    (string) @path
                    .
                    (keyword_argument
                        name: (identifier) @kw_name
                        (#eq? @kw_name "methods")
                        value: (list
                            (string) @method
                        )
                    )
                )
            )
        )
        definition: (function_definition
            name: (identifier) @func_name
        )
    )
    """

    # Tree-sitter query for FastAPI class-based routes
    FASTAPI_QUERY = """
    (decorated_definition
        (decorator
            (call
                function: (call
                    function: (attribute
                        object: (identifier) @app_var
                        attribute: (identifier) @method
                    )
                )
                arguments: (argument_list
                    (string) @path
                )
            )
        )
        definition: (function_definition
            name: (identifier) @func_name
        )
    )
    """

    # Query for Celery tasks
    CELERY_TASK_QUERY = """
    (decorated_definition
        (decorator
            (call
                (attribute
                    object: (identifier) @celery_var
                    attribute: (identifier) @task_method
                    (#eq? @task_method "task")
                )
            )
        )
        definition: (function_definition
            name: (identifier) @func_name
        )
    )
    """

    def __init__(self) -> None:
        """Initialize the Python AST detector."""
        super().__init__()
        self.logger = get_logger(__name__)

    def _extract_entry_points(
        self, root: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract entry points from Python AST.

        Args:
            root: Root node of the AST.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of detected entry points.
        """
        entry_points: list[EntryPoint] = []

        # Extract Flask/FastAPI routes
        entry_points.extend(self._extract_flask_routes(root, content, file_path))

        # Extract routes with methods parameter
        entry_points.extend(self._extract_flask_routes_with_methods(root, content, file_path))

        # Extract Celery tasks
        entry_points.extend(self._extract_celery_tasks(root, content, file_path))

        return entry_points

    def _extract_flask_routes(
        self, root: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract Flask/FastAPI routes.

        Args:
            root: Root node of the AST.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of HTTP entry points.
        """
        entry_points: list[EntryPoint] = []

        try:
            query = self._query(self.FLASK_ROUTE_QUERY)
            captures = query.captures(root)

            current_data: dict[str, Any] = {}

            for capture_name, node in captures:
                if capture_name == "method":
                    current_data["method"] = self._get_text(node, content)
                elif capture_name == "path":
                    path_text = self._get_text(node, content)
                    current_data["path"] = path_text.strip('"\'').strip('b"\'')
                elif capture_name == "func_name":
                    current_data["func_name"] = self._get_text(node, content)
                    current_data["line"] = self._get_line_number(node)

                # When we have all data, create entry point
                if all(k in current_data for k in ["method", "path", "func_name"]):
                    method = self._get_http_method(current_data["method"])
                    framework = self._detect_framework(current_data["method"])

                    entry = EntryPoint(
                        type=EntryPointType.HTTP,
                        method=method,
                        path=current_data["path"],
                        handler=current_data["func_name"],
                        file=str(file_path),
                        line=current_data.get("line", 0),
                        framework=framework,
                    )
                    entry_points.append(entry)
                    current_data = {}

        except Exception as e:
            self.logger.debug(f"Failed to extract Flask routes: {e}")

        return entry_points

    def _extract_flask_routes_with_methods(
        self, root: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract Flask routes with methods parameter.

        Args:
            root: Root node of the AST.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of HTTP entry points.
        """
        entry_points: list[EntryPoint] = []

        try:
            query = self._query(self.FLASK_ROUTE_METHODS_QUERY)
            captures = query.captures(root)

            current_data: dict[str, Any] = {}
            methods: list[str] = []

            for capture_name, node in captures:
                if capture_name == "path":
                    path_text = self._get_text(node, content)
                    current_data["path"] = path_text.strip('"\'')
                elif capture_name == "method":
                    method_text = self._get_text(node, content)
                    methods.append(method_text.strip('"\'').upper())
                elif capture_name == "func_name":
                    current_data["func_name"] = self._get_text(node, content)
                    current_data["line"] = self._get_line_number(node)

                # When we have all data
                if "func_name" in current_data and "path" in current_data:
                    for method_str in methods:
                        method = self._method_str_to_enum(method_str)
                        entry = EntryPoint(
                            type=EntryPointType.HTTP,
                            method=method,
                            path=current_data["path"],
                            handler=current_data["func_name"],
                            file=str(file_path),
                            line=current_data.get("line", 0),
                            framework="flask",
                        )
                        entry_points.append(entry)

                    current_data = {}
                    methods = []

        except Exception as e:
            self.logger.debug(f"Failed to extract Flask routes with methods: {e}")

        return entry_points

    def _extract_celery_tasks(
        self, root: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract Celery task definitions.

        Args:
            root: Root node of the AST.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of CRON entry points.
        """
        entry_points: list[EntryPoint] = []

        try:
            query = self._query(self.CELERY_TASK_QUERY)
            captures = query.captures(root)

            func_name = None

            for capture_name, node in captures:
                if capture_name == "func_name":
                    func_name = self._get_text(node, content)
                    line_num = self._get_line_number(node)

                    if func_name:
                        entry = EntryPoint(
                            type=EntryPointType.CRON,
                            path="celery_task",
                            handler=func_name,
                            file=str(file_path),
                            line=line_num,
                            framework="celery",
                            metadata={"task_type": "celery"},
                        )
                        entry_points.append(entry)
                        func_name = None

        except Exception as e:
            self.logger.debug(f"Failed to extract Celery tasks: {e}")

        return entry_points

    def _get_http_method(self, method_str: str) -> HTTPMethod:
        """Get HTTP method from string.

        Args:
            method_str: Method string (e.g., "get", "post").

        Returns:
            HTTP method enum value.
        """
        mapping = {
            "get": HTTPMethod.GET,
            "post": HTTPMethod.POST,
            "put": HTTPMethod.PUT,
            "delete": HTTPMethod.DELETE,
            "patch": HTTPMethod.PATCH,
            "route": HTTPMethod.ALL,
        }
        return mapping.get(method_str.lower(), HTTPMethod.ALL)

    def _method_str_to_enum(self, method_str: str) -> HTTPMethod:
        """Convert method string to HTTPMethod enum.

        Args:
            method_str: Method string (e.g., "GET", "POST").

        Returns:
            HTTP method enum value.
        """
        mapping = {
            "GET": HTTPMethod.GET,
            "POST": HTTPMethod.POST,
            "PUT": HTTPMethod.PUT,
            "DELETE": HTTPMethod.DELETE,
            "PATCH": HTTPMethod.PATCH,
            "HEAD": HTTPMethod.HEAD,
            "OPTIONS": HTTPMethod.OPTIONS,
        }
        return mapping.get(method_str.upper(), HTTPMethod.ALL)

    def _detect_framework(self, method_str: str) -> str:
        """Detect framework from method name.

        Args:
            method_str: Method string.

        Returns:
            Framework name.
        """
        if method_str.lower() == "route":
            return "flask"
        # FastAPI typically uses get, post, etc. directly
        return "fastapi"
