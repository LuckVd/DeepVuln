"""Go AST-based attack surface detector using Tree-sitter."""

from pathlib import Path
from typing import Any

import tree_sitter_go as tsgo

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
class GoASTDetector(ASTDetector):
    """AST-based detector for Go frameworks (Gin, Echo, etc.)."""

    language_module = tsgo
    language_name = "go"
    file_extensions = [".go"]

    # Tree-sitter query for Gin/Echo routes
    GIN_ROUTE_QUERY = """
    (call_expression
        function: (selector_expression
            operand: (identifier) @router_var
            field: (field_identifier) @method
        )
        arguments: (argument_list
            (interpreted_string_literal) @path
            (identifier) @handler
        )
    )
    """

    # Alternative query for routes with inline function
    GIN_INLINE_ROUTE_QUERY = """
    (call_expression
        function: (selector_expression
            operand: (identifier) @router_var
            field: (field_identifier) @method
        )
        arguments: (argument_list
            (interpreted_string_literal) @path
            (func_literal) @handler
        )
    )
    """

    # Query for route groups
    GIN_GROUP_QUERY = """
    (short_var_declaration
        left: (expression_list
            (identifier) @group_var
        )
        right: (expression_list
            (call_expression
                function: (selector_expression
                    field: (field_identifier) @group_method
                    (#eq? @group_method "Group")
                )
                arguments: (argument_list
                    (interpreted_string_literal) @prefix
                )
            )
        )
    )
    """

    # Query for cron jobs
    CRON_QUERY = """
    (call_expression
        function: (selector_expression
            field: (field_identifier) @cron_method
            (#eq? @cron_method "AddFunc")
        )
        arguments: (argument_list
            (interpreted_string_literal) @schedule
            (identifier) @handler
        )
    )
    """

    def __init__(self) -> None:
        """Initialize the Go AST detector."""
        super().__init__()
        self.logger = get_logger(__name__)

    def _extract_entry_points(
        self, root: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract entry points from Go AST.

        Args:
            root: Root node of the AST.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of detected entry points.
        """
        entry_points: list[EntryPoint] = []

        # Extract route groups for prefix
        group_prefixes = self._extract_group_prefixes(root, content)

        # Extract Gin/Echo routes
        entry_points.extend(self._extract_routes(root, content, file_path, group_prefixes))

        # Extract cron jobs
        entry_points.extend(self._extract_cron_jobs(root, content, file_path))

        return entry_points

    def _extract_group_prefixes(self, root: Any, content: str) -> dict[str, str]:
        """Extract route group prefixes.

        Args:
            root: Root node of the AST.
            content: Original source code content.

        Returns:
            Dict mapping variable names to prefixes.
        """
        prefixes: dict[str, str] = {}

        try:
            query = self._query(self.GIN_GROUP_QUERY)
            captures = query.captures(root)

            var_name = None

            for capture_name, node in captures:
                if capture_name == "group_var":
                    var_name = self._get_text(node, content)
                elif capture_name == "prefix" and var_name:
                    prefix = self._get_text(node, content).strip('"\'')
                    prefixes[var_name] = prefix
                    var_name = None

        except Exception as e:
            self.logger.debug(f"Failed to extract group prefixes: {e}")

        return prefixes

    def _extract_routes(
        self,
        root: Any,
        content: str,
        file_path: Path,
        group_prefixes: dict[str, str],
    ) -> list[EntryPoint]:
        """Extract Gin/Echo HTTP routes.

        Args:
            root: Root node of the AST.
            content: Original source code content.
            file_path: Path to the source file.
            group_prefixes: Dict of variable name to prefix mappings.

        Returns:
            List of HTTP entry points.
        """
        entry_points: list[EntryPoint] = []

        try:
            query = self._query(self.GIN_ROUTE_QUERY)
            captures = query.captures(root)

            current_data: dict[str, Any] = {}

            for capture_name, node in captures:
                if capture_name == "method":
                    current_data["method"] = self._get_text(node, content)
                    current_data["router_var"] = current_data.get("router_var")
                elif capture_name == "router_var":
                    current_data["router_var"] = self._get_text(node, content)
                elif capture_name == "path":
                    path_text = self._get_text(node, content)
                    current_data["path"] = path_text.strip('"\'')
                elif capture_name == "handler":
                    current_data["handler"] = self._get_text(node, content)
                    current_data["line"] = self._get_line_number(node)

                # When we have all data, create entry point
                if all(k in current_data for k in ["method", "path", "handler"]):
                    method = self._get_http_method(current_data["method"])
                    router_var = current_data.get("router_var", "")
                    prefix = group_prefixes.get(router_var, "")

                    full_path = prefix + current_data["path"] if prefix else current_data["path"]
                    framework = self._detect_framework(router_var, content)

                    entry = EntryPoint(
                        type=EntryPointType.HTTP,
                        method=method,
                        path=full_path,
                        handler=current_data["handler"],
                        file=str(file_path),
                        line=current_data.get("line", 0),
                        framework=framework,
                    )
                    entry_points.append(entry)
                    current_data = {}

        except Exception as e:
            self.logger.debug(f"Failed to extract routes: {e}")

        return entry_points

    def _extract_cron_jobs(
        self, root: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract cron job definitions.

        Args:
            root: Root node of the AST.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of CRON entry points.
        """
        entry_points: list[EntryPoint] = []

        try:
            query = self._query(self.CRON_QUERY)
            captures = query.captures(root)

            schedule = None
            handler = None

            for capture_name, node in captures:
                if capture_name == "schedule":
                    schedule = self._get_text(node, content).strip('"\'')
                elif capture_name == "handler":
                    handler = self._get_text(node, content)
                    line_num = self._get_line_number(node)

                if schedule and handler:
                    entry = EntryPoint(
                        type=EntryPointType.CRON,
                        path=schedule,
                        handler=handler,
                        file=str(file_path),
                        line=line_num,
                        framework="cron",
                        metadata={"schedule": schedule},
                    )
                    entry_points.append(entry)
                    schedule = None
                    handler = None

        except Exception as e:
            self.logger.debug(f"Failed to extract cron jobs: {e}")

        return entry_points

    def _get_http_method(self, method_str: str) -> HTTPMethod:
        """Get HTTP method from string.

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
            "Any": HTTPMethod.ALL,
            "ANY": HTTPMethod.ALL,
        }
        return mapping.get(method_str.upper(), HTTPMethod.ALL)

    def _detect_framework(self, var_name: str, content: str) -> str:
        """Detect framework from variable name and context.

        Args:
            var_name: Router variable name.
            content: Source code content.

        Returns:
            Framework name.
        """
        # Check for common patterns
        if "gin" in content.lower() or "Gin" in var_name:
            return "gin"
        if "echo" in content.lower() or "Echo" in var_name:
            return "echo"
        if "fiber" in content.lower():
            return "fiber"
        if "chi" in content.lower():
            return "chi"
        # Default to gin as most common
        return "gin"
