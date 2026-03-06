"""
Python Call Graph Builder.

Builds call graphs from Python source code using Tree-sitter AST parsing.
Supports:
- Function definitions
- Method definitions
- Function calls
- Method calls
- Decorator detection (entry points)
"""

from typing import Any

import tree_sitter_python as tspython

from src.layers.l3_analysis.call_graph.builders.base import CallGraphBuilder
from src.layers.l3_analysis.call_graph.models import (
    CallEdge,
    CallNode,
    CallType,
    NodeType,
)


class PythonCallGraphBuilder(CallGraphBuilder):
    """Call graph builder for Python code."""

    language_module = tspython
    language_name = "python"
    file_extensions = [".py", ".pyw"]

    # Entry point decorators
    ENTRY_POINT_DECORATORS = {
        # Flask
        "route", "get", "post", "put", "delete", "patch",
        # FastAPI
        "api_route",
        # Celery
        "task", "shared_task",
        # Click
        "command", "group",
    }

    def _extract_functions(
        self,
        root: Any,
        content: str,
        file_path: str,
    ) -> list[CallNode]:
        """Extract all function and method definitions from AST."""
        nodes = []

        # Manual traversal to find function definitions
        self._traverse_for_functions(root, content, file_path, nodes, None)

        return nodes

    def _traverse_for_functions(
        self,
        node: Any,
        content: str,
        file_path: str,
        nodes: list[CallNode],
        class_name: str | None,
    ) -> None:
        """Recursively traverse AST to find functions and methods."""
        if node.type == "class_definition":
            # Get class name
            for child in node.children:
                if child.type == "identifier":
                    class_name = self._get_text(child, content)
                    break

        if node.type == "function_definition":
            # This is a function or method
            func_name = None
            for child in node.children:
                if child.type == "identifier":
                    func_name = self._get_text(child, content)
                    break

            if func_name:
                line = self._get_line_number(node)
                node_id = self._create_node_id(file_path, func_name, class_name)

                # Check for entry point decorators
                is_entry, entry_type = self._check_entry_point(
                    node, content, func_name
                )

                call_node = CallNode(
                    id=node_id,
                    name=func_name,
                    file_path=file_path,
                    line=line,
                    node_type=NodeType.METHOD if class_name else NodeType.FUNCTION,
                    is_entry_point=is_entry,
                    entry_point_type=entry_type,
                    class_name=class_name,
                )
                nodes.append(call_node)

        # Recurse into children
        for child in node.children:
            # Track class context for methods
            current_class = class_name
            if node.type == "class_definition":
                for c in node.children:
                    if c.type == "identifier":
                        current_class = self._get_text(c, content)
                        break
            self._traverse_for_functions(child, content, file_path, nodes, current_class)

    def _check_entry_point(
        self,
        func_node: Any,
        content: str,
        func_name: str,
    ) -> tuple[bool, str | None]:
        """Check if a function is an entry point based on decorators."""
        if not func_node:
            return False, None

        # Look for decorated_definition parent
        parent = func_node.parent
        if parent and parent.type == "decorated_definition":
            decorators = []
            for child in parent.children:
                if child.type == "decorator":
                    decorator_text = self._get_text(child, content)
                    decorators.append(decorator_text)

            entry_type = self._parse_decorators_for_entry(decorators)
            if entry_type:
                return True, entry_type

        return False, None

    def _parse_decorators_for_entry(self, decorators: list[str]) -> str | None:
        """Parse decorators to determine entry point type."""
        for dec in decorators:
            dec_lower = dec.lower()

            # Flask/FastAPI HTTP routes
            if any(d in dec_lower for d in ["@app.route", "@route", "@get(", "@post(", "@put(", "@delete(", "@patch("]):
                return "HTTP"

            # Celery tasks
            if "task" in dec_lower:
                return "ASYNC_TASK"

            # Click CLI
            if "@command" in dec_lower or "@group" in dec_lower:
                return "CLI"

        return None

    def _extract_calls(
        self,
        func_node: CallNode,
        root: Any,
        content: str,
        file_path: str,
    ) -> list[CallEdge]:
        """Extract function calls from a function body."""
        calls = []

        # Find the function definition in AST
        func_ast = self._find_function_ast(root, content, func_node.name, func_node.class_name)
        if not func_ast:
            return calls

        # Find all call expressions in the function body
        self._extract_calls_from_node(
            func_ast, func_node, content, file_path, calls
        )

        return calls

    def _find_function_ast(
        self,
        root: Any,
        content: str,
        func_name: str,
        class_name: str | None = None,
    ) -> Any | None:
        """Find the AST node for a function."""
        return self._find_function_in_tree(root, content, func_name, class_name, None)

    def _find_function_in_tree(
        self,
        node: Any,
        content: str,
        func_name: str,
        class_name: str | None,
        current_class: str | None,
    ) -> Any | None:
        """Recursively search for function in tree."""
        # Track class context
        if node.type == "class_definition":
            for child in node.children:
                if child.type == "identifier":
                    current_class = self._get_text(child, content)
                    break

        if node.type == "function_definition":
            name_node = None
            for child in node.children:
                if child.type == "identifier":
                    name_node = self._get_text(child, content)
                    break

            if name_node == func_name:
                # Check if this is a method (in a class)
                if class_name:
                    if current_class == class_name:
                        return node
                else:
                    # Standalone function
                    if current_class is None:
                        return node

        # Recurse into children
        for child in node.children:
            result = self._find_function_in_tree(
                child, content, func_name, class_name, current_class
            )
            if result:
                return result

        return None

    def _extract_calls_from_node(
        self,
        node: Any,
        caller_node: CallNode,
        content: str,
        file_path: str,
        calls: list[CallEdge],
    ) -> None:
        """Recursively extract call expressions from a node."""
        if node.type == "call":
            callee_name = self._extract_callee_name(node, content)

            if callee_name:
                line = self._get_line_number(node)
                callee_id = self._create_callee_id(file_path, callee_name)

                # Determine call type
                call_type = self._determine_call_type(node, content)

                edge = CallEdge(
                    caller_id=caller_node.id,
                    callee_id=callee_id,
                    call_site=f"{file_path}:{line}",
                    call_type=call_type,
                    line_number=line,
                )
                calls.append(edge)

        # Recurse into children
        for child in node.children:
            self._extract_calls_from_node(child, caller_node, content, file_path, calls)

    def _extract_callee_name(self, call_node: Any, content: str) -> str | None:
        """Extract the name of the called function/method."""
        for child in call_node.children:
            if child.type == "identifier":
                # Direct function call: func()
                return self._get_text(child, content)
            elif child.type == "attribute":
                # Method call: obj.method()
                attr_name = None
                for attr_child in child.children:
                    if attr_child.type == "identifier":
                        attr_name = self._get_text(attr_child, content)
                return attr_name
            elif child.type == "call":
                # Chained call: func()()
                return self._extract_callee_name(child, content)

        return None

    def _determine_call_type(self, call_node: Any, content: str) -> CallType:
        """Determine the type of call (direct, virtual, etc.)."""
        for child in call_node.children:
            if child.type == "attribute":
                return CallType.VIRTUAL
            elif child.type == "identifier":
                return CallType.DIRECT
        return CallType.DIRECT
