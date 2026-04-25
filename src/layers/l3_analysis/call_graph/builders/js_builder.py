"""
JavaScript/TypeScript Call Graph Builder.

Builds call graphs from JavaScript and TypeScript source code using
Tree-sitter AST parsing.  Supports:

- Function declarations, function expressions, arrow functions
- Method definitions (classes, objects)
- Direct calls, method calls, constructor (new) calls
- Property access / optional chaining
- Import / require relationships
- Export relationships
- Class declarations with method, getter, and setter definitions
"""

from typing import Any

try:
    import tree_sitter_javascript as tsjs
except ImportError:
    tsjs = None  # type: ignore[assignment]

from src.layers.l3_analysis.call_graph.builders.base import CallGraphBuilder
from src.layers.l3_analysis.call_graph.models import (
    CallEdge,
    CallNode,
    CallType,
    NodeType,
)

# Tree-sitter node types that represent callable definitions.
_FUNCTION_NODE_TYPES = frozenset({
    "function_declaration",
    "function",
    "arrow_function",
    "generator_function_declaration",
    "generator_function",
})

# Node types inside a class body that act as method-like definitions.
_METHOD_NODE_TYPES = frozenset({
    "method_definition",
    "getter",
    "setter",
})

# Expressions that represent a call site.
_CALL_NODE_TYPES = frozenset({
    "call_expression",
    "new_expression",
})

# Keywords commonly used in JS/TS that indicate an entry-point handler.
_ENTRY_POINT_HANDLER_NAMES = frozenset({
    # Express / Connect / HTTP
    "get", "post", "put", "delete", "patch", "all", "use", "head", "options",
    # Fastify
    "fastify", "inject",
    # Koa
    "use",
    # AWS Lambda handlers
    "handler", "lambdaHandler",
})


class JSCallGraphBuilder(CallGraphBuilder):
    """Call graph builder for JavaScript and TypeScript code."""

    language_module = tsjs
    language_name = "javascript"
    file_extensions = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

    # ------------------------------------------------------------------
    # Function / method extraction
    # ------------------------------------------------------------------

    def _extract_functions(
        self,
        root: Any,
        content: str,
        file_path: str,
    ) -> list[CallNode]:
        """Extract all function, method, and class definitions from AST."""
        nodes: list[CallNode] = []
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
        """Recursively walk the AST collecting function/method definitions."""
        # ---- class context tracking ----
        if node.type == "class_declaration":
            class_name = self._first_child_text(node, "identifier", content)
            # Also emit a CLASS node so the graph can represent the type.
            self._maybe_emit_class_node(node, content, file_path, class_name, nodes)

        # ---- standalone / nested function declarations ----
        if node.type in _FUNCTION_NODE_TYPES:
            func_name = self._extract_func_name(node, content)
            if func_name:
                self._emit_function_node(
                    node, content, file_path, func_name, class_name, nodes
                )

        # ---- variable declarator that holds a function / arrow ----
        if node.type == "variable_declarator":
            self._maybe_extract_var_func(node, content, file_path, class_name, nodes)

        # ---- class methods, getters, setters ----
        if node.type in _METHOD_NODE_TYPES:
            method_name = self._method_name(node, content)
            if method_name:
                self._emit_function_node(
                    node, content, file_path, method_name, class_name, nodes
                )

        # ---- export statements that wrap functions ----
        if node.type in ("export_statement", "export_default_declaration"):
            self._extract_from_export(node, content, file_path, nodes)

        # Recurse into children while propagating class context.
        for child in node.children:
            self._traverse_for_functions(
                child, content, file_path, nodes,
                class_name if node.type != "class_declaration"
                else class_name,
            )

    # ------------------------------------------------------------------
    # Helpers: name extraction
    # ------------------------------------------------------------------

    def _extract_func_name(self, node: Any, content: str) -> str | None:
        """Get the declared name of a function-like node."""
        # function_declaration / generator_function_declaration have a named
        # child "identifier" for the name.
        return self._first_child_text(node, "identifier", content)

    def _method_name(self, node: Any, content: str) -> str | None:
        """Get the name of a method_definition / getter / setter node."""
        # The property name is the first child whose type is one of the
        # "property_identifier" family.
        for child in node.children:
            if child.type in (
                "property_identifier",
                "private_property_identifier",
                "string",
            ):
                return self._get_text(child, content)
        return None

    def _maybe_extract_var_func(
        self,
        node: Any,
        content: str,
        file_path: str,
        class_name: str | None,
        nodes: list[CallNode],
    ) -> None:
        """Check if a variable_declarator assigns a function/arrow value."""
        name_id = None
        value_is_func = False
        for child in node.children:
            if child.type == "identifier":
                name_id = self._get_text(child, content)
            if child.type in _FUNCTION_NODE_TYPES:
                value_is_func = True
            # Handle `require()` initialisers that return a function.
            if child.type == "call_expression":
                callee = child.child_by_field_name("function")
                if callee and self._is_require(callee, content):
                    value_is_func = True

        if name_id and value_is_func:
            self._emit_function_node(
                node, content, file_path, name_id, class_name, nodes
            )

    def _extract_from_export(
        self,
        node: Any,
        content: str,
        file_path: str,
        nodes: list[CallNode],
    ) -> None:
        """Look for function definitions nested inside export statements."""
        for child in node.children:
            if child.type in _FUNCTION_NODE_TYPES:
                func_name = self._extract_func_name(child, content)
                if func_name:
                    self._emit_function_node(
                        child, content, file_path, func_name, None, nodes
                    )
            if child.type == "variable_declaration":
                for decl in child.children:
                    if decl.type == "variable_declarator":
                        self._maybe_extract_var_func(
                            decl, content, file_path, None, nodes
                        )

    # ------------------------------------------------------------------
    # Helpers: node emission
    # ------------------------------------------------------------------

    def _emit_function_node(
        self,
        node: Any,
        content: str,
        file_path: str,
        func_name: str,
        class_name: str | None,
        nodes: list[CallNode],
    ) -> None:
        """Create and append a CallNode for the given AST function node."""
        line = self._get_line_number(node)
        node_id = self._create_node_id(file_path, func_name, class_name)

        is_entry, entry_type = self._check_entry_point(node, content, func_name)

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

    def _maybe_emit_class_node(
        self,
        node: Any,
        content: str,
        file_path: str,
        class_name: str | None,
        nodes: list[CallNode],
    ) -> None:
        """Emit a CLASS CallNode for a class_declaration."""
        if not class_name:
            return
        line = self._get_line_number(node)
        node_id = self._create_node_id(file_path, class_name, None)
        nodes.append(CallNode(
            id=node_id,
            name=class_name,
            file_path=file_path,
            line=line,
            node_type=NodeType.CLASS,
        ))

    # ------------------------------------------------------------------
    # Entry point detection
    # ------------------------------------------------------------------

    def _check_entry_point(
        self,
        func_node: Any,
        content: str,
        func_name: str,
    ) -> tuple[bool, str | None]:
        """Heuristically determine if a function is an external entry point."""
        # 1. Exported functions are entry points.
        if self._is_exported(func_node):
            return True, "EXPORT"

        # 2. Handler-named functions (AWS Lambda, etc.).
        if func_name in ("handler", "lambdaHandler", "main"):
            return True, "HANDLER"

        # 3. Functions whose name starts with uppercase and are exported
        #    (React component convention).
        if func_name and func_name[0].isupper() and self._is_exported(func_node):
            return True, "COMPONENT"

        return False, None

    def _is_exported(self, node: Any) -> bool:
        """Walk upward to see if the node is inside an export statement."""
        current = node.parent
        while current:
            if current.type in (
                "export_statement",
                "export_default_declaration",
                "export_clause",
            ):
                return True
            current = current.parent
        return False

    # ------------------------------------------------------------------
    # Call extraction
    # ------------------------------------------------------------------

    def _extract_calls(
        self,
        func_node: CallNode,
        root: Any,
        content: str,
        file_path: str,
    ) -> list[CallEdge]:
        """Extract call expressions from the body of *func_node*."""
        calls: list[CallEdge] = []

        func_ast = self._find_function_ast(
            root, content, func_node.name, func_node.class_name
        )
        if func_ast is None:
            return calls

        self._extract_calls_from_node(func_ast, func_node, content, file_path, calls)
        return calls

    def _find_function_ast(
        self,
        root: Any,
        content: str,
        func_name: str,
        class_name: str | None = None,
    ) -> Any | None:
        """Locate the AST node for a given function name."""
        return self._find_in_tree(root, content, func_name, class_name, None)

    def _find_in_tree(
        self,
        node: Any,
        content: str,
        func_name: str,
        class_name: str | None,
        current_class: str | None,
    ) -> Any | None:
        """Recursive search for a function AST node."""
        if node.type == "class_declaration":
            current_class = self._first_child_text(node, "identifier", content)

        if node.type in _FUNCTION_NODE_TYPES:
            name = self._extract_func_name(node, content)
            if name == func_name:
                if class_name:
                    if current_class == class_name:
                        return node
                elif current_class is None:
                    return node

        if node.type in _METHOD_NODE_TYPES:
            name = self._method_name(node, content)
            if name == func_name and current_class == class_name:
                return node

        if node.type == "variable_declarator":
            for child in node.children:
                if child.type == "identifier":
                    vname = self._get_text(child, content)
                    if vname == func_name and current_class == class_name:
                        return node

        for child in node.children:
            result = self._find_in_tree(
                child, content, func_name, class_name, current_class
            )
            if result is not None:
                return result
        return None

    # ------------------------------------------------------------------
    # Call-site traversal
    # ------------------------------------------------------------------

    def _extract_calls_from_node(
        self,
        node: Any,
        caller_node: CallNode,
        content: str,
        file_path: str,
        calls: list[CallEdge],
    ) -> None:
        """Walk a subtree collecting call_expression / new_expression nodes."""
        if node.type in _CALL_NODE_TYPES:
            callee_name = self._extract_callee_name(node, content)
            if callee_name:
                line = self._get_line_number(node)
                callee_id = self._create_callee_id(file_path, callee_name)
                call_type = self._determine_call_type(node, content)

                calls.append(CallEdge(
                    caller_id=caller_node.id,
                    callee_id=callee_id,
                    call_site=f"{file_path}:{line}",
                    call_type=call_type,
                    line_number=line,
                ))

        # Recurse into children.
        for child in node.children:
            self._extract_calls_from_node(
                child, caller_node, content, file_path, calls
            )

    def _extract_callee_name(self, call_node: Any, content: str) -> str | None:
        """Resolve the name being called from a call/new expression."""
        func_node = call_node.child_by_field_name("function")
        if func_node is None:
            return None

        # Direct identifier call:  foo()
        if func_node.type == "identifier":
            return self._get_text(func_node, content)

        # Member expression:  obj.method()  /  obj?.method()
        if func_node.type in ("member_expression", "optional_chain"):
            return self._member_name(func_node, content)

        # Chained / nested call:  foo()()
        if func_node.type in _CALL_NODE_TYPES:
            return self._extract_callee_name(func_node, content)

        # Call via computed property:  obj[fnName]()
        if func_node.type == "computed_property_name":
            return self._get_text(func_node, content)

        return None

    def _member_name(self, member_node: Any, content: str) -> str:
        """Extract the property name from a member_expression or optional_chain."""
        prop = member_node.child_by_field_name("property")
        if prop is not None:
            return self._get_text(prop, content)
        # Fallback: last identifier child.
        for child in reversed(member_node.children):
            if child.type in ("property_identifier", "identifier"):
                return self._get_text(child, content)
        return self._get_text(member_node, content)

    def _determine_call_type(self, call_node: Any, content: str) -> CallType:
        """Classify the call as DIRECT, VIRTUAL, or DYNAMIC."""
        func_node = call_node.child_by_field_name("function")
        if func_node is None:
            return CallType.DIRECT

        if call_node.type == "new_expression":
            return CallType.DIRECT

        if func_node.type in ("member_expression", "optional_chain"):
            return CallType.VIRTUAL

        if func_node.type in _CALL_NODE_TYPES:
            # Chained call -- look deeper.
            return self._determine_call_type(func_node, content)

        return CallType.DIRECT

    # ------------------------------------------------------------------
    # Import / require helpers (metadata enrichment)
    # ------------------------------------------------------------------

    def _is_require(self, callee_node: Any, content: str) -> bool:
        """Return True if the callee is `require`."""
        return (
            callee_node.type == "identifier"
            and self._get_text(callee_node, content) == "require"
        )

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _first_child_text(
        self, node: Any, child_type: str, content: str
    ) -> str | None:
        """Return text of the first child matching *child_type*, or None."""
        for child in node.children:
            if child.type == child_type:
                return self._get_text(child, content)
        return None
