"""
Go Call Graph Builder.

Builds call graphs from Go source code using tree-sitter AST parsing.
Supports:
- Function declarations (``func ...``)
- Method declarations (``func (recv Type) ...``)
- Call expressions: direct (``f()``), method/selector (``s.m()``), chained
- Entry-point detection: ``main``, ``init``, net/http handler signature
  (params containing ``http.ResponseWriter`` + ``*http.Request``)

Phase 18/P2-Go: previously Go had no call-graph builder, so Go files were
silently skipped and the Go attack-path reachability chain was empty.
"""

from typing import Any

try:
    import tree_sitter_go as tsgo
except ImportError:
    tsgo = None  # type: ignore[assignment]

from src.layers.l3_analysis.call_graph.builders.base import CallGraphBuilder
from src.layers.l3_analysis.call_graph.models import (
    CallEdge,
    CallNode,
    CallType,
    NodeType,
)

_FUNC_NODE_TYPES = frozenset({"function_declaration", "method_declaration"})
_HTTP_RESPONSE = "ResponseWriter"
_HTTP_REQUEST = "Request"


class GoCallGraphBuilder(CallGraphBuilder):
    """Call graph builder for Go code."""

    language_module = tsgo
    language_name = "go"
    file_extensions = [".go"]

    # -- Abstract interface implementation -------------------------------

    def _extract_functions(
        self, root: Any, content: str, file_path: str,
    ) -> list[CallNode]:
        """Extract all function/method definitions from AST."""
        nodes: list[CallNode] = []
        self._traverse_for_functions(root, content, file_path, nodes)
        return nodes

    def _extract_calls(
        self, func_node: CallNode, root: Any, content: str, file_path: str,
    ) -> list[CallEdge]:
        """Extract call expressions from the body of *func_node*."""
        calls: list[CallEdge] = []
        func_ast = self._find_function_ast(root, content, func_node.name, func_node.class_name)
        if func_ast is not None:
            self._extract_calls_from_node(func_ast, func_node, content, file_path, calls)
        return calls

    # -- Function extraction ----------------------------------------------

    def _traverse_for_functions(
        self, node: Any, content: str, file_path: str, nodes: list[CallNode],
    ) -> None:
        """Recursively walk the AST collecting function/method definitions."""
        if node.type in _FUNC_NODE_TYPES:
            name = self._func_name(node, content)
            recv = (
                self._receiver_type(node, content)
                if node.type == "method_declaration" else None
            )
            if name:
                self._emit_node(node, content, file_path, name, recv, nodes)
        for child in node.children:
            self._traverse_for_functions(child, content, file_path, nodes)

    def _func_name(self, node: Any, content: str) -> str | None:
        """Get the declared name of a function/method (the 'name' field)."""
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return self._get_text(name_node, content)
        return self._first_child_text(node, "identifier", content)

    def _receiver_type(self, node: Any, content: str) -> str | None:
        """Extract the receiver type of a method, e.g. ``(s *Server)`` -> ``Server``."""
        recv = node.child_by_field_name("receiver")
        if recv is None:
            return None
        for child in recv.children:
            if not child.is_named:
                continue
            text = self._get_text(child, content).replace("*", "").strip()
            if not text:
                continue
            # "s Server" -> "Server"; "s pkg.Server" -> "Server"
            token = text.split()[-1] if " " in text else text
            return token.split(".")[-1]
        return None

    def _emit_node(
        self, node: Any, content: str, file_path: str,
        func_name: str, class_name: str | None, nodes: list[CallNode],
    ) -> None:
        is_entry, entry_type = self._check_entry_point(node, content, func_name)
        nodes.append(CallNode(
            id=self._create_node_id(file_path, func_name, class_name),
            name=func_name, file_path=file_path, line=self._get_line_number(node),
            node_type=NodeType.METHOD if class_name else NodeType.FUNCTION,
            is_entry_point=is_entry, entry_point_type=entry_type,
            class_name=class_name,
            metadata={},
        ))

    # -- Entry-point detection --------------------------------------------

    def _check_entry_point(
        self, node: Any, content: str, func_name: str,
    ) -> tuple[bool, str | None]:
        """Determine if a function is an external entry point.

        Go has no annotations; entry points are detected by signature:
        - ``func main()`` (no receiver) -> MAIN
        - ``func init()`` -> INIT
        - any func/method whose params contain http.ResponseWriter + *http.Request
          -> HTTP handler
        """
        if func_name == "main" and node.child_by_field_name("receiver") is None:
            params = node.child_by_field_name("parameters")
            if params is None or not self._has_named_params(params):
                return True, "MAIN"
        if func_name == "init":
            return True, "INIT"
        params = node.child_by_field_name("parameters")
        if params is not None and self._has_http_handler_signature(params, content):
            return True, "HTTP"
        return False, None

    @staticmethod
    def _has_named_params(params_node: Any) -> bool:
        return any(c.is_named for c in params_node.children)

    def _has_http_handler_signature(self, params_node: Any, content: str) -> bool:
        text = self._get_text(params_node, content)
        return _HTTP_RESPONSE in text and _HTTP_REQUEST in text

    # -- Call-site traversal ----------------------------------------------

    def _find_function_ast(
        self, root: Any, content: str, func_name: str, class_name: str | None = None,
    ) -> Any | None:
        return self._find_in_tree(root, content, func_name, class_name, None)

    def _find_in_tree(
        self, node: Any, content: str, func_name: str,
        class_name: str | None, current_recv: str | None,
    ) -> Any | None:
        if node.type == "method_declaration":
            current_recv = self._receiver_type(node, content)
        if node.type in _FUNC_NODE_TYPES:
            if self._func_name(node, content) == func_name:
                if class_name and current_recv == class_name:
                    return node
                if not class_name and node.type == "function_declaration":
                    return node
        for child in node.children:
            result = self._find_in_tree(child, content, func_name, class_name, current_recv)
            if result is not None:
                return result
        return None

    def _extract_calls_from_node(
        self, node: Any, caller_node: CallNode, content: str,
        file_path: str, calls: list[CallEdge],
    ) -> None:
        """Walk a subtree collecting call_expression nodes."""
        if node.type == "call_expression":
            callee = self._extract_callee_name(node, content)
            if callee:
                line = self._get_line_number(node)
                calls.append(CallEdge(
                    caller_id=caller_node.id,
                    callee_id=self._create_callee_id(file_path, callee),
                    call_site=f"{file_path}:{line}",
                    call_type=self._determine_call_type(node),
                    line_number=line,
                    metadata={},
                ))
        for child in node.children:
            self._extract_calls_from_node(child, caller_node, content, file_path, calls)

    def _extract_callee_name(self, call_node: Any, content: str) -> str | None:
        """Resolve the name being called from a call_expression.

        Handles:
        - ``f()``            -> identifier "f"
        - ``s.m()``          -> selector_expression field "m"
        - ``a.b().c()``      -> chained; recurse to the outermost selector field
        """
        func_child = call_node.child_by_field_name("function")
        if func_child is None:
            for c in call_node.children:
                if c.is_named:
                    func_child = c
                    break
        if func_child is None:
            return None
        if func_child.type == "identifier":
            return self._get_text(func_child, content)
        if func_child.type == "selector_expression":
            for c in func_child.children:
                if c.type == "field_identifier":
                    return self._get_text(c, content)
        if func_child.type == "call_expression":
            return self._extract_callee_name(func_child, content)
        return None

    def _determine_call_type(self, call_node: Any) -> CallType:
        """Classify the call as DIRECT or VIRTUAL (method/selector)."""
        func_child = call_node.child_by_field_name("function")
        if func_child is not None and func_child.type == "selector_expression":
            return CallType.VIRTUAL
        return CallType.DIRECT

    # -- Utility helpers --------------------------------------------------

    def _first_child_text(
        self, node: Any, child_type: str, content: str,
    ) -> str | None:
        for child in node.children:
            if child.type == child_type:
                return self._get_text(child, content)
        return None
