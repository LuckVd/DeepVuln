"""
Java Call Graph Builder.

Builds call graphs from Java source code using Tree-sitter AST parsing.
Supports:
- Method declarations (instance, static, constructors)
- Method invocations (instance, static, chained)
- Constructor calls (new expressions)
- Field access (read/write)
- Import relationships
- Inheritance (extends / implements)
- Interface method detection
- Entry point detection (main method, servlets, Spring annotations)
"""

from typing import Any

try:
    import tree_sitter_java as tsjava
except ImportError:
    tsjava = None  # type: ignore[assignment]

from src.layers.l3_analysis.call_graph.builders.base import CallGraphBuilder
from src.layers.l3_analysis.call_graph.models import (
    CallEdge,
    CallNode,
    CallType,
    NodeType,
)

_METHOD_NODE_TYPES = frozenset({"method_declaration", "constructor_declaration"})
_CALL_NODE_TYPES = frozenset({"method_invocation", "object_creation_expression"})
_HTTP_ANNOTATIONS = frozenset({
    "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
    "DeleteMapping", "PatchMapping", "Path", "GET", "POST", "PUT", "DELETE",
    "WebServlet", "WebFilter", "WebListener",
})
_LISTENER_ANNOTATIONS = frozenset({"RabbitListener", "KafkaListener", "JmsListener"})
_SERVLET_METHODS = frozenset({
    "doGet", "doPost", "doPut", "doDelete", "service", "init", "destroy",
})


class JavaCallGraphBuilder(CallGraphBuilder):
    """Call graph builder for Java code."""

    language_module = tsjava
    language_name = "java"
    file_extensions = [".java"]

    # -- Abstract interface implementation -----------------------------------

    def _extract_functions(
        self, root: Any, content: str, file_path: str,
    ) -> list[CallNode]:
        """Extract all method and constructor definitions from AST."""
        nodes: list[CallNode] = []
        self._traverse_for_functions(root, content, file_path, nodes, None)
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

    # -- AST traversal for function definitions ------------------------------

    def _traverse_for_functions(
        self, node: Any, content: str, file_path: str,
        nodes: list[CallNode], class_name: str | None,
    ) -> None:
        """Recursively walk the AST collecting method/constructor definitions."""
        if node.type in ("class_declaration", "enum_declaration"):
            class_name = self._first_child_text(node, "identifier", content)
            self._maybe_emit_class_node(node, content, file_path, class_name, nodes)

        if node.type == "interface_declaration":
            iface = self._first_child_text(node, "identifier", content)
            self._maybe_emit_class_node(node, content, file_path, iface, nodes)

        if node.type in _METHOD_NODE_TYPES:
            name = self._extract_method_name(node, content, class_name)
            if name:
                self._emit_method_node(node, content, file_path, name, class_name, nodes)

        if node.type == "compact_constructor_declaration":
            name = self._first_child_text(node, "identifier", content)
            if name:
                self._emit_method_node(node, content, file_path, name, class_name, nodes)

        for child in node.children:
            child_class = class_name
            if node.type in ("class_declaration", "enum_declaration"):
                for c in node.children:
                    if c.type == "identifier":
                        child_class = self._get_text(c, content)
                        break
            self._traverse_for_functions(child, content, file_path, nodes, child_class)

    def _extract_method_name(
        self, node: Any, content: str, class_name: str | None,
    ) -> str | None:
        """Get the declared name of a method or constructor."""
        if node.type == "constructor_declaration":
            return "<init>" if not class_name else class_name
        return self._first_child_text(node, "identifier", content)

    # -- Node emission -------------------------------------------------------

    def _emit_method_node(
        self, node: Any, content: str, file_path: str,
        func_name: str, class_name: str | None, nodes: list[CallNode],
    ) -> None:
        """Create and append a CallNode for the given AST method node."""
        line = self._get_line_number(node)
        is_entry, entry_type = self._check_entry_point(node, content, func_name)
        nodes.append(CallNode(
            id=self._create_node_id(file_path, func_name, class_name),
            name=func_name, file_path=file_path, line=line,
            node_type=NodeType.METHOD if class_name else NodeType.FUNCTION,
            is_entry_point=is_entry, entry_point_type=entry_type,
            class_name=class_name,
            metadata=self._method_metadata(node, content),
        ))

    def _maybe_emit_class_node(
        self, node: Any, content: str, file_path: str,
        class_name: str | None, nodes: list[CallNode],
    ) -> None:
        """Emit a CLASS CallNode for a class or interface declaration."""
        if not class_name:
            return
        nodes.append(CallNode(
            id=self._create_node_id(file_path, class_name, None),
            name=class_name, file_path=file_path,
            line=self._get_line_number(node), node_type=NodeType.CLASS,
            metadata=self._class_metadata(node, content),
        ))

    # -- Metadata extraction -------------------------------------------------

    def _method_metadata(self, node: Any, content: str) -> dict[str, Any]:
        """Extract method-level metadata (modifiers, return type, static flag)."""
        meta: dict[str, Any] = {}
        modifiers: list[str] = []
        return_type = None
        for child in node.children:
            if child.type == "modifiers":
                modifiers.extend(self._get_text(m, content) for m in child.children)
            if child.type in ("type_identifier", "void_type", "generic_type"):
                return_type = self._get_text(child, content)
        if modifiers:
            meta["modifiers"] = modifiers
        if return_type:
            meta["return_type"] = return_type
        meta["is_static"] = any("static" in m for m in modifiers)
        return meta

    def _class_metadata(self, node: Any, content: str) -> dict[str, Any]:
        """Extract class-level metadata (superclass, interfaces, modifiers)."""
        meta: dict[str, Any] = {}
        modifiers: list[str] = []
        superclass = None
        interfaces: list[str] = []
        for child in node.children:
            if child.type == "modifiers":
                modifiers.extend(self._get_text(m, content) for m in child.children)
            if child.type == "superclass":
                for sc in child.children:
                    if sc.type == "type_identifier":
                        superclass = self._get_text(sc, content)
            if child.type == "super_interfaces":
                self._collect_type_identifiers(child, content, interfaces)
        if modifiers:
            meta["modifiers"] = modifiers
        if superclass:
            meta["superclass"] = superclass
        if interfaces:
            meta["interfaces"] = interfaces
        return meta

    def _collect_type_identifiers(
        self, node: Any, content: str, names: list[str],
    ) -> None:
        """Recursively collect type_identifier names from a subtree."""
        for child in node.children:
            if child.type == "type_identifier":
                names.append(self._get_text(child, content))
            elif child.is_named:
                self._collect_type_identifiers(child, content, names)

    # -- Entry point detection -----------------------------------------------

    def _check_entry_point(
        self, func_node: Any, content: str, func_name: str,
    ) -> tuple[bool, str | None]:
        """Determine if a method is an external entry point."""
        annotations = self._collect_annotations(func_node, content)
        for ann in annotations:
            if ann in _HTTP_ANNOTATIONS:
                return True, "HTTP"
            if ann in _LISTENER_ANNOTATIONS:
                return True, "ASYNC_TASK"
            if ann == "Scheduled":
                return True, "SCHEDULED"

        if func_name == "main" and self._is_main_method(func_node, content):
            return True, "MAIN"
        if func_name in _SERVLET_METHODS:
            return True, "HTTP"
        return False, None

    def _collect_annotations(self, node: Any, content: str) -> list[str]:
        """Gather annotation names from the modifiers of a node."""
        names: list[str] = []
        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    if mod.type in ("marker_annotation", "annotation"):
                        ann = self._first_child_text(mod, "identifier", content)
                        if ann:
                            names.append(ann)
        return names

    def _is_main_method(self, node: Any, content: str) -> bool:
        """Check if a method matches `public static void main`."""
        is_public = is_static = is_void = False
        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    t = self._get_text(mod, content)
                    if t == "public":
                        is_public = True
                    elif t == "static":
                        is_static = True
            if child.type == "void_type":
                is_void = True
        return is_public and is_static and is_void

    # -- Call-site traversal -------------------------------------------------

    def _find_function_ast(
        self, root: Any, content: str, func_name: str, class_name: str | None = None,
    ) -> Any | None:
        """Locate the AST node for a given method name."""
        return self._find_in_tree(root, content, func_name, class_name, None)

    def _find_in_tree(
        self, node: Any, content: str, func_name: str,
        class_name: str | None, current_class: str | None,
    ) -> Any | None:
        """Recursive search for a method AST node."""
        if node.type in ("class_declaration", "enum_declaration"):
            current_class = self._first_child_text(node, "identifier", content)

        if node.type in _METHOD_NODE_TYPES:
            name = self._extract_method_name(node, content, current_class)
            if name == func_name:
                if class_name and current_class == class_name:
                    return node
                if not class_name and current_class is None:
                    return node

        for child in node.children:
            result = self._find_in_tree(child, content, func_name, class_name, current_class)
            if result is not None:
                return result
        return None

    def _extract_calls_from_node(
        self, node: Any, caller_node: CallNode, content: str,
        file_path: str, calls: list[CallEdge],
    ) -> None:
        """Walk a subtree collecting method_invocation / object_creation_expression."""
        if node.type in _CALL_NODE_TYPES:
            callee_name = self._extract_callee_name(node, content)
            if callee_name:
                line = self._get_line_number(node)
                calls.append(CallEdge(
                    caller_id=caller_node.id,
                    callee_id=self._create_callee_id(file_path, callee_name),
                    call_site=f"{file_path}:{line}",
                    call_type=self._determine_call_type(node, content),
                    line_number=line,
                    metadata=self._call_metadata(node, content),
                ))
        for child in node.children:
            self._extract_calls_from_node(child, caller_node, content, file_path, calls)

    # -- Callee name resolution ----------------------------------------------

    def _extract_callee_name(self, call_node: Any, content: str) -> str | None:
        """Resolve the name being called from a method_invocation or new expression."""
        if call_node.type == "method_invocation":
            # The identifier child is the method name regardless of receiver.
            return self._first_child_text(call_node, "identifier", content)

        if call_node.type == "object_creation_expression":
            # new ClassName() or new ClassName<T>()
            for child in call_node.children:
                if child.type == "type_identifier":
                    return self._get_text(child, content)
                if child.type == "generic_type":
                    return self._first_child_text(child, "type_identifier", content)
        return None

    def _determine_call_type(self, call_node: Any, content: str) -> CallType:
        """Classify the call as DIRECT or VIRTUAL."""
        if call_node.type == "object_creation_expression":
            return CallType.DIRECT

        # Method invocation: virtual if there is a receiver object.
        for child in call_node.children:
            txt = self._get_text(child, content)
            if child.type == "identifier" and txt in ("super", "this"):
                return CallType.VIRTUAL
            if child.type in ("field_access", "method_invocation", "primary_expression"):
                return CallType.VIRTUAL
            if child.type == ".":
                return CallType.VIRTUAL

        return CallType.DIRECT

    def _call_metadata(self, call_node: Any, content: str) -> dict[str, Any]:
        """Enrich call edge with Java-specific metadata."""
        meta: dict[str, Any] = {}
        if call_node.type == "object_creation_expression":
            meta["call_kind"] = "constructor"
            for child in call_node.children:
                if child.type in ("type_identifier", "generic_type"):
                    meta["constructed_type"] = self._get_text(child, content)
        elif call_node.type == "method_invocation":
            meta["call_kind"] = "method"
            for child in call_node.children:
                txt = self._get_text(child, content)
                if txt == "super":
                    meta["qualifier"] = "super"
                elif txt == "this":
                    meta["qualifier"] = "this"
            for child in call_node.children:
                if child.type == "argument_list":
                    meta["argument_count"] = sum(1 for a in child.children if a.is_named)
        return meta

    # -- Import extraction ---------------------------------------------------

    def _extract_imports(self, root: Any, content: str) -> list[dict[str, Any]]:
        """Extract import declarations with path, is_static, is_wildcard."""
        imports: list[dict[str, Any]] = []
        self._collect_imports(root, content, imports)
        return imports

    def _collect_imports(
        self, node: Any, content: str, imports: list[dict[str, Any]],
    ) -> None:
        """Recursively find import_declaration nodes."""
        if node.type == "import_declaration":
            is_static = is_wildcard = False
            full_path = None
            for child in node.children:
                txt = self._get_text(child, content)
                if txt == "static":
                    is_static = True
                elif child.type == "asterisk":
                    is_wildcard = True
                elif child.type in ("scoped_identifier", "scoped_type_identifier"):
                    full_path = txt
            if full_path:
                if is_wildcard and not full_path.endswith(".*"):
                    full_path += ".*"
                imports.append({
                    "path": full_path,
                    "is_static": is_static,
                    "is_wildcard": is_wildcard,
                })
            return
        for child in node.children:
            self._collect_imports(child, content, imports)

    # -- Utility helpers -----------------------------------------------------

    def _first_child_text(
        self, node: Any, child_type: str, content: str,
    ) -> str | None:
        """Return text of the first child matching *child_type*, or None."""
        for child in node.children:
            if child.type == child_type:
                return self._get_text(child, content)
        return None
