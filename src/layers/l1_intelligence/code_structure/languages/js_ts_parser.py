"""JavaScript / TypeScript code structure parser using Tree-sitter.

Handles .js, .jsx, .ts, .tsx files and extracts classes, functions, methods,
arrow functions, imports (ESM + CJS + dynamic), exports, TS interfaces,
type aliases, enums, decorators, and builds call graphs.
"""

import logging
from pathlib import Path
from typing import Any

from ..models import (
    CallEdge,
    CallGraph,
    ClassDef,
    ClassType,
    FieldDef,
    FunctionDef,
    ImportDef,
    ModuleInfo,
    Parameter,
    ParseOptions,
    Visibility,
)
from .base import LanguageParserBase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tree-sitter imports with graceful degradation
# ---------------------------------------------------------------------------
try:
    import tree_sitter_javascript as tsjs
except ImportError:
    tsjs = None  # type: ignore[assignment]

try:
    import tree_sitter_typescript as tsts
except ImportError:
    tsts = None  # type: ignore[assignment]


class JsTsStructureParser(LanguageParserBase):
    """Parser for JavaScript and TypeScript source code structure.

    Extracts classes, functions (including arrow), methods, getters/setters,
    imports (ESM, CommonJS require, dynamic import), exports, TS interfaces,
    type aliases, enums, and builds function call graphs via Tree-sitter.
    """

    extensions = [".js", ".jsx", ".ts", ".tsx"]
    language_name = "javascript"

    # Tree-sitter query patterns used by the base class helpers
    CLASS_QUERY = "(class_declaration) @class"
    FUNCTION_QUERY = (
        "(function_declaration) @func "
        "(generator_function_declaration) @func "
        "(lexical_declaration (variable_declarator value: (arrow_function))) @func "
        "(lexical_declaration (variable_declarator value: (function_expression))) @func "
        "(variable_declaration (variable_declarator value: (arrow_function))) @func "
        "(variable_declaration (variable_declarator value: (function_expression))) @func "
    )
    IMPORT_QUERY = "(import_statement) @import"
    CALL_QUERY = "(call_expression) @call"

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def __init__(self, options: ParseOptions | None = None) -> None:
        super().__init__(options)
        self._is_typescript = False

    def _init_parser(self) -> None:
        """Initialise the Tree-sitter parser for JS or TS."""
        from tree_sitter import Language, Parser

        if self._is_typescript and tsts is not None:
            lang = Language(tsts.language_typescript())
        elif not self._is_typescript and tsjs is not None:
            lang = Language(tsjs.language())
        elif tsjs is not None:
            # Fallback to JS parser for .tsx if typescript grammar unavailable
            lang = Language(tsjs.language())
        else:
            raise ImportError(
                "Neither tree-sitter-javascript nor tree-sitter-typescript is installed"
            )

        self._language = lang
        self._parser = Parser(self._language)

    # ------------------------------------------------------------------
    # Public parse entry
    # ------------------------------------------------------------------

    def parse(self, content: str, file_path: Path) -> ModuleInfo:
        """Parse JS/TS source and extract structure.

        Args:
            content: Source code text.
            file_path: Path to the file.

        Returns:
            Parsed module information.
        """
        ext = file_path.suffix.lower()
        self._is_typescript = ext in (".ts", ".tsx")
        self.language_name = "typescript" if self._is_typescript else "javascript"

        if self._parser is None:
            self._init_parser()

        module = ModuleInfo(
            file_path=str(file_path),
            language=self.language_name,
            line_count=content.count("\n") + 1,
            module_name=file_path.stem,
        )

        try:
            tree = self._parse_tree(content.encode("utf-8"))
            root = tree.root_node
            raw = content.encode("utf-8")

            module.imports = self._extract_imports_walk(root, raw)
            module.classes = self._extract_classes_walk(root, raw, file_path)
            module.functions = self._extract_top_level_functions_walk(root, raw, file_path)
            module.global_variables = self._extract_global_variables(root, raw)

            if self._is_typescript:
                # TS-specific: interfaces, type aliases, enums
                self._extract_ts_interfaces(root, raw, file_path, module)
                self._extract_ts_type_aliases(root, raw, file_path, module)
                self._extract_ts_enums(root, raw, file_path, module)

            if self.options.build_call_graph:
                module.call_graph = self._build_call_graph_walk(
                    root, raw, file_path, module
                )
        except Exception as exc:
            module.parse_errors.append(str(exc))
            logger.error("Error parsing %s: %s", file_path, exc)

        return module

    # ==================================================================
    # Imports
    # ==================================================================

    def _extract_imports_walk(self, root: Any, content: bytes) -> list[ImportDef]:
        """Walk the tree for ESM imports, require() calls, and dynamic import()."""
        imports: list[ImportDef] = []
        self._walk_imports(root, content, imports)
        return imports

    def _walk_imports(self, node: Any, content: bytes, out: list[ImportDef]) -> None:
        if node.type == "import_statement":
            imp = self._parse_esm_import(node, content)
            if imp:
                out.append(imp)
            return  # no need to recurse inside

        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if callee:
                callee_text = self._get_node_text(content, callee)
                if callee_text == "require":
                    imp = self._parse_require_call(node, content)
                    if imp:
                        out.append(imp)
                        return
                if callee_text == "import":
                    imp = self._parse_dynamic_import(node, content)
                    if imp:
                        out.append(imp)
                        return

        for child in node.children:
            self._walk_imports(child, content, out)

    def _parse_esm_import(self, node: Any, content: bytes) -> ImportDef | None:
        """Parse ``import ... from 'module'``."""
        source = None
        names: list[str] = []
        alias: str | None = None
        is_wildcard = False

        for child in node.children:
            if child.type == "string":
                source = self._strip_string(self._get_node_text(content, child))
            elif child.type == "import_clause":
                for ic in child.children:
                    if ic.type == "identifier":
                        names.append(self._get_node_text(content, ic))
                    elif ic.type == "named_imports":
                        for ni in ic.children:
                            if ni.type == "import_specifier":
                                ni_name = ni.child_by_field_name("name")
                                ni_alias = ni.child_by_field_name("alias")
                                if ni_name:
                                    names.append(self._get_node_text(content, ni_name))
                                if ni_alias:
                                    alias = self._get_node_text(content, ni_alias)
                            elif ni.type == "identifier":
                                names.append(self._get_node_text(content, ni))
                    elif ic.type == "namespace_import":
                        for ns in ic.children:
                            if ns.type == "identifier":
                                alias = self._get_node_text(content, ns)
                                is_wildcard = True
                    elif ic.type == "identifier":
                        # default import identifier at top level
                        if not names:
                            names.append(self._get_node_text(content, ic))

        if source:
            return ImportDef(
                module=source,
                names=names,
                alias=alias,
                is_wildcard=is_wildcard,
                line=self._get_node_line(node),
            )
        return None

    def _parse_require_call(self, node: Any, content: bytes) -> ImportDef | None:
        """Parse ``require('module')``."""
        args = node.child_by_field_name("arguments")
        if not args:
            return None
        for child in args.children:
            if child.type == "string":
                source = self._strip_string(self._get_node_text(content, child))
                return ImportDef(module=source, line=self._get_node_line(node))
        return None

    def _parse_dynamic_import(self, node: Any, content: bytes) -> ImportDef | None:
        """Parse ``import('module')`` (dynamic import)."""
        args = node.child_by_field_name("arguments")
        if not args:
            return None
        for child in args.children:
            if child.type == "string":
                source = self._strip_string(self._get_node_text(content, child))
                return ImportDef(module=source, line=self._get_node_line(node))
        return None

    # ==================================================================
    # Classes
    # ==================================================================

    def _extract_classes_walk(
        self, root: Any, content: bytes, file_path: Path
    ) -> list[ClassDef]:
        classes: list[ClassDef] = []
        self._walk_classes(root, content, file_path, classes, parent_class=None)
        return classes

    def _walk_classes(
        self,
        node: Any,
        content: bytes,
        file_path: Path,
        out: list[ClassDef],
        parent_class: str | None,
    ) -> None:
        if node.type in ("class_declaration", "class"):
            cls = self._extract_class(node, content, file_path)
            if cls:
                # Adjust full_name for nested classes
                if parent_class:
                    cls = cls.model_copy(
                        update={"full_name": f"{parent_class}.{cls.name}"}
                    )
                out.append(cls)
                # Recurse into class body for nested classes
                body = self._find_child(node, "class_body") or self._find_child(node, "object_body")
                if body:
                    self._walk_classes(body, content, file_path, out, parent_class=cls.name)
            return

        for child in node.children:
            self._walk_classes(child, content, file_path, out, parent_class)

    def _extract_class(
        self, node: Any, content: bytes, file_path: Path
    ) -> ClassDef | None:
        """Required by base class; extract a single class node."""
        name_node = node.child_by_field_name("name")
        name = self._get_node_text(content, name_node) if name_node else None
        if not name:
            # Could be an anonymous class expression assigned to a variable
            if node.type == "class":
                parent = node.parent
                if parent and parent.type == "variable_declarator":
                    name_node = parent.child_by_field_name("name")
                    if name_node:
                        name = self._get_node_text(content, name_node)
            if not name:
                return None

        full_name = name

        # Heritage / extends
        bases: list[str] = []
        implements: list[str] = []
        heritage = node.child_by_field_name("herapeutics")  # not a real field
        # Walk children to find class_heritage
        for child in node.children:
            if child.type == "class_heritage":
                for hc in child.children:
                    if hc.type == "extends_clause":
                        for ec in hc.children:
                            if ec.type not in ("extends",):
                                bases.append(self._get_node_text(content, ec))
                    elif hc.type == "implements_clause":
                        for ic in hc.children:
                            if ic.type not in ("implements",):
                                implements.append(self._get_node_text(content, ic))
                    elif hc.type not in ("extends", "implements"):
                        text = self._get_node_text(content, hc)
                        if text != "extends" and text != "implements":
                            bases.append(text)

        # Decorators (TS)
        decorators = self._collect_decorators(node, content)

        # Methods & fields from class body
        methods: list[FunctionDef] = []
        fields: list[FieldDef] = []
        nested: list[ClassDef] = []

        body = self._find_child(node, "class_body") or self._find_child(node, "object_body")
        if body:
            for member in body.children:
                if member.type == "method_definition":
                    m = self._extract_method(member, content, file_path, name)
                    if m:
                        methods.append(m)
                elif member.type == "public_field_definition":
                    f = self._extract_public_field(member, content)
                    if f:
                        fields.append(f)
                elif member.type in ("class_declaration", "class"):
                    nc = self._extract_class(member, content, file_path)
                    if nc:
                        nc = nc.model_copy(update={"full_name": f"{name}.{nc.name}"})
                        nested.append(nc)
                elif member.type == "property_identifier":
                    # Shorthand field
                    fields.append(FieldDef(
                        name=self._get_node_text(content, member),
                        visibility=Visibility.PUBLIC,
                        line=self._get_node_line(member),
                    ))

        return ClassDef(
            name=name,
            full_name=full_name,
            type=ClassType.CLASS,
            bases=bases,
            implements=implements,
            methods=methods,
            fields=fields,
            nested_classes=nested,
            decorators=decorators,
            line_start=self._get_node_line(node),
            line_end=self._get_node_end_line(node),
            file_path=str(file_path),
        )

    # ------------------------------------------------------------------
    # Methods (including constructor, getters, setters)
    # ------------------------------------------------------------------

    def _extract_method(
        self, node: Any, content: bytes, file_path: Path, class_name: str
    ) -> FunctionDef | None:
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None
        method_name = self._get_node_text(content, name_node)
        full_name = f"{class_name}.{method_name}"

        params = self._extract_parameters(node, content)
        return_type = self._extract_return_type(node, content)
        is_async = self._has_child_type(node, "async")
        is_static = self._has_child_type(node, "static")
        is_generator = self._has_child_type(node, "generator")
        visibility = self._js_visibility(method_name)
        decorators = self._collect_decorators(node, content)

        # Kind: get / set
        kind = self._get_method_kind(node)

        return FunctionDef(
            name=method_name,
            full_name=full_name,
            parameters=params,
            return_type=return_type,
            visibility=visibility,
            is_static=is_static,
            is_async=is_async,
            decorators=decorators,
            annotations=[kind] if kind in ("getter", "setter", "constructor") else [],
            line_start=self._get_node_line(node),
            line_end=self._get_node_end_line(node),
            file_path=str(file_path),
        )

    # ==================================================================
    # Functions (declarations, expressions, arrow, async, generator)
    # ==================================================================

    def _extract_top_level_functions_walk(
        self, root: Any, content: bytes, file_path: Path
    ) -> list[FunctionDef]:
        functions: list[FunctionDef] = []
        for child in root.children:
            func = self._try_extract_function(child, content, file_path)
            if func:
                functions.append(func)
        return functions

    def _try_extract_function(
        self, node: Any, content: bytes, file_path: Path, class_name: str | None = None
    ) -> FunctionDef | None:
        """Attempt to extract a function from various AST shapes."""
        if node.type == "function_declaration":
            return self._extract_function(node, content, file_path, class_name)

        if node.type == "generator_function_declaration":
            return self._extract_function(node, content, file_path, class_name)

        if node.type == "lexical_declaration" or node.type == "variable_declaration":
            return self._extract_function_from_var_decl(node, content, file_path, class_name)

        if node.type == "export_statement":
            # export function / export default function
            for child in node.children:
                if child.type in ("function_declaration", "generator_function_declaration"):
                    return self._extract_function(child, content, file_path, class_name)
                if child.type in ("lexical_declaration", "variable_declaration"):
                    return self._extract_function_from_var_decl(
                        child, content, file_path, class_name
                    )

        return None

    def _extract_function_from_var_decl(
        self, node: Any, content: bytes, file_path: Path, class_name: str | None = None
    ) -> FunctionDef | None:
        """Handle ``const fn = () => {}`` and ``const fn = function() {}``."""
        for child in node.children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value")
                if name_node and value_node and value_node.type in (
                    "arrow_function",
                    "function_expression",
                ):
                    name = self._get_node_text(content, name_node)
                    return self._build_function_def(
                        name, value_node, content, file_path, class_name
                    )
        return None

    def _extract_function(
        self, node: Any, content: bytes, file_path: Path, class_name: str | None = None
    ) -> FunctionDef | None:
        """Required by base class; extract a named function declaration."""
        name_node = node.child_by_field_name("name")
        name = self._get_node_text(content, name_node) if name_node else None
        if not name:
            return None
        return self._build_function_def(name, node, content, file_path, class_name)

    def _build_function_def(
        self,
        name: str,
        node: Any,
        content: bytes,
        file_path: Path,
        class_name: str | None,
    ) -> FunctionDef:
        """Build a FunctionDef from a function/arrow AST node."""
        full_name = f"{class_name}.{name}" if class_name else name
        params = self._extract_parameters(node, content)
        return_type = self._extract_return_type(node, content)
        is_async = self._has_child_type(node, "async")
        is_generator = self._has_child_type(node, "generator") or node.type == "generator_function_declaration"
        visibility = self._js_visibility(name)
        decorators = self._collect_decorators(node, content)
        is_static = self._has_child_type(node, "static")

        annotations: list[str] = []
        if is_generator:
            annotations.append("generator")
        if node.type == "arrow_function":
            annotations.append("arrow")

        return FunctionDef(
            name=name,
            full_name=full_name,
            parameters=params,
            return_type=return_type,
            visibility=visibility,
            is_static=is_static,
            is_async=is_async,
            decorators=decorators,
            annotations=annotations,
            line_start=self._get_node_line(node),
            line_end=self._get_node_end_line(node),
            file_path=str(file_path),
        )

    # ------------------------------------------------------------------
    # Parameters
    # ------------------------------------------------------------------

    def _extract_parameters(self, node: Any, content: bytes) -> list[Parameter]:
        params: list[Parameter] = []
        params_node = node.child_by_field_name("parameters")
        if not params_node:
            return params

        for child in params_node.children:
            if child.type == "identifier":
                params.append(Parameter(name=self._get_node_text(content, child)))
            elif child.type == "required_parameter":
                params.append(self._parse_param(child, content, required=True))
            elif child.type == "optional_parameter":
                params.append(self._parse_param(child, content, required=False))
            elif child.type == "rest_parameter":
                p = self._parse_param(child, content, required=True)
                if p:
                    p = p.model_copy(update={"is_variadic": True})
                    params.append(p)
            elif child.type == "assignment_pattern":
                # Default value param
                left = child.child_by_field_name("left")
                if left:
                    p_name = self._get_node_text(content, left)
                    right = child.child_by_field_name("right")
                    default = self._get_node_text(content, right) if right else None
                    params.append(Parameter(name=p_name, default_value=default))

        return params

    def _parse_param(
        self, node: Any, content: bytes, required: bool
    ) -> Parameter:
        name_node = node.child_by_field_name("name") or node.child_by_field_name("pattern")
        name = self._get_node_text(content, name_node) if name_node else "unknown"
        type_node = node.child_by_field_name("type")
        p_type = self._get_node_text(content, type_node) if type_node else None
        default_node = node.child_by_field_name("value")
        default = self._get_node_text(content, default_node) if default_node else None
        return Parameter(name=name, type=p_type, default_value=default)

    # ==================================================================
    # TypeScript-specific: interfaces, type aliases, enums
    # ==================================================================

    def _extract_ts_interfaces(
        self, root: Any, content: bytes, file_path: Path, module: ModuleInfo
    ) -> None:
        self._walk_for_type(root, content, "interface_declaration", file_path, module)

    def _extract_ts_type_aliases(
        self, root: Any, content: bytes, file_path: Path, module: ModuleInfo
    ) -> None:
        self._walk_for_type(root, content, "type_alias_declaration", file_path, module)

    def _extract_ts_enums(
        self, root: Any, content: bytes, file_path: Path, module: ModuleInfo
    ) -> None:
        self._walk_for_type(root, content, "enum_declaration", file_path, module)

    def _walk_for_type(
        self,
        node: Any,
        content: bytes,
        target_type: str,
        file_path: Path,
        module: ModuleInfo,
    ) -> None:
        if node.type == target_type:
            name_node = node.child_by_field_name("name")
            name = self._get_node_text(content, name_node) if name_node else "unknown"
            class_type = {
                "interface_declaration": ClassType.INTERFACE,
                "enum_declaration": ClassType.ENUM,
            }.get(target_type, ClassType.CLASS)

            bases: list[str] = []
            implements: list[str] = []
            for child in node.children:
                if child.type in ("extends_clause", "extends_type_clause"):
                    for ec in child.children:
                        if ec.type not in ("extends",):
                            bases.append(self._get_node_text(content, ec))
                elif child.type in ("implements_clause",):
                    for ic in child.children:
                        if ic.type not in ("implements",):
                            implements.append(self._get_node_text(content, ic))

            # For interfaces and enums, also extract methods/fields
            methods: list[FunctionDef] = []
            fields: list[FieldDef] = []
            body = self._find_child(node, "object_type") or self._find_child(node, "enum_body")
            if body:
                for member in body.children:
                    if member.type in ("property_signature", "property_definition"):
                        pname = member.child_by_field_name("name")
                        if pname:
                            fields.append(FieldDef(
                                name=self._get_node_text(content, pname),
                                line=self._get_node_line(member),
                            ))
                    elif member.type in ("method_signature", "method_definition"):
                        mname = member.child_by_field_name("name")
                        if mname:
                            m = self._extract_method(member, content, file_path, name)
                            if m:
                                methods.append(m)
                    elif member.type == "enum_assignment":
                        ename = None
                        for ec in member.children:
                            if ec.type == "property_identifier":
                                ename = self._get_node_text(content, ec)
                        if ename:
                            fields.append(FieldDef(name=ename, line=self._get_node_line(member)))

            cls = ClassDef(
                name=name,
                full_name=name,
                type=class_type,
                bases=bases,
                implements=implements,
                methods=methods,
                fields=fields,
                line_start=self._get_node_line(node),
                line_end=self._get_node_end_line(node),
                file_path=str(file_path),
            )
            module.classes.append(cls)
            return

        for child in node.children:
            self._walk_for_type(child, content, target_type, file_path, module)

    # ==================================================================
    # Global variables
    # ==================================================================

    def _extract_global_variables(self, root: Any, content: bytes) -> list[FieldDef]:
        fields: list[FieldDef] = []
        for child in root.children:
            if child.type in ("lexical_declaration", "variable_declaration"):
                for vc in child.children:
                    if vc.type == "variable_declarator":
                        name_node = vc.child_by_field_name("name")
                        value_node = vc.child_by_field_name("value")
                        if name_node and value_node and value_node.type not in (
                            "arrow_function",
                            "function_expression",
                        ):
                            fields.append(FieldDef(
                                name=self._get_node_text(content, name_node),
                                default_value=self._get_node_text(content, value_node)[:80],
                                line=self._get_node_line(child),
                            ))
        return fields

    # ==================================================================
    # Call graph
    # ==================================================================

    def _build_call_graph_walk(
        self, root: Any, content: bytes, file_path: Path, module: ModuleInfo
    ) -> CallGraph:
        edges: list[CallEdge] = []
        line_map = self._build_line_to_function_map(module)
        self._walk_calls(root, content, file_path, line_map, edges)
        return CallGraph(edges=edges)

    def _walk_calls(
        self,
        node: Any,
        content: bytes,
        file_path: Path,
        line_map: dict[int, str],
        edges: list[CallEdge],
        current_func: str = "unknown",
    ) -> None:
        # Update context when entering a function-like node
        if node.type in (
            "function_declaration",
            "generator_function_declaration",
            "arrow_function",
            "function_expression",
            "method_definition",
        ):
            name_node = node.child_by_field_name("name")
            if name_node:
                name = self._get_node_text(content, name_node)
                current_func = name
            else:
                # Arrow or anonymous -- check parent variable_declarator
                parent = node.parent
                if parent and parent.type == "variable_declarator":
                    pn = parent.child_by_field_name("name")
                    if pn:
                        current_func = self._get_node_text(content, pn)

        if node.type == "call_expression":
            edge = self._extract_call(node, content, file_path, current_func)
            if edge:
                edges.append(edge)

        for child in node.children:
            self._walk_calls(child, content, file_path, line_map, edges, current_func)

    def _extract_call(
        self, node: Any, content: bytes, file_path: Path, caller_name: str
    ) -> CallEdge | None:
        """Required by base class; extract a call expression."""
        func_node = node.child_by_field_name("function")
        if not func_node:
            return None

        callee_type = None
        if func_node.type == "identifier":
            callee_name = self._get_node_text(content, func_node)
        elif func_node.type == "member_expression":
            callee_name = self._get_node_text(content, func_node)
            obj = func_node.child_by_field_name("object")
            if obj:
                callee_type = self._get_node_text(content, obj)
        elif func_node.type == "call_expression":
            # Chained call -- use the outer expression text
            callee_name = self._get_node_text(content, func_node)[:80]
        else:
            callee_name = self._get_node_text(content, func_node)

        if callee_name:
            return CallEdge(
                caller=caller_name,
                callee=callee_name,
                callee_type=callee_type,
                line=self._get_node_line(node),
                file_path=str(file_path),
            )
        return None

    # ==================================================================
    # Helpers
    # ==================================================================

    def _find_child(self, node: Any, child_type: str) -> Any | None:
        """Return the first direct child of *node* matching *child_type*."""
        for child in node.children:
            if child.type == child_type:
                return child
        return None

    def _has_child_type(self, node: Any, type_name: str) -> bool:
        """Check if a direct child of *node* has the given type."""
        for child in node.children:
            if child.type == type_name:
                return True
        return False

    def _collect_decorators(self, node: Any, content: bytes) -> list[str]:
        """Collect decorator names from the decorator node that precedes *node*.

        In the JS/TS grammar, decorators appear as a ``decorator`` node
        preceding the decorated declaration.  Some grammars also wrap them
        in a ``decorator_list`` child.
        """
        decorators: list[str] = []
        # Check children for decorator_list first
        for child in node.children:
            if child.type == "decorator_list":
                for dc in child.children:
                    decorators.append(self._get_node_text(content, dc))
                return decorators

        # Walk previous siblings
        prev = node.prev_named_sibling
        while prev and prev.type == "decorator":
            decorators.append(self._get_node_text(content, prev))
            prev = prev.prev_named_sibling
        decorators.reverse()
        return decorators

    def _extract_return_type(self, node: Any, content: bytes) -> str | None:
        rt = node.child_by_field_name("return_type")
        if rt:
            return self._get_node_text(content, rt)
        return None

    def _extract_public_field(self, node: Any, content: bytes) -> FieldDef | None:
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None
        name = self._get_node_text(content, name_node)
        type_node = node.child_by_field_name("type")
        vis = self._js_visibility(name)
        is_static = self._has_child_type(node, "static")
        value_node = node.child_by_field_name("value")
        default = self._get_node_text(content, value_node)[:80] if value_node else None
        return FieldDef(
            name=name,
            type=self._get_node_text(content, type_node) if type_node else None,
            visibility=vis,
            is_static=is_static,
            default_value=default,
            line=self._get_node_line(node),
        )

    @staticmethod
    def _js_visibility(name: str) -> Visibility:
        """Determine JS/TS visibility from naming conventions."""
        if name.startswith("#"):
            return Visibility.PRIVATE
        if name.startswith("_"):
            return Visibility.INTERNAL
        return Visibility.PUBLIC

    @staticmethod
    def _get_method_kind(node: Any) -> str:
        """Return 'getter', 'setter', 'constructor', or 'method'."""
        for child in node.children:
            if child.type == "get":
                return "getter"
            if child.type == "set":
                return "setter"
        name_node = node.child_by_field_name("name")
        if name_node:
            # Access via the node text (constructor keyword)
            if hasattr(name_node, "text") and name_node.text == b"constructor":
                return "constructor"
            # Some grammars use property_identifier with value "constructor"
            try:
                from tree_sitter import Node  # noqa: F401
                if name_node.type == "property_identifier" and hasattr(name_node, "text") and name_node.text == b"constructor":
                    return "constructor"
            except Exception:
                pass
        return "method"

    @staticmethod
    def _strip_string(s: str) -> str:
        """Remove surrounding quotes from a string literal."""
        if len(s) >= 2 and s[0] in ("'", '"', "`") and s[-1] == s[0]:
            return s[1:-1]
        return s
