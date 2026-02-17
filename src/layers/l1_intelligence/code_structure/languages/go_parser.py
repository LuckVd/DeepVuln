"""Go code structure parser using Tree-sitter."""

import logging
from pathlib import Path
from typing import Any

import tree_sitter_go as tsgo

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


class GoStructureParser(LanguageParserBase):
    """Parser for Go source code structure.

    Extracts structs, interfaces, functions, methods, imports,
    and builds function call graphs using Tree-sitter.
    """

    extensions = [".go"]
    language_name = "go"

    def __init__(self, options: ParseOptions | None = None) -> None:
        """Initialize the Go structure parser.

        Args:
            options: Parse options.
        """
        super().__init__(options)

    def _init_parser(self) -> None:
        """Initialize the Tree-sitter Go parser."""
        from tree_sitter import Language, Parser

        self._language = Language(tsgo.language())
        self._parser = Parser(self._language)

    def parse(self, content: str, file_path: Path) -> ModuleInfo:
        """Parse Go source code and extract structure.

        Args:
            content: Source code content.
            file_path: Path to the source file.

        Returns:
            Parsed module information.
        """
        # Initialize parser if needed
        if self._parser is None:
            self._init_parser()

        module = ModuleInfo(
            file_path=str(file_path),
            language=self.language_name,
            line_count=content.count("\n") + 1,
        )

        try:
            # Parse with Tree-sitter
            tree = self._parse_tree(content.encode("utf-8"))
            root = tree.root_node

            # Extract package name
            module.package = self._extract_package(root, content.encode("utf-8"))

            # Extract imports
            module.imports = self._extract_imports(root, content.encode("utf-8"))

            # Extract types (structs and interfaces)
            module.classes = self._extract_types(root, content.encode("utf-8"), file_path)

            # Extract top-level functions
            module.functions = self._extract_functions(root, content.encode("utf-8"), file_path)

            # Build call graph
            if self.options.build_call_graph:
                module.call_graph = self._build_call_graph(
                    root, content.encode("utf-8"), file_path, module
                )

        except Exception as e:
            module.parse_errors.append(str(e))
            logger.error(f"Error parsing {file_path}: {e}")

        return module

    def _extract_package(self, root: Any, content: bytes) -> str | None:
        """Extract package declaration.

        Args:
            root: Root AST node.
            content: Source code content.

        Returns:
            Package name if found.
        """
        for child in root.children:
            if child.type == "package_clause":
                for pkg_child in child.children:
                    if pkg_child.type == "package_identifier":
                        return self._get_node_text(content, pkg_child)
        return None

    def _extract_imports(self, root: Any, content: bytes) -> list[ImportDef]:
        """Extract all import statements.

        Args:
            root: Root AST node.
            content: Source code content.

        Returns:
            List of import definitions.
        """
        imports: list[ImportDef] = []

        for child in root.children:
            if child.type == "import_declaration":
                imports.extend(self._extract_import_declaration(child, content))

        return imports

    def _extract_import_declaration(self, node: Any, content: bytes) -> list[ImportDef]:
        """Extract imports from an import declaration.

        Args:
            node: Import declaration node.
            content: Source code content.

        Returns:
            List of import definitions.
        """
        imports: list[ImportDef] = []

        for child in node.children:
            if child.type == "import_spec":
                # Single import: import "fmt"
                imp = self._extract_import_spec(child, content)
                if imp:
                    imports.append(imp)
            elif child.type == "import_spec_list":
                # Multiple imports: import ("fmt"; "os")
                for spec in child.children:
                    if spec.type == "import_spec":
                        imp = self._extract_import_spec(spec, content)
                        if imp:
                            imports.append(imp)

        return imports

    def _extract_import_spec(self, node: Any, content: bytes) -> ImportDef | None:
        """Extract a single import spec.

        Args:
            node: Import spec node.
            content: Source code content.

        Returns:
            ImportDef if extraction successful.
        """
        module_name = None
        alias = None

        for child in node.children:
            if child.type == "interpreted_string_literal":
                # Get the string content without quotes
                for str_child in child.children:
                    if str_child.type == "interpreted_string_literal_content":
                        module_name = self._get_node_text(content, str_child)
                        break
                if not module_name:
                    # Fallback: remove quotes manually
                    text = self._get_node_text(content, child)
                    module_name = text.strip('"')
            elif child.type == "package_identifier":
                # import alias "module"
                alias = self._get_node_text(content, child)
            elif child.type == "dot":
                # import . "module" (dot import)
                alias = "."

        if module_name:
            return ImportDef(
                module=module_name,
                alias=alias,
                line=self._get_node_line(node),
            )
        return None

    def _extract_import(self, node: Any, content: bytes) -> ImportDef | None:
        """Extract a single import statement (not used directly).

        Args:
            node: Import declaration node.
            content: Source code content.

        Returns:
            ImportDef if extraction successful.
        """
        return None

    def _extract_types(
        self, root: Any, content: bytes, file_path: Path
    ) -> list[ClassDef]:
        """Extract all type declarations (structs and interfaces).

        Args:
            root: Root AST node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            List of class definitions.
        """
        classes: list[ClassDef] = []

        for child in root.children:
            if child.type == "type_declaration":
                cls = self._extract_type_declaration(child, content, file_path)
                if cls:
                    classes.append(cls)

        return classes

    def _extract_type_declaration(
        self, node: Any, content: bytes, file_path: Path
    ) -> ClassDef | None:
        """Extract type from a type declaration.

        Args:
            node: Type declaration node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            ClassDef if extraction successful.
        """
        for child in node.children:
            if child.type == "type_spec":
                return self._extract_type_spec(child, content, file_path)

        return None

    def _extract_type_spec(
        self, node: Any, content: bytes, file_path: Path
    ) -> ClassDef | None:
        """Extract type from a type spec.

        Args:
            node: Type spec node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            ClassDef if extraction successful.
        """
        name = None
        class_type = ClassType.CLASS

        for child in node.children:
            if child.type == "type_identifier":
                name = self._get_node_text(content, child)
            elif child.type == "struct_type":
                class_type = ClassType.STRUCT
                struct_cls = self._extract_struct(name, child, content, file_path)
                if struct_cls:
                    return struct_cls
            elif child.type == "interface_type":
                class_type = ClassType.INTERFACE
                interface_cls = self._extract_interface(name, child, content, file_path)
                if interface_cls:
                    return interface_cls

        return None

    def _extract_struct(
        self, name: str, node: Any, content: bytes, file_path: Path
    ) -> ClassDef | None:
        """Extract struct definition.

        Args:
            name: Struct name.
            node: Struct type node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            ClassDef for the struct.
        """
        fields: list[FieldDef] = []

        for child in node.children:
            if child.type == "field_declaration_list":
                for field_child in child.children:
                    if field_child.type == "field_declaration":
                        field = self._extract_struct_field(field_child, content)
                        if field:
                            fields.append(field)

        full_name = f"{self._current_package}.{name}" if hasattr(self, '_current_package') and self._current_package else name

        return ClassDef(
            name=name,
            full_name=full_name,
            type=ClassType.STRUCT,
            fields=fields,
            line_start=self._get_node_line(node),
            line_end=self._get_node_end_line(node),
            file_path=str(file_path),
        )

    def _extract_struct_field(self, node: Any, content: bytes) -> FieldDef | None:
        """Extract struct field.

        Args:
            node: Field declaration node.
            content: Source code content.

        Returns:
            FieldDef if extraction successful.
        """
        name = None
        field_type = None
        visibility = Visibility.PUBLIC

        for child in node.children:
            if child.type == "field_identifier":
                name = self._get_node_text(content, child)
                # Determine visibility based on case
                if name and name[0].islower():
                    visibility = Visibility.INTERNAL
            elif child.type in ("type_identifier", "pointer_type", "slice_type", "map_type", "channel_type"):
                field_type = self._get_node_text(content, child)
            elif child.type == "qualified_type":
                # package.Type
                field_type = self._get_node_text(content, child)

        if name:
            return FieldDef(
                name=name,
                type=field_type,
                visibility=visibility,
                line=self._get_node_line(node),
            )
        return None

    def _extract_interface(
        self, name: str, node: Any, content: bytes, file_path: Path
    ) -> ClassDef | None:
        """Extract interface definition.

        Args:
            name: Interface name.
            node: Interface type node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            ClassDef for the interface.
        """
        methods: list[FunctionDef] = []

        for child in node.children:
            if child.type == "method_elem":
                method = self._extract_interface_method(child, content, file_path, name)
                if method:
                    methods.append(method)

        full_name = f"{self._current_package}.{name}" if hasattr(self, '_current_package') and self._current_package else name

        return ClassDef(
            name=name,
            full_name=full_name,
            type=ClassType.INTERFACE,
            methods=methods,
            line_start=self._get_node_line(node),
            line_end=self._get_node_end_line(node),
            file_path=str(file_path),
        )

    def _extract_interface_method(
        self, node: Any, content: bytes, file_path: Path, interface_name: str
    ) -> FunctionDef | None:
        """Extract interface method signature.

        Args:
            node: Method elem node.
            content: Source code content.
            file_path: Path to the file.
            interface_name: Name of containing interface.

        Returns:
            FunctionDef for the method.
        """
        name = None
        parameters: list[Parameter] = []
        return_type = None

        for child in node.children:
            if child.type == "field_identifier":
                name = self._get_node_text(content, child)
            elif child.type == "parameter_list":
                parameters = self._extract_go_parameters(child, content)
            elif child.type in ("type_identifier", "pointer_type", "qualified_type"):
                return_type = self._get_node_text(content, child)

        if name:
            visibility = Visibility.PUBLIC if name[0].isupper() else Visibility.INTERNAL
            return FunctionDef(
                name=name,
                full_name=f"{interface_name}.{name}",
                parameters=parameters,
                return_type=return_type,
                visibility=visibility,
                line_start=self._get_node_line(node),
                line_end=self._get_node_end_line(node),
                file_path=str(file_path),
            )
        return None

    def _extract_functions(
        self, root: Any, content: bytes, file_path: Path
    ) -> list[FunctionDef]:
        """Extract all top-level function declarations.

        Args:
            root: Root AST node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            List of function definitions.
        """
        functions: list[FunctionDef] = []

        for child in root.children:
            if child.type == "function_declaration":
                func = self._extract_function_declaration(child, content, file_path)
                if func:
                    functions.append(func)
            elif child.type == "method_declaration":
                # Methods are extracted as part of their struct/interface
                # But we also add them to top-level functions for call graph
                method = self._extract_method_declaration(child, content, file_path)
                if method:
                    functions.append(method)

        return functions

    def _extract_function_declaration(
        self, node: Any, content: bytes, file_path: Path
    ) -> FunctionDef | None:
        """Extract function declaration.

        Args:
            node: Function declaration node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            FunctionDef if extraction successful.
        """
        name = None
        parameters: list[Parameter] = []
        return_type = None

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
            elif child.type == "parameter_list":
                parameters = self._extract_go_parameters(child, content)
            elif child.type in ("type_identifier", "pointer_type", "slice_type", "qualified_type", "tuple_type"):
                # Return type (could be multiple in a tuple_type)
                return_type = self._get_node_text(content, child)

        if name:
            visibility = Visibility.PUBLIC if name[0].isupper() else Visibility.INTERNAL
            return FunctionDef(
                name=name,
                full_name=name,
                parameters=parameters,
                return_type=return_type,
                visibility=visibility,
                line_start=self._get_node_line(node),
                line_end=self._get_node_end_line(node),
                file_path=str(file_path),
            )
        return None

    def _extract_method_declaration(
        self, node: Any, content: bytes, file_path: Path
    ) -> FunctionDef | None:
        """Extract method declaration with receiver.

        Args:
            node: Method declaration node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            FunctionDef if extraction successful.
        """
        name = None
        receiver_type = None
        parameters: list[Parameter] = []
        return_type = None

        for child in node.children:
            if child.type == "field_identifier":
                name = self._get_node_text(content, child)
            elif child.type == "parameter_list":
                # First parameter_list is the receiver
                if receiver_type is None:
                    # Extract receiver type
                    for param in child.children:
                        if param.type == "parameter_declaration":
                            for pchild in param.children:
                                if pchild.type in ("type_identifier", "pointer_type"):
                                    receiver_type = self._get_node_text(content, pchild)
                                    # Clean up pointer type
                                    if receiver_type and receiver_type.startswith("*"):
                                        receiver_type = receiver_type[1:]
                                    break
                else:
                    # Second parameter_list is the actual parameters
                    parameters = self._extract_go_parameters(child, content)
            elif child.type in ("type_identifier", "pointer_type", "slice_type", "qualified_type"):
                return_type = self._get_node_text(content, child)

        if name:
            visibility = Visibility.PUBLIC if name[0].isupper() else Visibility.INTERNAL
            full_name = f"{receiver_type}.{name}" if receiver_type else name
            return FunctionDef(
                name=name,
                full_name=full_name,
                parameters=parameters,
                return_type=return_type,
                visibility=visibility,
                line_start=self._get_node_line(node),
                line_end=self._get_node_end_line(node),
                file_path=str(file_path),
            )
        return None

    def _extract_go_parameters(self, params_node: Any, content: bytes) -> list[Parameter]:
        """Extract Go function parameters.

        Args:
            params_node: Parameter list node.
            content: Source code content.

        Returns:
            List of parameters.
        """
        parameters: list[Parameter] = []

        for child in params_node.children:
            if child.type == "parameter_declaration":
                param = self._extract_go_parameter(child, content)
                if param:
                    parameters.append(param)
            elif child.type == "variadic_parameter_declaration":
                # ...type (variadic)
                param = self._extract_variadic_parameter(child, content)
                if param:
                    parameters.append(param)

        return parameters

    def _extract_go_parameter(self, node: Any, content: bytes) -> Parameter | None:
        """Extract a single Go parameter.

        Args:
            node: Parameter declaration node.
            content: Source code content.

        Returns:
            Parameter if extraction successful.
        """
        name = None
        param_type = None

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
            elif child.type in ("type_identifier", "pointer_type", "slice_type", "map_type", "qualified_type"):
                param_type = self._get_node_text(content, child)

        if name:
            return Parameter(name=name, type=param_type)
        elif param_type:
            # Go allows unnamed parameters
            return Parameter(name="", type=param_type)
        return None

    def _extract_variadic_parameter(self, node: Any, content: bytes) -> Parameter | None:
        """Extract variadic parameter (...T).

        Args:
            node: Variadic parameter declaration node.
            content: Source code content.

        Returns:
            Parameter if extraction successful.
        """
        name = None
        param_type = None

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
            elif child.type in ("type_identifier", "slice_type"):
                param_type = "..." + (self._get_node_text(content, child) or "")

        if name:
            return Parameter(name=name, type=param_type, is_variadic=True)
        return None

    def _extract_function(
        self, node: Any, content: bytes, file_path: Path, class_name: str | None = None
    ) -> FunctionDef | None:
        """Not used for Go - we use specific methods."""
        return None

    def _extract_class(
        self, node: Any, content: bytes, file_path: Path
    ) -> ClassDef | None:
        """Extract class from AST node (not used directly for Go).

        Go uses type_declaration -> type_spec -> struct_type/interface_type
        which is handled by _extract_type_declaration.

        Args:
            node: Type declaration node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            ClassDef if extraction successful.
        """
        return self._extract_type_declaration(node, content, file_path)

    def _extract_call(
        self, node: Any, content: bytes, file_path: Path, caller_name: str
    ) -> CallEdge | None:
        """Extract function call from AST node.

        Args:
            node: Call expression node.
            content: Source code content.
            file_path: Path to the file.
            caller_name: Full name of the calling function.

        Returns:
            CallEdge if extraction successful.
        """
        return self._extract_go_call(node, content, file_path, caller_name)

    def _build_call_graph(
        self, root: Any, content: bytes, file_path: Path, module: ModuleInfo
    ) -> CallGraph:
        """Build call graph by walking the tree.

        Args:
            root: Root AST node.
            content: Source code content.
            file_path: Path to the file.
            module: Parsed module info.

        Returns:
            Call graph.
        """
        edges: list[CallEdge] = []

        # Build a map of function node -> full_name
        func_map: dict[Any, str] = {}
        for func in module.functions:
            self._find_and_map_go_functions(root, content, func.full_name, func_map)

        # Walk the tree and find calls
        self._extract_go_calls_recursive(root, content, file_path, func_map, edges)

        return CallGraph(edges=edges)

    def _find_and_map_go_functions(
        self, node: Any, content: bytes, func_full_name: str, func_map: dict[Any, str]
    ) -> None:
        """Find Go function nodes and map them to their full names."""
        if node.type in ("function_declaration", "method_declaration"):
            name = None
            for child in node.children:
                if child.type in ("identifier", "field_identifier"):
                    name = self._get_node_text(content, child)
                    break
            if name:
                expected_name = func_full_name.split(".")[-1]
                if name == expected_name:
                    func_map[node] = func_full_name

        for child in node.children:
            self._find_and_map_go_functions(child, content, func_full_name, func_map)

    def _extract_go_calls_recursive(
        self,
        node: Any,
        content: bytes,
        file_path: Path,
        func_map: dict[Any, str],
        edges: list[CallEdge],
        current_func: str = "unknown",
    ) -> None:
        """Recursively extract function calls."""
        if node.type in ("function_declaration", "method_declaration"):
            current_func = func_map.get(node, current_func)

        if node.type == "call_expression":
            call = self._extract_go_call(node, content, file_path, current_func)
            if call:
                edges.append(call)

        for child in node.children:
            self._extract_go_calls_recursive(child, content, file_path, func_map, edges, current_func)

    def _extract_go_call(
        self, node: Any, content: bytes, file_path: Path, caller_name: str
    ) -> CallEdge | None:
        """Extract function call from AST node.

        Args:
            node: Call expression node.
            content: Source code content.
            file_path: Path to the file.
            caller_name: Full name of the calling function.

        Returns:
            CallEdge if extraction successful.
        """
        callee_name = None

        for child in node.children:
            if child.type == "identifier":
                # Simple function call: func()
                callee_name = self._get_node_text(content, child)
            elif child.type == "selector_expression":
                # Method call: obj.method() or pkg.Func()
                callee_name = self._get_node_text(content, child)
            elif child.type == "parenthesized_expression":
                # Could be a complex expression
                pass

        if callee_name:
            return CallEdge(
                caller=caller_name,
                callee=callee_name,
                line=self._get_node_line(node),
                file_path=str(file_path),
            )
        return None
