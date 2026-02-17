"""Java code structure parser using Tree-sitter."""

import logging
from pathlib import Path
from typing import Any

import tree_sitter_java as tsjava

from ..models import (
    CallEdge,
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


class JavaStructureParser(LanguageParserBase):
    """Parser for Java source code structure.

    Extracts classes, interfaces, enums, methods, fields, imports,
    and builds method call graphs using Tree-sitter.
    """

    extensions = [".java"]
    language_name = "java"

    def __init__(self, options: ParseOptions | None = None) -> None:
        """Initialize the Java structure parser.

        Args:
            options: Parse options.
        """
        super().__init__(options)
        self._current_package: str | None = None

    def _init_parser(self) -> None:
        """Initialize the Tree-sitter Java parser."""
        from tree_sitter import Language, Parser

        self._language = Language(tsjava.language())
        self._parser = Parser(self._language)

    def parse(self, content: str, file_path: Path) -> ModuleInfo:
        """Parse Java source code and extract structure.

        Args:
            content: Source code content.
            file_path: Path to the source file.

        Returns:
            Parsed module information.
        """
        # Reset package for this file
        self._current_package = None

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

            # Extract package - walk the tree
            self._current_package = self._extract_package(root, content.encode("utf-8"))
            module.package = self._current_package

            # Extract imports - walk the tree
            module.imports = self._extract_imports(root, content.encode("utf-8"))

            # Extract classes
            module.classes = self._extract_classes(root, content.encode("utf-8"), file_path)

            # Java doesn't have top-level functions
            module.functions = []

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
        """Extract package declaration by walking the tree.

        Args:
            root: Root AST node.
            content: Source code content.

        Returns:
            Package name if found.
        """
        for child in root.children:
            if child.type == "package_declaration":
                for pkg_child in child.children:
                    if pkg_child.type == "scoped_identifier":
                        return self._get_node_text(content, pkg_child)
        return None

    def _extract_imports(self, root: Any, content: bytes) -> list[ImportDef]:
        """Extract all import statements by walking the tree.

        Args:
            root: Root AST node.
            content: Source code content.

        Returns:
            List of import definitions.
        """
        imports: list[ImportDef] = []

        for child in root.children:
            if child.type == "import_declaration":
                imp = self._extract_import(child, content)
                if imp:
                    imports.append(imp)

        return imports

    def _extract_import(self, node: Any, content: bytes) -> ImportDef | None:
        """Extract a single import statement.

        Args:
            node: Import declaration node.
            content: Source code content.

        Returns:
            ImportDef if extraction successful.
        """
        is_wildcard = False
        module_name = None

        for child in node.children:
            if child.type == "scoped_identifier":
                module_name = self._get_node_text(content, child)
            elif child.type == "asterisk":
                is_wildcard = True

        if module_name:
            return ImportDef(
                module=module_name,
                is_wildcard=is_wildcard,
                line=self._get_node_line(node),
            )

        return None

    def _extract_classes(
        self, root: Any, content: bytes, file_path: Path
    ) -> list[ClassDef]:
        """Extract all class definitions by walking the tree.

        Args:
            root: Root AST node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            List of class definitions.
        """
        classes: list[ClassDef] = []

        for child in root.children:
            if child.type in ("class_declaration", "interface_declaration", "enum_declaration"):
                cls = self._extract_class(child, content, file_path)
                if cls:
                    classes.append(cls)
                    # Extract nested classes
                    self._extract_nested_classes(child, content, file_path, classes, cls.name)

        return classes

    def _extract_nested_classes(
        self,
        class_node: Any,
        content: bytes,
        file_path: Path,
        classes: list[ClassDef],
        parent_name: str,
    ) -> None:
        """Extract nested classes from a class body.

        Args:
            class_node: Class declaration node.
            content: Source code content.
            file_path: Path to the file.
            classes: List to append classes to.
            parent_name: Name of the containing class.
        """
        for child in class_node.children:
            if child.type in ("class_body", "interface_body", "enum_body"):
                for member in child.children:
                    if member.type in ("class_declaration", "interface_declaration", "enum_declaration"):
                        nested = self._extract_class(member, content, file_path)
                        if nested:
                            nested.full_name = f"{parent_name}.{nested.name}"
                            classes.append(nested)
                            # Recursively extract deeper nested classes
                            self._extract_nested_classes(
                                member, content, file_path, classes, nested.name
                            )

    def _extract_class(
        self, node: Any, content: bytes, file_path: Path
    ) -> ClassDef | None:
        """Extract class definition from AST node.

        Args:
            node: Class declaration node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            ClassDef if extraction successful.
        """
        # Determine class type
        class_type = ClassType.CLASS
        if node.type == "interface_declaration":
            class_type = ClassType.INTERFACE
        elif node.type == "enum_declaration":
            class_type = ClassType.ENUM

        # Get class name
        name = None
        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
                break

        if not name:
            return None

        # Build full name with package
        full_name = f"{self._current_package}.{name}" if self._current_package else name

        # Extract modifiers and annotations
        visibility = Visibility.PACKAGE
        annotations: list[str] = []
        is_abstract = False

        for child in node.children:
            if child.type == "modifiers":
                visibility, annotations, is_abstract = self._parse_modifiers(child, content)

        # Extract extends (superclass) and implements (super_interfaces)
        bases: list[str] = []
        implements: list[str] = []

        for child in node.children:
            if child.type == "superclass":
                # extends User
                for ext_child in child.children:
                    if ext_child.type == "type_identifier":
                        bases.append(self._get_node_text(content, ext_child))
            elif child.type == "super_interfaces":
                # implements Serializable, Cloneable
                for impl_child in child.children:
                    if impl_child.type == "type_list":
                        for t in impl_child.children:
                            if t.type == "type_identifier":
                                implements.append(self._get_node_text(content, t))

        # Extract methods and fields
        methods: list[FunctionDef] = []
        fields: list[FieldDef] = []

        for child in node.children:
            if child.type in ("class_body", "interface_body", "enum_body"):
                for member in child.children:
                    if member.type == "method_declaration":
                        method = self._extract_method(member, content, file_path, name)
                        if method:
                            methods.append(method)
                    elif member.type == "field_declaration":
                        field = self._extract_field(member, content)
                        if field:
                            fields.append(field)
                    elif member.type == "enum_constant":
                        field = self._extract_enum_constant(member, content)
                        if field:
                            fields.append(field)
                    elif member.type == "constructor_declaration":
                        # Handle constructors as methods
                        method = self._extract_constructor(member, content, file_path, name)
                        if method:
                            methods.append(method)

        # Adjust class type for abstract classes
        if is_abstract and class_type == ClassType.CLASS:
            class_type = ClassType.ABSTRACT_CLASS

        return ClassDef(
            name=name,
            full_name=full_name,
            type=class_type,
            bases=bases,
            implements=implements,
            methods=methods,
            fields=fields,
            annotations=annotations,
            line_start=self._get_node_line(node),
            line_end=self._get_node_end_line(node),
            file_path=str(file_path),
        )

    def _parse_modifiers(
        self, modifiers_node: Any, content: bytes
    ) -> tuple[Visibility, list[str], bool]:
        """Parse modifiers node to extract visibility, annotations, and abstract flag.

        Args:
            modifiers_node: Modifiers node.
            content: Source code content.

        Returns:
            Tuple of (visibility, annotations, is_abstract).
        """
        visibility = Visibility.PACKAGE
        annotations: list[str] = []
        is_abstract = False

        for mod in modifiers_node.children:
            if mod.type == "public":
                visibility = Visibility.PUBLIC
            elif mod.type == "private":
                visibility = Visibility.PRIVATE
            elif mod.type == "protected":
                visibility = Visibility.PROTECTED
            elif mod.type == "abstract":
                is_abstract = True
            elif mod.type in ("annotation", "marker_annotation"):
                ann_name = self._get_annotation_name(mod, content)
                if ann_name:
                    annotations.append(ann_name)

        return visibility, annotations, is_abstract

    def _get_annotation_name(self, node: Any, content: bytes) -> str | None:
        """Get annotation name from annotation node.

        Args:
            node: Annotation node.
            content: Source code content.

        Returns:
            Annotation name or None.
        """
        for child in node.children:
            if child.type in ("identifier", "type_identifier"):
                return self._get_node_text(content, child)
            elif child.type == "scoped_type_identifier":
                return self._get_node_text(content, child)
        return None

    def _extract_method(
        self, node: Any, content: bytes, file_path: Path, class_name: str
    ) -> FunctionDef | None:
        """Extract method definition from AST node.

        Args:
            node: Method declaration node.
            content: Source code content.
            file_path: Path to the file.
            class_name: Name of containing class.

        Returns:
            FunctionDef if extraction successful.
        """
        name = None
        return_type = None
        parameters: list[Parameter] = []

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
            elif child.type in ("type_identifier", "scoped_type_identifier", "primitive_type", "array_type", "void_type", "integral_type"):
                # integral_type covers int, long, short, byte, char, boolean, float, double
                return_type = self._get_node_text(content, child)
            elif child.type == "formal_parameters":
                parameters = self._extract_parameters(child, content)

        if not name:
            return None

        # Extract modifiers
        visibility = Visibility.PACKAGE  # Default to package-private
        is_static = False
        is_abstract = False
        annotations: list[str] = []

        for child in node.children:
            if child.type == "modifiers":
                visibility, annotations, is_abstract = self._parse_modifiers(child, content)
                for mod in child.children:
                    if mod.type == "static":
                        is_static = True

        full_name = f"{class_name}.{name}"

        return FunctionDef(
            name=name,
            full_name=full_name,
            parameters=parameters,
            return_type=return_type,
            visibility=visibility,
            is_static=is_static,
            is_abstract=is_abstract,
            annotations=annotations,
            line_start=self._get_node_line(node),
            line_end=self._get_node_end_line(node),
            file_path=str(file_path),
        )

    def _extract_constructor(
        self, node: Any, content: bytes, file_path: Path, class_name: str
    ) -> FunctionDef | None:
        """Extract constructor definition.

        Args:
            node: Constructor declaration node.
            content: Source code content.
            file_path: Path to the file.
            class_name: Name of containing class.

        Returns:
            FunctionDef for the constructor.
        """
        name = class_name  # Constructor name equals class name
        parameters: list[Parameter] = []

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
            elif child.type == "formal_parameters":
                parameters = self._extract_parameters(child, content)

        # Extract modifiers
        visibility = Visibility.PUBLIC
        annotations: list[str] = []

        for child in node.children:
            if child.type == "modifiers":
                visibility, annotations, _ = self._parse_modifiers(child, content)

        return FunctionDef(
            name=name,
            full_name=f"{class_name}.{name}",
            parameters=parameters,
            return_type=None,
            visibility=visibility,
            annotations=annotations,
            line_start=self._get_node_line(node),
            line_end=self._get_node_end_line(node),
            file_path=str(file_path),
        )

    def _extract_parameters(
        self, params_node: Any, content: bytes
    ) -> list[Parameter]:
        """Extract method parameters.

        Args:
            params_node: Formal parameters node.
            content: Source code content.

        Returns:
            List of parameters.
        """
        parameters: list[Parameter] = []

        for child in params_node.children:
            if child.type == "formal_parameter":
                param = self._extract_parameter(child, content)
                if param:
                    parameters.append(param)

        return parameters

    def _extract_parameter(
        self, node: Any, content: bytes
    ) -> Parameter | None:
        """Extract a single parameter.

        Args:
            node: Formal parameter node.
            content: Source code content.

        Returns:
            Parameter if extraction successful.
        """
        name = None
        param_type = None

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
            elif child.type in ("type_identifier", "scoped_type_identifier", "primitive_type", "array_type", "integral_type"):
                param_type = self._get_node_text(content, child)

        if name:
            return Parameter(name=name, type=param_type)
        return None

    def _extract_field(
        self, node: Any, content: bytes
    ) -> FieldDef | None:
        """Extract field definition.

        Args:
            node: Field declaration node.
            content: Source code content.

        Returns:
            FieldDef if extraction successful.
        """
        name = None
        field_type = None
        visibility = Visibility.PRIVATE
        is_static = False
        annotations: list[str] = []

        for child in node.children:
            if child.type in ("type_identifier", "scoped_type_identifier", "primitive_type", "array_type"):
                field_type = self._get_node_text(content, child)
            elif child.type == "variable_declarator":
                for vc in child.children:
                    if vc.type == "identifier":
                        name = self._get_node_text(content, vc)
            elif child.type == "modifiers":
                visibility, annotations, _ = self._parse_modifiers(child, content)
                for mod in child.children:
                    if mod.type == "static":
                        is_static = True

        if name:
            return FieldDef(
                name=name,
                type=field_type,
                visibility=visibility,
                is_static=is_static,
                annotations=annotations,
                line=self._get_node_line(node),
            )
        return None

    def _extract_enum_constant(
        self, node: Any, content: bytes
    ) -> FieldDef | None:
        """Extract enum constant as a field.

        Args:
            node: Enum constant node.
            content: Source code content.

        Returns:
            FieldDef for the enum constant.
        """
        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
                return FieldDef(
                    name=name,
                    type="enum_constant",
                    visibility=Visibility.PUBLIC,
                    is_static=True,
                    is_final=True,
                    line=self._get_node_line(node),
                )
        return None

    def _extract_function(
        self, node: Any, content: bytes, file_path: Path, class_name: str | None = None
    ) -> FunctionDef | None:
        """Not used for Java - all functions are methods."""
        return None

    def _extract_import_node(self, node: Any, content: bytes) -> ImportDef | None:
        """Extract import - alias for _extract_import."""
        return self._extract_import(node, content)

    def _extract_call(
        self, node: Any, content: bytes, file_path: Path, caller_name: str
    ) -> CallEdge | None:
        """Extract method call from AST node.

        Args:
            node: Method invocation node.
            content: Source code content.
            file_path: Path to the file.
            caller_name: Full name of the calling method.

        Returns:
            CallEdge if extraction successful.
        """
        callee_name = None
        callee_object = None

        for child in node.children:
            if child.type == "identifier":
                callee_name = self._get_node_text(content, child)
            elif child.type == "field_access":
                for fc in child.children:
                    if fc.type == "identifier":
                        callee_object = self._get_node_text(content, fc)

        if callee_name:
            if callee_object:
                callee = f"{callee_object}.{callee_name}"
            else:
                callee = callee_name

            return CallEdge(
                caller=caller_name,
                callee=callee,
                line=self._get_node_line(node),
                file_path=str(file_path),
            )
        return None

    def _build_call_graph(
        self, root: Any, content: bytes, file_path: Path, module: ModuleInfo
    ):
        """Build call graph by walking the tree."""
        from ..models import CallGraph

        edges: list[CallEdge] = []

        # Build a map of method node -> full_name
        method_map: dict[Any, str] = {}
        for cls in module.classes:
            for method in cls.methods:
                # Find the method node
                self._find_and_map_methods(root, content, cls.name, method.name, method_map)

        # Walk the tree and find method invocations
        self._extract_calls_recursive(root, content, file_path, method_map, edges)

        return CallGraph(edges=edges)

    def _find_and_map_methods(
        self, node: Any, content: bytes, class_name: str, method_name: str, method_map: dict
    ) -> None:
        """Find method nodes and map them to their full names."""
        if node.type == "method_declaration":
            for child in node.children:
                if child.type == "identifier":
                    name = self._get_node_text(content, child)
                    if name == method_name:
                        method_map[node] = f"{class_name}.{method_name}"
                        break

        for child in node.children:
            self._find_and_map_methods(child, content, class_name, method_name, method_map)

    def _extract_calls_recursive(
        self,
        node: Any,
        content: bytes,
        file_path: Path,
        method_map: dict[Any, str],
        edges: list[CallEdge],
        current_method: str = "unknown",
    ) -> None:
        """Recursively extract method calls."""
        if node.type == "method_declaration":
            # Update current method context
            for child in node.children:
                if child.type == "identifier":
                    method_name = self._get_node_text(content, child)
                    # Find the class context
                    current_method = method_map.get(node, method_name)
                    break

        if node.type == "method_invocation":
            call = self._extract_call(node, content, file_path, current_method)
            if call:
                edges.append(call)

        for child in node.children:
            self._extract_calls_recursive(child, content, file_path, method_map, edges, current_method)
