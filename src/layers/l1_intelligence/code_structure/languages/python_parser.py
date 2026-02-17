"""Python code structure parser using Tree-sitter."""

import logging
from pathlib import Path
from typing import Any

import tree_sitter_python as tspython

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


class PythonStructureParser(LanguageParserBase):
    """Parser for Python source code structure.

    Extracts classes, functions, decorators, imports,
    and builds function call graphs using Tree-sitter.
    """

    extensions = [".py"]
    language_name = "python"

    def __init__(self, options: ParseOptions | None = None) -> None:
        """Initialize the Python structure parser.

        Args:
            options: Parse options.
        """
        super().__init__(options)

    def _init_parser(self) -> None:
        """Initialize the Tree-sitter Python parser."""
        from tree_sitter import Language, Parser

        self._language = Language(tspython.language())
        self._parser = Parser(self._language)

    def parse(self, content: str, file_path: Path) -> ModuleInfo:
        """Parse Python source code and extract structure.

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
            module_name=file_path.stem,
        )

        try:
            # Parse with Tree-sitter
            tree = self._parse_tree(content.encode("utf-8"))
            root = tree.root_node

            # Extract imports
            module.imports = self._extract_imports(root, content.encode("utf-8"))

            # Extract classes
            module.classes = self._extract_classes(root, content.encode("utf-8"), file_path)

            # Extract top-level functions
            module.functions = self._extract_top_level_functions(
                root, content.encode("utf-8"), file_path
            )

            # Build call graph
            if self.options.build_call_graph:
                module.call_graph = self._build_call_graph(
                    root, content.encode("utf-8"), file_path, module
                )

        except Exception as e:
            module.parse_errors.append(str(e))
            logger.error(f"Error parsing {file_path}: {e}")

        return module

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
            if child.type == "import_statement":
                # import x, y, z
                imp = self._extract_import_statement(child, content)
                if imp:
                    imports.extend(imp)
            elif child.type == "import_from_statement":
                # from x import y, z
                imp = self._extract_import_from_statement(child, content)
                if imp:
                    imports.extend(imp)

        return imports

    def _extract_import_statement(self, node: Any, content: bytes) -> list[ImportDef]:
        """Extract simple import statement (import x, y, z).

        Args:
            node: Import statement node.
            content: Source code content.

        Returns:
            List of import definitions.
        """
        imports: list[ImportDef] = []

        for child in node.children:
            if child.type == "dotted_name":
                # import module
                module_name = self._get_node_text(content, child)
                imports.append(ImportDef(
                    module=module_name,
                    line=self._get_node_line(node),
                ))
            elif child.type == "aliased_import":
                # import module as alias
                module_name = None
                alias = None
                for ac in child.children:
                    if ac.type == "dotted_name":
                        module_name = self._get_node_text(content, ac)
                    elif ac.type == "identifier":
                        alias = self._get_node_text(content, ac)
                if module_name:
                    imports.append(ImportDef(
                        module=module_name,
                        alias=alias,
                        line=self._get_node_line(node),
                    ))

        return imports

    def _extract_import_from_statement(self, node: Any, content: bytes) -> list[ImportDef]:
        """Extract from-import statement (from x import y, z).

        Args:
            node: Import from statement node.
            content: Source code content.

        Returns:
            List of import definitions.
        """
        imports: list[ImportDef] = []

        # Get module name (the part after 'from')
        module_name = None
        for child in node.children:
            if child.type in ("dotted_name", "relative_import"):
                module_name = self._get_node_text(content, child)
                break

        if not module_name:
            return imports

        # Get imported names
        names: list[str] = []
        is_wildcard = False
        found_import_keyword = False

        for child in node.children:
            if child.type == "import":
                found_import_keyword = True
                continue

            if not found_import_keyword:
                continue

            if child.type == "wildcard_import":
                is_wildcard = True
            elif child.type == "dotted_name":
                # Direct dotted_name after 'import' keyword (no import_list wrapper)
                names.append(self._get_node_text(content, child))
            elif child.type == "aliased_import":
                # name as alias
                for ac in child.children:
                    if ac.type == "dotted_name":
                        names.append(self._get_node_text(content, ac))
                        break
            elif child.type == "identifier":
                # Simple identifier import
                names.append(self._get_node_text(content, child))

        if is_wildcard:
            imports.append(ImportDef(
                module=module_name,
                is_wildcard=True,
                line=self._get_node_line(node),
            ))
        elif names:
            imports.append(ImportDef(
                module=module_name,
                names=names,
                line=self._get_node_line(node),
            ))

        return imports

    def _extract_import(self, node: Any, content: bytes) -> ImportDef | None:
        """Extract a single import statement (not used, we use specific methods).

        Args:
            node: Import declaration node.
            content: Source code content.

        Returns:
            ImportDef if extraction successful.
        """
        # This method is required by base class but we handle imports differently
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
            if child.type == "class_definition":
                cls = self._extract_class(child, content, file_path)
                if cls:
                    classes.append(cls)
            elif child.type == "decorated_definition":
                # Handle decorated class definitions
                cls = self._extract_decorated_class(child, content, file_path)
                if cls:
                    classes.append(cls)

        return classes

    def _extract_decorated_class(
        self, node: Any, content: bytes, file_path: Path
    ) -> ClassDef | None:
        """Extract class from a decorated_definition node.

        Args:
            node: Decorated definition node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            ClassDef if extraction successful.
        """
        # Extract decorators from this node
        decorators: list[str] = []
        class_node = None

        for child in node.children:
            if child.type == "decorator":
                decorator_name = self._extract_decorator_name(child, content)
                if decorator_name:
                    decorators.append(decorator_name)
            elif child.type == "class_definition":
                class_node = child

        if not class_node:
            return None

        # Extract the class
        cls = self._extract_class(class_node, content, file_path)
        if cls:
            # Use model_copy to update Pydantic model immutably
            cls = cls.model_copy(update={"decorators": decorators})

        return cls

    def _extract_class(
        self, node: Any, content: bytes, file_path: Path, parent_class: str | None = None
    ) -> ClassDef | None:
        """Extract class definition from AST node.

        Args:
            node: Class definition node.
            content: Source code content.
            file_path: Path to the file.
            parent_class: Name of parent class if nested.

        Returns:
            ClassDef if extraction successful.
        """
        # Get class name
        name = None
        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
                break

        if not name:
            return None

        # Build full name
        if parent_class:
            full_name = f"{parent_class}.{name}"
        else:
            full_name = name

        # Extract decorators
        decorators = self._extract_decorators(node, content)

        # Extract base classes (inheritance)
        bases: list[str] = []
        for child in node.children:
            if child.type == "argument_list":
                # class Name(Base1, Base2)
                for arg in child.children:
                    if arg.type in ("identifier", "attribute", "dotted_name"):
                        bases.append(self._get_node_text(content, arg))

        # Determine class type
        class_type = ClassType.CLASS
        # Check for abstract base class
        base_names = [b.lower() for b in bases]
        if "abc" in str(decorators).lower() or "abcmeta" in str(base_names).lower():
            class_type = ClassType.ABSTRACT_CLASS

        # Extract docstring
        docstring = self._extract_class_docstring(node, content)

        # Extract methods and nested classes
        methods: list[FunctionDef] = []
        nested_classes: list[ClassDef] = []
        fields: list[FieldDef] = []

        for child in node.children:
            if child.type == "block":
                for member in child.children:
                    if member.type == "function_definition":
                        method = self._extract_function(member, content, file_path, name)
                        if method:
                            methods.append(method)
                    elif member.type == "decorated_definition":
                        # Handle decorated methods
                        decorated = self._extract_decorated_class_member(member, content, file_path, name)
                        if decorated:
                            if isinstance(decorated, FunctionDef):
                                methods.append(decorated)
                            elif isinstance(decorated, ClassDef):
                                nested_classes.append(decorated)
                    elif member.type == "class_definition":
                        nested = self._extract_class(member, content, file_path, name)
                        if nested:
                            nested_classes.append(nested)
                    elif member.type == "expression_statement":
                        # Check for class attributes
                        field = self._extract_class_field(member, content)
                        if field:
                            fields.append(field)

        return ClassDef(
            name=name,
            full_name=full_name,
            type=class_type,
            bases=bases,
            methods=methods,
            fields=fields,
            nested_classes=nested_classes,
            decorators=decorators,
            docstring=docstring,
            line_start=self._get_node_line(node),
            line_end=self._get_node_end_line(node),
            file_path=str(file_path),
        )

    def _extract_decorators(self, node: Any, content: bytes) -> list[str]:
        """Extract decorators from a decorated node.

        Args:
            node: Function or class definition node.
            content: Source code content.

        Returns:
            List of decorator names.
        """
        decorators: list[str] = []

        # Check if previous sibling is a decorator
        prev = node.prev_sibling
        while prev and prev.type == "decorator":
            decorator_name = self._extract_decorator_name(prev, content)
            if decorator_name:
                decorators.append(decorator_name)
            prev = prev.prev_sibling

        # Reverse to get correct order
        decorators.reverse()
        return decorators

    def _extract_decorator_name(self, node: Any, content: bytes) -> str | None:
        """Extract decorator name from decorator node.

        Args:
            node: Decorator node.
            content: Source code content.

        Returns:
            Decorator name or None.
        """
        for child in node.children:
            if child.type == "identifier":
                return self._get_node_text(content, child)
            elif child.type == "attribute":
                # @module.decorator
                return self._get_node_text(content, child)
            elif child.type == "call":
                # @decorator() or @decorator(args)
                for call_child in child.children:
                    if call_child.type in ("identifier", "attribute"):
                        return self._get_node_text(content, call_child)
        return None

    def _extract_class_docstring(self, node: Any, content: bytes) -> str | None:
        """Extract docstring from class body.

        Args:
            node: Class definition node.
            content: Source code content.

        Returns:
            Docstring if found.
        """
        for child in node.children:
            if child.type == "block":
                for member in child.children:
                    if member.type == "expression_statement":
                        for expr in member.children:
                            if expr.type == "string":
                                return self._extract_string_content(expr, content)
        return None

    def _extract_string_content(self, node: Any, content: bytes) -> str | None:
        """Extract string content, removing quotes.

        Args:
            node: String node.
            content: Source code content.

        Returns:
            String content without quotes.
        """
        text = self._get_node_text(content, node)
        # Remove surrounding quotes
        if text.startswith('"""') or text.startswith("'''"):
            return text[3:-3]
        elif text.startswith('"') or text.startswith("'"):
            return text[1:-1]
        return text

    def _extract_class_field(self, node: Any, content: bytes) -> FieldDef | None:
        """Extract class field/attribute from expression statement.

        Args:
            node: Expression statement node.
            content: Source code content.

        Returns:
            FieldDef if it's a class attribute.
        """
        for child in node.children:
            if child.type == "assignment":
                left = None
                right = None
                for assign_child in child.children:
                    if assign_child.type == "identifier":
                        left = self._get_node_text(content, assign_child)
                    elif assign_child.type not in ("=",):
                        # Skip the equals sign
                        if assign_child.type != "=":
                            right = self._get_node_text(content, assign_child)

                if left and not left.startswith("_"):
                    return FieldDef(
                        name=left,
                        type=None,
                        default_value=right[:50] if right else None,
                        visibility=Visibility.PUBLIC,
                        line=self._get_node_line(node),
                    )
        return None

    def _extract_top_level_functions(
        self, root: Any, content: bytes, file_path: Path
    ) -> list[FunctionDef]:
        """Extract top-level function definitions.

        Args:
            root: Root AST node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            List of function definitions.
        """
        functions: list[FunctionDef] = []

        for child in root.children:
            if child.type == "function_definition":
                func = self._extract_function(child, content, file_path)
                if func:
                    functions.append(func)
            elif child.type == "decorated_definition":
                # Handle decorated function definitions
                func = self._extract_decorated_function(child, content, file_path)
                if func:
                    functions.append(func)

        return functions

    def _extract_decorated_function(
        self, node: Any, content: bytes, file_path: Path
    ) -> FunctionDef | None:
        """Extract function from a decorated_definition node.

        Args:
            node: Decorated definition node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            FunctionDef if extraction successful.
        """
        # Extract decorators from this node
        decorators: list[str] = []
        func_node = None

        for child in node.children:
            if child.type == "decorator":
                decorator_name = self._extract_decorator_name(child, content)
                if decorator_name:
                    decorators.append(decorator_name)
            elif child.type == "function_definition":
                func_node = child

        if not func_node:
            return None

        # Extract the function
        func = self._extract_function(func_node, content, file_path)
        if func:
            # Use model_copy to update Pydantic model immutably
            func = func.model_copy(update={"decorators": decorators})

        return func

    def _extract_decorated_class_member(
        self, node: Any, content: bytes, file_path: Path, class_name: str
    ) -> FunctionDef | ClassDef | None:
        """Extract method or nested class from a decorated_definition node inside a class.

        Args:
            node: Decorated definition node.
            content: Source code content.
            file_path: Path to the file.
            class_name: Name of containing class.

        Returns:
            FunctionDef or ClassDef if extraction successful.
        """
        # Extract decorators from this node
        decorators: list[str] = []
        member_node = None
        member_type = None

        for child in node.children:
            if child.type == "decorator":
                decorator_name = self._extract_decorator_name(child, content)
                if decorator_name:
                    decorators.append(decorator_name)
            elif child.type == "function_definition":
                member_node = child
                member_type = "function"
            elif child.type == "class_definition":
                member_node = child
                member_type = "class"

        if not member_node:
            return None

        if member_type == "function":
            func = self._extract_function(member_node, content, file_path, class_name)
            if func:
                func = func.model_copy(update={"decorators": decorators})
            return func
        elif member_type == "class":
            cls = self._extract_class(member_node, content, file_path, class_name)
            if cls:
                cls = cls.model_copy(update={"decorators": decorators})
            return cls

        return None

    def _extract_function(
        self, node: Any, content: bytes, file_path: Path, class_name: str | None = None
    ) -> FunctionDef | None:
        """Extract function/method definition from AST node.

        Args:
            node: Function definition node.
            content: Source code content.
            file_path: Path to the file.
            class_name: Name of containing class if method.

        Returns:
            FunctionDef if extraction successful.
        """
        # Get function name
        name = None
        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
                break

        if not name:
            return None

        # Build full name
        if class_name:
            full_name = f"{class_name}.{name}"
        else:
            full_name = name

        # Extract parameters
        parameters: list[Parameter] = []
        for child in node.children:
            if child.type == "parameters":
                parameters = self._extract_parameters(child, content, class_name)

        # Extract return type annotation
        return_type = None
        for child in node.children:
            if child.type == "type":
                return_type = self._get_node_text(content, child)

        # Extract decorators
        decorators = self._extract_decorators(node, content)

        # Determine visibility
        visibility = Visibility.PUBLIC
        if name.startswith("__") and not name.endswith("__"):
            visibility = Visibility.PRIVATE
        elif name.startswith("_"):
            visibility = Visibility.INTERNAL

        # Check for async
        is_async = False
        for child in node.children:
            if child.type == "async":
                is_async = True
                break

        # Check for staticmethod/classmethod
        is_static = "staticmethod" in decorators

        # Extract docstring
        docstring = self._extract_function_docstring(node, content)

        # Determine if abstract
        is_abstract = "abstractmethod" in decorators

        return FunctionDef(
            name=name,
            full_name=full_name,
            parameters=parameters,
            return_type=return_type,
            visibility=visibility,
            is_static=is_static,
            is_async=is_async,
            is_abstract=is_abstract,
            decorators=decorators,
            docstring=docstring,
            line_start=self._get_node_line(node),
            line_end=self._get_node_end_line(node),
            file_path=str(file_path),
        )

    def _extract_parameters(
        self, params_node: Any, content: bytes, class_name: str | None = None
    ) -> list[Parameter]:
        """Extract function parameters.

        Args:
            params_node: Parameters node.
            content: Source code content.
            class_name: Name of containing class (to skip 'self'/'cls').

        Returns:
            List of parameters.
        """
        parameters: list[Parameter] = []

        for child in params_node.children:
            if child.type == "identifier":
                # Simple positional parameter (like 'self' or 'cls')
                param_name = self._get_node_text(content, child)
                # Skip self/cls for methods
                if class_name and param_name in ("self", "cls"):
                    continue
                parameters.append(Parameter(name=param_name))

            elif child.type == "typed_parameter":
                # Parameter with type annotation: name: type
                param = self._extract_typed_parameter(child, content, class_name)
                if param:
                    parameters.append(param)

            elif child.type == "default_parameter":
                # Parameter with default: name=default
                param = self._extract_default_parameter(child, content, class_name)
                if param:
                    parameters.append(param)

            elif child.type == "typed_default_parameter":
                # Parameter with type and default: name: type = default
                param = self._extract_typed_default_parameter(child, content, class_name)
                if param:
                    parameters.append(param)

            elif child.type == "list_splat_pattern":
                # *args
                param = self._extract_splat_parameter(child, content, "list")
                if param:
                    parameters.append(param)

            elif child.type == "dictionary_splat_pattern":
                # **kwargs
                param = self._extract_splat_parameter(child, content, "dict")
                if param:
                    parameters.append(param)

        return parameters

    def _extract_typed_parameter(
        self, node: Any, content: bytes, class_name: str | None = None
    ) -> Parameter | None:
        """Extract typed parameter (name: type).

        Args:
            node: Typed parameter node.
            content: Source code content.
            class_name: Name of containing class.

        Returns:
            Parameter if extraction successful.
        """
        name = None
        param_type = None

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
            elif child.type == "type":
                param_type = self._get_node_text(content, child)

        if name:
            # Skip self/cls for methods
            if class_name and name in ("self", "cls"):
                return None
            return Parameter(name=name, type=param_type)
        return None

    def _extract_default_parameter(
        self, node: Any, content: bytes, class_name: str | None = None
    ) -> Parameter | None:
        """Extract parameter with default value (name=default).

        Args:
            node: Default parameter node.
            content: Source code content.
            class_name: Name of containing class.

        Returns:
            Parameter if extraction successful.
        """
        name = None
        default = None

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
            elif child.type not in ("=",):
                if not default:
                    default = self._get_node_text(content, child)

        if name:
            # Skip self/cls for methods
            if class_name and name in ("self", "cls"):
                return None
            return Parameter(name=name, default_value=default)
        return None

    def _extract_typed_default_parameter(
        self, node: Any, content: bytes, class_name: str | None = None
    ) -> Parameter | None:
        """Extract parameter with type and default (name: type = default).

        Args:
            node: Typed default parameter node.
            content: Source code content.
            class_name: Name of containing class.

        Returns:
            Parameter if extraction successful.
        """
        name = None
        param_type = None
        default = None

        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
            elif child.type == "type":
                param_type = self._get_node_text(content, child)
            elif child.type not in ("=", ":", "?"):
                # Skip separators, get default value
                if not default:
                    default = self._get_node_text(content, child)

        if name:
            # Skip self/cls for methods
            if class_name and name in ("self", "cls"):
                return None
            return Parameter(name=name, type=param_type, default_value=default)
        return None

    def _extract_splat_parameter(
        self, node: Any, content: bytes, splat_type: str
    ) -> Parameter | None:
        """Extract *args or **kwargs parameter.

        Args:
            node: Splat pattern node.
            content: Source code content.
            splat_type: 'list' for *args, 'dict' for **kwargs.

        Returns:
            Parameter if extraction successful.
        """
        for child in node.children:
            if child.type == "identifier":
                name = self._get_node_text(content, child)
                return Parameter(
                    name=name,
                    is_variadic=True,
                    type="*" if splat_type == "list" else "**",
                )
        return None

    def _extract_function_docstring(self, node: Any, content: bytes) -> str | None:
        """Extract docstring from function body.

        Args:
            node: Function definition node.
            content: Source code content.

        Returns:
            Docstring if found.
        """
        for child in node.children:
            if child.type == "block":
                for member in child.children:
                    if member.type == "expression_statement":
                        for expr in member.children:
                            if expr.type == "string":
                                return self._extract_string_content(expr, content)
        return None

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
            self._find_and_map_functions(root, content, func.name, func_map)
        for cls in module.classes:
            for method in cls.methods:
                self._find_and_map_functions(root, content, f"{cls.name}.{method.name}", func_map, cls.name)

        # Walk the tree and find calls
        self._extract_calls_recursive(root, content, file_path, func_map, edges)

        return CallGraph(edges=edges)

    def _find_and_map_functions(
        self, node: Any, content: bytes, func_full_name: str, func_map: dict[Any, str], class_name: str | None = None
    ) -> None:
        """Find function nodes and map them to their full names."""
        if node.type == "function_definition":
            for child in node.children:
                if child.type == "identifier":
                    name = self._get_node_text(content, child)
                    expected_name = func_full_name.split(".")[-1]
                    if name == expected_name:
                        func_map[node] = func_full_name
                        break

        for child in node.children:
            self._find_and_map_functions(child, content, func_full_name, func_map, class_name)

    def _extract_calls_recursive(
        self,
        node: Any,
        content: bytes,
        file_path: Path,
        func_map: dict[Any, str],
        edges: list[CallEdge],
        current_func: str = "unknown",
    ) -> None:
        """Recursively extract function calls."""
        if node.type == "function_definition":
            # Update current function context
            current_func = func_map.get(node, current_func)
        elif node.type == "decorated_definition":
            # Check if this decorated definition contains a function
            for child in node.children:
                if child.type == "function_definition":
                    current_func = func_map.get(child, current_func)
                    break

        if node.type == "call":
            call = self._extract_call(node, content, file_path, current_func)
            if call:
                edges.append(call)

        for child in node.children:
            self._extract_calls_recursive(child, content, file_path, func_map, edges, current_func)

    def _extract_call(
        self, node: Any, content: bytes, file_path: Path, caller_name: str
    ) -> CallEdge | None:
        """Extract function call from AST node.

        Args:
            node: Call node.
            content: Source code content.
            file_path: Path to the file.
            caller_name: Full name of the calling function.

        Returns:
            CallEdge if extraction successful.
        """
        callee_name = None
        callee_type = None

        for child in node.children:
            if child.type == "identifier":
                # Simple function call: func()
                callee_name = self._get_node_text(content, child)
            elif child.type == "attribute":
                # Method call: obj.method() or module.func()
                callee_name = self._get_node_text(content, child)
                # Try to extract the object/type
                for attr_child in child.children:
                    if attr_child.type == "identifier":
                        callee_type = self._get_node_text(content, attr_child)
                        break
            elif child.type == "call":
                # Chained call: func()() - get the inner call
                pass  # Skip for now

        if callee_name:
            return CallEdge(
                caller=caller_name,
                callee=callee_name,
                callee_type=callee_type,
                line=self._get_node_line(node),
                file_path=str(file_path),
            )
        return None
