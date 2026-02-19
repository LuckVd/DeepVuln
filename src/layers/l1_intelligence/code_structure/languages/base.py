"""Base class for language-specific code structure parsers."""

from abc import abstractmethod
from pathlib import Path
from typing import Any

from ..base import TreeSitterParser
from ..models import (
    CallEdge,
    CallGraph,
    ClassDef,
    FunctionDef,
    ImportDef,
    ModuleInfo,
    ParseOptions,
)


class LanguageParserBase(TreeSitterParser):
    """Base class for language-specific structure parsers using Tree-sitter."""

    # Tree-sitter query patterns - override in subclasses
    CLASS_QUERY: str = ""
    FUNCTION_QUERY: str = ""
    METHOD_QUERY: str = ""
    FIELD_QUERY: str = ""
    IMPORT_QUERY: str = ""
    CALL_QUERY: str = ""

    def __init__(self, options: ParseOptions | None = None) -> None:
        """Initialize the parser.

        Args:
            options: Parse options.
        """
        super().__init__(options)
        self._current_class: str | None = None  # Track current class for method parsing

    @abstractmethod
    def _extract_class(self, node: Any, content: bytes, file_path: Path) -> ClassDef | None:
        """Extract class definition from AST node.

        Args:
            node: Tree-sitter node for the class.
            content: Full source code content.
            file_path: Path to the file.

        Returns:
            ClassDef if extraction successful, None otherwise.
        """
        pass

    @abstractmethod
    def _extract_function(
        self, node: Any, content: bytes, file_path: Path, class_name: str | None = None
    ) -> FunctionDef | None:
        """Extract function/method definition from AST node.

        Args:
            node: Tree-sitter node for the function.
            content: Full source code content.
            file_path: Path to the file.
            class_name: Name of containing class if method.

        Returns:
            FunctionDef if extraction successful, None otherwise.
        """
        pass

    @abstractmethod
    def _extract_import(self, node: Any, content: bytes) -> ImportDef | None:
        """Extract import statement from AST node.

        Args:
            node: Tree-sitter node for the import.
            content: Full source code content.

        Returns:
            ImportDef if extraction successful, None otherwise.
        """
        pass

    @abstractmethod
    def _extract_call(
        self, node: Any, content: bytes, file_path: Path, caller_name: str
    ) -> CallEdge | None:
        """Extract function call from AST node.

        Args:
            node: Tree-sitter node for the call.
            content: Full source code content.
            file_path: Path to the file.
            caller_name: Full name of the calling function.

        Returns:
            CallEdge if extraction successful, None otherwise.
        """
        pass

    def parse(self, content: str, file_path: Path) -> ModuleInfo:
        """Parse source code and extract structure.

        Args:
            content: Source code content.
            file_path: Path to the source file.

        Returns:
            Parsed module information.
        """
        module = ModuleInfo(
            file_path=str(file_path),
            language=self.language_name,
            line_count=content.count("\n") + 1,
        )

        try:
            # Parse with Tree-sitter
            tree = self._parse_tree(content.encode("utf-8"))
            root = tree.root_node

            # Extract package/module name
            module.package = self._extract_package(root, content.encode("utf-8"))
            module.module_name = self._extract_module_name(root, content.encode("utf-8"), file_path)

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

        return module

    def _extract_package(self, root: Any, content: bytes) -> str | None:
        """Extract package/module declaration. Override in subclasses.

        Args:
            root: Root AST node.
            content: Source code content.

        Returns:
            Package name if found.
        """
        return None

    def _extract_module_name(
        self, root: Any, content: bytes, file_path: Path
    ) -> str | None:
        """Extract module name. Override in subclasses.

        Args:
            root: Root AST node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            Module name if found.
        """
        return file_path.stem

    def _extract_imports(self, root: Any, content: bytes) -> list[ImportDef]:
        """Extract all import statements.

        Args:
            root: Root AST node.
            content: Source code content.

        Returns:
            List of import definitions.
        """
        imports: list[ImportDef] = []

        if not self.IMPORT_QUERY:
            return imports

        try:
            query = self._language.query(self.IMPORT_QUERY)
            captures = query.captures(root)

            for node, capture_name in captures:
                imp = self._extract_import(node, content)
                if imp:
                    imports.append(imp)
        except Exception:
            pass

        return imports

    def _extract_classes(
        self, root: Any, content: bytes, file_path: Path
    ) -> list[ClassDef]:
        """Extract all class definitions.

        Args:
            root: Root AST node.
            content: Source code content.
            file_path: Path to the file.

        Returns:
            List of class definitions.
        """
        classes: list[ClassDef] = []

        if not self.CLASS_QUERY:
            return classes

        try:
            query = self._language.query(self.CLASS_QUERY)
            captures = query.captures(root)

            for node, capture_name in captures:
                cls = self._extract_class(node, content, file_path)
                if cls:
                    classes.append(cls)
        except Exception:
            pass

        return classes

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

        if not self.FUNCTION_QUERY:
            return functions

        try:
            query = self._language.query(self.FUNCTION_QUERY)
            captures = query.captures(root)

            for node, capture_name in captures:
                # Skip methods (functions inside classes)
                if self._is_inside_class(node):
                    continue

                func = self._extract_function(node, content, file_path)
                if func:
                    functions.append(func)
        except Exception:
            pass

        return functions

    def _is_inside_class(self, node: Any) -> bool:
        """Check if a node is inside a class definition.

        Args:
            node: Tree-sitter node.

        Returns:
            True if node is inside a class.
        """
        parent = node.parent
        while parent:
            if parent.type in ("class_declaration", "class_definition", "class"):
                return True
            parent = parent.parent
        return False

    def _build_call_graph(
        self, root: Any, content: bytes, file_path: Path, module: ModuleInfo
    ) -> CallGraph:
        """Build call graph for the module.

        Args:
            root: Root AST node.
            content: Source code content.
            file_path: Path to the file.
            module: Parsed module info.

        Returns:
            Call graph.
        """
        edges: list[CallEdge] = []

        if not self.CALL_QUERY:
            return CallGraph(edges=edges)

        try:
            query = self._language.query(self.CALL_QUERY)
            captures = query.captures(root)

            # Build a map of line -> containing function
            line_to_function = self._build_line_to_function_map(module)

            for node, capture_name in captures:
                line = self._get_node_line(node)
                caller_name = line_to_function.get(line, "unknown")

                call = self._extract_call(node, content, file_path, caller_name)
                if call:
                    edges.append(call)
        except Exception:
            pass

        return CallGraph(edges=edges)

    def _build_line_to_function_map(self, module: ModuleInfo) -> dict[int, str]:
        """Build a map from line numbers to containing function names.

        Args:
            module: Parsed module info.

        Returns:
            Dictionary mapping line numbers to function full names.
        """
        line_map: dict[int, str] = {}

        for func in module.functions:
            for line in range(func.line_start, func.line_end + 1):
                line_map[line] = func.full_name

        for cls in module.classes:
            for method in cls.methods:
                for line in range(method.line_start, method.line_end + 1):
                    line_map[line] = method.full_name

        return line_map

    def _find_containing_class(self, node: Any) -> str | None:
        """Find the name of the class containing a node.

        Args:
            node: Tree-sitter node.

        Returns:
            Class name if found, None otherwise.
        """
        parent = node.parent
        while parent:
            if parent.type in ("class_declaration", "class_definition", "class"):
                # Try to get class name - this is language-specific
                name_node = parent.child_by_field_name("name")
                if name_node:
                    return self._get_node_text(b"", name_node)
            parent = parent.parent
        return None
