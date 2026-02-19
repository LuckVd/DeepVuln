"""Data models for code structure parsing."""

from enum import Enum

from pydantic import BaseModel, Field


class Visibility(str, Enum):
    """Visibility/access modifier for class members."""

    PUBLIC = "public"
    PRIVATE = "private"
    PROTECTED = "protected"
    PACKAGE = "package"  # Java default
    INTERNAL = "internal"  # Go/Python


class ClassType(str, Enum):
    """Type of class-like structure."""

    CLASS = "class"
    INTERFACE = "interface"
    ENUM = "enum"
    STRUCT = "struct"
    TRAIT = "trait"  # Rust/Scala
    ABSTRACT_CLASS = "abstract_class"


class Parameter(BaseModel):
    """Function/method parameter."""

    name: str
    type: str | None = None
    default_value: str | None = None
    is_variadic: bool = False  # *args, **kwargs, varargs
    is_keyword_only: bool = False  # Python keyword-only args


class FieldDef(BaseModel):
    """Class field/attribute definition."""

    name: str
    type: str | None = None
    visibility: Visibility = Visibility.PUBLIC
    is_static: bool = False
    is_final: bool = False
    default_value: str | None = None
    annotations: list[str] = Field(default_factory=list)
    line: int = 0


class FunctionDef(BaseModel):
    """Function/method definition."""

    name: str
    full_name: str  # ClassName.methodName or module.function_name
    parameters: list[Parameter] = Field(default_factory=list)
    return_type: str | None = None
    visibility: Visibility = Visibility.PUBLIC
    is_static: bool = False
    is_async: bool = False
    is_abstract: bool = False
    decorators: list[str] = Field(default_factory=list)
    annotations: list[str] = Field(default_factory=list)  # Java annotations
    docstring: str | None = None
    body_lines: int = 0  # Number of lines in function body
    line_start: int = 0
    line_end: int = 0
    file_path: str = ""

    @property
    def signature(self) -> str:
        """Get function signature string."""
        params = ", ".join(
            f"{p.name}: {p.type}" if p.type else p.name for p in self.parameters
        )
        ret = f" -> {self.return_type}" if self.return_type else ""
        return f"{self.name}({params}){ret}"


class ClassDef(BaseModel):
    """Class/interface/struct definition."""

    name: str
    full_name: str  # package.ClassName or module.ClassName
    type: ClassType = ClassType.CLASS
    bases: list[str] = Field(default_factory=list)  # Parent classes
    implements: list[str] = Field(default_factory=list)  # Interfaces implemented
    methods: list[FunctionDef] = Field(default_factory=list)
    fields: list[FieldDef] = Field(default_factory=list)
    nested_classes: list["ClassDef"] = Field(default_factory=list)
    annotations: list[str] = Field(default_factory=list)
    docstring: str | None = None
    line_start: int = 0
    line_end: int = 0
    file_path: str = ""

    @property
    def method_count(self) -> int:
        """Get total method count including nested classes."""
        count = len(self.methods)
        for nested in self.nested_classes:
            count += nested.method_count
        return count

    @property
    def field_count(self) -> int:
        """Get total field count including nested classes."""
        count = len(self.fields)
        for nested in self.nested_classes:
            count += nested.field_count
        return count


class ImportDef(BaseModel):
    """Import statement definition."""

    module: str  # The module being imported
    names: list[str] = Field(default_factory=list)  # Specific names imported
    alias: str | None = None  # import x as alias
    is_wildcard: bool = False  # from x import *
    line: int = 0


class CallEdge(BaseModel):
    """Edge in the call graph representing a function/method call."""

    caller: str  # full_name of caller function/method
    callee: str  # full_name or symbol of callee
    callee_type: str | None = None  # Type of callee if known
    line: int = 0
    file_path: str = ""
    is_virtual: bool = False  # Virtual/polymorphic call
    confidence: float = 1.0  # Confidence in call resolution


class CallGraph(BaseModel):
    """Call graph for a module or project."""

    edges: list[CallEdge] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)  # Known entry points

    def get_callers(self, callee: str) -> list[CallEdge]:
        """Get all callers of a function."""
        return [e for e in self.edges if e.callee == callee]

    def get_callees(self, caller: str) -> list[CallEdge]:
        """Get all functions called by a function."""
        return [e for e in self.edges if e.caller == caller]


class ModuleInfo(BaseModel):
    """Parsed information about a single source file."""

    file_path: str
    language: str
    package: str | None = None  # Java package, Go package, etc.
    module_name: str | None = None  # Python module name

    imports: list[ImportDef] = Field(default_factory=list)
    classes: list[ClassDef] = Field(default_factory=list)
    functions: list[FunctionDef] = Field(default_factory=list)  # Top-level functions
    global_variables: list[FieldDef] = Field(default_factory=list)

    call_graph: CallGraph = Field(default_factory=CallGraph)

    # Metadata
    line_count: int = 0
    parse_errors: list[str] = Field(default_factory=list)

    @property
    def all_functions(self) -> list[FunctionDef]:
        """Get all functions including class methods."""
        functions = list(self.functions)
        for cls in self.classes:
            functions.extend(cls.methods)
            for nested in cls.nested_classes:
                functions.extend(nested.methods)
        return functions

    @property
    def class_count(self) -> int:
        """Get total class count including nested."""
        count = len(self.classes)
        for cls in self.classes:
            count += len(cls.nested_classes)
        return count


class ProjectStructure(BaseModel):
    """Parsed structure of an entire project."""

    root_path: str
    primary_language: str | None = None
    languages: list[str] = Field(default_factory=list)

    modules: dict[str, ModuleInfo] = Field(default_factory=dict)  # file_path -> ModuleInfo

    # Aggregated data
    all_classes: dict[str, ClassDef] = Field(default_factory=dict)  # full_name -> ClassDef
    all_functions: dict[str, FunctionDef] = Field(default_factory=dict)  # full_name -> FunctionDef
    global_call_graph: CallGraph = Field(default_factory=CallGraph)

    # Statistics
    total_files: int = 0
    total_lines: int = 0
    parse_errors: dict[str, str] = Field(default_factory=dict)  # file_path -> error

    def get_class(self, name: str) -> ClassDef | None:
        """Get a class by name or full name."""
        if name in self.all_classes:
            return self.all_classes[name]
        # Try partial match
        for full_name, cls in self.all_classes.items():
            if full_name.endswith(f".{name}") or full_name == name:
                return cls
        return None

    def get_function(self, name: str) -> FunctionDef | None:
        """Get a function by name or full name."""
        if name in self.all_functions:
            return self.all_functions[name]
        # Try partial match
        for full_name, func in self.all_functions.items():
            if full_name.endswith(f".{name}") or full_name == name:
                return func
        return None

    def resolve_call(self, caller_module: str, callee_name: str) -> list[str]:
        """Resolve a call to possible target functions.

        Args:
            caller_module: Module where the call is made
            callee_name: Name of the called function

        Returns:
            List of possible full names for the callee
        """
        candidates = []

        # Check if it's a fully qualified name
        if "." in callee_name:
            if callee_name in self.all_functions:
                candidates.append(callee_name)
            return candidates

        # Check in same module
        if caller_module in self.modules:
            module = self.modules[caller_module]
            for func in module.functions:
                if func.name == callee_name:
                    candidates.append(func.full_name)
            for cls in module.classes:
                for method in cls.methods:
                    if method.name == callee_name:
                        candidates.append(method.full_name)

        # Check imported functions
        if caller_module in self.modules:
            module = self.modules[caller_module]
            for imp in module.imports:
                for name in imp.names:
                    if name == callee_name:
                        # Try to resolve import
                        full_name = f"{imp.module}.{callee_name}"
                        if full_name in self.all_functions:
                            candidates.append(full_name)

        return candidates


class ParseOptions(BaseModel):
    """Options for code structure parsing."""

    include_body: bool = False  # Include function bodies (expensive)
    include_comments: bool = False  # Include comments
    include_docstrings: bool = True  # Include docstrings
    build_call_graph: bool = True  # Build call graph
    resolve_imports: bool = False  # Try to resolve imports across files
    max_file_size: int = 1024 * 1024  # Max file size to parse (1MB)
    excluded_dirs: list[str] = Field(
        default_factory=lambda: [
            "node_modules",
            "venv",
            ".venv",
            "__pycache__",
            ".git",
            "build",
            "dist",
            "target",
            "vendor",
        ]
    )
    included_extensions: list[str] = Field(
        default_factory=lambda: [".py", ".java", ".go", ".ts", ".js", ".kt"]
    )
