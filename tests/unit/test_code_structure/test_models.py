"""Tests for code structure data models."""


from src.layers.l1_intelligence.code_structure.models import (
    CallEdge,
    CallGraph,
    ClassDef,
    ClassType,
    FunctionDef,
    ImportDef,
    ModuleInfo,
    Parameter,
    ParseOptions,
    ProjectStructure,
    Visibility,
)


class TestParameter:
    """Tests for Parameter model."""

    def test_basic_parameter(self):
        """Test creating a basic parameter."""
        param = Parameter(name="value", type="int")
        assert param.name == "value"
        assert param.type == "int"
        assert param.default_value is None
        assert not param.is_variadic

    def test_variadic_parameter(self):
        """Test creating a variadic parameter."""
        param = Parameter(name="args", type="any", is_variadic=True)
        assert param.is_variadic

    def test_parameter_with_default(self):
        """Test parameter with default value."""
        param = Parameter(name="timeout", type="int", default_value="30")
        assert param.default_value == "30"


class TestFunctionDef:
    """Tests for FunctionDef model."""

    def test_basic_function(self):
        """Test creating a basic function definition."""
        func = FunctionDef(
            name="calculate",
            full_name="utils.calculate",
            line_start=10,
            line_end=20,
        )
        assert func.name == "calculate"
        assert func.full_name == "utils.calculate"
        assert func.visibility == Visibility.PUBLIC
        assert not func.is_static
        assert not func.is_async

    def test_function_signature(self):
        """Test function signature property."""
        func = FunctionDef(
            name="add",
            full_name="math.add",
            parameters=[
                Parameter(name="a", type="int"),
                Parameter(name="b", type="int"),
            ],
            return_type="int",
            line_start=1,
            line_end=5,
        )
        assert func.signature == "add(a: int, b: int) -> int"

    def test_method_with_decorators(self):
        """Test method with decorators."""
        func = FunctionDef(
            name="get_user",
            full_name="UserController.get_user",
            decorators=["@GetMapping", "@ResponseBody"],
            line_start=15,
            line_end=25,
        )
        assert len(func.decorators) == 2
        assert "@GetMapping" in func.decorators


class TestClassDef:
    """Tests for ClassDef model."""

    def test_basic_class(self):
        """Test creating a basic class definition."""
        cls = ClassDef(
            name="UserService",
            full_name="com.example.UserService",
            line_start=1,
            line_end=100,
        )
        assert cls.name == "UserService"
        assert cls.type == ClassType.CLASS
        assert len(cls.methods) == 0
        assert len(cls.fields) == 0

    def test_class_with_inheritance(self):
        """Test class with inheritance."""
        cls = ClassDef(
            name="AdminController",
            full_name="com.example.AdminController",
            bases=["BaseController"],
            implements=["AdminInterface"],
            line_start=1,
            line_end=50,
        )
        assert len(cls.bases) == 1
        assert len(cls.implements) == 1

    def test_class_with_methods(self):
        """Test class with methods."""
        cls = ClassDef(
            name="Calculator",
            full_name="Calculator",
            methods=[
                FunctionDef(name="add", full_name="Calculator.add", line_start=5, line_end=10),
                FunctionDef(name="subtract", full_name="Calculator.subtract", line_start=12, line_end=17),
            ],
            line_start=1,
            line_end=20,
        )
        assert cls.method_count == 2

    def test_nested_class_count(self):
        """Test class count including nested classes."""
        cls = ClassDef(
            name="Outer",
            full_name="Outer",
            methods=[FunctionDef(name="m1", full_name="Outer.m1", line_start=1, line_end=5)],
            nested_classes=[
                ClassDef(
                    name="Inner",
                    full_name="Outer.Inner",
                    methods=[
                        FunctionDef(name="m2", full_name="Outer.Inner.m2", line_start=1, line_end=5)
                    ],
                    line_start=1,
                    line_end=10,
                )
            ],
            line_start=1,
            line_end=30,
        )
        assert cls.method_count == 2  # m1 + m2


class TestCallEdge:
    """Tests for CallEdge model."""

    def test_basic_call_edge(self):
        """Test creating a basic call edge."""
        edge = CallEdge(
            caller="Main.run",
            callee="Utils.process",
            line=42,
            file_path="Main.java",
        )
        assert edge.caller == "Main.run"
        assert edge.callee == "Utils.process"
        assert edge.line == 42
        assert not edge.is_virtual


class TestCallGraph:
    """Tests for CallGraph model."""

    def test_empty_call_graph(self):
        """Test empty call graph."""
        graph = CallGraph()
        assert len(graph.edges) == 0

    def test_get_callers(self):
        """Test getting callers of a function."""
        graph = CallGraph(
            edges=[
                CallEdge(caller="A.foo", callee="B.bar", line=1),
                CallEdge(caller="C.baz", callee="B.bar", line=2),
                CallEdge(caller="A.foo", callee="C.baz", line=3),
            ]
        )
        callers = graph.get_callers("B.bar")
        assert len(callers) == 2
        caller_names = {e.caller for e in callers}
        assert caller_names == {"A.foo", "C.baz"}

    def test_get_callees(self):
        """Test getting functions called by a function."""
        graph = CallGraph(
            edges=[
                CallEdge(caller="A.foo", callee="B.bar", line=1),
                CallEdge(caller="A.foo", callee="C.baz", line=2),
            ]
        )
        callees = graph.get_callees("A.foo")
        assert len(callees) == 2


class TestModuleInfo:
    """Tests for ModuleInfo model."""

    def test_empty_module(self):
        """Test empty module."""
        module = ModuleInfo(file_path="empty.py", language="python")
        assert module.file_path == "empty.py"
        assert module.language == "python"
        assert len(module.classes) == 0
        assert len(module.functions) == 0

    def test_all_functions(self):
        """Test getting all functions including methods."""
        module = ModuleInfo(
            file_path="test.py",
            language="python",
            functions=[
                FunctionDef(name="main", full_name="main", line_start=1, line_end=10)
            ],
            classes=[
                ClassDef(
                    name="Foo",
                    full_name="Foo",
                    methods=[
                        FunctionDef(name="bar", full_name="Foo.bar", line_start=5, line_end=10)
                    ],
                    line_start=1,
                    line_end=20,
                )
            ],
        )
        all_funcs = module.all_functions
        assert len(all_funcs) == 2  # main + bar

    def test_class_count(self):
        """Test class count property."""
        module = ModuleInfo(
            file_path="test.py",
            language="python",
            classes=[
                ClassDef(name="A", full_name="A", line_start=1, line_end=10),
                ClassDef(name="B", full_name="B", line_start=11, line_end=20),
            ],
        )
        assert module.class_count == 2


class TestProjectStructure:
    """Tests for ProjectStructure model."""

    def test_empty_project(self):
        """Test empty project."""
        project = ProjectStructure(root_path="/project")
        assert project.root_path == "/project"
        assert len(project.modules) == 0
        assert len(project.all_classes) == 0

    def test_get_class(self):
        """Test getting a class by name."""
        project = ProjectStructure(
            root_path="/project",
            all_classes={
                "com.example.User": ClassDef(
                    name="User", full_name="com.example.User", line_start=1, line_end=50
                ),
            },
        )
        # By full name
        cls = project.get_class("com.example.User")
        assert cls is not None
        assert cls.name == "User"

        # By short name
        cls = project.get_class("User")
        assert cls is not None

    def test_resolve_call(self):
        """Test call resolution - same module."""
        project = ProjectStructure(
            root_path="/project",
            modules={
                "utils.py": ModuleInfo(
                    file_path="utils.py",
                    language="python",
                    functions=[
                        FunctionDef(name="helper", full_name="helper", line_start=1, line_end=10)
                    ],
                ),
            },
            all_functions={
                "helper": FunctionDef(name="helper", full_name="helper", line_start=1, line_end=10)
            },
        )
        # Should find function in same module
        candidates = project.resolve_call("utils.py", "helper")
        assert "helper" in candidates

    def test_resolve_call_imported(self):
        """Test call resolution - imported function."""
        project = ProjectStructure(
            root_path="/project",
            modules={
                "main.py": ModuleInfo(
                    file_path="main.py",
                    language="python",
                    imports=[
                        ImportDef(module="utils", names=["helper"], line=1)
                    ],
                ),
                "utils.py": ModuleInfo(
                    file_path="utils.py",
                    language="python",
                    functions=[
                        FunctionDef(name="helper", full_name="utils.helper", line_start=1, line_end=10)
                    ],
                ),
            },
            all_functions={
                "utils.helper": FunctionDef(name="helper", full_name="utils.helper", line_start=1, line_end=10)
            },
        )
        # Should resolve through import - finds utils.helper via import
        candidates = project.resolve_call("main.py", "helper")
        assert "utils.helper" in candidates


class TestParseOptions:
    """Tests for ParseOptions model."""

    def test_default_options(self):
        """Test default parse options."""
        options = ParseOptions()
        assert not options.include_body
        assert options.include_docstrings
        assert options.build_call_graph
        assert ".py" in options.included_extensions
        assert "node_modules" in options.excluded_dirs

    def test_custom_options(self):
        """Test custom parse options."""
        options = ParseOptions(
            include_body=True,
            build_call_graph=False,
            max_file_size=500000,
        )
        assert options.include_body
        assert not options.build_call_graph
        assert options.max_file_size == 500000
