"""Tests for Go code structure parser."""

import pytest

from src.layers.l1_intelligence.code_structure.languages.go_parser import (
    GoStructureParser,
)
from src.layers.l1_intelligence.code_structure.models import (
    ClassType,
    Visibility,
)


@pytest.fixture
def parser():
    """Create a Go parser instance."""
    return GoStructureParser()


class TestGoPackageAndImports:
    """Tests for package and import parsing."""

    def test_parse_package(self, parser, tmp_path):
        """Test parsing package declaration."""
        code = """
package main

func main() {}
"""
        file_path = tmp_path / "main.go"
        module = parser.parse(code, file_path)

        assert module.package == "main"

    def test_parse_single_import(self, parser, tmp_path):
        """Test parsing single import."""
        code = """
package main

import "fmt"

func main() {}
"""
        file_path = tmp_path / "main.go"
        module = parser.parse(code, file_path)

        assert len(module.imports) == 1
        assert module.imports[0].module == "fmt"

    def test_parse_multiple_imports(self, parser, tmp_path):
        """Test parsing multiple imports."""
        code = """
package main

import (
    "fmt"
    "net/http"
    "github.com/gin-gonic/gin"
)

func main() {}
"""
        file_path = tmp_path / "main.go"
        module = parser.parse(code, file_path)

        assert len(module.imports) == 3
        modules = [imp.module for imp in module.imports]
        assert "fmt" in modules
        assert "net/http" in modules
        assert "github.com/gin-gonic/gin" in modules

    def test_parse_import_with_alias(self, parser, tmp_path):
        """Test parsing import with alias."""
        code = """
package main

import json "encoding/json"

func main() {}
"""
        file_path = tmp_path / "main.go"
        module = parser.parse(code, file_path)

        assert len(module.imports) == 1
        assert module.imports[0].module == "encoding/json"
        assert module.imports[0].alias == "json"


class TestGoStructParsing:
    """Tests for struct parsing."""

    def test_parse_simple_struct(self, parser, tmp_path):
        """Test parsing a simple struct."""
        code = """
package main

type User struct {
    Name string
    Age  int
}
"""
        file_path = tmp_path / "user.go"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        cls = module.classes[0]
        assert cls.name == "User"
        assert cls.type == ClassType.STRUCT
        assert len(cls.fields) == 2

    def test_parse_struct_with_pointer_field(self, parser, tmp_path):
        """Test parsing struct with pointer field."""
        code = """
package main

type Config struct {
    Host *string
    Port int
}
"""
        file_path = tmp_path / "config.go"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        cls = module.classes[0]
        assert cls.name == "Config"

        host_field = [f for f in cls.fields if f.name == "Host"][0]
        assert host_field.type == "*string"

    def test_parse_struct_field_visibility(self, parser, tmp_path):
        """Test parsing struct field visibility."""
        code = """
package main

type Entity struct {
    PublicField  string
    privateField int
}
"""
        file_path = tmp_path / "entity.go"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        visibilities = {f.name: f.visibility for f in cls.fields}
        assert visibilities["PublicField"] == Visibility.PUBLIC
        assert visibilities["privateField"] == Visibility.INTERNAL


class TestGoInterfaceParsing:
    """Tests for interface parsing."""

    def test_parse_simple_interface(self, parser, tmp_path):
        """Test parsing a simple interface."""
        code = """
package main

type Reader interface {
    Read(p []byte) (n int, err error)
}
"""
        file_path = tmp_path / "reader.go"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        cls = module.classes[0]
        assert cls.name == "Reader"
        assert cls.type == ClassType.INTERFACE
        assert len(cls.methods) == 1

    def test_parse_interface_with_multiple_methods(self, parser, tmp_path):
        """Test parsing interface with multiple methods."""
        code = """
package main

type ReadWriter interface {
    Read(p []byte) (n int, err error)
    Write(p []byte) (n int, err error)
    Close() error
}
"""
        file_path = tmp_path / "rw.go"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        cls = module.classes[0]
        assert cls.name == "ReadWriter"
        assert len(cls.methods) == 3

        method_names = {m.name for m in cls.methods}
        assert "Read" in method_names
        assert "Write" in method_names
        assert "Close" in method_names


class TestGoFunctionParsing:
    """Tests for function parsing."""

    def test_parse_simple_function(self, parser, tmp_path):
        """Test parsing a simple function."""
        code = """
package main

func main() {
    println("Hello")
}
"""
        file_path = tmp_path / "main.go"
        module = parser.parse(code, file_path)

        assert len(module.functions) == 1
        func = module.functions[0]
        assert func.name == "main"
        assert func.visibility == Visibility.INTERNAL  # lowercase

    def test_parse_function_with_params(self, parser, tmp_path):
        """Test parsing function with parameters."""
        code = """
package main

func Add(a int, b int) int {
    return a + b
}
"""
        file_path = tmp_path / "math.go"
        module = parser.parse(code, file_path)

        assert len(module.functions) == 1
        func = module.functions[0]
        assert func.name == "Add"
        assert func.visibility == Visibility.PUBLIC  # uppercase
        assert len(func.parameters) == 2
        assert func.return_type == "int"

    def test_parse_function_with_variadic(self, parser, tmp_path):
        """Test parsing function with variadic parameter."""
        code = """
package main

func Sum(nums ...int) int {
    total := 0
    for _, n := range nums {
        total += n
    }
    return total
}
"""
        file_path = tmp_path / "sum.go"
        module = parser.parse(code, file_path)

        assert len(module.functions) == 1
        func = module.functions[0]
        assert func.name == "Sum"
        assert len(func.parameters) == 1
        assert func.parameters[0].is_variadic


class TestGoMethodParsing:
    """Tests for method parsing."""

    def test_parse_method(self, parser, tmp_path):
        """Test parsing method with receiver."""
        code = """
package main

type User struct {
    Name string
}

func (u *User) GetName() string {
    return u.Name
}
"""
        file_path = tmp_path / "user.go"
        module = parser.parse(code, file_path)

        # Find the method
        methods = [f for f in module.functions if f.name == "GetName"]
        assert len(methods) == 1

        method = methods[0]
        assert method.full_name == "User.GetName"
        assert method.return_type == "string"

    def test_parse_multiple_methods(self, parser, tmp_path):
        """Test parsing multiple methods on same type."""
        code = """
package main

type Counter struct {
    value int
}

func (c *Counter) Increment() {
    c.value++
}

func (c *Counter) GetValue() int {
    return c.value
}
"""
        file_path = tmp_path / "counter.go"
        module = parser.parse(code, file_path)

        # Should have Counter struct and 2 methods
        assert len(module.classes) == 1

        methods = [f for f in module.functions if "." in f.full_name]
        assert len(methods) == 2

        method_names = {m.name for m in methods}
        assert "Increment" in method_names
        assert "GetValue" in method_names


class TestGoCallGraph:
    """Tests for call graph construction."""

    def test_parse_function_calls(self, parser, tmp_path):
        """Test parsing function calls."""
        code = """
package main

func validate(data string) bool {
    return true
}

func process(data string) string {
    validate(data)
    return data
}
"""
        file_path = tmp_path / "pipeline.go"
        module = parser.parse(code, file_path)

        # Check call graph has edges
        assert len(module.call_graph.edges) > 0

        # Find calls from process
        process_calls = module.call_graph.get_callees("process")
        callee_names = {e.callee for e in process_calls}

        assert "validate" in callee_names


class TestGoComplexCases:
    """Tests for complex Go code patterns."""

    def test_parse_http_handler(self, parser, tmp_path):
        """Test parsing HTTP handler pattern."""
        code = """
package main

import (
    "net/http"
)

type Handler struct {
    service *Service
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    h.service.Process(r)
    w.Write([]byte("OK"))
}
"""
        file_path = tmp_path / "handler.go"
        module = parser.parse(code, file_path)

        assert module.package == "main"
        assert len(module.imports) == 1
        assert len(module.classes) == 1

        # Check struct
        handler_cls = module.classes[0]
        assert handler_cls.name == "Handler"
        assert handler_cls.type == ClassType.STRUCT

        # Check method
        methods = [f for f in module.functions if f.name == "ServeHTTP"]
        assert len(methods) == 1

    def test_parse_grpc_service(self, parser, tmp_path):
        """Test parsing gRPC service pattern."""
        code = """
package main

type UserServiceServer interface {
    GetUser(req *GetUserRequest) (*User, error)
    CreateUser(req *CreateUserRequest) (*User, error)
}

type userServiceServer struct {
    repo Repository
}

func (s *userServiceServer) GetUser(req *GetUserRequest) (*User, error) {
    return s.repo.Find(req.Id)
}
"""
        file_path = tmp_path / "grpc.go"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 2

        # Check interface
        interface_cls = [c for c in module.classes if c.name == "UserServiceServer"][0]
        assert interface_cls.type == ClassType.INTERFACE
        assert len(interface_cls.methods) == 2

        # Check struct
        struct_cls = [c for c in module.classes if c.name == "userServiceServer"][0]
        assert struct_cls.type == ClassType.STRUCT

    def test_parse_gin_handler(self, parser, tmp_path):
        """Test parsing Gin framework handler."""
        code = """
package main

import "github.com/gin-gonic/gin"

func SetupRouter() *gin.Engine {
    r := gin.Default()
    r.GET("/ping", pingHandler)
    return r
}

func pingHandler(c *gin.Context) {
    c.JSON(200, gin.H{"message": "pong"})
}
"""
        file_path = tmp_path / "router.go"
        module = parser.parse(code, file_path)

        assert len(module.functions) == 2

        setup_func = [f for f in module.functions if f.name == "SetupRouter"][0]
        assert setup_func.visibility == Visibility.PUBLIC

        # Check call graph
        assert len(module.call_graph.edges) > 0

    def test_parse_with_slices_and_maps(self, parser, tmp_path):
        """Test parsing with complex types."""
        code = """
package main

type Config struct {
    Tags  []string
    Ports map[string]int
}
"""
        file_path = tmp_path / "config.go"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        cls = module.classes[0]

        tags_field = [f for f in cls.fields if f.name == "Tags"][0]
        assert "[]" in tags_field.type or "slice" in tags_field.type.lower()

        ports_field = [f for f in cls.fields if f.name == "Ports"][0]
        assert ports_field.type is not None
