"""Tests for Java code structure parser."""

import pytest

from src.layers.l1_intelligence.code_structure.languages.java_parser import (
    JavaStructureParser,
)
from src.layers.l1_intelligence.code_structure.models import (
    ClassType,
    Visibility,
)


@pytest.fixture
def parser():
    """Create a Java parser instance."""
    return JavaStructureParser()


class TestJavaPackageAndImports:
    """Tests for package and import parsing."""

    def test_parse_package(self, parser, tmp_path):
        """Test parsing package declaration."""
        code = """
        package com.example.service;

        public class UserService {
        }
        """
        file_path = tmp_path / "UserService.java"
        module = parser.parse(code, file_path)

        assert module.package == "com.example.service"
        assert len(module.classes) == 1
        assert module.classes[0].name == "UserService"

    def test_parse_imports(self, parser, tmp_path):
        """Test parsing import statements."""
        code = """
        package com.example;

        import java.util.List;
        import java.util.ArrayList;
        import org.springframework.stereotype.Service;

        public class MyService {
        }
        """
        file_path = tmp_path / "MyService.java"
        module = parser.parse(code, file_path)

        assert len(module.imports) == 3
        import_modules = [imp.module for imp in module.imports]
        assert "java.util.List" in import_modules
        assert "java.util.ArrayList" in import_modules
        assert "org.springframework.stereotype.Service" in import_modules

    def test_parse_wildcard_import(self, parser, tmp_path):
        """Test parsing wildcard import."""
        code = """
        import java.util.*;

        public class Test {
        }
        """
        file_path = tmp_path / "Test.java"
        module = parser.parse(code, file_path)

        assert len(module.imports) >= 1
        wildcard = [imp for imp in module.imports if imp.is_wildcard]
        assert len(wildcard) >= 1


class TestJavaClassParsing:
    """Tests for class parsing."""

    def test_parse_simple_class(self, parser, tmp_path):
        """Test parsing a simple class."""
        code = """
        public class User {
            private String name;
            private int age;

            public String getName() {
                return name;
            }
        }
        """
        file_path = tmp_path / "User.java"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        cls = module.classes[0]
        assert cls.name == "User"
        assert cls.type == ClassType.CLASS
        # Check that class has fields and methods
        assert len(cls.fields) >= 2
        assert len(cls.methods) >= 1

    def test_parse_interface(self, parser, tmp_path):
        """Test parsing an interface."""
        code = """
        public interface UserService {
            User findById(Long id);
            void save(User user);
        }
        """
        file_path = tmp_path / "UserService.java"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        cls = module.classes[0]
        assert cls.name == "UserService"
        assert cls.type == ClassType.INTERFACE

    def test_parse_enum(self, parser, tmp_path):
        """Test parsing an enum."""
        code = """
        public enum Status {
            ACTIVE,
            INACTIVE,
            PENDING
        }
        """
        file_path = tmp_path / "Status.java"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        cls = module.classes[0]
        assert cls.name == "Status"
        assert cls.type == ClassType.ENUM

    def test_parse_class_with_inheritance(self, parser, tmp_path):
        """Test parsing class with extends/implements."""
        code = """
        public class AdminUser extends User implements Serializable {
        }
        """
        file_path = tmp_path / "AdminUser.java"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        cls = module.classes[0]
        assert cls.name == "AdminUser"
        assert "User" in cls.bases
        assert "Serializable" in cls.implements

    def test_parse_nested_class(self, parser, tmp_path):
        """Test parsing nested class."""
        code = """
        public class Outer {
            private int value;

            public static class Inner {
                private String name;
            }
        }
        """
        file_path = tmp_path / "Outer.java"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 2
        outer = [c for c in module.classes if c.name == "Outer"][0]
        inner = [c for c in module.classes if c.name == "Inner"][0]

        assert inner.full_name == "Outer.Inner"


class TestJavaMethodParsing:
    """Tests for method parsing."""

    def test_parse_method(self, parser, tmp_path):
        """Test parsing method definition."""
        code = """
        public class Calculator {
            public int add(int a, int b) {
                return a + b;
            }
        }
        """
        file_path = tmp_path / "Calculator.java"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        assert len(cls.methods) == 1

        method = cls.methods[0]
        assert method.name == "add"
        assert method.return_type == "int"
        assert len(method.parameters) == 2
        assert method.parameters[0].name == "a"
        assert method.parameters[0].type == "int"

    def test_parse_method_visibility(self, parser, tmp_path):
        """Test parsing method visibility."""
        code = """
        public class Service {
            public void publicMethod() {}
            private void privateMethod() {}
            protected void protectedMethod() {}
            void packageMethod() {}
        }
        """
        file_path = tmp_path / "Service.java"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        assert len(cls.methods) == 4

        visibilities = {m.name: m.visibility for m in cls.methods}
        assert visibilities["publicMethod"] == Visibility.PUBLIC
        assert visibilities["privateMethod"] == Visibility.PRIVATE
        assert visibilities["protectedMethod"] == Visibility.PROTECTED
        assert visibilities["packageMethod"] == Visibility.PACKAGE

    def test_parse_static_method(self, parser, tmp_path):
        """Test parsing static method."""
        code = """
        public class Utils {
            public static String format(String input) {
                return input.trim();
            }
        }
        """
        file_path = tmp_path / "Utils.java"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        method = cls.methods[0]
        assert method.is_static

    def test_parse_method_with_annotations(self, parser, tmp_path):
        """Test parsing method with annotations."""
        code = """
        public class UserController {
            @GetMapping("/users")
            @ResponseBody
            public List<User> getUsers() {
                return userService.findAll();
            }
        }
        """
        file_path = tmp_path / "UserController.java"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        method = cls.methods[0]
        assert "GetMapping" in method.annotations
        assert "ResponseBody" in method.annotations


class TestJavaFieldParsing:
    """Tests for field parsing."""

    def test_parse_fields(self, parser, tmp_path):
        """Test parsing class fields."""
        code = """
        public class User {
            private String name;
            private int age;
            public static final String TYPE = "USER";
        }
        """
        file_path = tmp_path / "User.java"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        assert len(cls.fields) == 3

        field_names = {f.name for f in cls.fields}
        assert "name" in field_names
        assert "age" in field_names
        assert "TYPE" in field_names

    def test_parse_field_visibility(self, parser, tmp_path):
        """Test parsing field visibility."""
        code = """
        public class Entity {
            public String publicField;
            private String privateField;
            protected String protectedField;
        }
        """
        file_path = tmp_path / "Entity.java"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        visibilities = {f.name: f.visibility for f in cls.fields}
        assert visibilities["publicField"] == Visibility.PUBLIC
        assert visibilities["privateField"] == Visibility.PRIVATE
        assert visibilities["protectedField"] == Visibility.PROTECTED


class TestJavaAnnotations:
    """Tests for annotation parsing."""

    def test_parse_class_annotations(self, parser, tmp_path):
        """Test parsing class-level annotations."""
        code = """
        @Service
        @Transactional
        public class OrderService {
        }
        """
        file_path = tmp_path / "OrderService.java"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        assert "Service" in cls.annotations
        assert "Transactional" in cls.annotations


class TestJavaCallGraph:
    """Tests for call graph construction."""

    def test_parse_method_calls(self, parser, tmp_path):
        """Test parsing method calls."""
        code = """
        public class OrderProcessor {
            public void process(Order order) {
                validate(order);
                save(order);
                notify(order);
            }

            private void validate(Order order) {}
            private void save(Order order) {}
            private void notify(Order order) {}
        }
        """
        file_path = tmp_path / "OrderProcessor.java"
        module = parser.parse(code, file_path)

        # Check call graph has edges
        assert len(module.call_graph.edges) > 0

        # Find calls from process method
        process_calls = module.call_graph.get_callees("OrderProcessor.process")
        callee_names = {e.callee for e in process_calls}

        assert "validate" in callee_names
        assert "save" in callee_names
        assert "notify" in callee_names


class TestJavaComplexCases:
    """Tests for complex Java code patterns."""

    def test_parse_spring_controller(self, parser, tmp_path):
        """Test parsing a Spring controller."""
        code = """
        package com.example.controller;

        import org.springframework.web.bind.annotation.*;

        @RestController
        @RequestMapping("/api/users")
        public class UserController {

            private final UserService userService;

            public UserController(UserService userService) {
                this.userService = userService;
            }

            @GetMapping("/{id}")
            public User getUser(@PathVariable Long id) {
                return userService.findById(id);
            }

            @PostMapping
            public User createUser(@RequestBody User user) {
                return userService.save(user);
            }
        }
        """
        file_path = tmp_path / "UserController.java"
        module = parser.parse(code, file_path)

        assert module.package == "com.example.controller"
        assert len(module.imports) >= 1

        cls = module.classes[0]
        assert cls.name == "UserController"
        assert "RestController" in cls.annotations
        assert "RequestMapping" in cls.annotations

        # Check methods
        method_names = {m.name for m in cls.methods}
        assert "getUser" in method_names
        assert "createUser" in method_names
        assert "UserController" in method_names  # Constructor

    def test_parse_dubbo_service(self, parser, tmp_path):
        """Test parsing a Dubbo service."""
        code = """
        package com.example.service;

        import org.apache.dubbo.config.annotation.DubboService;

        @DubboService(version = "1.0.0")
        public class UserServiceImpl implements UserService {

            @Override
            public User findById(Long id) {
                return userMapper.selectById(id);
            }
        }
        """
        file_path = tmp_path / "UserServiceImpl.java"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        assert cls.name == "UserServiceImpl"
        assert "DubboService" in cls.annotations
        assert "UserService" in cls.implements
