"""Tests for Python code structure parser."""

import pytest

from src.layers.l1_intelligence.code_structure.languages.python_parser import (
    PythonStructureParser,
)
from src.layers.l1_intelligence.code_structure.models import (
    ClassType,
    Visibility,
)


@pytest.fixture
def parser():
    """Create a Python parser instance."""
    return PythonStructureParser()


class TestPythonImports:
    """Tests for import parsing."""

    def test_parse_simple_import(self, parser, tmp_path):
        """Test parsing simple import statement."""
        code = """
import os
import sys

def main():
    pass
"""
        file_path = tmp_path / "test.py"
        module = parser.parse(code, file_path)

        assert len(module.imports) == 2
        import_modules = [imp.module for imp in module.imports]
        assert "os" in import_modules
        assert "sys" in import_modules

    def test_parse_import_with_alias(self, parser, tmp_path):
        """Test parsing import with alias."""
        code = """
import numpy as np
import pandas as pd

def process():
    pass
"""
        file_path = tmp_path / "test.py"
        module = parser.parse(code, file_path)

        assert len(module.imports) == 2
        numpy_imp = [imp for imp in module.imports if imp.module == "numpy"][0]
        assert numpy_imp.alias == "np"

    def test_parse_from_import(self, parser, tmp_path):
        """Test parsing from-import statement."""
        code = """
from typing import List, Dict
from collections import OrderedDict

def func():
    pass
"""
        file_path = tmp_path / "test.py"
        module = parser.parse(code, file_path)

        assert len(module.imports) == 2
        typing_imp = [imp for imp in module.imports if imp.module == "typing"][0]
        assert "List" in typing_imp.names
        assert "Dict" in typing_imp.names

    def test_parse_wildcard_import(self, parser, tmp_path):
        """Test parsing wildcard import."""
        code = """
from module import *

def func():
    pass
"""
        file_path = tmp_path / "test.py"
        module = parser.parse(code, file_path)

        assert len(module.imports) >= 1
        wildcard = [imp for imp in module.imports if imp.is_wildcard]
        assert len(wildcard) >= 1


class TestPythonClassParsing:
    """Tests for class parsing."""

    def test_parse_simple_class(self, parser, tmp_path):
        """Test parsing a simple class."""
        code = """
class User:
    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name
"""
        file_path = tmp_path / "user.py"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        cls = module.classes[0]
        assert cls.name == "User"
        assert cls.type == ClassType.CLASS
        assert len(cls.methods) == 2  # __init__ + get_name

    def test_parse_class_with_inheritance(self, parser, tmp_path):
        """Test parsing class with inheritance."""
        code = """
class AdminUser(User):
    pass

class Manager(User, Serializable):
    pass
"""
        file_path = tmp_path / "users.py"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 2

        admin = [c for c in module.classes if c.name == "AdminUser"][0]
        assert "User" in admin.bases

        manager = [c for c in module.classes if c.name == "Manager"][0]
        assert "User" in manager.bases
        assert "Serializable" in manager.bases

    def test_parse_nested_class(self, parser, tmp_path):
        """Test parsing nested class."""
        code = """
class Outer:
    class Inner:
        def inner_method(self):
            pass

    def outer_method(self):
        pass
"""
        file_path = tmp_path / "nested.py"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        outer = module.classes[0]
        assert outer.name == "Outer"
        assert len(outer.nested_classes) == 1
        assert outer.nested_classes[0].name == "Inner"

    def test_parse_class_with_decorators(self, parser, tmp_path):
        """Test parsing class with decorators."""
        code = """
@dataclass
@serializable
class User:
    name: str
    age: int
"""
        file_path = tmp_path / "user.py"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        cls = module.classes[0]
        assert "dataclass" in cls.decorators
        assert "serializable" in cls.decorators


class TestPythonFunctionParsing:
    """Tests for function parsing."""

    def test_parse_top_level_function(self, parser, tmp_path):
        """Test parsing top-level function."""
        code = """
def calculate(a: int, b: int) -> int:
    return a + b
"""
        file_path = tmp_path / "calc.py"
        module = parser.parse(code, file_path)

        assert len(module.functions) == 1
        func = module.functions[0]
        assert func.name == "calculate"
        assert func.return_type == "int"
        assert len(func.parameters) == 2

    def test_parse_function_with_default(self, parser, tmp_path):
        """Test parsing function with default parameter."""
        code = """
def greet(name, greeting="Hello"):
    return f"{greeting}, {name}"
"""
        file_path = tmp_path / "greet.py"
        module = parser.parse(code, file_path)

        assert len(module.functions) == 1
        func = module.functions[0]
        assert len(func.parameters) == 2

        greeting_param = [p for p in func.parameters if p.name == "greeting"][0]
        assert greeting_param.default_value == '"Hello"'

    def test_parse_function_with_varargs(self, parser, tmp_path):
        """Test parsing function with *args and **kwargs."""
        code = """
def func(*args, **kwargs):
    pass
"""
        file_path = tmp_path / "varargs.py"
        module = parser.parse(code, file_path)

        assert len(module.functions) == 1
        func = module.functions[0]
        assert len(func.parameters) == 2

        args_param = [p for p in func.parameters if p.name == "args"][0]
        assert args_param.is_variadic

        kwargs_param = [p for p in func.parameters if p.name == "kwargs"][0]
        assert kwargs_param.is_variadic

    def test_parse_async_function(self, parser, tmp_path):
        """Test parsing async function."""
        code = """
async def fetch_data(url):
    return await request(url)
"""
        file_path = tmp_path / "async_func.py"
        module = parser.parse(code, file_path)

        assert len(module.functions) == 1
        func = module.functions[0]
        assert func.is_async

    def test_parse_function_visibility(self, parser, tmp_path):
        """Test parsing function visibility based on naming."""
        code = """
def public_func():
    pass

def _internal_func():
    pass

def __private_func():
    pass
"""
        file_path = tmp_path / "visibility.py"
        module = parser.parse(code, file_path)

        assert len(module.functions) == 3

        visibilities = {f.name: f.visibility for f in module.functions}
        assert visibilities["public_func"] == Visibility.PUBLIC
        assert visibilities["_internal_func"] == Visibility.INTERNAL
        assert visibilities["__private_func"] == Visibility.PRIVATE


class TestPythonMethodParsing:
    """Tests for method parsing."""

    def test_parse_method(self, parser, tmp_path):
        """Test parsing method definition."""
        code = """
class Calculator:
    def add(self, a: int, b: int) -> int:
        return a + b
"""
        file_path = tmp_path / "calc.py"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        assert len(cls.methods) == 1

        method = cls.methods[0]
        assert method.name == "add"
        assert method.return_type == "int"
        # self should be filtered out
        assert len(method.parameters) == 2
        param_names = [p.name for p in method.parameters]
        assert "a" in param_names
        assert "b" in param_names
        assert "self" not in param_names

    def test_parse_method_decorators(self, parser, tmp_path):
        """Test parsing method with decorators."""
        code = """
class Service:
    @staticmethod
    def create():
        pass

    @classmethod
    def get_instance(cls):
        pass

    @property
    def value(self):
        return self._value
"""
        file_path = tmp_path / "service.py"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        assert len(cls.methods) == 3

        method_decorators = {m.name: m.decorators for m in cls.methods}
        assert "staticmethod" in method_decorators["create"]
        assert "classmethod" in method_decorators["get_instance"]
        assert "property" in method_decorators["value"]

    def test_parse_staticmethod(self, parser, tmp_path):
        """Test parsing static method."""
        code = """
class Utils:
    @staticmethod
    def format_string(s):
        return s.strip()
"""
        file_path = tmp_path / "utils.py"
        module = parser.parse(code, file_path)

        cls = module.classes[0]
        method = cls.methods[0]
        assert method.is_static


class TestPythonCallGraph:
    """Tests for call graph construction."""

    def test_parse_function_calls(self, parser, tmp_path):
        """Test parsing function calls."""
        code = """
def validate(data):
    return True

def process(data):
    validate(data)
    save(data)
    return data

def save(data):
    pass
"""
        file_path = tmp_path / "pipeline.py"
        module = parser.parse(code, file_path)

        # Check call graph has edges
        assert len(module.call_graph.edges) > 0

        # Find calls from process
        process_calls = module.call_graph.get_callees("process")
        callee_names = {e.callee for e in process_calls}

        assert "validate" in callee_names
        assert "save" in callee_names

    def test_parse_method_calls(self, parser, tmp_path):
        """Test parsing method calls."""
        code = """
class Processor:
    def run(self):
        self.validate()
        self.process()

    def validate(self):
        pass

    def process(self):
        pass
"""
        file_path = tmp_path / "processor.py"
        module = parser.parse(code, file_path)

        # Check call graph has edges
        assert len(module.call_graph.edges) > 0

        # Find calls from run method
        run_calls = module.call_graph.get_callees("Processor.run")
        callee_names = {e.callee for e in run_calls}

        # Should find validate and process calls (as self.validate, self.process)
        assert any("validate" in c for c in callee_names)
        assert any("process" in c for c in callee_names)


class TestPythonComplexCases:
    """Tests for complex Python code patterns."""

    def test_parse_flask_route(self, parser, tmp_path):
        """Test parsing a Flask route."""
        code = """
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])

@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())
"""
        file_path = tmp_path / "routes.py"
        module = parser.parse(code, file_path)

        assert len(module.imports) >= 1
        assert len(module.functions) == 2

        # Check decorators
        get_users = [f for f in module.functions if f.name == "get_users"][0]
        assert any("route" in d for d in get_users.decorators)

    def test_parse_django_model(self, parser, tmp_path):
        """Test parsing a Django model."""
        code = """
from django.db import models

class User(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'users'
"""
        file_path = tmp_path / "models.py"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        user_cls = module.classes[0]
        assert user_cls.name == "User"
        assert "models.Model" in user_cls.bases

        # Check nested class
        assert len(user_cls.nested_classes) == 1
        assert user_cls.nested_classes[0].name == "Meta"

    def test_parse_fastapi_endpoint(self, parser, tmp_path):
        """Test parsing a FastAPI endpoint."""
        code = """
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

class Item(BaseModel):
    name: str
    price: float

@app.post("/items/")
async def create_item(item: Item):
    return item

@app.get("/items/{item_id}")
def read_item(item_id: int):
    return {"item_id": item_id}
"""
        file_path = tmp_path / "main.py"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        assert len(module.functions) == 2

        # Check async function
        create_item = [f for f in module.functions if f.name == "create_item"][0]
        assert create_item.is_async
        assert "app.post" in create_item.decorators

    def test_parse_dataclass(self, parser, tmp_path):
        """Test parsing a dataclass."""
        code = """
from dataclasses import dataclass
from typing import Optional

@dataclass
class User:
    name: str
    age: int
    email: Optional[str] = None

    def is_adult(self) -> bool:
        return self.age >= 18
"""
        file_path = tmp_path / "user.py"
        module = parser.parse(code, file_path)

        assert len(module.classes) == 1
        user_cls = module.classes[0]
        assert "dataclass" in user_cls.decorators
        assert len(user_cls.methods) == 1

        is_adult = user_cls.methods[0]
        assert is_adult.name == "is_adult"
        assert is_adult.return_type == "bool"

    def test_parse_with_docstrings(self, parser, tmp_path):
        """Test parsing with docstrings."""
        code = '''
"""Module docstring."""

def process(data):
    """Process the data.

    Args:
        data: Input data to process.

    Returns:
        Processed data.
    """
    return data

class Service:
    """Service class for handling requests."""

    def handle(self, request):
        """Handle the incoming request."""
        return self.process(request)
'''
        file_path = tmp_path / "service.py"
        module = parser.parse(code, file_path)

        # Check function docstring
        process_func = module.functions[0]
        assert process_func.docstring is not None
        assert "Process the data" in process_func.docstring

        # Check class docstring
        service_cls = module.classes[0]
        assert service_cls.docstring is not None
        assert "Service class" in service_cls.docstring
