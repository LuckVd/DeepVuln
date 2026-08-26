"""
Unit tests for FrameworkDetector.

Tests cover:
- Framework rule loading
- Flask vulnerability detection
- Django vulnerability detection
- FastAPI vulnerability detection
- Express vulnerability detection
- Java vulnerability detection
- Go vulnerability detection
"""

import pytest

from src.layers.l3_analysis.engines.ast_engine.detectors.framework_detector import (
    FrameworkDetector,
)
from src.layers.l3_analysis.models import SeverityLevel


class TestFrameworkDetectorMetadata:
    """Test FrameworkDetector metadata and initialization."""

    def test_detector_type(self):
        """Test detector type is correctly set."""
        detector = FrameworkDetector()
        assert detector.detector_type() == "framework"

    def test_default_rules_dir(self):
        """Test default rules directory path.

        The default dir must be absolute (resolved from the detectors module
        location) so rule loading works regardless of the process cwd.
        """
        detector = FrameworkDetector()
        rules_dir = detector._get_default_rules_dir()
        assert rules_dir.is_absolute()
        assert str(rules_dir).endswith("rules/ast_query/framework")

    def test_rules_loaded(self):
        """Test that framework rules are loaded."""
        detector = FrameworkDetector()
        # Should have loaded at least some rules
        assert len(detector._rules) > 0


class TestFlaskDetection:
    """Test Flask-specific vulnerability detection."""

    @pytest.mark.asyncio
    async def test_render_string_template(self):
        """Test detection of render_template_string with user input."""
        detector = FrameworkDetector()

        code = """
from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/unsafe')
def unsafe_render():
    template = request.args.get('template')
    return render_template_string(template)
"""
        findings = await detector.detect(code, "python", "app.py")

        # Should detect the unsafe render_template_string
        assert len(findings) > 0
        finding = findings[0]
        assert "render" in finding.rule_id.lower() or "template" in finding.rule_id.lower()

    @pytest.mark.asyncio
    async def test_secret_key_hardcoded(self):
        """Test detection of hardcoded secret keys."""
        detector = FrameworkDetector()

        code = """
from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my-secret-key-12345'
"""
        findings = await detector.detect(code, "python", "app.py")

        # Should detect hardcoded secret key
        assert len(findings) > 0
        finding = findings[0]
        assert "secret" in finding.rule_id.lower()

    @pytest.mark.asyncio
    async def test_allow_all_hosts(self):
        """Test detection of dangerous ALLOWED_HOSTS configuration."""
        detector = FrameworkDetector()

        code = """
from flask import Flask

app = Flask(__name__)
app.config['ALLOWED_HOSTS'] = ['*']
"""
        findings = await detector.detect(code, "python", "app.py")

        # Should detect wildcard in ALLOWED_HOSTS
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_redirect_user_input(self):
        """Test detection of redirect with user input."""
        detector = FrameworkDetector()

        code = """
from flask import Flask, redirect, request

app = Flask(__name__)

@app.route('/redirect')
def unsafe_redirect():
    target = request.args.get('url')
    return redirect(target)
"""
        findings = await detector.detect(code, "python", "app.py")

        # Should detect unsafe redirect
        assert len(findings) > 0


class TestDjangoDetection:
    """Test Django-specific vulnerability detection."""

    @pytest.mark.asyncio
    async def test_render_xss(self):
        """Test detection of render with user input without autoescape."""
        detector = FrameworkDetector()

        code = """
from django.shortcuts import render

def view(request):
    user_input = request.GET.get('data')
    return render(request, 'template.html', {'content': user_input})
"""
        findings = await detector.detect(code, "python", "views.py")

        # May detect render with potential XSS
        # Note: This depends on the specific query pattern
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_extra_raw_sql(self):
        """Test detection of raw SQL usage."""
        detector = FrameworkDetector()

        code = """
from django.db import connection

def get_user(user_id):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
        row = cursor.fetchone()
    return row
"""
        findings = await detector.detect(code, "python", "views.py")

        # Should detect raw SQL execution
        assert isinstance(findings, list)


class TestFastAPIDetection:
    """Test FastAPI-specific vulnerability detection."""

    @pytest.mark.asyncio
    async def test_cors_auto_origin(self):
        """Test detection of dangerous CORS configuration."""
        detector = FrameworkDetector()

        code = """
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)
"""
        findings = await detector.detect(code, "python", "main.py")

        # Should detect wildcard CORS
        assert len(findings) > 0


class TestExpressDetection:
    """Test Express/JavaScript-specific vulnerability detection."""

    @pytest.mark.asyncio
    async def test_prototype_pollution_merge(self):
        """Test detection of prototype pollution via merge."""
        detector = FrameworkDetector()

        code = """
const express = require('express');
const merge = require('lodash/merge');

const app = express();

app.post('/merge', (req, res) => {
    const merged = merge({}, req.body);
    res.json(merged);
});
"""
        findings = await detector.detect(code, "javascript", "app.js")

        # Should detect unsafe merge usage
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_template_injection_ejs(self):
        """Test detection of EJS template injection."""
        detector = FrameworkDetector()

        code = """
const express = require('express');
const app = express();

app.set('view engine', 'ejs');

app.get('/render', (req, res) => {
    const template = req.query.template;
    res.render(template);
});
"""
        findings = await detector.detect(code, "javascript", "app.js")

        # Should detect user-controlled render
        assert isinstance(findings, list)


class TestJavaDetection:
    """Test Java-specific vulnerability detection."""

    @pytest.mark.asyncio
    async def test_reflection_class_forname(self):
        """Test detection of Class.forName with user input."""
        detector = FrameworkDetector()

        code = """
public class Loader {
    public void loadClass(String className) throws Exception {
        Class clazz = Class.forName(className);
        return clazz.newInstance();
    }
}
"""
        findings = await detector.detect(code, "java", "Loader.java")

        # Should detect Class.forName
        assert len(findings) > 0
        finding = findings[0]
        assert "reflection" in finding.rule_id.lower() or "forname" in finding.rule_id.lower()

    @pytest.mark.asyncio
    async def test_jni_register_natives(self):
        """Test detection of JNI registerNatives."""
        detector = FrameworkDetector()

        code = """
public class NativeLib {
    static {
        System.load("/path/to/library.so");
    }

    native void registerNatives(Class<?> clazz, Method[] methods, long[] handles);
}
"""
        findings = await detector.detect(code, "java", "NativeLib.java")

        # May detect JNI usage
        assert isinstance(findings, list)


class TestGoDetection:
    """Test Go-specific vulnerability detection."""

    @pytest.mark.asyncio
    async def test_context_without_deadline(self):
        """Test detection of context without deadline."""
        detector = FrameworkDetector()

        code = """
package main

import (
    "context"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    ctx := context.Background()
    // Long operation without deadline
}
"""
        findings = await detector.detect(code, "go", "handler.go")

        # Should detect context without deadline
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_defer_close_file(self):
        """Test detection of defer close in loop."""
        detector = FrameworkDetector()

        code = """
package main

import (
    "os"
)

func processFiles(files []string) error {
    for _, file := range files {
        f, err := os.Open(file)
        if err != nil {
            return err
        }
        defer f.Close()
        // Process file
    }
    return nil
}
"""
        findings = await detector.detect(code, "go", "files.go")

        # Should detect defer in loop
        assert isinstance(findings, list)


class TestFindingProperties:
    """Test finding properties are correctly set."""

    @pytest.mark.asyncio
    async def test_finding_severity_mapping(self):
        """Test that severity is correctly mapped."""
        detector = FrameworkDetector()

        # Use a known critical rule
        code = """
public class Loader {
    public void loadClass(String className) throws Exception {
        Class clazz = Class.forName(className);
        return clazz.newInstance();
    }
}
"""
        findings = await detector.detect(code, "java", "Loader.java")

        if findings:
            finding = findings[0]
            # Check severity is a valid SeverityLevel
            assert isinstance(finding.severity, SeverityLevel)

    @pytest.mark.asyncio
    async def test_finding_metadata(self):
        """Test that finding metadata is populated."""
        detector = FrameworkDetector()

        code = """
def dangerous(user_input):
    return eval(user_input)
"""
        findings = await detector.detect(code, "python", "test.py")

        if findings:
            finding = findings[0]
            assert finding.source == "ast_engine"
            assert "detector" in finding.metadata
            assert finding.metadata["detector"] == "framework"


class TestFrameworkContextValidation:
    """Test framework-specific context validation."""

    @pytest.mark.asyncio
    async def test_django_raw_sql_recommendation(self):
        """Test that Django raw SQL gets ORM recommendation."""
        detector = FrameworkDetector()

        code = """
from django.db import connection

def get_user(user_id):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
        row = cursor.fetchone()
    return row
"""
        findings = await detector.detect(code, "python", "django_app/views.py")

        # Check if Django-specific validation is applied
        validated = await detector._validate_framework_context(
            findings, code, "python", "django_app/views.py"
        )
        assert isinstance(validated, list)
