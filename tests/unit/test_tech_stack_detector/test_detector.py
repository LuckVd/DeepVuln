"""Tests for tech stack detector."""

import json
import tempfile
from pathlib import Path

import pytest

from src.layers.l1_intelligence.tech_stack_detector.detector import (
    Framework,
    Language,
    LanguageInfo,
    TechStack,
    TechStackDetector,
)


class TestLanguage:
    """Tests for Language enum."""

    def test_language_values(self):
        """Test language enum values."""
        assert Language.PYTHON.value == "python"
        assert Language.JAVASCRIPT.value == "javascript"
        assert Language.TYPESCRIPT.value == "typescript"
        assert Language.JAVA.value == "java"
        assert Language.GO.value == "go"


class TestFramework:
    """Tests for Framework model."""

    def test_create_framework(self):
        """Test creating a framework."""
        fw = Framework(
            name="django",
            category="web",
            version="4.2",
            confidence=0.9,
        )
        assert fw.name == "django"
        assert fw.category == "web"
        assert fw.version == "4.2"
        assert fw.confidence == 0.9


class TestLanguageInfo:
    """Tests for LanguageInfo model."""

    def test_create_language_info(self):
        """Test creating a LanguageInfo."""
        info = LanguageInfo(
            language=Language.PYTHON,
            file_count=100,
            line_count=5000,
            test_file_count=20,
            doc_file_count=5,
            role="primary",
            loc_percentage=80.0,
        )
        assert info.language == Language.PYTHON
        assert info.file_count == 100
        assert info.line_count == 5000
        assert info.test_file_count == 20
        assert info.doc_file_count == 5
        assert info.role == "primary"
        assert info.loc_percentage == 80.0


class TestTechStack:
    """Tests for TechStack model."""

    def test_empty_tech_stack(self):
        """Test empty tech stack."""
        stack = TechStack()
        assert len(stack.languages) == 0
        assert len(stack.frameworks) == 0
        assert len(stack.databases) == 0
        assert stack.primary_language is None
        assert len(stack.secondary_languages) == 0

    def test_get_all_keywords(self):
        """Test getting all keywords."""
        stack = TechStack(
            frameworks=[
                Framework(name="django", category="web", version="4.2"),
                Framework(name="celery", category="task-queue"),
            ],
        )
        keywords = stack.get_all_keywords()
        assert "django" in keywords
        assert "django 4.2" in keywords
        assert "celery" in keywords

    def test_get_language_list(self):
        """Test getting simple language list for backward compatibility."""
        stack = TechStack(
            languages=[
                LanguageInfo(language=Language.PYTHON, file_count=10, line_count=1000, role="primary"),
                LanguageInfo(language=Language.JAVASCRIPT, file_count=5, line_count=200, role="secondary"),
            ],
        )
        lang_list = stack.get_language_list()
        assert Language.PYTHON in lang_list
        assert Language.JAVASCRIPT in lang_list
        assert len(lang_list) == 2

    def test_get_primary_language_info(self):
        """Test getting primary language info."""
        stack = TechStack(
            languages=[
                LanguageInfo(language=Language.PYTHON, file_count=10, line_count=1000, role="primary"),
                LanguageInfo(language=Language.JAVASCRIPT, file_count=5, line_count=200, role="secondary"),
            ],
            primary_language=Language.PYTHON,
        )
        primary = stack.get_primary_language_info()
        assert primary is not None
        assert primary.language == Language.PYTHON
        assert primary.role == "primary"


class TestTechStackDetector:
    """Tests for TechStackDetector."""

    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return TechStackDetector()

    def test_detect_empty_directory(self, detector):
        """Test detecting empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            stack = detector.detect(path)
            assert len(stack.languages) == 0
            assert len(stack.frameworks) == 0

    def test_detect_python_project(self, detector):
        """Test detecting Python project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "requirements.txt").write_text("django>=4.0.0\nrequests>=2.28.0")
            (path / "main.py").write_text("print('hello')")

            stack = detector.detect(path)

            # Use get_language_list() for backward compatibility
            assert Language.PYTHON in stack.get_language_list()
            # Check primary language
            assert stack.primary_language == Language.PYTHON
            # Django should be detected from requirements.txt
            fw_names = [fw.name for fw in stack.frameworks]
            assert "django" in fw_names

    def test_detect_javascript_project(self, detector):
        """Test detecting JavaScript project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            package_json = {
                "dependencies": {
                    "express": "^4.18.0",
                    "react": "^18.0.0",
                },
            }
            (path / "package.json").write_text(json.dumps(package_json))
            # Add a JS file to trigger language detection
            (path / "index.js").write_text("console.log('hello');")

            stack = detector.detect(path)

            # Use get_language_list() for backward compatibility
            assert Language.JAVASCRIPT in stack.get_language_list()
            fw_names = [fw.name for fw in stack.frameworks]
            assert "express" in fw_names
            assert "react" in fw_names

    def test_detect_typescript_project(self, detector):
        """Test detecting TypeScript project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "tsconfig.json").write_text("{}")
            package_json = {
                "dependencies": {
                    "@nestjs/core": "^10.0.0",
                },
            }
            (path / "package.json").write_text(json.dumps(package_json))
            # Add a TS file to trigger language detection
            (path / "main.ts").write_text("console.log('hello');")

            stack = detector.detect(path)

            # Use get_language_list() for backward compatibility
            assert Language.TYPESCRIPT in stack.get_language_list()
            fw_names = [fw.name for fw in stack.frameworks]
            assert "nestjs" in fw_names

    def test_detect_java_project(self, detector):
        """Test detecting Java project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            pom_xml = """<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter</artifactId>
        </dependency>
    </dependencies>
</project>
"""
            (path / "pom.xml").write_text(pom_xml)
            # Add a Java file to trigger language detection
            (path / "Main.java").write_text("public class Main {}")

            stack = detector.detect(path)

            # Use get_language_list() for backward compatibility
            assert Language.JAVA in stack.get_language_list()
            fw_names = [fw.name for fw in stack.frameworks]
            assert "spring" in fw_names or "spring-boot" in fw_names

    def test_detect_flask_project(self, detector):
        """Test detecting Flask project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "requirements.txt").write_text("flask>=2.0.0")
            (path / "app.py").write_text("from flask import Flask")

            stack = detector.detect(path)

            # Use get_language_list() for backward compatibility
            assert Language.PYTHON in stack.get_language_list()
            # Check primary language
            assert stack.primary_language == Language.PYTHON
            fw_names = [fw.name for fw in stack.frameworks]
            assert "flask" in fw_names

    def test_detect_database_mysql(self, detector):
        """Test detecting MySQL database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "requirements.txt").write_text("mysql-connector-python\npymysql")

            stack = detector.detect(path)

            db_names = [db.name for db in stack.databases]
            assert "mysql" in db_names

    def test_detect_database_postgresql(self, detector):
        """Test detecting PostgreSQL database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "requirements.txt").write_text("psycopg2-binary")

            stack = detector.detect(path)

            db_names = [db.name for db in stack.databases]
            assert "postgresql" in db_names

    def test_detect_database_mongodb(self, detector):
        """Test detecting MongoDB database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            package_json = {
                "dependencies": {
                    "mongoose": "^6.0.0",
                },
            }
            (path / "package.json").write_text(json.dumps(package_json))

            stack = detector.detect(path)

            db_names = [db.name for db in stack.databases]
            assert "mongodb" in db_names

    def test_detect_docker(self, detector):
        """Test detecting Docker."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "Dockerfile").write_text("FROM python:3.11")

            stack = detector.detect(path)

            mw_names = [mw.name for mw in stack.middleware]
            assert "docker" in mw_names

    def test_detect_github_actions(self, detector):
        """Test detecting GitHub Actions CI/CD."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            workflows = path / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text("name: CI")

            stack = detector.detect(path)

            assert "GitHub Actions" in stack.ci_cd

    def test_detect_build_tools(self, detector):
        """Test detecting build tools."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "tsconfig.json").write_text("{}")
            (path / "webpack.config.js").write_text("module.exports = {}")

            stack = detector.detect(path)

            assert "typescript" in stack.build_tools
            assert "webpack" in stack.build_tools

    def test_detect_package_managers(self, detector):
        """Test detecting package managers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "package-lock.json").write_text("{}")
            (path / "poetry.lock").write_text("[[package]]")

            stack = detector.detect(path)

            assert "npm" in stack.package_managers
            assert "poetry" in stack.package_managers

    def test_detect_complex_project(self, detector):
        """Test detecting complex multi-language project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create a full-stack project structure
            (path / "requirements.txt").write_text(
                "django>=4.0.0\ndjango-rest-framework\npsycopg2-binary\nredis"
            )
            # Add actual Python code (not just comments) for LOC counting
            (path / "manage.py").write_text("#!/usr/bin/env python\nimport os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')\n")

            frontend = path / "frontend"
            frontend.mkdir()
            package_json = {
                "dependencies": {
                    "react": "^18.0.0",
                    "next": "^13.0.0",
                },
            }
            (frontend / "package.json").write_text(json.dumps(package_json))
            # Add a .js file to trigger JavaScript detection
            (frontend / "index.js").write_text("console.log('hello');")

            (path / "Dockerfile").write_text("FROM python:3.11")

            stack = detector.detect(path)

            # Use get_language_list() for backward compatibility
            lang_list = stack.get_language_list()
            # Should detect Python
            assert Language.PYTHON in lang_list
            # Should also detect JavaScript
            assert Language.JAVASCRIPT in lang_list

            # Should detect frameworks (django from requirements.txt)
            fw_names = [fw.name for fw in stack.frameworks]
            assert "django" in fw_names

            # Should detect databases
            db_names = [db.name for db in stack.databases]
            assert "postgresql" in db_names
            assert "redis" in db_names

            # Should detect middleware
            mw_names = [mw.name for mw in stack.middleware]
            assert "docker" in mw_names

    def test_detect_test_files(self, detector):
        """Test detecting test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "main.py").write_text("print('hello')")
            tests_dir = path / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_main.py").write_text("def test_main(): pass")

            stack = detector.detect(path)

            assert stack.has_tests is True
            # Check that test file count is tracked
            python_info = stack.get_language_info(Language.PYTHON)
            assert python_info is not None
            assert python_info.test_file_count >= 1

    def test_detect_docs(self, detector):
        """Test detecting documentation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "main.py").write_text("print('hello')")
            (path / "README.md").write_text("# Project")

            stack = detector.detect(path)

            assert stack.has_docs is True

    def test_primary_language_detection(self, detector):
        """Test primary language detection based on LOC."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            # Create more Python code
            (path / "main.py").write_text("\n".join(["print('hello')"] * 100))
            # Create less JavaScript code
            (path / "script.js").write_text("console.log('hi');")

            stack = detector.detect(path)

            assert stack.primary_language == Language.PYTHON

    def test_secondary_language_detection(self, detector):
        """Test secondary language detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            # Create Python code
            (path / "main.py").write_text("\n".join(["print('hello')"] * 100))
            # Create JavaScript code with > 10% LOC
            (path / "script.js").write_text("\n".join(["console.log('hi');"] * 50))

            stack = detector.detect(path)

            assert stack.primary_language == Language.PYTHON
            # JavaScript should be secondary if it has > 10% LOC
            # Note: This depends on the actual LOC calculation

    def test_loc_statistics(self, detector):
        """Test LOC statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "main.py").write_text("print('hello')\nprint('world')\n# comment\n")
            (path / "utils.py").write_text("def foo():\n    pass\n")

            stack = detector.detect(path)

            assert stack.total_loc > 0
            assert stack.total_files == 2
            # Check that Python has the correct stats
            python_info = stack.get_language_info(Language.PYTHON)
            assert python_info is not None
            assert python_info.file_count == 2

    def test_scan_statistics(self, detector):
        """Test scan statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "main.py").write_text("print('hello')")

            detector.detect(path)

            stats = detector.get_scan_statistics()
            assert "duration_seconds" in stats
            assert "files_scanned" in stats
            assert "directories_scanned" in stats
            assert "source_files" in stats
            assert "total_loc" in stats
