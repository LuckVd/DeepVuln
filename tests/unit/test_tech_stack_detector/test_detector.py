"""Tests for tech stack detector."""

import json
import tempfile
from pathlib import Path

import pytest

from src.layers.l1_intelligence.tech_stack_detector.detector import (
    Framework,
    Language,
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


class TestTechStack:
    """Tests for TechStack model."""

    def test_empty_tech_stack(self):
        """Test empty tech stack."""
        stack = TechStack()
        assert len(stack.languages) == 0
        assert len(stack.frameworks) == 0
        assert len(stack.databases) == 0

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

            assert Language.PYTHON in stack.languages
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

            stack = detector.detect(path)

            assert Language.JAVASCRIPT in stack.languages
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

            stack = detector.detect(path)

            assert Language.TYPESCRIPT in stack.languages
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

            stack = detector.detect(path)

            assert Language.JAVA in stack.languages
            fw_names = [fw.name for fw in stack.frameworks]
            assert "spring" in fw_names or "spring-boot" in fw_names

    def test_detect_flask_project(self, detector):
        """Test detecting Flask project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "requirements.txt").write_text("flask>=2.0.0")
            (path / "app.py").write_text("from flask import Flask")

            stack = detector.detect(path)

            assert Language.PYTHON in stack.languages
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
            (path / "manage.py").write_text("# Django manage.py")

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

            # Should detect Python
            assert Language.PYTHON in stack.languages

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
