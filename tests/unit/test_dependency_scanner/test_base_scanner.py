"""Tests for base dependency scanner."""

from pathlib import Path

import pytest

from src.layers.l1_intelligence.dependency_scanner.base_scanner import (
    BaseDependencyScanner,
    Dependency,
    DependencyFile,
    Ecosystem,
    ScanResult,
)


class TestEcosystem:
    """Tests for Ecosystem enum."""

    def test_ecosystem_values(self):
        """Test ecosystem enum values."""
        assert Ecosystem.NPM.value == "npm"
        assert Ecosystem.PYPI.value == "pypi"
        assert Ecosystem.MAVEN.value == "maven"
        assert Ecosystem.GO.value == "go"
        assert Ecosystem.CARGO.value == "cargo"


class TestDependency:
    """Tests for Dependency model."""

    def test_create_dependency(self):
        """Test creating a dependency."""
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )
        assert dep.name == "requests"
        assert dep.version == "2.28.0"
        assert dep.ecosystem == Ecosystem.PYPI
        assert dep.source_file == "requirements.txt"
        assert dep.is_direct is True
        assert dep.is_dev is False
        assert dep.is_optional is False

    def test_dependency_defaults(self):
        """Test dependency default values."""
        dep = Dependency(
            name="lodash",
            version="4.17.21",
            ecosystem=Ecosystem.NPM,
            source_file="package.json",
        )
        assert dep.is_direct is True
        assert dep.is_dev is False
        assert dep.is_optional is False
        assert dep.license is None
        assert dep.description is None

    def test_to_search_query(self):
        """Test search query generation."""
        dep = Dependency(
            name="express",
            version="^4.18.0",
            ecosystem=Ecosystem.NPM,
            source_file="package.json",
        )
        query = dep.to_search_query()
        assert "express" in query
        assert "4.18.0" in query

    def test_dependency_hash_and_equality(self):
        """Test dependency hash and equality."""
        dep1 = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )
        dep2 = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem=Ecosystem.PYPI,
            source_file="pyproject.toml",  # Different source file
        )
        dep3 = Dependency(
            name="requests",
            version="2.29.0",  # Different version
            ecosystem=Ecosystem.PYPI,
            source_file="requirements.txt",
        )

        # Same name, version, ecosystem should be equal
        assert dep1 == dep2
        assert hash(dep1) == hash(dep2)

        # Different version should not be equal
        assert dep1 != dep3


class TestDependencyFile:
    """Tests for DependencyFile model."""

    def test_create_dependency_file(self):
        """Test creating a dependency file."""
        dep_file = DependencyFile(
            path=Path("package.json"),
            ecosystem=Ecosystem.NPM,
        )
        assert dep_file.path == Path("package.json")
        assert dep_file.ecosystem == Ecosystem.NPM
        assert dep_file.exists is False
        assert dep_file.parse_error is None

    def test_dependency_file_with_error(self):
        """Test dependency file with parse error."""
        dep_file = DependencyFile(
            path=Path("package.json"),
            ecosystem=Ecosystem.NPM,
            exists=True,
            parse_error="Invalid JSON",
        )
        assert dep_file.exists is True
        assert dep_file.parse_error == "Invalid JSON"


class TestScanResult:
    """Tests for ScanResult model."""

    def test_empty_scan_result(self):
        """Test empty scan result."""
        result = ScanResult(source_path="/test/path")
        assert result.total_dependencies == 0
        assert len(result.dependencies) == 0
        assert len(result.errors) == 0

    def test_add_dependency(self):
        """Test adding dependencies."""
        result = ScanResult(source_path="/test/path")

        dep = Dependency(
            name="react",
            version="18.0.0",
            ecosystem=Ecosystem.NPM,
            source_file="package.json",
        )
        result.add_dependency(dep)

        assert result.total_dependencies == 1
        assert result.direct_dependencies == 1
        assert len(result.dependencies) == 1

    def test_add_dev_dependency(self):
        """Test adding dev dependencies."""
        result = ScanResult(source_path="/test/path")

        dep = Dependency(
            name="jest",
            version="29.0.0",
            ecosystem=Ecosystem.NPM,
            source_file="package.json",
            is_dev=True,
        )
        result.add_dependency(dep)

        assert result.total_dependencies == 1
        assert result.dev_dependencies == 1

    def test_get_unique_packages(self):
        """Test getting unique packages."""
        result = ScanResult(source_path="/test/path")

        result.add_dependency(
            Dependency(
                name="lodash",
                version="4.17.21",
                ecosystem=Ecosystem.NPM,
                source_file="package.json",
            )
        )
        result.add_dependency(
            Dependency(
                name="requests",
                version="2.28.0",
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        )
        # Add duplicate (same name and ecosystem)
        result.add_dependency(
            Dependency(
                name="lodash",
                version="4.17.20",  # Different version
                ecosystem=Ecosystem.NPM,
                source_file="package-lock.json",
            )
        )

        packages = result.get_unique_packages()
        # Should only return 2 unique packages (lodash appears once)
        assert len(packages) == 2
        names = [p.name for p in packages]
        assert "lodash" in names
        assert "requests" in names

    def test_get_dependencies_by_ecosystem(self):
        """Test filtering by ecosystem."""
        result = ScanResult(source_path="/test/path")

        result.add_dependency(
            Dependency(
                name="lodash",
                version="4.17.21",
                ecosystem=Ecosystem.NPM,
                source_file="package.json",
            )
        )
        result.add_dependency(
            Dependency(
                name="requests",
                version="2.28.0",
                ecosystem=Ecosystem.PYPI,
                source_file="requirements.txt",
            )
        )

        npm_deps = result.get_dependencies_by_ecosystem(Ecosystem.NPM)
        assert len(npm_deps) == 1
        assert npm_deps[0].name == "lodash"


class TestBaseDependencyScanner:
    """Tests for BaseDependencyScanner abstract class."""

    def test_cannot_instantiate_abstract(self):
        """Test that abstract class cannot be instantiated."""
        with pytest.raises(TypeError):
            BaseDependencyScanner()  # type: ignore

    def test_subclass_must_implement_scan(self):
        """Test that subclass must implement scan method."""

        class IncompleteScanner(BaseDependencyScanner):
            ecosystem = Ecosystem.NPM
            supported_files = ["package.json"]

        with pytest.raises(TypeError):
            IncompleteScanner()  # type: ignore
