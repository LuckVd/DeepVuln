"""Tests for NPM dependency scanner."""

import json
import tempfile
from pathlib import Path

import pytest

from src.layers.l1_intelligence.dependency_scanner.base_scanner import Ecosystem
from src.layers.l1_intelligence.dependency_scanner.npm_scanner import NpmScanner


class TestNpmScanner:
    """Tests for NpmScanner."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return NpmScanner()

    def test_ecosystem(self, scanner):
        """Test scanner ecosystem."""
        assert scanner.ecosystem == Ecosystem.NPM

    def test_supported_files(self, scanner):
        """Test supported files."""
        assert "package.json" in scanner.supported_files
        assert "package-lock.json" in scanner.supported_files

    def test_can_scan_package_json(self, scanner):
        """Test can_scan for package.json file."""
        assert scanner.can_scan(Path("package.json")) is True

    def test_can_scan_no_package_file(self, scanner):
        """Test can_scan for non-package file."""
        assert scanner.can_scan(Path("other.txt")) is False

    def test_scan_empty_directory(self, scanner):
        """Test scanning empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            deps = scanner.scan(path)
            assert len(deps) == 0

    def test_scan_empty_package_json(self, scanner):
        """Test scanning empty package.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "package.json").write_text("{}")
            deps = scanner.scan(path)
            assert len(deps) == 0

    def test_scan_package_json_with_dependencies(self, scanner):
        """Test scanning package.json with dependencies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            package_json = {
                "dependencies": {
                    "express": "^4.18.0",
                    "lodash": "4.17.21",
                },
                "devDependencies": {
                    "jest": "^29.0.0",
                },
            }
            (path / "package.json").write_text(json.dumps(package_json))
            deps = scanner.scan(path)

            assert len(deps) == 3
            dep_names = [d.name for d in deps]
            assert "express" in dep_names
            assert "lodash" in dep_names
            assert "jest" in dep_names

    def test_scan_package_json_with_peer_dependencies(self, scanner):
        """Test scanning package.json with peer dependencies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            package_json = {
                "peerDependencies": {
                    "react": ">=16.8.0",
                },
            }
            (path / "package.json").write_text(json.dumps(package_json))
            deps = scanner.scan(path)

            assert len(deps) == 1
            assert deps[0].name == "react"
            assert deps[0].is_direct is True

    def test_scan_package_lock_json(self, scanner):
        """Test scanning package-lock.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            package_lock = {
                "lockfileVersion": 2,
                "packages": {
                    "": {
                        "name": "test-project",
                        "dependencies": {
                            "express": "^4.18.0",
                        },
                    },
                    "node_modules/express": {
                        "version": "4.18.2",
                    },
                    "node_modules/lodash": {
                        "version": "4.17.21",
                    },
                },
            }
            (path / "package-lock.json").write_text(json.dumps(package_lock))
            deps = scanner.scan(path)

            # Should find packages from lock file
            assert len(deps) >= 1
            dep_names = [d.name for d in deps]
            # express or lodash should be found
            assert any(name in dep_names for name in ["express", "lodash"])

    def test_scan_invalid_json(self, scanner):
        """Test scanning invalid JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "package.json").write_text("not valid json")
            deps = scanner.scan(path)

            # Should not crash, return empty list
            assert len(deps) == 0

    def test_clean_version(self, scanner):
        """Test version cleaning."""
        assert scanner._clean_version("^4.18.0") == "4.18.0"
        assert scanner._clean_version("~4.17.21") == "4.17.21"
        assert scanner._clean_version(">=16.8.0") == "16.8.0"
        assert scanner._clean_version("4.17.21") == "4.17.21"
        assert scanner._clean_version("*") == "*"

    def test_is_local_package(self, scanner):
        """Test local package detection."""
        assert scanner._is_local_package("file:../local-pkg") is True
        assert scanner._is_local_package("workspace:*") is True
        assert scanner._is_local_package("./local") is True
        assert scanner._is_local_package("^4.18.0") is False
        assert scanner._is_local_package("4.17.21") is False

    def test_scan_nested_project(self, scanner):
        """Test scanning nested project directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            nested = path / "frontend"
            nested.mkdir()

            package_json = {
                "dependencies": {
                    "react": "^18.0.0",
                },
            }
            (nested / "package.json").write_text(json.dumps(package_json))

            deps = scanner.scan(path)

            # Should find package.json in subdirectory
            assert len(deps) == 1
            assert deps[0].name == "react"

    def test_scan_dev_dependencies_marked(self, scanner):
        """Test that dev dependencies are properly marked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            package_json = {
                "dependencies": {
                    "express": "^4.18.0",
                },
                "devDependencies": {
                    "jest": "^29.0.0",
                },
            }
            (path / "package.json").write_text(json.dumps(package_json))
            deps = scanner.scan(path)

            express_dep = next((d for d in deps if d.name == "express"), None)
            jest_dep = next((d for d in deps if d.name == "jest"), None)

            assert express_dep is not None
            assert express_dep.is_dev is False

            assert jest_dep is not None
            assert jest_dep.is_dev is True

    def test_scan_optional_dependencies(self, scanner):
        """Test scanning optional dependencies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            package_json = {
                "optionalDependencies": {
                    "fsevents": "^2.3.0",
                },
            }
            (path / "package.json").write_text(json.dumps(package_json))
            deps = scanner.scan(path)

            assert len(deps) == 1
            assert deps[0].name == "fsevents"
            assert deps[0].is_optional is True
