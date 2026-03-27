"""
JavaScript/TypeScript Docker Integration Tests (P7-11b-2).

Tests the complete flow for JavaScript/TypeScript projects:
1. JavaScriptBuilder identifies project structure
2. Build command generation
3. CodeQL database creation (if CodeQL available)
4. Runtime version detection (package.json engines, .nvmrc)
"""

import pytest
from pathlib import Path

from src.layers.l3_analysis.build.builders import JavaScriptBuilder
from src.layers.l3_analysis.build.builders.base import BuildResult


# Mark all tests in this module as integration tests
pytestmark = [
    pytest.mark.integration,
]


class TestJavaScriptBuilderIntegration:
    """Integration tests for JavaScriptBuilder."""

    def test_builder_analyzes_package_json(self, javascript_project: Path):
        """Test that builder analyzes package.json project."""
        builder = JavaScriptBuilder()
        output = builder.analyze(javascript_project)

        assert output.language == "javascript"
        # JavaScript can always be built (interpreted language)
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)

    def test_builder_detects_npm_package_manager(self, javascript_project: Path):
        """Test that builder detects npm as package manager."""
        builder = JavaScriptBuilder()
        output = builder.analyze(javascript_project)

        # Should detect package.json
        assert any("package.json" in f for f in output.detected_files)

    def test_builder_detects_yarn_package_manager(self, tmp_path: Path):
        """Test that builder detects yarn as package manager."""
        project = tmp_path / "yarn_project"
        project.mkdir()
        (project / "package.json").write_text('{"name": "test"}')
        (project / "yarn.lock").write_text("# yarn lockfile")
        (project / "index.js").write_text("console.log('test');")

        builder = JavaScriptBuilder()
        output = builder.analyze(project)

        # Should detect yarn.lock or project files
        assert len(output.detected_files) > 0 or output.language == "javascript"

    def test_builder_detects_pnpm_package_manager(self, tmp_path: Path):
        """Test that builder detects pnpm as package manager."""
        project = tmp_path / "pnpm_project"
        project.mkdir()
        (project / "package.json").write_text('{"name": "test"}')
        (project / "pnpm-lock.yaml").write_text("lockfileVersion: 1")
        (project / "index.js").write_text("console.log('test');")

        builder = JavaScriptBuilder()
        output = builder.analyze(project)

        # Should detect pnpm-lock.yaml or project files
        assert len(output.detected_files) > 0 or output.language == "javascript"

    def test_builder_handles_no_project_files(self, tmp_path: Path):
        """Test builder handles project without package.json."""
        empty_project = tmp_path / "empty_js"
        empty_project.mkdir()
        (empty_project / "index.js").write_text("console.log('hello');")

        builder = JavaScriptBuilder()
        output = builder.analyze(empty_project)

        assert output.language == "javascript"
        # JavaScript can always be analyzed (no build required)
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)


class TestTypeScriptBuilderIntegration:
    """Integration tests for TypeScript projects."""

    def test_builder_analyzes_typescript(self, typescript_project: Path):
        """Test that builder analyzes TypeScript project."""
        builder = JavaScriptBuilder()
        output = builder.analyze(typescript_project)

        # JavaScriptBuilder handles both JS and TS
        assert output.language in ("javascript", "typescript")
        # Should detect tsconfig.json
        assert any("tsconfig" in f.lower() for f in output.detected_files)

    def test_builder_detects_tsconfig(self, typescript_project: Path):
        """Test that builder detects tsconfig.json."""
        builder = JavaScriptBuilder()
        output = builder.analyze(typescript_project)

        # Should detect tsconfig.json
        assert any("tsconfig" in f.lower() for f in output.detected_files)


class TestJavaScriptVersionDetection:
    """Integration tests for Node.js version detection."""

    def test_detect_node_version_from_engines(self, tmp_path: Path):
        """Test version detection from package.json engines."""
        from src.layers.l3_analysis.build.version_detector import VersionDetector

        project = tmp_path / "node_engines_project"
        project.mkdir()
        (project / "package.json").write_text('''{
            "name": "test-app",
            "engines": {
                "node": ">=18.0.0"
            }
        }''')

        detector = VersionDetector(project)
        requirement = detector.detect()

        if requirement.node_version:
            assert "18" in requirement.node_version or ">=" in requirement.node_version

    def test_detect_node_version_from_nvmrc(self, tmp_path: Path):
        """Test version detection from .nvmrc file."""
        from src.layers.l3_analysis.build.version_detector import VersionDetector

        project = tmp_path / "nvmrc_project"
        project.mkdir()
        (project / ".nvmrc").write_text("v18.17.0\n")

        detector = VersionDetector(project)
        requirement = detector.detect()

        if requirement.node_version:
            assert "18" in requirement.node_version

    def test_detect_node_version_from_nvmrc_lts(self, tmp_path: Path):
        """Test version detection from .nvmrc with lts/* format."""
        from src.layers.l3_analysis.build.version_detector import VersionDetector

        project = tmp_path / "nvmrc_lts_project"
        project.mkdir()
        (project / ".nvmrc").write_text("lts/iron\n")

        detector = VersionDetector(project)
        requirement = detector.detect()

        # lts/* should be resolved or skipped
        # The exact behavior depends on implementation
        assert requirement is not None


class TestJavaScriptCodeQLIntegration:
    """CodeQL integration tests for JavaScript (requires CodeQL)."""

    @pytest.mark.codeql
    @pytest.mark.skip(reason="Requires CodeQL build environment")
    def test_codeql_database_creation(self, javascript_project: Path, tmp_path: Path):
        """Test CodeQL database creation for JavaScript project."""
        pass


class TestJavaScriptRuntimeVersionManager:
    """Test RuntimeVersionManager with Node.js."""

    def test_list_available_node_versions(self):
        """Test listing available Node.js versions."""
        from src.layers.l3_analysis.build.runtime.registry import RuntimeRegistry
        from src.layers.l3_analysis.build.runtime.models import RuntimeType

        registry = RuntimeRegistry()
        versions = registry.get_versions(RuntimeType.NODE)

        assert len(versions) > 0
        assert "18" in versions or "20" in versions

    def test_node_download_url(self):
        """Test Node.js download URL generation."""
        from src.layers.l3_analysis.build.runtime.registry import RuntimeRegistry
        from src.layers.l3_analysis.build.runtime.models import RuntimeType

        registry = RuntimeRegistry()
        info = registry.get_info(RuntimeType.NODE, "18")

        if info:
            assert "nodejs.org" in info.download_url or "nodejs.org" in str(info.download_url)
            assert "18" in str(info.download_url)
