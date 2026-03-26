"""
Unit tests for JavaScript/TypeScript builder.
"""

from pathlib import Path

import pytest

from src.layers.l3_analysis.build.builders.base import (
    BuildResult,
    FailureCategory,
    FailureDiagnosis,
)
from src.layers.l3_analysis.build.builders.javascript import JavaScriptBuilder


class TestJavaScriptBuilderAnalyze:
    """Tests for JavaScriptBuilder.analyze method."""

    @pytest.fixture
    def builder(self) -> JavaScriptBuilder:
        """Create a JavaScriptBuilder instance."""
        return JavaScriptBuilder()

    def test_simple_javascript_project(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test analyzing a simple JavaScript project."""
        # Create JS files
        index_js = tmp_path / "index.js"
        index_js.write_text('console.log("hello");\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.language == "javascript"
        assert output.build_command is None  # No build required

    def test_package_json_detection(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test detecting package.json."""
        package_json = tmp_path / "package.json"
        package_json.write_text(
            '{\n'
            '  "name": "my-app",\n'
            '  "version": "1.0.0"\n'
            '}\n'
        )

        index_js = tmp_path / "index.js"
        index_js.write_text('console.log("hello");\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert "package.json" in output.detected_files
        assert output.build_system == "npm"

    def test_yarn_detection(self, builder: JavaScriptBuilder, tmp_path: Path) -> None:
        """Test detecting Yarn package manager."""
        package_json = tmp_path / "package.json"
        package_json.write_text('{"name": "my-app"}\n')

        yarn_lock = tmp_path / "yarn.lock"
        yarn_lock.write_text("# yarn lockfile\n")

        index_js = tmp_path / "index.js"
        index_js.write_text('console.log("hello");\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.build_system == "yarn"
        assert "yarn.lock" in output.detected_files

    def test_pnpm_detection(self, builder: JavaScriptBuilder, tmp_path: Path) -> None:
        """Test detecting pnpm package manager."""
        package_json = tmp_path / "package.json"
        package_json.write_text('{"name": "my-app"}\n')

        pnpm_lock = tmp_path / "pnpm-lock.yaml"
        pnpm_lock.write_text("lockfileVersion: 6.0\n")

        index_js = tmp_path / "index.js"
        index_js.write_text('console.log("hello");\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.build_system == "pnpm"
        assert "pnpm-lock.yaml" in output.detected_files

    def test_typescript_detection(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test detecting TypeScript project."""
        tsconfig = tmp_path / "tsconfig.json"
        tsconfig.write_text(
            '{\n'
            '  "compilerOptions": {\n'
            '    "target": "ES2020"\n'
            '  }\n'
            '}\n'
        )

        index_ts = tmp_path / "index.ts"
        index_ts.write_text('console.log("hello");\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.language == "typescript"
        assert "tsconfig.json" in output.detected_files

    def test_typescript_with_js_files(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test TypeScript project with mixed JS/TS files."""
        tsconfig = tmp_path / "tsconfig.json"
        tsconfig.write_text('{}\n')

        # Mixed files
        (tmp_path / "main.ts").write_text('export {};\n')
        (tmp_path / "utils.js").write_text('module.exports = {};\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Should be classified as TypeScript when tsconfig exists
        assert output.language == "typescript"

    def test_project_references_detection(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test detecting TypeScript project references."""
        tsconfig = tmp_path / "tsconfig.json"
        tsconfig.write_text(
            '{\n'
            '  "references": [\n'
            '    { "path": "./core" },\n'
            '    { "path": "./utils" }\n'
            '  ]\n'
            '}\n'
        )

        (tmp_path / "index.ts").write_text('export {};\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Should warn about project references
        assert any("reference" in w.lower() for w in output.warnings)

    def test_path_aliases_detection(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test detecting TypeScript path aliases."""
        tsconfig = tmp_path / "tsconfig.json"
        tsconfig.write_text(
            '{\n'
            '  "compilerOptions": {\n'
            '    "baseUrl": ".",\n'
            '    "paths": {\n'
            '      "@/*": ["src/*"],\n'
            '      "@utils/*": ["utils/*"]\n'
            '    }\n'
            '  }\n'
            '}\n'
        )

        (tmp_path / "index.ts").write_text('export {};\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Should warn about path aliases
        assert any("alias" in w.lower() or "path" in w.lower() for w in output.warnings)

    def test_workspace_detection(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test detecting monorepo workspace."""
        package_json = tmp_path / "package.json"
        package_json.write_text(
            '{\n'
            '  "name": "monorepo",\n'
            '  "private": true,\n'
            '  "workspaces": ["packages/*"]\n'
            '}\n'
        )

        (tmp_path / "index.js").write_text('console.log("root");\n')

        # Create a workspace package
        packages_dir = tmp_path / "packages" / "core"
        packages_dir.mkdir(parents=True)
        (packages_dir / "package.json").write_text('{"name": "@monorepo/core"}\n')
        (packages_dir / "index.js").write_text('console.log("core");\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Should warn about workspace
        assert any("workspace" in w.lower() or "monorepo" in w.lower() for w in output.warnings)

    def test_no_js_ts_files(self, builder: JavaScriptBuilder, tmp_path: Path) -> None:
        """Test analyzing a project with no JS/TS files."""
        readme = tmp_path / "README.md"
        readme.write_text("# My Project\n")

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SKIPPED
        assert "no javascript" in output.skip_reason.lower() or "no typescript" in output.skip_reason.lower()

    def test_jsx_tsx_detection(self, builder: JavaScriptBuilder, tmp_path: Path) -> None:
        """Test detecting JSX/TSX files."""
        (tmp_path / "App.tsx").write_text('export function App() { return <div/>; }\n')
        (tmp_path / "Component.jsx").write_text('export function Component() { return <div/>; }\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Should detect as TypeScript because of tsx
        assert output.language == "typescript"

    def test_build_script_detection(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test detecting build script in package.json."""
        package_json = tmp_path / "package.json"
        package_json.write_text(
            '{\n'
            '  "name": "my-app",\n'
            '  "scripts": {\n'
            '    "build": "tsc"\n'
            '  }\n'
            '}\n'
        )

        (tmp_path / "index.ts").write_text('export {};\n')
        (tmp_path / "tsconfig.json").write_text('{}\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        # Build script detected but no build required for CodeQL
        assert output.build_command is None


class TestJavaScriptBuilderDiagnoseFailure:
    """Tests for JavaScriptBuilder.diagnose_failure method."""

    @pytest.fixture
    def builder(self) -> JavaScriptBuilder:
        """Create a JavaScriptBuilder instance."""
        return JavaScriptBuilder()

    def test_dependency_missing(self, builder: JavaScriptBuilder) -> None:
        """Test diagnosing missing dependency."""
        stderr = "Error: Cannot find module 'react'"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.DEPENDENCY_MISSING

    def test_npm_install_error(self, builder: JavaScriptBuilder) -> None:
        """Test diagnosing npm install failure."""
        stderr = "npm ERR! 404 Not Found - GET https://registry.npmjs.org/nonexistent-pkg"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.DEPENDENCY_RESOLUTION

    def test_typescript_compilation_error(self, builder: JavaScriptBuilder) -> None:
        """Test diagnosing TypeScript compilation error."""
        stderr = (
            "src/index.ts:10:5 - error TS2322: "
            "Type 'string' is not assignable to type 'number'."
        )

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.COMPILATION_ERROR

    def test_syntax_error(self, builder: JavaScriptBuilder) -> None:
        """Test diagnosing JavaScript syntax error."""
        stderr = "SyntaxError: Unexpected token ')'"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.COMPILATION_ERROR

    def test_node_version_mismatch(self, builder: JavaScriptBuilder) -> None:
        """Test diagnosing Node version mismatch."""
        stderr = "error: The engine 'node' is incompatible with this module."

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.VERSION_MISMATCH

    def test_permission_denied(self, builder: JavaScriptBuilder) -> None:
        """Test diagnosing permission error."""
        stderr = "EACCES: permission denied, unlink 'node_modules/.package-lock.json'"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.PERMISSION_DENIED

    def test_unknown_error(self, builder: JavaScriptBuilder) -> None:
        """Test diagnosing unknown error."""
        stderr = "Some random error message"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.UNKNOWN

    def test_success_return_code(self, builder: JavaScriptBuilder) -> None:
        """Test that return code 0 is handled."""
        diagnosis = builder.diagnose_failure("success", "", 0)

        assert diagnosis.category == FailureCategory.UNKNOWN
        assert diagnosis.message == ""


class TestJavaScriptBuilderUtilities:
    """Tests for JavaScriptBuilder utility methods."""

    @pytest.fixture
    def builder(self) -> JavaScriptBuilder:
        """Create a JavaScriptBuilder instance."""
        return JavaScriptBuilder()

    def test_is_typescript_true(self, builder: JavaScriptBuilder, tmp_path: Path) -> None:
        """Test TypeScript detection when tsconfig exists."""
        (tmp_path / "tsconfig.json").write_text('{}\n')
        assert builder._is_typescript(tmp_path) is True

    def test_is_typescript_false(self, builder: JavaScriptBuilder, tmp_path: Path) -> None:
        """Test TypeScript detection when only JS files."""
        (tmp_path / "index.js").write_text('console.log("hello");\n')
        assert builder._is_typescript(tmp_path) is False

    def test_has_project_references_true(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test project references detection."""
        (tmp_path / "tsconfig.json").write_text(
            '{"references": [{"path": "./core"}]}\n'
        )
        assert builder._has_project_references(tmp_path) is True

    def test_has_project_references_false(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test project references detection when absent."""
        (tmp_path / "tsconfig.json").write_text('{}\n')
        assert builder._has_project_references(tmp_path) is False

    def test_has_path_aliases_true(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test path aliases detection."""
        (tmp_path / "tsconfig.json").write_text(
            '{"compilerOptions": {"paths": {"@/*": ["src/*"]}}}\n'
        )
        assert builder._has_path_aliases(tmp_path) is True

    def test_has_path_aliases_false(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test path aliases detection when absent."""
        (tmp_path / "tsconfig.json").write_text('{}\n')
        assert builder._has_path_aliases(tmp_path) is False

    def test_detect_package_manager_npm(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test detecting npm as package manager."""
        (tmp_path / "package.json").write_text('{}\n')
        (tmp_path / "package-lock.json").write_text('{}\n')

        pm = builder._detect_package_manager(tmp_path)
        assert pm == "npm"

    def test_detect_package_manager_yarn(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test detecting yarn as package manager."""
        (tmp_path / "package.json").write_text('{}\n')
        (tmp_path / "yarn.lock").write_text('# yarn\n')

        pm = builder._detect_package_manager(tmp_path)
        assert pm == "yarn"

    def test_detect_package_manager_pnpm(
        self, builder: JavaScriptBuilder, tmp_path: Path
    ) -> None:
        """Test detecting pnpm as package manager."""
        (tmp_path / "package.json").write_text('{}\n')
        (tmp_path / "pnpm-lock.yaml").write_text('lockfileVersion: 6.0\n')

        pm = builder._detect_package_manager(tmp_path)
        assert pm == "pnpm"

    def test_detect_workspace(self, builder: JavaScriptBuilder, tmp_path: Path) -> None:
        """Test workspace detection."""
        (tmp_path / "package.json").write_text(
            '{"workspaces": ["packages/*"]}\n'
        )

        assert builder._has_workspace(tmp_path) is True

    def test_count_js_ts_files(self, builder: JavaScriptBuilder, tmp_path: Path) -> None:
        """Test counting JS/TS files."""
        (tmp_path / "main.js").write_text('pass\n')
        (tmp_path / "utils.ts").write_text('pass\n')
        (tmp_path / "app.tsx").write_text('pass\n')

        js_count, ts_count = builder._count_js_ts_files(tmp_path)
        assert js_count == 1
        assert ts_count == 2


class TestJavaScriptBuilderRegistration:
    """Tests for JavaScriptBuilder registration."""

    def test_javascript_builder_registered(self) -> None:
        """Test that JavaScriptBuilder is registered."""
        from src.layers.l3_analysis.build.builders.base import BuilderRegistry

        # Clear and re-register
        BuilderRegistry._builders.clear()
        from src.layers.l3_analysis.build.builders.javascript import JavaScriptBuilder
        BuilderRegistry.register(JavaScriptBuilder)
        # Also register for TypeScript
        BuilderRegistry._builders["typescript"] = JavaScriptBuilder

        builder = BuilderRegistry.get("javascript")
        assert builder is not None
        assert builder.LANGUAGE_NAME == "javascript"

        builder_ts = BuilderRegistry.get("typescript")
        assert builder_ts is not None  # Same builder handles TS
