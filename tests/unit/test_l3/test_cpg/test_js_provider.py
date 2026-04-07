"""
JSCPGProvider Unit Tests.

Test JavaScript/TypeScript-specific CPG path provider implementation.
"""

from pathlib import Path

import pytest

from src.layers.l3_analysis.engines.ast_engine.cpg.providers.js_provider import (
    JSCPGProvider,
)


class TestJSCPGProvider:
    """Test JSCPGProvider."""

    def test_init(self):
        """Test JSCPGProvider initialization."""
        provider = JSCPGProvider()

        assert provider is not None
        assert provider.file_patterns == ["*.js", "*.jsx", "*.ts", "*.tsx"]

    def test_file_patterns(self):
        """Test file patterns property."""
        provider = JSCPGProvider()

        patterns = provider.file_patterns
        assert "*.js" in patterns
        assert "*.jsx" in patterns
        assert "*.ts" in patterns
        assert "*.tsx" in patterns

    def test_get_file_extensions(self):
        """Test getting file extensions."""
        provider = JSCPGProvider()

        extensions = provider.get_file_extensions()
        assert "*.js" in extensions
        assert "*.jsx" in extensions
        assert "*.ts" in extensions
        assert "*.tsx" in extensions

    def test_supports_language(self):
        """Test language support checking."""
        provider = JSCPGProvider()

        assert provider.supports_language("javascript")
        assert provider.supports_language("typescript")
        assert not provider.supports_language("python")
        assert not provider.supports_language("java")

    def test_supports_file(self):
        """Test file support checking."""
        provider = JSCPGProvider()

        # JavaScript files
        assert provider.supports_file(Path("test.js"))
        assert provider.supports_file(Path("component.jsx"))

        # TypeScript files
        assert provider.supports_file(Path("app.ts"))
        assert provider.supports_file(Path("utils.tsx"))

        # Other files
        assert not provider.supports_file(Path("test.py"))
        assert not provider.supports_file(Path("test.java"))

    def test_get_paths_empty_cpg(self, tmp_path):
        """Test getting paths when CPG is empty."""
        provider = JSCPGProvider()

        # Create an empty file
        empty_file = tmp_path / "empty.js"
        empty_file.write_text("")

        paths = provider.get_paths(empty_file, "eval")

        # Should return empty list for empty/invalid source
        assert isinstance(paths, list)

    def test_get_paths_simple_js_file(self, tmp_path):
        """Test getting paths for a simple JavaScript file."""
        provider = JSCPGProvider()

        # Create a simple JS file
        simple_file = tmp_path / "simple.js"
        simple_file.write_text("""
function hello() {
    console.log("Hello, world!");
}

function add(a, b) {
    return a + b;
}
""")

        paths = provider.get_paths(simple_file, "eval")

        # Should return a list (may be empty)
        assert isinstance(paths, list)

    def test_get_paths_with_eval(self, tmp_path):
        """Test getting paths for code with eval."""
        provider = JSCPGProvider()

        # Create a file with eval
        eval_file = tmp_path / "with_eval.js"
        eval_file.write_text("""
function process(userInput) {
    const result = eval(userInput);  // Dangerous
    return result;
}
""")

        paths = provider.get_paths(eval_file, "eval")

        # Should return a list
        assert isinstance(paths, list)

    def test_get_paths_typescript_file(self, tmp_path):
        """Test getting paths for a TypeScript file."""
        provider = JSCPGProvider()

        # Create a TypeScript file
        ts_file = tmp_path / "app.ts"
        ts_file.write_text("""
interface User {
    name: string;
}

function greet(user: User): void {
    console.log(`Hello, ${user.name}`);
}
""")

        paths = provider.get_paths(ts_file, "eval")

        # Should return a list
        assert isinstance(paths, list)

    def test_get_paths_from_directory(self, tmp_path):
        """Test getting paths from a directory."""
        provider = JSCPGProvider()

        # Create multiple JS/TS files
        (tmp_path / "file1.js").write_text("function foo() {}\n")
        (tmp_path / "file2.ts").write_text("function bar() {}\n")
        (tmp_path / "component.jsx").write_text("const C = () => null;\n")
        (tmp_path / "readme.md").write_text("# Docs\n")

        paths = provider.get_paths(tmp_path, "eval")

        assert isinstance(paths, list)

    def test_default_sink_pattern(self, tmp_path):
        """Test default sink pattern."""
        provider = JSCPGProvider()

        test_file = tmp_path / "test.js"
        test_file.write_text("const x = 1;\n")

        # Use default sink pattern
        paths = provider.get_paths(test_file)

        assert isinstance(paths, list)

    def test_custom_sink_pattern(self, tmp_path):
        """Test custom sink pattern."""
        provider = JSCPGProvider()

        test_file = tmp_path / "test.js"
        test_file.write_text("""
// Using dangerous Function constructor
const fn = new Function(userInput);
""")

        # Custom pattern for Function constructor
        paths = provider.get_paths(test_file, "Function")

        assert isinstance(paths, list)

    def test_base_provider_functionality(self):
        """Test inherited BaseCPGProvider functionality."""
        provider = JSCPGProvider()

        # Should have logger
        assert hasattr(provider, "logger")

        # Should have base methods
        assert hasattr(provider, "_build_cpg")
        assert hasattr(provider, "_find_paths")

    def test_multiple_js_extensions_in_directory(self, tmp_path):
        """Test that all JS-like extensions are handled."""
        provider = JSCPGProvider()

        # Create files with different JS extensions
        (tmp_path / "script.js").write_text("// JS\n")
        (tmp_path / "component.jsx").write_text("// JSX\n")
        (tmp_path / "module.ts").write_text("// TS\n")
        (tmp_path / "view.tsx").write_text("// TSX\n")

        paths = provider.get_paths(tmp_path, "eval")

        # Should handle all file types
        assert isinstance(paths, list)
