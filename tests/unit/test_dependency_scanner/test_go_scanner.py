"""Unit tests for Go dependency scanner."""

from pathlib import Path

from src.layers.l1_intelligence.dependency_scanner.base_scanner import Ecosystem
from src.layers.l1_intelligence.dependency_scanner.go_scanner import GoScanner


class TestGoScanner:
    """Tests for GoScanner."""

    def test_ecosystem(self) -> None:
        """Test ecosystem is GO."""
        scanner = GoScanner()
        assert scanner.ecosystem == Ecosystem.GO

    def test_supported_files(self) -> None:
        """Test supported files."""
        scanner = GoScanner()
        assert "go.mod" in scanner.supported_files
        assert "go.sum" in scanner.supported_files

    def test_can_scan_go_mod(self, tmp_path: Path) -> None:
        """Test can_scan for go.mod."""
        scanner = GoScanner()
        go_mod = tmp_path / "go.mod"
        go_mod.write_text("module example.com/test\n")
        assert scanner.can_scan(go_mod)

    def test_can_scan_go_sum(self, tmp_path: Path) -> None:
        """Test can_scan for go.sum."""
        scanner = GoScanner()
        go_sum = tmp_path / "go.sum"
        go_sum.write_text("example.com/test v1.0.0 h1:abc123=\n")
        assert scanner.can_scan(go_sum)

    def test_scan_empty_directory(self, tmp_path: Path) -> None:
        """Test scan on empty directory."""
        scanner = GoScanner()
        deps = scanner.scan(tmp_path)
        assert deps == []

    def test_scan_no_go_files(self, tmp_path: Path) -> None:
        """Test scan with no Go files."""
        scanner = GoScanner()
        # Create a non-Go file
        (tmp_path / "README.md").write_text("# Test")
        deps = scanner.scan(tmp_path)
        assert deps == []

    def test_scan_simple_go_mod(self, tmp_path: Path) -> None:
        """Test scan with simple go.mod."""
        scanner = GoScanner()
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            """module example.com/test

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/stretchr/testify v1.8.4
)
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 2

        # Check first dependency
        gin_dep = next((d for d in deps if "gin" in d.name), None)
        assert gin_dep is not None
        assert gin_dep.version == "1.9.1"
        assert gin_dep.ecosystem == Ecosystem.GO
        assert gin_dep.is_direct is True

    def test_scan_go_mod_with_indirect(self, tmp_path: Path) -> None:
        """Test scan with indirect dependencies."""
        scanner = GoScanner()
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            """module example.com/test

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
)

require (
    github.com/some/indirect v1.0.0 // indirect
    github.com/another/indirect v2.0.0 // indirect
)
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 3

        # Check indirect dependencies
        indirect_deps = [d for d in deps if not d.is_direct]
        assert len(indirect_deps) == 2

    def test_scan_go_mod_single_line_require(self, tmp_path: Path) -> None:
        """Test scan with single-line require."""
        scanner = GoScanner()
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            """module example.com/test

go 1.21

require github.com/gin-gonic/gin v1.9.1
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 1
        assert "gin" in deps[0].name

    def test_scan_go_mod_with_go_sum(self, tmp_path: Path) -> None:
        """Test scan with go.sum for precise versions."""
        scanner = GoScanner()
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            """module example.com/test

go 1.21

require github.com/gin-gonic/gin v1.9.1
"""
        )

        go_sum = tmp_path / "go.sum"
        go_sum.write_text(
            """github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cCL4K4Si7C97nkO0CzLcejJFxgBn1
github.com/gin-gonic/gin v1.9.1/go.mod h1:abc123
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 1
        # Version should come from go.sum
        assert deps[0].version == "1.9.1"

    def test_scan_nested_go_mod(self, tmp_path: Path) -> None:
        """Test scan with nested go.mod files."""
        scanner = GoScanner()

        # Root go.mod
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            """module example.com/root

go 1.21

require github.com/gin-gonic/gin v1.9.1
"""
        )

        # Nested go.mod
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        nested_mod = subdir / "go.mod"
        nested_mod.write_text(
            """module example.com/subdir

go 1.21

require github.com/stretchr/testify v1.8.4
"""
        )

        deps = scanner.scan(tmp_path)
        # Should find dependencies from both modules
        assert len(deps) == 2

    def test_scan_skip_vendor(self, tmp_path: Path) -> None:
        """Test that vendor directory is skipped."""
        scanner = GoScanner()

        # Root go.mod
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            """module example.com/test

go 1.21
"""
        )

        # Vendor go.mod (should be skipped)
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()
        vendor_mod = vendor_dir / "go.mod"
        vendor_mod.write_text(
            """module example.com/vendor

require github.com/some/pkg v1.0.0
"""
        )

        deps = scanner.scan(tmp_path)
        # Should only have 0 deps (root has none, vendor is skipped)
        assert len(deps) == 0

    def test_get_go_version(self, tmp_path: Path) -> None:
        """Test getting Go version from go.mod."""
        scanner = GoScanner()
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            """module example.com/test

go 1.21
"""
        )

        version = scanner.get_go_version(tmp_path)
        assert version == "1.21"

    def test_get_go_version_missing(self, tmp_path: Path) -> None:
        """Test getting Go version when go.mod is missing."""
        scanner = GoScanner()
        version = scanner.get_go_version(tmp_path)
        assert version is None

    def test_get_module_name(self, tmp_path: Path) -> None:
        """Test getting module name from go.mod."""
        scanner = GoScanner()
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            """module github.com/example/myapp

go 1.21
"""
        )

        name = scanner.get_module_name(tmp_path)
        assert name == "github.com/example/myapp"

    def test_get_module_name_missing(self, tmp_path: Path) -> None:
        """Test getting module name when go.mod is missing."""
        scanner = GoScanner()
        name = scanner.get_module_name(tmp_path)
        assert name is None

    def test_parse_go_mod_with_comments(self, tmp_path: Path) -> None:
        """Test parsing go.mod with comments."""
        scanner = GoScanner()
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            """module example.com/test

go 1.21

require (
    // This is a comment
    github.com/gin-gonic/gin v1.9.1 // another comment
    github.com/stretchr/testify v1.8.4 // indirect
)
"""
        )

        deps = scanner.scan(tmp_path)
        assert len(deps) == 2

    def test_scan_realistic_go_mod(self, tmp_path: Path) -> None:
        """Test scanning a realistic go.mod similar to hertz."""
        scanner = GoScanner()
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            """module github.com/cloudwego/hertz

go 1.19

require (
	github.com/bytedance/gopkg v0.1.3
	github.com/bytedance/sonic v1.15.0
	github.com/cloudwego/gopkg v0.1.9
	github.com/cloudwego/netpoll v0.7.2
	github.com/fsnotify/fsnotify v1.5.4
	github.com/stretchr/testify v1.10.0
	github.com/tidwall/gjson v1.14.4
	golang.org/x/sync v0.8.0
	golang.org/x/sys v0.24.0
	google.golang.org/protobuf v1.34.1
)

require (
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	golang.org/x/arch v0.0.0-20210923205945-b76863e36670 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
"""
        )

        deps = scanner.scan(tmp_path)

        # Should have 21 dependencies (10 direct + 11 indirect)
        assert len(deps) == 21

        # Check direct dependencies
        direct_deps = [d for d in deps if d.is_direct]
        assert len(direct_deps) == 10

        # Check indirect dependencies
        indirect_deps = [d for d in deps if not d.is_direct]
        assert len(indirect_deps) == 11

        # Check specific dependency
        netpoll_dep = next((d for d in deps if "netpoll" in d.name), None)
        assert netpoll_dep is not None
        assert netpoll_dep.version == "0.7.2"
        assert netpoll_dep.is_direct is True
