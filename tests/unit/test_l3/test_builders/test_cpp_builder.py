"""
Unit tests for C++ builder.
"""

from pathlib import Path

import pytest

from src.layers.l3_analysis.build.builders.base import (
    BuildResult,
    FailureCategory,
    FailureDiagnosis,
)
from src.layers.l3_analysis.build.builders.cpp import CppBuilder


class TestCppBuilderAnalyze:
    """Tests for CppBuilder.analyze method."""

    @pytest.fixture
    def builder(self) -> CppBuilder:
        """Create a CppBuilder instance."""
        return CppBuilder()

    def test_compile_commands_at_root(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test with compile_commands.json in root."""
        # Create valid compile_commands.json
        compile_commands = tmp_path / "compile_commands.json"
        compile_commands.write_text(
            '[\n'
            '  {\n'
            '    "directory": "/tmp/test",\n'
            '    "command": "gcc -c main.c",\n'
            '    "file": "main.c"\n'
            '  }\n'
            ']'
        )

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.language == "cpp"
        assert output.build_system == "compile_commands"
        assert "compile_commands.json" in output.detected_files

    def test_compile_commands_in_build_dir(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test with compile_commands.json in build/."""
        # Create build directory
        build_dir = tmp_path / "build"
        build_dir.mkdir()

        # Create valid compile_commands.json
        compile_commands = build_dir / "compile_commands.json"
        compile_commands.write_text(
            '[\n'
            '  {\n'
            '    "directory": "/tmp/test",\n'
            '    "command": "gcc -c main.c",\n'
            '    "file": "main.c"\n'
            '  }\n'
            ']'
        )

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SUCCESS
        assert output.build_system == "compile_commands"
        assert "build/compile_commands.json" in output.detected_files

    def test_compile_commands_invalid_json(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test with invalid compile_commands.json."""
        # Create invalid compile_commands.json
        compile_commands = tmp_path / "compile_commands.json"
        compile_commands.write_text('not valid json')

        # Create a simple CMakeLists.txt to fallback to
        cmake_lists = tmp_path / "CMakeLists.txt"
        cmake_lists.write_text('project(test)\n')

        output = builder.analyze(tmp_path)

        # Should skip invalid compile_commands and find CMake
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)

    def test_compile_commands_empty_array(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test with empty compile_commands.json array."""
        # Create empty compile_commands.json
        compile_commands = tmp_path / "compile_commands.json"
        compile_commands.write_text('[]')

        # Create a simple CMakeLists.txt to fallback to
        cmake_lists = tmp_path / "CMakeLists.txt"
        cmake_lists.write_text('project(test)\n')

        output = builder.analyze(tmp_path)

        # Should skip empty compile_commands
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)

    def test_cmake_project(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test CMakeLists.txt project."""
        # Create simple CMakeLists.txt
        cmake_lists = tmp_path / "CMakeLists.txt"
        cmake_lists.write_text(
            'cmake_minimum_required(VERSION 3.10)\n'
            'project(test)\n'
            'add_executable(test main.cpp)\n'
        )

        output = builder.analyze(tmp_path)

        # Result depends on whether cmake is installed
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)
        assert output.language == "cpp"
        assert "CMakeLists.txt" in output.detected_files
        assert output.build_system == "cmake"

        if output.result == BuildResult.SUCCESS:
            assert "cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in output.dependency_command

    def test_cmake_with_complex_options(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test CMakeLists.txt with complex options detection."""
        # Create CMakeLists.txt with find_package
        cmake_lists = tmp_path / "CMakeLists.txt"
        cmake_lists.write_text(
            'cmake_minimum_required(VERSION 3.10)\n'
            'project(test)\n'
            'find_package(Boost REQUIRED)\n'
            'add_executable(test main.cpp)\n'
        )

        # Test the helper method directly
        has_complex = builder._has_complex_cmake_options(cmake_lists)
        assert has_complex is True

    def test_simple_makefile(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test simple Makefile."""
        # Create simple Makefile
        makefile = tmp_path / "Makefile"
        makefile.write_text(
            'all: test\n\n'
            'test: main.o\n'
            '\tgcc -o test main.o\n\n'
            'main.o: main.c\n'
            '\tgcc -c main.c\n'
        )

        main_c = tmp_path / "main.c"
        main_c.write_text('int main() { return 0; }\n')

        output = builder.analyze(tmp_path)

        # Should find Makefile and either succeed or skip (depending on complexity detection)
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)
        assert output.language == "cpp"
        assert "Makefile" in output.detected_files
        assert output.build_system == "make"

    def test_complex_makefile_skipped(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test complex Makefile is skipped."""
        # Create Makefile with shell calls and includes
        makefile = tmp_path / "Makefile"
        makefile.write_text(
            'CC := $(shell which gcc)\n'
            'include config.mk\n\n'
            'all: test\n\n'
            'test: main.o\n'
            '\t$(CC) -o test main.o\n'
        )

        output = builder.analyze(tmp_path)

        # Should skip due to complexity
        assert output.result == BuildResult.SKIPPED
        assert "Complex Makefile" in output.skip_reason

    def test_makefile_with_sudo_skipped(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test Makefile with sudo is skipped."""
        # Create Makefile with sudo
        makefile = tmp_path / "Makefile"
        makefile.write_text(
            'install:\n'
            '\t@sudo cp test /usr/local/bin/\n'
        )

        output = builder.analyze(tmp_path)

        # Should skip due to sudo
        assert output.result == BuildResult.SKIPPED

    def test_header_only_project(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test header-only project is skipped with reason."""
        # Create only header files
        include_dir = tmp_path / "include"
        include_dir.mkdir()

        header1 = include_dir / "header1.hpp"
        header1.write_text('#pragma once\n\nclass Header1 {};\n')

        header2 = include_dir / "header2.h"
        header2.write_text('#ifndef HEADER2_H\n#define HEADER2_H\n#endif\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SKIPPED
        assert "Header-only" in output.skip_reason
        assert output.build_system == "header-only"

    def test_no_build_system_skipped(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test project without build system is skipped."""
        # Create only source files without build system
        main_c = tmp_path / "main.c"
        main_c.write_text('int main() { return 0; }\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SKIPPED
        assert "No standard C/C++ build system found" in output.skip_reason
        assert "compile_commands.json, CMake, Makefile" in output.skip_reason

    def test_mixed_source_and_header(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test project with both source and header but no build system."""
        # Create source and header files
        main_c = tmp_path / "main.c"
        main_c.write_text('int main() { return 0; }\n')

        header_h = tmp_path / "header.h"
        header_h.write_text('#ifndef HEADER_H\n#define HEADER_H\n#endif\n')

        output = builder.analyze(tmp_path)

        assert output.result == BuildResult.SKIPPED
        # Should NOT be considered header-only (has source files)
        assert "Header-only" not in output.skip_reason


class TestCppBuilderDiagnose:
    """Tests for CppBuilder.diagnose_failure method."""

    @pytest.fixture
    def builder(self) -> CppBuilder:
        """Create a CppBuilder instance."""
        return CppBuilder()

    def test_diagnose_compiler_error(self, builder: CppBuilder) -> None:
        """Test diagnosing compilation errors."""
        stderr = "main.c:5:10: error: expected ';' before 'return'"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.COMPILATION_ERROR
        assert "compilation error" in diagnosis.message.lower()

    def test_diagnose_missing_header(self, builder: CppBuilder) -> None:
        """Test diagnosing missing header error."""
        stderr = "main.c:1:10: fatal error: missing.h: No such file or directory"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.DEPENDENCY_MISSING
        assert "missing header" in diagnosis.message.lower()

    def test_diagnose_linker_error(self, builder: CppBuilder) -> None:
        """Test diagnosing linker errors."""
        stderr = "/usr/bin/ld: undefined reference to 'function()'"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.COMPILATION_ERROR
        assert "linker error" in diagnosis.message.lower()
        assert "undefined reference" in diagnosis.message.lower()

    def test_diagnose_cmake_error(self, builder: CppBuilder) -> None:
        """Test diagnosing CMake errors."""
        stderr = "CMake Error: Could not find Boost"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.DEPENDENCY_MISSING
        assert "cmake" in diagnosis.message.lower()
        assert "could not find" in diagnosis.message.lower()

    def test_diagnose_cmake_config_error(self, builder: CppBuilder) -> None:
        """Test diagnosing CMake configuration errors."""
        stderr = "CMake Error at CMakeLists.txt:5 (message):"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.CONFIG_ERROR
        assert "cmake" in diagnosis.message.lower()

    def test_diagnose_make_error(self, builder: CppBuilder) -> None:
        """Test diagnosing Make errors."""
        stderr = "make: *** No rule to make target 'missing.o'"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.CONFIG_ERROR
        assert "make" in diagnosis.message.lower()

    def test_diagnose_permission_denied(self, builder: CppBuilder) -> None:
        """Test diagnosing permission denied errors."""
        stderr = "gcc: error: output.o: Permission denied"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.PERMISSION_DENIED
        assert "permission denied" in diagnosis.message.lower()

    def test_diagnose_unknown_error(self, builder: CppBuilder) -> None:
        """Test diagnosing unknown errors."""
        stderr = "Some random error message"

        diagnosis = builder.diagnose_failure("", stderr, 1)

        assert diagnosis.category == FailureCategory.UNKNOWN
        assert "unknown" in diagnosis.message.lower()

    def test_diagnose_success(self, builder: CppBuilder) -> None:
        """Test diagnosing success (return code 0)."""
        diagnosis = builder.diagnose_failure("", "", 0)

        assert diagnosis.category == FailureCategory.UNKNOWN
        assert diagnosis.message == ""


class TestCppBuilderAvailability:
    """Tests for CppBuilder availability checks."""

    @pytest.fixture
    def builder(self) -> CppBuilder:
        """Create a CppBuilder instance."""
        return CppBuilder()

    def test_is_available(self, builder: CppBuilder) -> None:
        """Test is_available method."""
        # Just test that the method exists and returns a boolean
        result = builder.is_available()
        assert isinstance(result, bool)

    def test_get_version(self, builder: CppBuilder) -> None:
        """Test get_version method."""
        # Just test that the method exists
        result = builder.get_version()
        # May return None or a string
        assert result is None or isinstance(result, str)


class TestCppBuilderValidationHelpers:
    """Tests for CppBuilder helper methods."""

    @pytest.fixture
    def builder(self) -> CppBuilder:
        """Create a CppBuilder instance."""
        return CppBuilder()

    def test_validate_compile_commands_valid(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test _validate_compile_commands with valid input."""
        compile_commands = tmp_path / "compile_commands.json"
        compile_commands.write_text(
            '[\n'
            '  {\n'
            '    "directory": "/tmp/test",\n'
            '    "command": "gcc -c main.c",\n'
            '    "file": "main.c"\n'
            '  }\n'
            ']'
        )

        result = builder._validate_compile_commands(compile_commands)
        assert result is True

    def test_validate_compile_commands_not_list(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test _validate_compile_commands with non-list JSON."""
        compile_commands = tmp_path / "compile_commands.json"
        compile_commands.write_text('{"invalid": "object"}')

        result = builder._validate_compile_commands(compile_commands)
        assert result is False

    def test_validate_compile_commands_empty(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test _validate_compile_commands with empty array."""
        compile_commands = tmp_path / "compile_commands.json"
        compile_commands.write_text('[]')

        result = builder._validate_compile_commands(compile_commands)
        assert result is False

    def test_validate_compile_commands_missing_fields(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test _validate_compile_commands with missing required fields."""
        compile_commands = tmp_path / "compile_commands.json"
        compile_commands.write_text(
            '[\n'
            '  {\n'
            '    "only": "one field"\n'
            '  }\n'
            ']'
        )

        result = builder._validate_compile_commands(compile_commands)
        assert result is False

    def test_validate_compile_commands_invalid_json(self, builder: CppBuilder, tmp_path: Path) -> None:
        """Test _validate_compile_commands with invalid JSON."""
        compile_commands = tmp_path / "compile_commands.json"
        compile_commands.write_text('not json at all')

        result = builder._validate_compile_commands(compile_commands)
        assert result is False
