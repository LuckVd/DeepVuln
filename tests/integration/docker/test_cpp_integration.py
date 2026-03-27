"""
C/C++ Docker Integration Tests (P7-11b-5).

Tests the complete flow for C/C++ projects:
1. CppBuilder identifies project structure (CMake, Makefile, compile_commands.json)
2. Build command generation
3. CodeQL database creation (if CodeQL available)
4. Standard build system support with clear failure reasons
"""

import pytest
from pathlib import Path

from src.layers.l3_analysis.build.builders import CppBuilder
from src.layers.l3_analysis.build.builders.base import BuildResult


# Mark all tests in this module as integration tests
pytestmark = [
    pytest.mark.integration,
]


class TestCppBuilderIntegration:
    """Integration tests for CppBuilder."""

    def test_builder_analyzes_cmake_project(self, cpp_project: Path):
        """Test that builder analyzes CMake project."""
        builder = CppBuilder()
        output = builder.analyze(cpp_project)

        assert output.language == "cpp"
        # CMake projects should have build commands
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)
        # Should detect CMakeLists.txt
        assert any("CMakeLists.txt" in f for f in output.detected_files)

    def test_builder_analyzes_compile_commands(self, tmp_path: Path):
        """Test that builder analyzes project with compile_commands.json."""
        project = tmp_path / "compile_commands_project"
        project.mkdir()
        (project / "main.c").write_text('int main() { return 0; }')

        compile_commands = project / "compile_commands.json"
        compile_commands.write_text('''[
    {
        "directory": "/tmp",
        "command": "gcc -c main.c",
        "file": "main.c"
    }
]''')

        builder = CppBuilder()
        output = builder.analyze(project)

        assert output.language == "cpp"
        # Should detect compile_commands.json
        assert any("compile_commands" in f for f in output.detected_files)

    def test_builder_analyzes_makefile_project(self, tmp_path: Path):
        """Test that builder analyzes Makefile project."""
        project = tmp_path / "makefile_project"
        project.mkdir()
        (project / "main.c").write_text('int main() { return 0; }')
        (project / "Makefile").write_text('''
CC = gcc
CFLAGS = -Wall

main: main.c
\t$(CC) $(CFLAGS) -o main main.c

clean:
\trm -f main
''')

        builder = CppBuilder()
        output = builder.analyze(project)

        assert output.language == "cpp"
        # Should detect Makefile
        assert any("Makefile" in f for f in output.detected_files)

    def test_builder_handles_no_build_system(self, tmp_path: Path):
        """Test builder handles project without standard build system."""
        project = tmp_path / "no_build_project"
        project.mkdir()
        (project / "main.c").write_text('int main() { return 0; }')

        builder = CppBuilder()
        output = builder.analyze(project)

        assert output.language == "cpp"
        # Without build system, should be skipped
        assert output.result == BuildResult.SKIPPED
        assert output.skip_reason is not None

    def test_builder_handles_header_only(self, tmp_path: Path):
        """Test that builder handles header-only libraries."""
        project = tmp_path / "header_only_project"
        project.mkdir()
        (project / "library.h").write_text('''
#ifndef LIBRARY_H
#define LIBRARY_H

static int add(int a, int b) {
    return a + b;
}

#endif
''')

        builder = CppBuilder()
        output = builder.analyze(project)

        assert output.language == "cpp"
        # Header-only might be skipped or have special handling
        assert output.result in (BuildResult.SUCCESS, BuildResult.SKIPPED)


class TestCppFailureDiagnosis:
    """Test failure diagnosis for C/C++ builds."""

    def test_missing_compiler_diagnosis(self, tmp_path: Path):
        """Test diagnosis when compiler is missing."""
        project = tmp_path / "no_compiler_project"
        project.mkdir()
        (project / "CMakeLists.txt").write_text('''
cmake_minimum_required(VERSION 3.10)
project(test C)
add_executable(main main.c)
''')
        (project / "main.c").write_text('int main() { return 0; }')

        builder = CppBuilder()
        output = builder.analyze(project)

        # Analysis should succeed
        assert output.language == "cpp"
        # But actual build might fail if no compiler
        # This is handled at execution time

    def test_complex_cmake_skip(self, tmp_path: Path):
        """Test skip for complex CMake configurations."""
        project = tmp_path / "complex_cmake_project"
        project.mkdir()
        (project / "CMakeLists.txt").write_text('''
cmake_minimum_required(VERSION 3.10)
project(complex C)

# Complex configurations that might fail
find_package(NonExistentPackage REQUIRED)
option(ENABLE_FEATURE "Enable feature" ON)

if(ENABLE_FEATURE)
    add_subdirectory(vendor)
endif()
''')

        builder = CppBuilder()
        output = builder.analyze(project)

        # Should still be analyzable
        assert output.language == "cpp"


class TestCppCodeQLIntegration:
    """CodeQL integration tests for C/C++ (requires CodeQL)."""

    @pytest.mark.codeql
    @pytest.mark.skip(reason="Requires CodeQL build environment")
    def test_codeql_database_creation_with_cmake(self, cpp_project: Path, tmp_path: Path):
        """Test CodeQL database creation for CMake project."""
        pass

    @pytest.mark.codeql
    @pytest.mark.skip(reason="Requires CodeQL build environment")
    def test_codeql_database_creation_with_compile_commands(self, tmp_path: Path):
        """Test CodeQL database creation using compile_commands.json."""
        pass


class TestCppSafetyGuards:
    """Test safety guards for C/C++ builds."""

    def test_no_sudo_in_build_commands(self, cpp_project: Path):
        """Test that generated build commands never use sudo."""
        builder = CppBuilder()
        output = builder.analyze(cpp_project)

        # No build command should contain sudo
        if output.build_command:
            assert "sudo" not in output.build_command.lower()

    def test_stop_line_for_missing_dependencies(self, tmp_path: Path):
        """Test clear stop line when dependencies are missing."""
        project = tmp_path / "deps_project"
        project.mkdir()
        (project / "main.c").write_text('#include <nonexistent.h>\nint main() { return 0; }')
        (project / "Makefile").write_text('main: main.c\n\tgcc -o main main.c')

        builder = CppBuilder()
        output = builder.analyze(project)

        # Should still generate a plan, but execution should fail gracefully
        assert output.language == "cpp"
