"""
Context Builder

Builds code context for Agent tasks by extracting relevant code snippets,
imports, and related functions.
"""

from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.task.models import TaskContext


class ContextBuilder:
    """
    Builds code context for Agent tasks.

    The context builder:
    1. Extracts code snippets from files
    2. Includes relevant imports
    3. Adds related function code
    4. Manages context size limits
    """

    # Maximum context size in characters
    DEFAULT_MAX_CONTEXT_SIZE = 8000

    # Maximum related functions to include
    DEFAULT_MAX_RELATED_FUNCTIONS = 3

    # Lines of context to include around target
    DEFAULT_CONTEXT_LINES = 20

    def __init__(
        self,
        max_context_size: int = DEFAULT_MAX_CONTEXT_SIZE,
        max_related_functions: int = DEFAULT_MAX_RELATED_FUNCTIONS,
        context_lines: int = DEFAULT_CONTEXT_LINES,
    ):
        """
        Initialize the context builder.

        Args:
            max_context_size: Maximum context size in characters.
            max_related_functions: Maximum related functions to include.
            context_lines: Lines of context around target code.
        """
        self.logger = get_logger(__name__)
        self.max_context_size = max_context_size
        self.max_related_functions = max_related_functions
        self.context_lines = context_lines

    def build_context(
        self,
        source_path: Path,
        file_path: str,
        line_start: int | None = None,
        line_end: int | None = None,
        function_name: str | None = None,
        include_imports: bool = True,
        include_related: bool = True,
    ) -> str:
        """
        Build code context for a target.

        Args:
            source_path: Root path of the source code.
            file_path: Relative path to the file.
            line_start: Start line of interest.
            line_end: End line of interest.
            function_name: Function name to extract.
            include_imports: Whether to include imports.
            include_related: Whether to include related functions.

        Returns:
            Code context string.
        """
        full_path = source_path / file_path

        if not full_path.exists():
            self.logger.warning(f"File not found: {full_path}")
            return ""

        try:
            content = full_path.read_text(encoding="utf-8")
            lines = content.splitlines()
        except Exception as e:
            self.logger.error(f"Error reading file {full_path}: {e}")
            return ""

        context_parts = []

        # Add imports if requested
        if include_imports:
            imports = self._extract_imports(lines)
            if imports:
                context_parts.append(imports)

        # Extract main code snippet
        if function_name:
            # Extract function by name
            snippet = self._extract_function(lines, function_name)
        elif line_start and line_end:
            # Extract by line range
            snippet = self._extract_lines(lines, line_start, line_end)
        elif line_start:
            # Extract around line with context
            snippet = self._extract_around_line(lines, line_start, self.context_lines)
        else:
            # Include entire file if small enough
            snippet = self._truncate_content(content)

        if snippet:
            context_parts.append(snippet)

        # Add related functions if requested
        if include_related and function_name:
            related = self._find_related_functions(
                lines,
                function_name,
                source_path,
                file_path,
            )
            for rel_name, rel_code in related[:self.max_related_functions]:
                context_parts.append(f"\n# Related function: {rel_name}\n{rel_code}")

        # Combine and truncate if needed
        full_context = "\n\n".join(context_parts)
        return self._truncate_content(full_context)

    def build_context_from_task_context(
        self,
        task_context: TaskContext,
        source_path: Path,
    ) -> TaskContext:
        """
        Build full context for a TaskContext object.

        Args:
            task_context: Task context to populate.
            source_path: Root path of source code.

        Returns:
            Updated TaskContext with code snippet.
        """
        code_snippet = self.build_context(
            source_path=source_path,
            file_path=task_context.file_path,
            line_start=task_context.line_start,
            line_end=task_context.line_end,
            function_name=task_context.function_name,
        )

        # Create updated context
        task_context.code_snippet = code_snippet

        # Extract imports
        full_path = source_path / task_context.file_path
        if full_path.exists():
            try:
                content = full_path.read_text(encoding="utf-8")
                lines = content.splitlines()
                task_context.imports = self._extract_imports_list(lines)
            except Exception:
                pass

        return task_context

    def _extract_imports(self, lines: list[str]) -> str:
        """Extract import statements."""
        imports = []

        for line in lines:
            stripped = line.strip()
            # Python imports
            if stripped.startswith(("import ", "from ")):
                imports.append(line)
            # JavaScript/TypeScript imports
            elif stripped.startswith(("import ", "import{", "import {", "require(")):
                imports.append(line)
            # Java imports
            elif stripped.startswith("import "):
                imports.append(line)
            # Go imports
            elif stripped.startswith(("import ", 'import (')):
                imports.append(line)
            # Stop at first non-import, non-empty, non-comment line
            elif stripped and not stripped.startswith(("#", "//", "/*", "*")):
                # Check if we've started actual code
                if imports:
                    break

        return "\n".join(imports) if imports else ""

    def _extract_imports_list(self, lines: list[str]) -> list[str]:
        """Extract import statements as a list."""
        imports = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("import ", "from ", "require(")):
                imports.append(stripped)
            elif stripped and not stripped.startswith(("#", "//", "/*", "*")):
                if imports:
                    break

        return imports

    def _extract_function(self, lines: list[str], function_name: str) -> str:
        """Extract a function by name."""
        result_lines = []
        in_function = False
        indent_level = 0
        start_indent = 0

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Detect function start (language-agnostic patterns)
            if not in_function:
                # Python
                if stripped.startswith(f"def {function_name}(") or stripped.startswith(f"async def {function_name}("):
                    in_function = True
                    start_indent = len(line) - len(line.lstrip())
                    result_lines.append(line)
                    continue
                # JavaScript/TypeScript
                elif f"function {function_name}" in stripped or f"{function_name}(" in stripped:
                    if "function" in stripped or "=>" in stripped or stripped.startswith("async"):
                        in_function = True
                        start_indent = len(line) - len(line.lstrip())
                        result_lines.append(line)
                        continue
                # Java
                elif function_name + "(" in stripped and ("public" in stripped or "private" in stripped or "protected" in stripped):
                    in_function = True
                    start_indent = len(line) - len(line.lstrip())
                    result_lines.append(line)
                    continue
                # Go
                elif stripped.startswith(f"func {function_name}(") or f"func ({function_name}" in stripped:
                    in_function = True
                    start_indent = len(line) - len(line.lstrip())
                    result_lines.append(line)
                    continue
            else:
                # In function, track indentation
                current_indent = len(line) - len(line.lstrip()) if stripped else start_indent + 1

                result_lines.append(line)

                # Check for function end
                if stripped and current_indent <= start_indent and i > 0:
                    # We've outdented past the function
                    if not stripped.startswith(("#", "//")):
                        break

        return "\n".join(result_lines)

    def _extract_lines(
        self,
        lines: list[str],
        line_start: int,
        line_end: int,
    ) -> str:
        """Extract lines by range."""
        start = max(0, line_start - 1)  # Convert to 0-indexed
        end = min(len(lines), line_end)
        return "\n".join(lines[start:end])

    def _extract_around_line(
        self,
        lines: list[str],
        target_line: int,
        context_lines: int,
    ) -> str:
        """Extract lines around a target with context."""
        start = max(0, target_line - context_lines - 1)
        end = min(len(lines), target_line + context_lines)
        return "\n".join(lines[start:end])

    def _find_related_functions(
        self,
        lines: list[str],
        function_name: str,
        source_path: Path,
        file_path: str,
    ) -> list[tuple[str, str]]:
        """
        Find related functions called within a function.

        Returns list of (function_name, function_code) tuples.
        """
        related = []

        # First, find function calls in the main function
        main_function = self._extract_function(lines, function_name)
        called_functions = self._extract_function_calls(main_function)

        # Then extract those functions
        for called in called_functions:
            if len(related) >= self.max_related_functions:
                break

            # Look in current file
            func_code = self._extract_function(lines, called)
            if func_code:
                related.append((called, func_code))
                continue

            # Could extend to search in other files, but skip for now

        return related

    def _extract_function_calls(self, code: str) -> list[str]:
        """Extract function names that are called in code."""
        import re

        # Simple pattern for function calls
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        matches = re.findall(pattern, code)

        # Filter out common non-function patterns
        skip = {
            "if", "for", "while", "switch", "catch", "def", "class",
            "import", "from", "return", "print", "len", "str", "int",
            "list", "dict", "set", "tuple", "range", "open", "type",
            "isinstance", "hasattr", "getattr", "setattr",
        }

        return [m for m in matches if m not in skip and not m.startswith("_")]

    def _truncate_content(self, content: str) -> str:
        """Truncate content to max size."""
        if len(content) <= self.max_context_size:
            return content

        truncated = content[:self.max_context_size]
        # Try to end at a reasonable point
        last_newline = truncated.rfind("\n")
        if last_newline > self.max_context_size * 0.8:
            truncated = truncated[:last_newline]

        return truncated + "\n\n... (truncated)"

    def build_entry_point_context(
        self,
        source_path: Path,
        file_path: str,
        function_name: str,
        entry_point_type: str,
        http_method: str | None = None,
        endpoint_path: str | None = None,
    ) -> str:
        """
        Build context specifically for an entry point analysis.

        Args:
            source_path: Root path of source code.
            file_path: File containing the entry point.
            function_name: Handler function name.
            entry_point_type: Type of entry point.
            http_method: HTTP method if applicable.
            endpoint_path: Endpoint path if applicable.

        Returns:
            Context string optimized for entry point analysis.
        """
        # Build base context
        context = self.build_context(
            source_path=source_path,
            file_path=file_path,
            function_name=function_name,
            include_imports=True,
            include_related=True,
        )

        # Add entry point metadata
        header = f"# Entry Point Analysis\n"
        header += f"# Type: {entry_point_type}\n"
        if http_method and endpoint_path:
            header += f"# Endpoint: {http_method} {endpoint_path}\n"
        header += f"# Handler: {function_name}\n\n"

        return header + context

    def estimate_tokens(self, content: str) -> int:
        """
        Estimate token count for content.

        Uses a simple heuristic: ~4 characters per token.
        """
        return len(content) // 4
