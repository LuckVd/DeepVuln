"""
Context Builder

Builds code context for Agent tasks by extracting relevant code snippets,
imports, and related functions.

Enhanced with:
- Call chain analysis (who calls this function?)
- Dependency code extraction (extract imported class implementations)
- Data flow markers (mark user-controlled vs internal data)
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.task.models import TaskContext


@dataclass
class CallChainInfo:
    """Information about a function's call chain."""
    function_name: str
    file_path: str
    callers: list[dict[str, str]]  # List of {name, file, line}
    is_entry_point: bool  # Is this externally callable?
    entry_point_type: str | None  # HTTP, RPC, MQ, etc.


@dataclass
class DataFlowMarker:
    """Marker for data flow analysis."""
    variable_name: str
    source_type: str  # user_input, config, internal, trusted
    source_location: str
    description: str


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

    # =========================================================================
    # Enhanced Context Building Methods (P1 Enhancement)
    # =========================================================================

    def build_enhanced_context(
        self,
        source_path: Path,
        file_path: str,
        function_name: str | None = None,
        line_start: int | None = None,
        line_end: int | None = None,
        include_call_chain: bool = True,
        include_dependencies: bool = True,
        include_data_flow: bool = True,
    ) -> str:
        """
        Build enhanced context with call chain, dependencies, and data flow info.

        This is the main entry point for P1 enhanced context building.

        Args:
            source_path: Root path of source code.
            file_path: Relative path to target file.
            function_name: Target function name.
            line_start: Start line of interest.
            line_end: End line of interest.
            include_call_chain: Whether to include call chain analysis.
            include_dependencies: Whether to include dependency code.
            include_data_flow: Whether to include data flow markers.

        Returns:
            Enhanced context string for security analysis.
        """
        context_parts = []

        # 1. Build base context
        base_context = self.build_context(
            source_path=source_path,
            file_path=file_path,
            function_name=function_name,
            line_start=line_start,
            line_end=line_end,
            include_imports=True,
            include_related=True,
        )
        context_parts.append(base_context)

        # 2. Add call chain analysis
        if include_call_chain and function_name:
            call_chain = self.analyze_call_chain(
                source_path=source_path,
                file_path=file_path,
                function_name=function_name,
            )
            if call_chain:
                context_parts.append(self._format_call_chain(call_chain))

        # 3. Add dependency code
        if include_dependencies:
            deps = self.extract_dependencies(
                source_path=source_path,
                file_path=file_path,
            )
            if deps:
                context_parts.append(self._format_dependencies(deps))

        # 4. Add data flow markers
        if include_data_flow and function_name:
            data_flow = self.analyze_data_flow(
                source_path=source_path,
                file_path=file_path,
                function_name=function_name,
            )
            if data_flow:
                context_parts.append(self._format_data_flow(data_flow))

        return "\n\n".join(context_parts)

    def analyze_call_chain(
        self,
        source_path: Path,
        file_path: str,
        function_name: str,
        max_depth: int = 3,
    ) -> CallChainInfo | None:
        """
        Analyze the call chain for a function.

        Answers: Who calls this function? Is it an entry point?

        Args:
            source_path: Root path of source code.
            file_path: File containing the function.
            function_name: Function to analyze.
            max_depth: Maximum depth to search.

        Returns:
            CallChainInfo or None if not found.
        """
        full_path = source_path / file_path
        if not full_path.exists():
            return None

        try:
            content = full_path.read_text(encoding="utf-8")
        except Exception:
            return None

        # Check if this is an entry point
        is_entry, entry_type = self._detect_entry_point(content, function_name)

        # Find callers (simplified - searches for function calls in project)
        callers = self._find_callers(
            source_path=source_path,
            target_function=function_name,
            target_file=file_path,
            max_depth=max_depth,
        )

        return CallChainInfo(
            function_name=function_name,
            file_path=file_path,
            callers=callers,
            is_entry_point=is_entry,
            entry_point_type=entry_type,
        )

    def _detect_entry_point(self, content: str, function_name: str) -> tuple[bool, str | None]:
        """
        Detect if a function is an entry point.

        Entry points are:
        - HTTP handlers (@GetMapping, @PostMapping, @RequestMapping, etc.)
        - RPC handlers (@Service, @RpcMethod, etc.)
        - Message handlers (@RabbitListener, @KafkaListener, etc.)
        - Scheduled jobs (@Scheduled)
        - CLI handlers (main method)
        """
        import re

        # Java/Spring patterns
        spring_http = [
            r'@(Get|Post|Put|Delete|Patch|Request)Mapping',
            r'@RestController', r'@Controller', r'@ResponseBody',
        ]
        spring_rpc = [r'@Service', r'@RpcService', r'@DubboService']
        spring_mq = [r'@(Rabbit|Kafka|Jms)Listener', r'@StreamListener']
        spring_schedule = [r'@Scheduled']

        # Check for annotations near the function
        # Find function definition line
        lines = content.split('\n')
        func_line_idx = None
        for i, line in enumerate(lines):
            if function_name + '(' in line and ('public' in line or 'private' in line or 'def ' in line):
                func_line_idx = i
                break

        if func_line_idx is None:
            return False, None

        # Check 5 lines above for annotations
        context_start = max(0, func_line_idx - 5)
        context = '\n'.join(lines[context_start:func_line_idx + 1])

        # Check patterns
        if any(re.search(p, context) for p in spring_http):
            return True, "HTTP"
        if any(re.search(p, context) for p in spring_rpc):
            return True, "RPC"
        if any(re.search(p, context) for p in spring_mq):
            return True, "MQ"
        if any(re.search(p, context) for p in spring_schedule):
            return True, "SCHEDULED"

        # Check for main method
        if function_name == "main":
            return True, "CLI"

        # Python Flask/FastAPI patterns
        python_http = [
            r'@(app|router)\.(get|post|put|delete|patch)\s*\(',
            r'@route\s*\(', r'@(Get|Post|Put|Delete)\s*\(',
        ]
        if any(re.search(p, context) for p in python_http):
            return True, "HTTP"

        return False, None

    def _find_callers(
        self,
        source_path: Path,
        target_function: str,
        target_file: str,
        max_depth: int,
    ) -> list[dict[str, str]]:
        """
        Find all functions that call the target function.

        Returns list of {name, file, line} dicts.
        """
        callers = []

        # Search all Java/Python files
        extensions = [".java", ".py", ".ts", ".js", ".go"]
        for ext in extensions:
            for file_path in source_path.rglob(f"*{ext}"):
                # Skip test files
                if "test" in str(file_path).lower() or "Test" in str(file_path):
                    continue

                try:
                    content = file_path.read_text(encoding="utf-8")
                    lines = content.split('\n')

                    for i, line in enumerate(lines):
                        # Simple pattern: function_name(
                        if target_function + '(' in line:
                            # Get the function containing this call
                            caller_func = self._get_containing_function(lines, i)
                            if caller_func:
                                rel_path = str(file_path.relative_to(source_path))
                                callers.append({
                                    "name": caller_func,
                                    "file": rel_path,
                                    "line": str(i + 1),
                                })
                                break  # One caller per file is enough

                except Exception:
                    continue

                if len(callers) >= 5:  # Limit callers
                    break

            if len(callers) >= 5:
                break

        return callers

    def _get_containing_function(self, lines: list[str], target_line: int) -> str | None:
        """Get the function name containing a given line."""
        import re

        # Search backwards for function definition
        for i in range(target_line, max(-1, target_line - 50), -1):
            line = lines[i]

            # Java pattern
            java_match = re.search(r'\b(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{', line)
            if java_match and any(kw in line for kw in ['public', 'private', 'protected']):
                return java_match.group(1)

            # Python pattern
            py_match = re.search(r'def\s+(\w+)\s*\(', line)
            if py_match:
                return py_match.group(1)

        return None

    def extract_dependencies(
        self,
        source_path: Path,
        file_path: str,
        max_deps: int = 3,
    ) -> list[tuple[str, str]]:
        """
        Extract code from imported/dependent classes.

        This helps provide context for understanding how external functions work.

        Args:
            source_path: Root path of source code.
            file_path: Target file.
            max_deps: Maximum dependencies to extract.

        Returns:
            List of (class_name, code) tuples.
        """
        full_path = source_path / file_path
        if not full_path.exists():
            return []

        try:
            content = full_path.read_text(encoding="utf-8")
        except Exception:
            return []

        # Extract imports
        imports = self._extract_imports_list(content.split('\n'))

        dependencies = []
        for imp in imports[:max_deps * 2]:  # Check more than needed
            if len(dependencies) >= max_deps:
                break

            # Try to find and extract the imported class
            dep_code = self._find_imported_class(source_path, imp)
            if dep_code:
                class_name = self._extract_class_name_from_import(imp)
                if class_name:
                    dependencies.append((class_name, dep_code))

        return dependencies

    def _find_imported_class(self, source_path: Path, import_stmt: str) -> str | None:
        """Find and read the source file for an imported class."""
        import re

        # Extract class name from import
        # Java: import com.example.SomeClass;
        # Python: from module import SomeClass
        # Go: import "github.com/example/pkg"

        # Java pattern
        java_match = re.search(r'import\s+([\w.]+\.(\w+));', import_stmt)
        if java_match:
            full_path = java_match.group(1)
            class_name = java_match.group(2)

            # Convert package path to file path
            file_path = full_path.replace('.', '/')
            for ext in ['.java', '.kt']:
                candidate = source_path / (file_path + ext)
                if candidate.exists():
                    try:
                        return candidate.read_text(encoding="utf-8")[:2000]  # Limit size
                    except Exception:
                        pass

        # Python pattern - search for the module
        py_match = re.search(r'from\s+([\w.]+)\s+import\s+(\w+)', import_stmt)
        if py_match:
            module = py_match.group(1)
            class_name = py_match.group(2)

            # Search for the file
            module_path = module.replace('.', '/')
            for ext in ['.py', '/__init__.py']:
                candidate = source_path / (module_path + ext)
                if candidate.exists():
                    try:
                        content = candidate.read_text(encoding="utf-8")
                        # Extract just the class definition
                        return self._extract_class_or_function(content, class_name)
                    except Exception:
                        pass

        return None

    def _extract_class_name_from_import(self, import_stmt: str) -> str | None:
        """Extract the class name from an import statement."""
        import re

        # Java
        match = re.search(r'import\s+[\w.]+\.(\w+);', import_stmt)
        if match:
            return match.group(1)

        # Python
        match = re.search(r'from\s+[\w.]+\s+import\s+(\w+)', import_stmt)
        if match:
            return match.group(1)

        return None

    def _extract_class_or_function(self, content: str, name: str) -> str:
        """Extract a class or function definition from content."""
        import re

        lines = content.split('\n')
        result = []
        in_block = False
        start_indent = 0

        for line in lines:
            stripped = line.strip()

            # Detect class or function start
            if not in_block:
                if re.search(rf'\bclass\s+{name}\b', stripped):
                    in_block = True
                    start_indent = len(line) - len(line.lstrip())
                    result.append(line)
                    continue
                if re.search(rf'\bdef\s+{name}\b', stripped):
                    in_block = True
                    start_indent = len(line) - len(line.lstrip())
                    result.append(line)
                    continue
            else:
                current_indent = len(line) - len(line.lstrip()) if stripped else start_indent + 1
                result.append(line)

                # Check for block end
                if stripped and current_indent <= start_indent and len(result) > 1:
                    break

        return '\n'.join(result)[:2000]  # Limit size

    def analyze_data_flow(
        self,
        source_path: Path,
        file_path: str,
        function_name: str,
    ) -> list[DataFlowMarker]:
        """
        Analyze data flow in a function.

        Identifies:
        - User-controlled input (parameters, request data)
        - Internal configuration (env vars, config files)
        - Trusted sources (database, internal APIs)

        Args:
            source_path: Root path of source code.
            file_path: Target file.
            function_name: Function to analyze.

        Returns:
            List of DataFlowMarker objects.
        """
        full_path = source_path / file_path
        if not full_path.exists():
            return []

        try:
            content = full_path.read_text(encoding="utf-8")
        except Exception:
            return []

        markers = []

        # Extract function code
        func_code = self._extract_function(content.split('\n'), function_name)
        if not func_code:
            return []

        # Pattern definitions
        user_input_patterns = [
            (r'@RequestParam', 'HTTP request parameter'),
            (r'@PathVariable', 'HTTP path variable'),
            (r'@RequestBody', 'HTTP request body'),
            (r'@RequestHeader', 'HTTP header'),
            (r'request\.getParameter', 'HTTP parameter'),
            (r'request\.getInputStream', 'HTTP input stream'),
            (r'\$_(GET|POST|REQUEST)', 'PHP superglobal'),
            (r'request\.args\.get', 'Flask request argument'),
            (r'request\.form', 'Flask form data'),
            (r'request\.json', 'Flask JSON data'),
        ]

        config_patterns = [
            (r'@Value\s*\(["\']', 'Spring @Value configuration'),
            (r'Environment\.getenv', 'Environment variable'),
            (r'System\.getProperty', 'Java system property'),
            (r'os\.environ', 'Environment variable'),
            (r'config\.get', 'Configuration value'),
            (r'@ConfigurationProperties', 'Configuration properties'),
        ]

        trusted_patterns = [
            (r'database\.query', 'Database query result'),
            (r'repository\.find', 'Repository find result'),
            (r'internalApi\.', 'Internal API call'),
        ]

        # Check for user input
        import re
        for pattern, desc in user_input_patterns:
            if re.search(pattern, func_code):
                # Extract variable name if possible
                markers.append(DataFlowMarker(
                    variable_name="user_input",
                    source_type="user_input",
                    source_location=f"{file_path}:{function_name}",
                    description=f"Potential user-controlled input: {desc}",
                ))
                break  # One marker per type is enough

        # Check for config
        for pattern, desc in config_patterns:
            if re.search(pattern, func_code):
                markers.append(DataFlowMarker(
                    variable_name="config_value",
                    source_type="config",
                    source_location=f"{file_path}:{function_name}",
                    description=f"Configuration value: {desc}",
                ))
                break

        # Check for trusted sources
        for pattern, desc in trusted_patterns:
            if re.search(pattern, func_code):
                markers.append(DataFlowMarker(
                    variable_name="trusted_data",
                    source_type="trusted",
                    source_location=f"{file_path}:{function_name}",
                    description=f"Trusted source: {desc}",
                ))
                break

        return markers

    def _format_call_chain(self, call_chain: CallChainInfo) -> str:
        """Format call chain info for inclusion in context."""
        lines = [
            "# " + "=" * 60,
            "# CALL CHAIN ANALYSIS",
            "# " + "=" * 60,
            "",
            f"Function: {call_chain.function_name}",
            f"File: {call_chain.file_path}",
            "",
        ]

        if call_chain.is_entry_point:
            lines.append(f"[ENTRY POINT] This function is an external entry point")
            lines.append(f"Entry Type: {call_chain.entry_point_type}")
            lines.append("")
            lines.append("WARNING: Input to this function may be user-controlled!")
        else:
            lines.append("[INTERNAL] This function is called internally")
            if call_chain.callers:
                lines.append("")
                lines.append("Called by:")
                for caller in call_chain.callers[:3]:
                    lines.append(f"  - {caller['name']} in {caller['file']}:{caller['line']}")
            else:
                lines.append("")
                lines.append("No external callers found - may be dead code or very internal")

        return "\n".join(lines)

    def _format_dependencies(self, deps: list[tuple[str, str]]) -> str:
        """Format dependency code for inclusion in context."""
        lines = [
            "# " + "=" * 60,
            "# DEPENDENCY CODE (for context)",
            "# " + "=" * 60,
            "",
        ]

        for class_name, code in deps:
            lines.append(f"## Class: {class_name}")
            lines.append("```")
            lines.append(code[:1500])  # Limit per dependency
            if len(code) > 1500:
                lines.append("... (truncated)")
            lines.append("```")
            lines.append("")

        return "\n".join(lines)

    def _format_data_flow(self, markers: list[DataFlowMarker]) -> str:
        """Format data flow markers for inclusion in context."""
        lines = [
            "# " + "=" * 60,
            "# DATA FLOW ANALYSIS",
            "# " + "=" * 60,
            "",
        ]

        if not markers:
            lines.append("No external data sources detected in this function.")
            lines.append("Input appears to be from internal/trusted sources only.")
        else:
            for marker in markers:
                icon = {
                    "user_input": "[USER CONTROLLED]",
                    "config": "[CONFIG]",
                    "trusted": "[TRUSTED]",
                    "internal": "[INTERNAL]",
                }.get(marker.source_type, "[UNKNOWN]")

                lines.append(f"{icon} {marker.description}")

        lines.append("")
        lines.append("# Severity hint: If no [USER CONTROLLED] markers, consider lowering severity.")

        return "\n".join(lines)
