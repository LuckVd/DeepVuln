"""LLM-assisted entry point detection with full LLM participation.

This module provides LLM-based detection for all types of entry points
(HTTP, RPC, gRPC, MQ, Cron, WebSocket, CLI) without framework restrictions.

Two-phase approach:
1. Phase 1: Project structure analysis - LLM identifies files to analyze
2. Phase 2: Entry point detection - LLM analyzes code to find entry points
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.models import (
    EntryPoint,
    EntryPointType,
    HTTPMethod,
)

logger = get_logger(__name__)


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class LLMEntryPoint:
    """Entry point detected by LLM."""

    method: str
    path: str
    function: str
    line: int | None = None
    description: str | None = None


@dataclass
class ProjectStructureAnalysis:
    """Result of Phase 1: Project structure analysis."""

    target_files: list[str] = field(default_factory=list)
    target_dirs: list[str] = field(default_factory=list)
    reasoning: str = ""
    detected_languages: list[str] = field(default_factory=list)
    detected_frameworks: list[str] = field(default_factory=list)


@dataclass
class FileAnalysisResult:
    """Result of Phase 2: Single file analysis."""

    file_path: str
    entry_points: list[EntryPoint] = field(default_factory=list)
    framework_detected: str = "unknown"
    confidence: float = 0.0
    error: str | None = None


# =============================================================================
# Prompt Templates
# =============================================================================

# Phase 1: Project Structure Analysis Prompt
PROJECT_STRUCTURE_PROMPT = """Analyze the following project structure and identify files/directories that likely contain external entry points.

Entry point types to look for:
- HTTP/Web API endpoints (handlers, controllers, routes)
- RPC services (gRPC, Dubbo, Thrift, custom RPC)
- Message Queue consumers (Kafka, RabbitMQ, Redis, etc.)
- Scheduled jobs/Cron tasks
- WebSocket handlers
- CLI commands exposed to external users
- Lambda/Serverless function handlers

Project: {project_name}

Project Structure:
```
{project_tree}
```

Detected Languages: {languages}

Instructions:
1. Identify files that likely contain entry point definitions
2. Identify directories that likely contain handler/controller code
3. Skip test files, config files, utility files, and data files
4. Consider the project's language and common framework patterns

Return JSON format:
{{
    "target_files": ["path/to/file1.ext", "path/to/file2.ext"],
    "target_dirs": ["handler/", "api/", "controller/"],
    "detected_languages": ["go", "python", "typescript"],
    "detected_frameworks": ["gin", "flask", "express"],
    "reasoning": "Brief explanation of your selection"
}}

If no entry point files are found, return:
{{"target_files": [], "target_dirs": [], "detected_languages": [], "detected_frameworks": [], "reasoning": "explanation"}}
"""


# Phase 2: Entry Point Detection Prompt
ENTRY_POINT_DETECTION_PROMPT = """Analyze the following source code and identify ALL external entry points.

File: {file_path}
Language: {language}

Code:
```
{code}
```

Entry point types to identify:
1. HTTP endpoints: Routes, handlers, controllers that process HTTP requests
   - Look for: route definitions, handler functions, HTTP method decorators
   - Include: method (GET/POST/PUT/DELETE/etc), path, handler function name

2. RPC/gRPC services: Service definitions, method handlers
   - Look for: service definitions, RPC method handlers
   - Include: service name, method name, handler function

3. Message Queue consumers: Queue/topic listeners, message handlers
   - Look for: queue subscriptions, message processing functions
   - Include: queue/topic name, handler function

4. Scheduled jobs: Cron jobs, scheduled tasks, timers
   - Look for: schedule definitions, cron expressions, timer setup
   - Include: schedule expression, handler function

5. WebSocket handlers: WebSocket endpoints, connection handlers
   - Look for: WebSocket route definitions, connection handlers
   - Include: path, handler function

6. CLI commands: Command-line interface entry points (if exposed externally)
   - Look for: command definitions, main functions that process CLI args
   - Include: command name, handler function

Return JSON format:
{{
    "entry_points": [
        {{
            "type": "http|rpc|grpc|mq|cron|websocket|cli",
            "method": "GET|POST|PUT|DELETE|PATCH|*",
            "path": "/api/path or service name or queue name",
            "handler": "function_name",
            "line": 42,
            "auth_required": true/false,
            "params": ["param1", "param2"],
            "description": "Brief description"
        }}
    ],
    "framework_detected": "gin|flask|fastapi|spring|express|custom|unknown",
    "confidence": 0.0-1.0,
    "notes": "Optional notes about the analysis"
}}

If no entry points are found, return:
{{"entry_points": [], "framework_detected": "unknown", "confidence": 0.0, "notes": "reason"}}
"""


# =============================================================================
# Project Structure Generator
# =============================================================================


class ProjectTreeGenerator:
    """Generate project structure tree for LLM analysis."""

    # Directories to skip
    SKIP_DIRS = {
        "node_modules",
        "venv",
        ".venv",
        "env",
        ".env",
        "__pycache__",
        ".git",
        ".github",
        ".gitlab",
        "dist",
        "build",
        "target",
        "vendor",
        "vendor",
        ".idea",
        ".vscode",
        "coverage",
        ".pytest_cache",
        ".mypy_cache",
        "eggs",
        "*.egg-info",
        "node_modules",
        "bower_components",
        "jspm_packages",
        ".npm",
        ".yarn",
    }

    # File patterns to skip
    SKIP_FILE_PATTERNS = {
        ".lock",
        ".sum",
        ".log",
        ".md",
        ".txt",
        ".rst",
        ".svg",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".map",
    }

    # Source file extensions
    SOURCE_EXTENSIONS = {
        ".go", ".py", ".java", ".kt", ".ts", ".tsx", ".js", ".jsx",
        ".rs", ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".hpp",
        ".scala", ".swift", ".m", ".proto", ".thrift", ".graphql",
    }

    def __init__(self, max_depth: int = 5, max_files: int = 500):
        """Initialize the generator.

        Args:
            max_depth: Maximum directory depth to traverse.
            max_files: Maximum number of files to include in tree.
        """
        self.max_depth = max_depth
        self.max_files = max_files

    def generate(self, source_path: Path) -> str:
        """Generate a tree representation of the project structure.

        Args:
            source_path: Path to source code.

        Returns:
            String representation of project tree.
        """
        lines = []
        file_count = 0

        def should_skip_dir(name: str) -> bool:
            return name.lower() in self.SKIP_DIRS or name.startswith(".")

        def should_skip_file(name: str) -> bool:
            name_lower = name.lower()
            # Skip test files in tree view (but still analyze them)
            if "test" in name_lower or "spec" in name_lower:
                return True
            # Skip common non-source files
            for pattern in self.SKIP_FILE_PATTERNS:
                if name_lower.endswith(pattern):
                    return True
            return False

        def walk_dir(path: Path, prefix: str = "", depth: int = 0) -> int:
            nonlocal file_count

            if depth > self.max_depth or file_count >= self.max_files:
                return 0

            try:
                items = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
            except PermissionError:
                return 0

            count = 0
            for i, item in enumerate(items):
                if file_count >= self.max_files:
                    lines.append(f"{prefix}... (truncated, too many files)")
                    break

                is_last = i == len(items) - 1
                connector = "└── " if is_last else "├── "
                new_prefix = prefix + ("    " if is_last else "│   ")

                if item.is_dir():
                    if should_skip_dir(item.name):
                        continue
                    lines.append(f"{prefix}{connector}{item.name}/")
                    count += walk_dir(item, new_prefix, depth + 1)
                else:
                    if should_skip_file(item.name):
                        continue
                    # Show file extension and size hint
                    size_hint = self._get_size_hint(item)
                    lines.append(f"{prefix}{connector}{item.name}{size_hint}")
                    file_count += 1
                    count += 1

            return count

        lines.append(f"{source_path.name}/")
        walk_dir(source_path)

        return "\n".join(lines)

    def _get_size_hint(self, path: Path) -> str:
        """Get size hint for a file."""
        try:
            size = path.stat().st_size
            if size > 100000:  # > 100KB
                return " [large]"
            elif size > 10000:  # > 10KB
                return " [medium]"
        except OSError:
            pass
        return ""

    def get_source_files(self, source_path: Path) -> list[Path]:
        """Get all source files in the project.

        Args:
            source_path: Path to source code.

        Returns:
            List of source file paths.
        """
        source_files = []

        for ext in self.SOURCE_EXTENSIONS:
            for file_path in source_path.rglob(f"*{ext}"):
                # Skip excluded directories
                if any(part.lower() in self.SKIP_DIRS for part in file_path.parts):
                    continue
                # Skip test files (optional, can be configured)
                if "test" in file_path.name.lower() or "spec" in file_path.name.lower():
                    continue
                source_files.append(file_path)

        return sorted(source_files)

    def detect_languages(self, source_path: Path) -> list[str]:
        """Detect programming languages used in the project.

        Args:
            source_path: Path to source code.

        Returns:
            List of detected languages.
        """
        extension_to_lang = {
            ".go": "Go",
            ".py": "Python",
            ".java": "Java",
            ".kt": "Kotlin",
            ".ts": "TypeScript",
            ".tsx": "TypeScript",
            ".js": "JavaScript",
            ".jsx": "JavaScript",
            ".rs": "Rust",
            ".rb": "Ruby",
            ".php": "PHP",
            ".cs": "C#",
            ".cpp": "C++",
            ".c": "C",
            ".scala": "Scala",
            ".swift": "Swift",
            ".proto": "Protobuf",
            ".thrift": "Thrift",
        }

        languages = set()

        for ext in self.SOURCE_EXTENSIONS:
            if list(source_path.rglob(f"*{ext}")):
                lang = extension_to_lang.get(ext, ext)
                languages.add(lang)

        return sorted(languages)


# =============================================================================
# LLM Full Detector
# =============================================================================


class LLMFullDetector:
    """Full LLM-based entry point detector with two-phase analysis.

    Phase 1: Analyze project structure to identify target files
    Phase 2: Analyze selected files to detect entry points
    """

    def __init__(
        self,
        llm_client: Any,
        model: str = "deepseek-chat",
        max_file_size: int = 50000,  # 50KB max per file
        max_files_to_analyze: int = 50,
    ):
        """Initialize the full LLM detector.

        Args:
            llm_client: LLM client instance (OpenAIClient or compatible).
            model: Model name to use.
            max_file_size: Maximum file size to analyze (bytes).
            max_files_to_analyze: Maximum number of files to analyze in Phase 2.
        """
        self.llm_client = llm_client
        self.model = model
        self.max_file_size = max_file_size
        self.max_files_to_analyze = max_files_to_analyze
        self.logger = get_logger(__name__)
        self._tree_generator = ProjectTreeGenerator()
        self._cache: dict[str, Any] = {}

    async def detect_full(self, source_path: Path) -> list[EntryPoint]:
        """Run full two-phase LLM detection.

        Args:
            source_path: Path to source code.

        Returns:
            List of detected entry points.
        """
        self.logger.info(f"Starting full LLM detection for {source_path}")

        all_entry_points: list[EntryPoint] = []

        # Phase 1: Analyze project structure
        self.logger.info("Phase 1: Analyzing project structure...")
        analysis = await self._analyze_project_structure(source_path)

        if not analysis.target_files and not analysis.target_dirs:
            self.logger.warning("Phase 1: No target files identified by LLM")
            return all_entry_points

        self.logger.info(
            f"Phase 1: LLM identified {len(analysis.target_files)} files, "
            f"{len(analysis.target_dirs)} dirs to analyze"
        )

        # Resolve target files
        target_files = self._resolve_target_files(
            source_path, analysis.target_files, analysis.target_dirs
        )

        # Limit files to analyze
        if len(target_files) > self.max_files_to_analyze:
            self.logger.warning(
                f"Limiting analysis to {self.max_files_to_analyze} files "
                f"(out of {len(target_files)} identified)"
            )
            target_files = target_files[:self.max_files_to_analyze]

        # Phase 2: Analyze each target file
        self.logger.info(f"Phase 2: Analyzing {len(target_files)} files...")
        for i, file_path in enumerate(target_files, 1):
            self.logger.debug(f"Phase 2: [{i}/{len(target_files)}] Analyzing {file_path.name}")

            try:
                result = await self._analyze_file(file_path, source_path)
                if result.entry_points:
                    all_entry_points.extend(result.entry_points)
                    self.logger.info(
                        f"Phase 2: Found {len(result.entry_points)} entry points in {file_path.name}"
                    )
            except Exception as e:
                self.logger.error(f"Phase 2: Failed to analyze {file_path}: {e}")

        self.logger.info(f"Full LLM detection complete: {len(all_entry_points)} entry points found")
        return all_entry_points

    async def _analyze_project_structure(self, source_path: Path) -> ProjectStructureAnalysis:
        """Phase 1: Analyze project structure to identify target files.

        Args:
            source_path: Path to source code.

        Returns:
            ProjectStructureAnalysis with target files and directories.
        """
        # Generate project tree
        project_tree = self._tree_generator.generate(source_path)
        languages = self._tree_generator.detect_languages(source_path)

        # Build prompt
        prompt = PROJECT_STRUCTURE_PROMPT.format(
            project_name=source_path.name,
            project_tree=project_tree,
            languages=", ".join(languages) if languages else "Unknown",
        )

        # Call LLM
        response = await self._call_llm(prompt)

        # Parse response
        return self._parse_structure_response(response)

    async def _analyze_file(self, file_path: Path, source_path: Path) -> FileAnalysisResult:
        """Phase 2: Analyze a single file for entry points.

        Args:
            file_path: Path to the file to analyze.
            source_path: Root source path.

        Returns:
            FileAnalysisResult with detected entry points.
        """
        result = FileAnalysisResult(file_path=str(file_path))

        # Read file content
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            result.error = f"Failed to read file: {e}"
            return result

        # Skip files that are too large
        if len(content) > self.max_file_size:
            # Try to read first part
            content = content[:self.max_file_size]
            self.logger.debug(f"Truncated large file: {file_path}")

        # Detect language from extension
        language = self._detect_language(file_path)

        # Build prompt
        relative_path = file_path.relative_to(source_path)
        prompt = ENTRY_POINT_DETECTION_PROMPT.format(
            file_path=str(relative_path),
            language=language,
            code=content,
        )

        # Call LLM
        response = await self._call_llm(prompt)

        # Parse response
        entry_points = self._parse_entry_points_response(response, file_path)
        result.entry_points = entry_points
        result.confidence = 0.8  # Default confidence for LLM detection

        return result

    def _resolve_target_files(
        self,
        source_path: Path,
        target_files: list[str],
        target_dirs: list[str],
    ) -> list[Path]:
        """Resolve target files from LLM response.

        Args:
            source_path: Root source path.
            target_files: List of file paths from LLM.
            target_dirs: List of directory paths from LLM.

        Returns:
            List of resolved file paths.
        """
        resolved: set[Path] = set()

        # Resolve explicit files
        for file_str in target_files:
            file_path = source_path / file_str
            if file_path.exists() and file_path.is_file():
                resolved.add(file_path)

        # Resolve files in directories
        for dir_str in target_dirs:
            dir_path = source_path / dir_str
            if dir_path.exists() and dir_path.is_dir():
                for ext in self._tree_generator.SOURCE_EXTENSIONS:
                    for file_path in dir_path.rglob(f"*{ext}"):
                        if file_path.is_file():
                            resolved.add(file_path)

        # If no targets resolved, fall back to all source files
        if not resolved:
            self.logger.warning("No target files resolved, falling back to all source files")
            resolved.update(self._tree_generator.get_source_files(source_path))

        return sorted(resolved)

    async def _call_llm(self, prompt: str) -> str:
        """Call LLM with the given prompt.

        Args:
            prompt: The prompt to send.

        Returns:
            LLM response text.
        """
        # Try our custom OpenAIClient (has complete method)
        if hasattr(self.llm_client, "complete"):
            response = await self.llm_client.complete(prompt)
            return response.content
        # Try OpenAI-style client with chat.completions
        elif hasattr(self.llm_client, "chat") and hasattr(self.llm_client.chat, "completions"):
            response = await self.llm_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
            )
            return response.choices[0].message.content
        # Try LangChain-style client
        elif hasattr(self.llm_client, "ainvoke"):
            response = await self.llm_client.ainvoke(prompt)
            return str(response)
        else:
            raise ValueError("Unsupported LLM client type")

    def _parse_structure_response(self, response: str) -> ProjectStructureAnalysis:
        """Parse LLM response for project structure analysis.

        Args:
            response: LLM response text.

        Returns:
            ProjectStructureAnalysis object.
        """
        analysis = ProjectStructureAnalysis()

        try:
            # Extract JSON from response
            json_match = re.search(r"\{[\s\S]*\}", response)
            if not json_match:
                self.logger.warning("No JSON found in structure analysis response")
                return analysis

            data = json.loads(json_match.group())

            analysis.target_files = data.get("target_files", [])
            analysis.target_dirs = data.get("target_dirs", [])
            analysis.detected_languages = data.get("detected_languages", [])
            analysis.detected_frameworks = data.get("detected_frameworks", [])
            analysis.reasoning = data.get("reasoning", "")

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse structure analysis response: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing structure analysis response: {e}")

        return analysis

    def _parse_entry_points_response(self, response: str, file_path: Path) -> list[EntryPoint]:
        """Parse LLM response for entry point detection.

        Args:
            response: LLM response text.
            file_path: Path to the analyzed file.

        Returns:
            List of EntryPoint objects.
        """
        entry_points = []

        try:
            # Extract JSON from response
            json_match = re.search(r"\{[\s\S]*\}", response)
            if not json_match:
                self.logger.warning("No JSON found in entry points response")
                return entry_points

            data = json.loads(json_match.group())

            for ep_data in data.get("entry_points", []):
                entry = self._create_entry_point(ep_data, file_path)
                if entry:
                    entry_points.append(entry)

            self.logger.info(
                f"LLM detected {len(entry_points)} entry points in {file_path.name}"
            )

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse entry points response: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing entry points response: {e}")

        return entry_points

    def _create_entry_point(self, data: dict, file_path: Path) -> EntryPoint | None:
        """Create EntryPoint from LLM response data.

        Args:
            data: Entry point data from LLM.
            file_path: Path to the file.

        Returns:
            EntryPoint object or None if invalid.
        """
        try:
            # Parse entry point type
            type_str = data.get("type", "http").lower()
            type_map = {
                "http": EntryPointType.HTTP,
                "rpc": EntryPointType.RPC,
                "grpc": EntryPointType.GRPC,
                "mq": EntryPointType.MQ,
                "message": EntryPointType.MQ,
                "kafka": EntryPointType.MQ,
                "cron": EntryPointType.CRON,
                "schedule": EntryPointType.CRON,
                "websocket": EntryPointType.WEBSOCKET,
                "ws": EntryPointType.WEBSOCKET,
                "cli": EntryPointType.CLI,
                "command": EntryPointType.CLI,
            }
            ep_type = type_map.get(type_str, EntryPointType.HTTP)

            # Parse HTTP method
            method = None
            if ep_type == EntryPointType.HTTP:
                method_str = data.get("method", "GET").upper()
                try:
                    method = HTTPMethod[method_str]
                except KeyError:
                    method = HTTPMethod.ALL

            # Create entry point
            # Ensure params is a list of strings
            params = data.get("params", [])
            if params is None:
                params = []
            elif isinstance(params, str):
                params = [params]
            elif isinstance(params, list):
                params = [str(p) for p in params if p is not None]

            entry = EntryPoint(
                type=ep_type,
                method=method,
                path=data.get("path", "/"),
                handler=data.get("handler", "unknown"),
                file=str(file_path),
                line=data.get("line", 0),
                auth_required=data.get("auth_required", False),
                params=params,
                framework=data.get("framework", "llm-detected"),
                metadata={
                    "description": data.get("description"),
                    "confidence": data.get("confidence", 0.8),
                    "detected_by": "llm-full",
                },
            )

            return entry

        except Exception as e:
            self.logger.error(f"Failed to create entry point: {e}")
            return None

    def _detect_language(self, file_path: Path) -> str:
        """Detect programming language from file extension.

        Args:
            file_path: Path to the file.

        Returns:
            Language name.
        """
        extension_to_lang = {
            ".go": "Go",
            ".py": "Python",
            ".java": "Java",
            ".kt": "Kotlin",
            ".ts": "TypeScript",
            ".tsx": "TypeScript",
            ".js": "JavaScript",
            ".jsx": "JavaScript",
            ".rs": "Rust",
            ".rb": "Ruby",
            ".php": "PHP",
            ".cs": "C#",
            ".cpp": "C++",
            ".c": "C",
            ".scala": "Scala",
            ".swift": "Swift",
            ".proto": "Protobuf",
            ".thrift": "Thrift",
        }
        return extension_to_lang.get(file_path.suffix.lower(), "Unknown")

    def clear_cache(self) -> None:
        """Clear the detection cache."""
        self._cache.clear()


# =============================================================================
# Legacy Classes (for backward compatibility)
# =============================================================================


class LLMHTTPDetector:
    """Legacy LLM-based HTTP entry point detector.

    Maintained for backward compatibility. Use LLMFullDetector for new code.
    """

    def __init__(self, llm_client: Any = None, model: str = "deepseek-chat"):
        """Initialize the LLM detector.

        Args:
            llm_client: LLM client instance.
            model: Model name to use for detection.
        """
        self._full_detector = LLMFullDetector(llm_client, model) if llm_client else None
        self.llm_client = llm_client
        self.model = model
        self.logger = get_logger(__name__)
        self._cache: dict[str, list[EntryPoint]] = {}

    async def detect(
        self,
        code: str,
        file_path: Path,
        use_cache: bool = True,
    ) -> list[EntryPoint]:
        """Detect HTTP entry points using LLM.

        Args:
            code: Source code content.
            file_path: Path to the source file.
            use_cache: Whether to use cached results.

        Returns:
            List of detected entry points.
        """
        if not self.llm_client or not self._full_detector:
            self.logger.warning("No LLM client configured, skipping LLM detection")
            return []

        cache_key = f"{file_path}:{hash(code)}"
        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        try:
            # Detect language from file extension
            language = self._full_detector._detect_language(file_path)

            # Build prompt
            prompt = ENTRY_POINT_DETECTION_PROMPT.format(
                file_path=str(file_path),
                language=language,
                code=code[:self._full_detector.max_file_size],  # Limit code size
            )

            # Call LLM
            response = await self._full_detector._call_llm(prompt)

            # Parse response
            entry_points = self._full_detector._parse_entry_points_response(response, file_path)

            if use_cache:
                self._cache[cache_key] = entry_points

            return entry_points

        except Exception as e:
            self.logger.error(f"LLM detection failed: {e}")
            return []

    def clear_cache(self) -> None:
        """Clear the detection cache."""
        self._cache.clear()


class HybridHTTPDetector:
    """Hybrid detector combining static and LLM-based detection.

    Maintained for backward compatibility.
    """

    def __init__(
        self,
        static_detectors: list[Any] | None = None,
        llm_client: Any = None,
        model: str = "deepseek-chat",
        enable_llm: bool = True,
    ):
        """Initialize the hybrid detector.

        Args:
            static_detectors: List of static detector instances.
            llm_client: LLM client for fallback detection.
            model: Model name for LLM detection.
            enable_llm: Whether to enable LLM fallback.
        """
        self.static_detectors = static_detectors or []
        self.llm_detector = (
            LLMHTTPDetector(llm_client, model) if enable_llm and llm_client else None
        )
        self.logger = get_logger(__name__)

    async def detect(
        self,
        code: str,
        file_path: Path,
        use_llm_fallback: bool = True,
    ) -> list[EntryPoint]:
        """Detect entry points using hybrid approach.

        Args:
            code: Source code content.
            file_path: Path to the source file.
            use_llm_fallback: Whether to use LLM fallback.

        Returns:
            List of detected entry points.
        """
        all_entry_points: list[EntryPoint] = []

        # Step 1: Run all static detectors
        for detector in self.static_detectors:
            try:
                entry_points = detector.detect(code, file_path)
                all_entry_points.extend(entry_points)
            except Exception as e:
                self.logger.debug(
                    f"Static detector {detector.__class__.__name__} failed: {e}"
                )

        # Step 2: If no entry points found and LLM is available, try LLM
        if (
            not all_entry_points
            and use_llm_fallback
            and self.llm_detector
            and self._should_use_llm(code, file_path)
        ):
            try:
                llm_entry_points = await self.llm_detector.detect(code, file_path)
                all_entry_points.extend(llm_entry_points)
            except Exception as e:
                self.logger.warning(f"LLM fallback failed: {e}")

        return all_entry_points

    def _should_use_llm(self, code: str, file_path: Path) -> bool:
        """Determine if LLM detection should be used for this file."""
        if len(code) < 100:
            return False
        if "test" in file_path.name.lower():
            return False
        http_indicators = [
            "http", "socket", "server", "request", "response",
            "handler", "route", "api",
        ]
        code_lower = code.lower()
        indicator_count = sum(1 for kw in http_indicators if kw in code_lower)
        return indicator_count >= 2


def create_hybrid_detector(
    llm_client: Any = None,
    model: str = "deepseek-chat",
    enable_llm: bool = True,
) -> HybridHTTPDetector:
    """Create a hybrid HTTP detector with all available static detectors.

    Args:
        llm_client: LLM client for fallback detection.
        model: Model name for LLM detection.
        enable_llm: Whether to enable LLM fallback.

    Returns:
        Configured HybridHTTPDetector instance.
    """
    from src.layers.l1_intelligence.attack_surface.http_detector import (
        HTTP_DETECTORS,
    )

    static_detectors = [detector_cls() for detector_cls in HTTP_DETECTORS]

    return HybridHTTPDetector(
        static_detectors=static_detectors,
        llm_client=llm_client,
        model=model,
        enable_llm=enable_llm,
    )
