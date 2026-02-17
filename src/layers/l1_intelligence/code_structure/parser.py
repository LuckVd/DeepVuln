"""Main code structure parser for parsing projects and directories."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator

from .base import CodeStructureParser
from .models import (
    CallEdge,
    ClassDef,
    FunctionDef,
    ModuleInfo,
    ParseOptions,
    ProjectStructure,
)

# Use standard logging to avoid circular import issues
logger = logging.getLogger(__name__)


class ProjectParser:
    """Parser for entire projects/directories."""

    def __init__(self, options: ParseOptions | None = None) -> None:
        """Initialize the project parser.

        Args:
            options: Parse options.
        """
        self.options = options or ParseOptions()
        self.parser = CodeStructureParser(self.options)

    def parse_project(self, root_path: Path) -> ProjectStructure:
        """Parse all source files in a project.

        Args:
            root_path: Root directory of the project.

        Returns:
            Parsed project structure.
        """
        root_path = Path(root_path).resolve()
        structure = ProjectStructure(root_path=str(root_path))

        # Find all parseable files
        files = list(self._find_source_files(root_path))
        logger.info(f"Found {len(files)} source files to parse")

        # Parse files in parallel
        modules = self._parse_files_parallel(files)

        # Aggregate results
        languages = set()
        for file_path, module in modules.items():
            structure.modules[file_path] = module

            if module.parse_errors:
                for error in module.parse_errors:
                    structure.parse_errors[file_path] = error
            else:
                # Aggregate classes
                for cls in module.classes:
                    structure.all_classes[cls.full_name] = cls
                    structure._add_nested_classes(cls)

                # Aggregate functions
                for func in module.all_functions:
                    structure.all_functions[func.full_name] = func

                # Aggregate call graph
                structure.global_call_graph.edges.extend(module.call_graph.edges)

            languages.add(module.language)
            structure.total_lines += module.line_count

        structure.total_files = len(structure.modules)
        structure.languages = list(languages)

        # Determine primary language
        if structure.languages:
            lang_counts: dict[str, int] = {}
            for module in structure.modules.values():
                lang_counts[module.language] = lang_counts.get(module.language, 0) + 1
            structure.primary_language = max(lang_counts, key=lang_counts.get)

        logger.info(
            f"Parsed {structure.total_files} files, "
            f"found {len(structure.all_classes)} classes, "
            f"{len(structure.all_functions)} functions"
        )

        return structure

    def _find_source_files(self, root_path: Path) -> Iterator[Path]:
        """Find all source files to parse.

        Args:
            root_path: Root directory to search.

        Yields:
            Paths to source files.
        """
        excluded_dirs = set(self.options.excluded_dirs)
        included_exts = set(self.options.included_extensions)

        for file_path in root_path.rglob("*"):
            # Skip excluded directories
            if any(part in excluded_dirs for part in file_path.parts):
                continue

            # Check extension
            if file_path.suffix.lower() not in included_exts:
                continue

            # Check file size
            try:
                if file_path.stat().st_size > self.options.max_file_size:
                    logger.debug(f"Skipping large file: {file_path}")
                    continue
            except OSError:
                continue

            yield file_path

    def _parse_files_parallel(self, files: list[Path]) -> dict[str, ModuleInfo]:
        """Parse multiple files in parallel.

        Args:
            files: List of file paths to parse.

        Returns:
            Dictionary mapping file paths to module info.
        """
        results: dict[str, ModuleInfo] = {}

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_path = {
                executor.submit(self.parser.parse_file, fp): fp for fp in files
            }

            for future in as_completed(future_to_path):
                file_path = future_to_path[future]
                try:
                    module = future.result()
                    results[str(file_path)] = module
                except Exception as e:
                    logger.error(f"Failed to parse {file_path}: {e}")
                    results[str(file_path)] = ModuleInfo(
                        file_path=str(file_path),
                        language="unknown",
                        parse_errors=[str(e)],
                    )

        return results

    def parse_directory(self, dir_path: Path) -> dict[str, ModuleInfo]:
        """Parse all files in a directory (non-recursive).

        Args:
            dir_path: Directory to parse.

        Returns:
            Dictionary mapping file paths to module info.
        """
        results: dict[str, ModuleInfo] = {}

        for file_path in dir_path.iterdir():
            if file_path.is_file() and self.parser.can_parse(file_path):
                try:
                    module = self.parser.parse_file(file_path)
                    results[str(file_path)] = module
                except Exception as e:
                    logger.error(f"Failed to parse {file_path}: {e}")
                    results[str(file_path)] = ModuleInfo(
                        file_path=str(file_path),
                        language="unknown",
                        parse_errors=[str(e)],
                    )

        return results


def _add_nested_classes(structure: ProjectStructure, cls: ClassDef) -> None:
    """Add nested classes to the structure. Helper method."""
    for nested in cls.nested_classes:
        structure.all_classes[nested.full_name] = nested
        _add_nested_classes(structure, nested)


# Add method to ProjectStructure dynamically
def _add_nested_classes_to_structure(self: ProjectStructure, cls: ClassDef) -> None:
    """Add nested classes to the structure."""
    for nested in cls.nested_classes:
        self.all_classes[nested.full_name] = nested
        _add_nested_classes_to_structure(self, nested)


ProjectStructure._add_nested_classes = _add_nested_classes_to_structure  # type: ignore


def parse_file(file_path: Path | str, options: ParseOptions | None = None) -> ModuleInfo:
    """Convenience function to parse a single file.

    Args:
        file_path: Path to the file.
        options: Parse options.

    Returns:
        Parsed module information.
    """
    parser = CodeStructureParser(options)
    return parser.parse_file(Path(file_path))


def parse_project(
    root_path: Path | str, options: ParseOptions | None = None
) -> ProjectStructure:
    """Convenience function to parse a project.

    Args:
        root_path: Root directory of the project.
        options: Parse options.

    Returns:
        Parsed project structure.
    """
    parser = ProjectParser(options)
    return parser.parse_project(Path(root_path))
