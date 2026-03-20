"""
P6-05: Sink and Source Registry

Central registry for managing sink and source definitions
across all supported languages.
"""

import re
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.sinks_sources.models import (
    SinkCategory,
    SinkDefinition,
    SinkLibrary,
    SourceCategory,
    SourceDefinition,
    SourceLibrary,
)


class SinkRegistry:
    """
    Registry for sink definitions across all languages.

    Provides fast lookup by category, language, and pattern matching.
    """

    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self._libraries: dict[str, SinkLibrary] = {}
        self._pattern_cache: dict[str, re.Pattern] = {}

    def register(self, library: SinkLibrary) -> None:
        """Register a sink library for a language."""
        self._libraries[library.language] = library
        self._build_pattern_cache(library)
        self.logger.debug(
            f"Registered {len(library.sinks)} sinks for {library.language}"
        )

    def get_library(self, language: str) -> SinkLibrary | None:
        """Get the sink library for a language."""
        return self._libraries.get(language)

    def get_sinks_by_category(
        self,
        category: SinkCategory,
        language: str | None = None,
    ) -> list[SinkDefinition]:
        """Get all sinks of a specific category, optionally filtered by language."""
        sinks = []
        if language:
            lib = self._libraries.get(language)
            if lib:
                sinks = lib.get_by_category(category)
        else:
            for lib in self._libraries.values():
                sinks.extend(lib.get_by_category(category))
        return sinks

    def match_function(
        self,
        function_call: str,
        language: str,
    ) -> list[SinkDefinition]:
        """
        Match a function call against sink patterns.

        Args:
            function_call: The function call string to match
            language: Programming language

        Returns:
            List of matching sink definitions
        """
        matches = []
        lib = self._libraries.get(language)
        if not lib:
            return matches

        for sink in lib.sinks:
            for pattern in sink.function_patterns:
                cache_key = f"{language}:{pattern}"
                if cache_key not in self._pattern_cache:
                    try:
                        self._pattern_cache[cache_key] = re.compile(pattern, re.IGNORECASE)
                    except re.error:
                        self.logger.warning(f"Invalid regex pattern: {pattern}")
                        continue

                if self._pattern_cache[cache_key].search(function_call):
                    matches.append(sink)
                    break

        return matches

    def get_all_patterns(self, language: str) -> list[str]:
        """Get all sink patterns for a language."""
        lib = self._libraries.get(language)
        return lib.get_patterns() if lib else []

    def _build_pattern_cache(self, library: SinkLibrary) -> None:
        """Pre-compile regex patterns for faster matching."""
        for sink in library.sinks:
            for pattern in sink.function_patterns:
                cache_key = f"{library.language}:{pattern}"
                if cache_key not in self._pattern_cache:
                    try:
                        self._pattern_cache[cache_key] = re.compile(pattern, re.IGNORECASE)
                    except re.error:
                        self.logger.warning(f"Invalid regex pattern: {pattern}")

    def get_statistics(self) -> dict[str, Any]:
        """Get registry statistics."""
        stats = {
            "languages": list(self._libraries.keys()),
            "total_sinks": sum(len(lib.sinks) for lib in self._libraries.values()),
            "by_category": {},
            "by_language": {},
        }

        for category in SinkCategory:
            stats["by_category"][category.value] = len(
                self.get_sinks_by_category(category)
            )

        for language, lib in self._libraries.items():
            stats["by_language"][language] = len(lib.sinks)

        return stats


class SourceRegistry:
    """
    Registry for source definitions across all languages.

    Provides fast lookup by category, language, and pattern matching.
    """

    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self._libraries: dict[str, SourceLibrary] = {}
        self._pattern_cache: dict[str, re.Pattern] = {}

    def register(self, library: SourceLibrary) -> None:
        """Register a source library for a language."""
        self._libraries[library.language] = library
        self._build_pattern_cache(library)
        self.logger.debug(
            f"Registered {len(library.sources)} sources for {library.language}"
        )

    def get_library(self, language: str) -> SourceLibrary | None:
        """Get the source library for a language."""
        return self._libraries.get(language)

    def get_sources_by_category(
        self,
        category: SourceCategory,
        language: str | None = None,
    ) -> list[SourceDefinition]:
        """Get all sources of a specific category, optionally filtered by language."""
        sources = []
        if language:
            lib = self._libraries.get(language)
            if lib:
                sources = lib.get_by_category(category)
        else:
            for lib in self._libraries.values():
                sources.extend(lib.get_by_category(category))
        return sources

    def match_function(
        self,
        function_call: str,
        language: str,
    ) -> list[SourceDefinition]:
        """
        Match a function call against source patterns.

        Args:
            function_call: The function call string to match
            language: Programming language

        Returns:
            List of matching source definitions
        """
        matches = []
        lib = self._libraries.get(language)
        if not lib:
            return matches

        for source in lib.sources:
            for pattern in source.function_patterns:
                cache_key = f"{language}:{pattern}"
                if cache_key not in self._pattern_cache:
                    try:
                        self._pattern_cache[cache_key] = re.compile(pattern, re.IGNORECASE)
                    except re.error:
                        self.logger.warning(f"Invalid regex pattern: {pattern}")
                        continue

                if self._pattern_cache[cache_key].search(function_call):
                    matches.append(source)
                    break

        return matches

    def match_annotation(
        self,
        annotation: str,
        language: str,
    ) -> list[SourceDefinition]:
        """
        Match an annotation against source annotation patterns.

        Args:
            annotation: The annotation string to match
            language: Programming language

        Returns:
            List of matching source definitions
        """
        matches = []
        lib = self._libraries.get(language)
        if not lib:
            return matches

        for source in lib.sources:
            for pattern in source.annotation_patterns:
                cache_key = f"{language}:ann:{pattern}"
                if cache_key not in self._pattern_cache:
                    try:
                        self._pattern_cache[cache_key] = re.compile(pattern, re.IGNORECASE)
                    except re.error:
                        continue

                if self._pattern_cache[cache_key].search(annotation):
                    matches.append(source)
                    break

        return matches

    def match_variable(
        self,
        variable: str,
        language: str,
    ) -> list[SourceDefinition]:
        """
        Match a variable name against source variable patterns.

        Args:
            variable: The variable name to match
            language: Programming language

        Returns:
            List of matching source definitions
        """
        matches = []
        lib = self._libraries.get(language)
        if not lib:
            return matches

        for source in lib.sources:
            for pattern in source.variable_patterns:
                cache_key = f"{language}:var:{pattern}"
                if cache_key not in self._pattern_cache:
                    try:
                        self._pattern_cache[cache_key] = re.compile(pattern, re.IGNORECASE)
                    except re.error:
                        continue

                if self._pattern_cache[cache_key].search(variable):
                    matches.append(source)
                    break

        return matches

    def get_all_patterns(self, language: str) -> list[str]:
        """Get all source patterns for a language."""
        lib = self._libraries.get(language)
        return lib.get_patterns() if lib else []

    def _build_pattern_cache(self, library: SourceLibrary) -> None:
        """Pre-compile regex patterns for faster matching."""
        for source in library.sources:
            for pattern in source.function_patterns + source.annotation_patterns + source.variable_patterns:
                cache_key = f"{library.language}:{pattern}"
                if cache_key not in self._pattern_cache:
                    try:
                        self._pattern_cache[cache_key] = re.compile(pattern, re.IGNORECASE)
                    except re.error:
                        self.logger.warning(f"Invalid regex pattern: {pattern}")

    def get_statistics(self) -> dict[str, Any]:
        """Get registry statistics."""
        stats = {
            "languages": list(self._libraries.keys()),
            "total_sources": sum(len(lib.sources) for lib in self._libraries.values()),
            "by_category": {},
            "by_language": {},
        }

        for category in SourceCategory:
            stats["by_category"][category.value] = len(
                self.get_sources_by_category(category)
            )

        for language, lib in self._libraries.items():
            stats["by_language"][language] = len(lib.sources)

        return stats


# Global registry instances
_sink_registry: SinkRegistry | None = None
_source_registry: SourceRegistry | None = None


def get_sink_registry() -> SinkRegistry:
    """Get the global sink registry, initializing if needed."""
    global _sink_registry
    if _sink_registry is None:
        _sink_registry = SinkRegistry()
        _load_default_sinks()
    return _sink_registry


def get_source_registry() -> SourceRegistry:
    """Get the global source registry, initializing if needed."""
    global _source_registry
    if _source_registry is None:
        _source_registry = SourceRegistry()
        _load_default_sources()
    return _source_registry


def _load_default_sinks() -> None:
    """Load default sink libraries."""
    from src.layers.l3_analysis.sinks_sources import java, python, go, php, javascript

    if _sink_registry:
        _sink_registry.register(java.get_sink_library())
        _sink_registry.register(python.get_sink_library())
        _sink_registry.register(go.get_sink_library())
        _sink_registry.register(php.get_sink_library())
        _sink_registry.register(javascript.get_sink_library())


def _load_default_sources() -> None:
    """Load default source libraries."""
    from src.layers.l3_analysis.sinks_sources import java, python, go, php, javascript

    if _source_registry:
        _source_registry.register(java.get_source_library())
        _source_registry.register(python.get_source_library())
        _source_registry.register(go.get_source_library())
        _source_registry.register(php.get_source_library())
        _source_registry.register(javascript.get_source_library())


__all__ = [
    "SinkRegistry",
    "SourceRegistry",
    "get_sink_registry",
    "get_source_registry",
]
