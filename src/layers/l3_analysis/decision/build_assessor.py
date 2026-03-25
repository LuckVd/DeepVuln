"""
Build difficulty assessor for CodeQL language decision.

Assesses the build difficulty for each language to help the LLM decisioner
make informed choices about which languages to prioritize for CodeQL scanning.
"""

from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

from .models import BuildDifficulty, BuildDifficultyLevel, LanguageStructure

logger = get_logger(__name__)


# Estimated CodeQL database creation times (seconds) per 10K LOC
# These are rough estimates based on empirical data
ESTIMATED_TIME_PER_10K_LOC: dict[str, int] = {
    "python": 30,       # No build required
    "javascript": 40,   # No build required
    "typescript": 50,   # May need compilation
    "java": 120,        # Maven/Gradle build
    "go": 90,           # Go build
    "csharp": 100,      # dotnet build
    "cpp": 300,         # Complex build systems
    "ruby": 45,         # No build required
    "swift": 150,       # Xcode build
    "kotlin": 130,      # Gradle build
    "scala": 140,       # SBT/Gradle build
}

# Build configuration files by language
BUILD_CONFIG_FILES: dict[str, list[str]] = {
    "python": ["setup.py", "pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock"],
    "javascript": ["package.json", "yarn.lock", "pnpm-lock.yaml"],
    "typescript": ["tsconfig.json", "package.json"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"],
    "go": ["go.mod", "go.sum"],
    "csharp": [".csproj", ".sln", "project.json"],
    "cpp": ["CMakeLists.txt", "Makefile", "configure", "BUILD", "MESON.build", "compile_commands.json"],
    "ruby": ["Gemfile", "gemspec"],
    "swift": ["Package.swift", "*.xcodeproj", "*.xcworkspace"],
    "kotlin": ["build.gradle", "build.gradle.kts"],
    "scala": ["build.sbt", "build.sc"],
}


class BuildDifficultyAssessor:
    """
    Assesses build difficulty for CodeQL database creation.

    Provides difficulty estimates and blocker identification for each language
    to inform the LLM decision process.
    """

    def __init__(self, project_path: Path):
        """
        Initialize the assessor.

        Args:
            project_path: Root path of the project to analyze.
        """
        self.project_path = project_path
        self._cache: dict[str, BuildDifficulty] = {}

    def assess(self, language: LanguageStructure) -> BuildDifficulty:
        """
        Assess build difficulty for a language.

        Args:
            language: Language structure information.

        Returns:
            BuildDifficulty assessment.
        """
        lang_name = language.name.lower()

        # Check cache
        if lang_name in self._cache:
            return self._cache[lang_name]

        # Get base difficulty level
        level = self._get_difficulty_level(lang_name)

        # Find build configurations
        build_signals = self._find_build_signals(lang_name)
        has_build_config = len(build_signals) > 0

        # Identify blockers
        blockers = self._identify_blockers(lang_name, build_signals)

        # Estimate time
        estimated_time = self._estimate_time(lang_name, language.line_count)

        difficulty = BuildDifficulty(
            level=level,
            estimated_time_seconds=estimated_time,
            has_build_config=has_build_config,
            blockers=blockers,
            build_signals=build_signals,
        )

        self._cache[lang_name] = difficulty
        return difficulty

    def assess_all(self, languages: list[LanguageStructure]) -> dict[str, BuildDifficulty]:
        """
        Assess build difficulty for all languages.

        Args:
            languages: List of language structures.

        Returns:
            Dictionary mapping language name to BuildDifficulty.
        """
        return {lang.name.lower(): self.assess(lang) for lang in languages}

    def _get_difficulty_level(self, language: str) -> BuildDifficultyLevel:
        """Get base difficulty level for a language."""
        easy_languages = {"python", "javascript", "typescript", "ruby"}
        medium_languages = {"java", "go", "csharp", "kotlin", "scala", "swift"}
        hard_languages = {"cpp", "c"}

        if language in easy_languages:
            return BuildDifficultyLevel.EASY
        elif language in medium_languages:
            return BuildDifficultyLevel.MEDIUM
        elif language in hard_languages:
            return BuildDifficultyLevel.HARD
        else:
            return BuildDifficultyLevel.UNKNOWN

    def _find_build_signals(self, language: str) -> list[str]:
        """Find build configuration files for a language."""
        signals = []
        config_patterns = BUILD_CONFIG_FILES.get(language, [])

        for pattern in config_patterns:
            if pattern.startswith("*"):
                # Glob pattern
                matches = list(self.project_path.rglob(pattern))
                if matches:
                    signals.append(pattern)
            else:
                # Exact file name
                found = list(self.project_path.rglob(pattern))
                if found:
                    signals.extend([str(f.relative_to(self.project_path)) for f in found[:3]])

        return signals[:5]  # Limit to 5 signals

    def _identify_blockers(self, language: str, build_signals: list[str]) -> list[str]:
        """Identify potential blockers for CodeQL database creation."""
        blockers = []

        # C/C++ specific blockers
        if language in {"cpp", "c"}:
            if not any("compile_commands.json" in s for s in build_signals):
                if not any("CMakeLists.txt" in s for s in build_signals):
                    blockers.append("No standard build system detected (CMake/compile_commands.json)")
                else:
                    blockers.append("Requires CMake configuration for proper extraction")

        # Java specific blockers
        if language == "java":
            if not build_signals:
                blockers.append("No build configuration found (pom.xml/build.gradle)")

        # Go specific blockers
        if language == "go":
            if not any("go.mod" in s for s in build_signals):
                blockers.append("No go.mod found - may have dependency resolution issues")

        return blockers

    def _estimate_time(self, language: str, loc: int) -> int:
        """
        Estimate CodeQL database creation time.

        Args:
            language: Language name.
            loc: Lines of code.

        Returns:
            Estimated time in seconds.
        """
        base_time_per_10k = ESTIMATED_TIME_PER_10K_LOC.get(language, 100)

        # Calculate based on LOC
        loc_units = max(1, loc / 10000)
        estimated = int(base_time_per_10k * loc_units)

        # Apply difficulty multiplier
        level = self._get_difficulty_level(language)
        if level == BuildDifficultyLevel.HARD:
            estimated = int(estimated * 1.5)  # 50% more time for hard languages
        elif level == BuildDifficultyLevel.MEDIUM:
            estimated = int(estimated * 1.2)  # 20% more time for medium languages

        # Minimum 60 seconds, maximum 30 minutes
        return max(60, min(1800, estimated))

    def get_summary(self, languages: list[LanguageStructure]) -> dict[str, Any]:
        """
        Get a summary of build difficulties for all languages.

        Args:
            languages: List of language structures.

        Returns:
            Summary dictionary with difficulty distribution.
        """
        difficulties = self.assess_all(languages)

        summary = {
            "total_languages": len(languages),
            "by_difficulty": {
                "easy": 0,
                "medium": 0,
                "hard": 0,
                "unknown": 0,
            },
            "total_estimated_time": 0,
            "languages_with_blockers": [],
        }

        for lang_name, diff in difficulties.items():
            summary["by_difficulty"][diff.level.value] += 1
            summary["total_estimated_time"] += diff.estimated_time_seconds
            if diff.blockers:
                summary["languages_with_blockers"].append(lang_name)

        return summary
