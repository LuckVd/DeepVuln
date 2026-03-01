"""LLM-assisted build diagnostics.

This module provides functionality to analyze build failures
using LLM and provide actionable suggestions.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.build.detector import BuildConfig
from src.layers.l3_analysis.build.executor import BuildResult

logger = get_logger(__name__)


@dataclass
class BuildDiagnostic:
    """Result of build failure diagnosis.

    Attributes:
        error_type: Category of the build error.
        root_cause: Identified root cause of the failure.
        suggestions: List of actionable suggestions.
        fixed_command: Suggested fixed build command (if applicable).
        confidence: Confidence level of the diagnosis (0-1).
        llm_analysis: Raw LLM analysis (if used).
    """

    error_type: str
    root_cause: str
    suggestions: list[str] = field(default_factory=list)
    fixed_command: str | None = None
    confidence: float = 0.0
    llm_analysis: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            "error_type": self.error_type,
            "root_cause": self.root_cause,
            "suggestions": self.suggestions,
            "fixed_command": self.fixed_command,
            "confidence": self.confidence,
        }


# Common error patterns for build diagnosis
ERROR_PATTERNS = {
    # Go errors
    "go: cannot find module": {
        "error_type": "missing_dependency",
        "root_cause": "Go module dependency not found",
        "suggestions": [
            "Run 'go mod download' to download dependencies",
            "Check if the module name is correct in go.mod",
            "Try 'go mod tidy' to clean up dependencies",
        ],
    },
    "cannot find package": {
        "error_type": "missing_package",
        "root_cause": "Required Go package not found",
        "suggestions": [
            "Run 'go mod download' to download all dependencies",
            "Check if GOPROXY is set correctly",
            "Verify the import path is correct",
        ],
    },
    "build constraints exclude all Go files": {
        "error_type": "build_constraints",
        "root_cause": "Build tags/constraints exclude all source files",
        "suggestions": [
            "Check for build tags in source files",
            "Specify correct build tags in the build command",
            "Use 'go build -tags <tag>' if needed",
        ],
    },
    "undefined:": {
        "error_type": "undefined_reference",
        "root_cause": "Undefined symbol reference",
        "suggestions": [
            "Check if all required packages are imported",
            "Verify function/variable names are correct",
            "Run 'go mod tidy' to ensure dependencies",
        ],
    },
    # Maven errors
    "Could not resolve dependencies": {
        "error_type": "maven_dependency",
        "root_cause": "Maven cannot resolve project dependencies",
        "suggestions": [
            "Run 'mvn dependency:resolve' to resolve dependencies",
            "Check if pom.xml has correct repository URLs",
            "Verify network connectivity to Maven Central",
        ],
    },
    "Failed to execute goal": {
        "error_type": "maven_goal_failed",
        "root_cause": "Maven goal execution failed",
        "suggestions": [
            "Check the specific goal that failed",
            "Run 'mvn clean install' for a fresh build",
            "Check Maven logs for detailed error",
        ],
    },
    # Gradle errors
    "Could not resolve all dependencies": {
        "error_type": "gradle_dependency",
        "root_cause": "Gradle cannot resolve dependencies",
        "suggestions": [
            "Run './gradlew dependencies' to list dependencies",
            "Check build.gradle for correct repositories",
            "Verify network connectivity",
        ],
    },
    "Execution failed for task": {
        "error_type": "gradle_task_failed",
        "root_cause": "Gradle task execution failed",
        "suggestions": [
            "Run './gradlew build --stacktrace' for detailed error",
            "Check the specific task that failed",
            "Verify project structure is correct",
        ],
    },
    # npm/yarn errors
    "npm ERR!": {
        "error_type": "npm_error",
        "root_cause": "npm command failed",
        "suggestions": [
            "Delete node_modules and package-lock.json",
            "Run 'npm install' again",
            "Check npm logs for details",
        ],
    },
    "yarn error": {
        "error_type": "yarn_error",
        "root_cause": "Yarn command failed",
        "suggestions": [
            "Delete node_modules and yarn.lock",
            "Run 'yarn install' again",
            "Check yarn logs for details",
        ],
    },
    # General errors
    "permission denied": {
        "error_type": "permission_denied",
        "root_cause": "Permission denied error",
        "suggestions": [
            "Check file/directory permissions",
            "Try running with appropriate permissions",
            "Check if files are locked by another process",
        ],
    },
    "out of memory": {
        "error_type": "out_of_memory",
        "root_cause": "Build ran out of memory",
        "suggestions": [
            "Increase available memory for build",
            "For Java: set MAVEN_OPTS='-Xmx2g' or GRADLE_OPTS='-Xmx2g'",
            "For Go: check CGO_ENABLED setting",
        ],
    },
    "command not found": {
        "error_type": "command_not_found",
        "root_cause": "Required command/tool not found",
        "suggestions": [
            "Install the required build tool",
            "Check if the tool is in PATH",
            "Verify the tool version is compatible",
        ],
    },
    "no such file or directory": {
        "error_type": "file_not_found",
        "root_cause": "Required file not found",
        "suggestions": [
            "Check if the file path is correct",
            "Verify project structure",
            "Run from the correct directory",
        ],
    },
}


class BuildDiagnostician:
    """Diagnoses build failures using pattern matching and LLM.

    This class provides:
    - Pattern-based error diagnosis
    - LLM-assisted analysis for complex errors
    - Actionable suggestions for fixing build issues
    """

    def __init__(self, llm_client=None):
        """Initialize the build diagnostician.

        Args:
            llm_client: Optional LLM client for advanced diagnosis.
        """
        self.llm_client = llm_client

    def diagnose(
        self,
        result: BuildResult,
        config: BuildConfig,
        source_path: Path,
    ) -> BuildDiagnostic:
        """Diagnose a build failure.

        Args:
            result: Build result containing error details.
            config: Build configuration used.
            source_path: Path to the source code.

        Returns:
            BuildDiagnostic with diagnosis and suggestions.
        """
        if result.success:
            return BuildDiagnostic(
                error_type="none",
                root_cause="Build succeeded",
                confidence=1.0,
            )

        # Combine stdout and stderr for analysis
        output = f"{result.stdout}\n{result.stderr}".lower()

        # Try pattern matching first
        for pattern, diagnosis in ERROR_PATTERNS.items():
            if pattern.lower() in output:
                diagnostic = BuildDiagnostic(
                    error_type=diagnosis["error_type"],
                    root_cause=diagnosis["root_cause"],
                    suggestions=diagnosis["suggestions"],
                    confidence=0.8,
                )

                # Try to get LLM analysis for more specific suggestions
                if self.llm_client:
                    llm_diagnostic = self._llm_diagnose(result, config, source_path)
                    if llm_diagnostic:
                        diagnostic.llm_analysis = llm_diagnostic.llm_analysis
                        if llm_diagnostic.fixed_command:
                            diagnostic.fixed_command = llm_diagnostic.fixed_command
                        diagnostic.suggestions.extend(llm_diagnostic.suggestions)

                logger.info(
                    f"Build diagnosis: {diagnostic.error_type} - {diagnostic.root_cause}"
                )
                return diagnostic

        # No pattern matched, try LLM diagnosis
        if self.llm_client:
            return self._llm_diagnose(result, config, source_path)

        # Fallback diagnosis
        return BuildDiagnostic(
            error_type="unknown",
            root_cause="Unknown build error",
            suggestions=[
                "Check the build output for specific errors",
                "Try running the build command manually",
                "Check project documentation for build requirements",
            ],
            confidence=0.3,
        )

    def _llm_diagnose(
        self,
        result: BuildResult,
        config: BuildConfig,
        source_path: Path,
    ) -> BuildDiagnostic | None:
        """Use LLM to diagnose build failure.

        Args:
            result: Build result containing error details.
            config: Build configuration used.
            source_path: Path to the source code.

        Returns:
            BuildDiagnostic with LLM analysis, or None if LLM unavailable.
        """
        if not self.llm_client:
            return None

        try:
            import asyncio

            async def _diagnose():
                prompt = self._build_diagnosis_prompt(result, config, source_path)
                response = await self.llm_client.complete(prompt)
                return self._parse_llm_response(response.content)

            return asyncio.run(_diagnose())

        except Exception as e:
            logger.warning(f"LLM diagnosis failed: {e}")
            return None

    def _build_diagnosis_prompt(
        self,
        result: BuildResult,
        config: BuildConfig,
        source_path: Path,
    ) -> str:
        """Build the prompt for LLM diagnosis."""
        return f"""Analyze this build failure and provide diagnosis and suggestions.

Project Information:
- Language: {config.language}
- Build System: {config.build_system.value}
- Build Command: {result.command}
- Working Directory: {source_path}

Build Output (stdout):
```
{result.stdout[:2000] if result.stdout else "None"}
```

Build Output (stderr):
```
{result.stderr[:2000] if result.stderr else "None"}
```

Return a JSON response with:
{{
    "error_type": "category of error (e.g., dependency_missing, syntax_error, configuration_error)",
    "root_cause": "brief explanation of the root cause",
    "suggestions": ["list of actionable suggestions"],
    "fixed_command": "suggested fix for the build command (if applicable, otherwise null)"
}}
"""

    def _parse_llm_response(self, response: str) -> BuildDiagnostic:
        """Parse LLM response into BuildDiagnostic."""
        from src.core.utils import robust_json_loads

        try:
            data = robust_json_loads(response)
            return BuildDiagnostic(
                error_type=data.get("error_type", "unknown"),
                root_cause=data.get("root_cause", "Unknown error"),
                suggestions=data.get("suggestions", []),
                fixed_command=data.get("fixed_command"),
                confidence=0.7,
                llm_analysis=response,
            )
        except Exception:
            # Fallback if JSON parsing fails
            return BuildDiagnostic(
                error_type="llm_analysis",
                root_cause="LLM provided analysis",
                suggestions=[response[:500]] if response else [],
                confidence=0.5,
                llm_analysis=response,
            )


def diagnose_build_failure(
    result: BuildResult,
    config: BuildConfig,
    source_path: Path,
    llm_client=None,
) -> BuildDiagnostic:
    """Convenience function to diagnose a build failure.

    Args:
        result: Build result containing error details.
        config: Build configuration used.
        source_path: Path to the source code.
        llm_client: Optional LLM client for advanced diagnosis.

    Returns:
        BuildDiagnostic with diagnosis and suggestions.
    """
    diagnostician = BuildDiagnostician(llm_client=llm_client)
    return diagnostician.diagnose(result, config, source_path)
