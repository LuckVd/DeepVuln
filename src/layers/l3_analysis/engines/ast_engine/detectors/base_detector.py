"""Base Detector - Abstract base class for AST-based vulnerability detectors."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import src.layers.l3_analysis.engines.ast_engine.detectors as detectors_module
from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.ast_engine.queries.query_engine import QueryEngine
from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    SeverityLevel,
)


def _get_rules_base_dir() -> Path:
    """Get the absolute path to the rules directory.

    This resolves relative paths from the project root (where 'src' is located),
    ensuring rules can be found regardless of the current working directory.
    """
    # Get the directory containing this module
    detectors_dir = Path(detectors_module.__file__).parent
    # Navigate from: .../src/layers/l3_analysis/engines/ast_engine/detectors
    # to: .../rules/ast_query
    # Go up: detectors -> ast_engine -> engines -> l3_analysis -> layers -> src -> project_root
    src_dir = detectors_dir.parent.parent.parent.parent.parent.parent
    return src_dir / "rules" / "ast_query"


class BaseDetector(ABC):
    """
    Base class for AST-based vulnerability detectors.

    Provides:
    - YAML rule loading from rules/ast_query/ directory
    - Query execution via QueryEngine
    - Finding generation with proper metadata
    - _post_validate hook for custom validation logic
    """

    def __init__(self, rules_dir: Path | None = None) -> None:
        """Initialize the detector.

        Args:
            rules_dir: Optional path to rules directory. Defaults to _get_default_rules_dir().
        """
        self._rules_dir = rules_dir or self._get_default_rules_dir()
        self._query_engine = QueryEngine()
        self._rules: dict[str, dict[str, Any]] = {}
        self.logger = get_logger(__name__)
        self._load_rules()

    @abstractmethod
    def detector_type(self) -> str:
        """Return detector type identifier (e.g., 'dangerous_api')."""
        pass

    @abstractmethod
    def _get_default_rules_dir(self) -> Path:
        """Return default rules directory for this detector."""
        pass

    async def detect(
        self,
        code: str,
        language: str,
        file_path: str,
    ) -> list[Finding]:
        """
        Run detection and return findings.

        Args:
            code: Source code to analyze.
            language: Programming language.
            file_path: Path to the source file.

        Returns:
            List of findings.
        """
        findings = await self._execute_queries(code, language, file_path)
        return await self._post_validate(findings, code, language, file_path)

    async def _post_validate(
        self,
        findings: list[Finding],
        code: str,
        language: str,
        file_path: str,
    ) -> list[Finding]:
        """
        Hook for custom validation logic.

        Override in subclasses to add:
        - Constant literal detection
        - Test code filtering
        - Context-aware validation

        Default: Returns findings unchanged.
        """
        return findings

    async def _execute_queries(
        self,
        code: str,
        language: str,
        file_path: str,
    ) -> list[Finding]:
        """Execute all loaded rules and generate findings."""
        findings = []

        for rule_id, rule in self._rules.items():
            if language not in rule.get("languages", []):
                continue

            query = rule.get("queries", {}).get(language)
            if not query:
                continue

            results = self._query_engine.execute_query(query, code, language)

            for result in results:
                finding = self._create_finding(
                    rule=rule,
                    query_result=result,
                    file_path=file_path,
                )
                if finding:
                    findings.append(finding)

        return findings

    def _create_finding(
        self,
        rule: dict[str, Any],
        query_result: dict[str, Any],
        file_path: str,
    ) -> Finding | None:
        """Create a Finding from rule and query result."""
        try:
            rule_id = rule.get("id", "unknown")
            severity_str = rule.get("severity", "medium")

            # Map severity string to enum
            severity_map = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
                "info": SeverityLevel.INFO,
            }
            severity = severity_map.get(severity_str.lower(), SeverityLevel.MEDIUM)

            location = CodeLocation(
                file=file_path,
                line=query_result.get("line", 1),
                column=query_result.get("column", 0),
                snippet=query_result.get("text", ""),
            )

            finding = Finding(
                id=f"ast-{rule_id}-{query_result.get('line', 0)}",
                rule_id=rule_id,
                type=FindingType.VULNERABILITY,
                severity=severity,
                confidence=0.8,
                title=rule.get("title", f"{rule_id} detected"),
                description=rule.get("description", ""),
                location=location,
                source="ast_engine",
                metadata={
                    "detector": self.detector_type(),
                    "capture": query_result.get("capture", ""),
                    "node_type": query_result.get("type", ""),
                },
            )

            # Add optional fields
            if "cwe" in rule:
                finding.cwe = rule["cwe"]
            if "category" in rule:
                finding.tags.append(rule["category"])

            return finding

        except Exception as e:
            self.logger.warning(f"Failed to create finding: {e}")
            return None

    def _load_rules(self) -> None:
        """Load YAML rules from rules directory."""
        rules = self._query_engine.load_yaml_rules_from_dir(self._rules_dir)
        for rule in rules:
            rule_id = rule.get("id")
            if rule_id:
                self._rules[rule_id] = rule
                self.logger.debug(f"Loaded rule: {rule_id}")

        self.logger.info(f"{self.detector_type()}: Loaded {len(self._rules)} rules")
