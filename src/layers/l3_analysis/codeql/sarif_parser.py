"""
SARIF Parser - Enhanced parsing for CodeQL dataflow results.

This module provides advanced SARIF parsing capabilities specifically
designed to extract complete data flow paths from CodeQL analysis results.
"""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.models import CodeLocation

logger = get_logger(__name__)


@dataclass
class PathLocation:
    """A single location in a data flow path."""

    # Location details
    file_path: str
    line: int
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None

    # Code context
    snippet: str | None = None
    message: str | None = None

    # Node classification
    node_type: str = "propagation"  # source, sink, sanitizer, propagation
    variable_name: str | None = None
    expression: str | None = None
    function_name: str | None = None

    # Additional context
    step_number: int = 0

    def to_code_location(self) -> CodeLocation:
        """Convert to CodeLocation model."""
        return CodeLocation(
            file=self.file_path,
            line=self.line,
            column=self.column,
            end_line=self.end_line,
            end_column=self.end_column,
            snippet=self.snippet,
            function=self.function_name,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "snippet": self.snippet,
            "message": self.message,
            "node_type": self.node_type,
            "variable_name": self.variable_name,
            "expression": self.expression,
            "function_name": self.function_name,
            "step_number": self.step_number,
        }


@dataclass
class ParsedDataflowPath:
    """A complete parsed data flow path from source to sink."""

    # Path identification
    path_id: str
    rule_id: str
    rule_name: str

    # Path locations
    locations: list[PathLocation] = field(default_factory=list)

    # Source and sink (extracted from locations)
    source: PathLocation | None = None
    sink: PathLocation | None = None

    # Path metadata
    message: str = ""
    severity: str = "medium"

    # Completeness
    is_complete: bool = False
    has_sanitizer: bool = False
    sanitizer_locations: list[PathLocation] = field(default_factory=list)

    # Additional info
    cwe: str | None = None
    owasp: str | None = None
    tags: list[str] = field(default_factory=list)

    @property
    def path_length(self) -> int:
        """Get the number of locations in the path."""
        return len(self.locations)

    @property
    def is_direct(self) -> bool:
        """Check if this is a direct flow (source directly to sink)."""
        return len(self.locations) <= 2

    @property
    def is_interprocedural(self) -> bool:
        """Check if this path crosses function boundaries."""
        functions = set()
        for loc in self.locations:
            if loc.function_name:
                functions.add(loc.function_name)
        return len(functions) > 1

    def get_intermediate_nodes(self) -> list[PathLocation]:
        """Get intermediate nodes (excluding source and sink)."""
        if len(self.locations) <= 2:
            return []
        return self.locations[1:-1]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "path_id": self.path_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "locations": [loc.to_dict() for loc in self.locations],
            "source": self.source.to_dict() if self.source else None,
            "sink": self.sink.to_dict() if self.sink else None,
            "message": self.message,
            "severity": self.severity,
            "is_complete": self.is_complete,
            "has_sanitizer": self.has_sanitizer,
            "sanitizer_locations": [loc.to_dict() for loc in self.sanitizer_locations],
            "cwe": self.cwe,
            "owasp": self.owasp,
            "tags": self.tags,
            "path_length": self.path_length,
            "is_direct": self.is_direct,
            "is_interprocedural": self.is_interprocedural,
        }


class SARIFParser:
    """
    Enhanced SARIF parser for CodeQL dataflow results.

    Parses SARIF output from CodeQL analysis and extracts:
    - Complete data flow paths with all intermediate nodes
    - Source and sink locations
    - Sanitizer information
    - Rule metadata
    """

    def __init__(self, source_root: Path | None = None):
        """
        Initialize the SARIF parser.

        Args:
            source_root: Root directory of source code for path normalization.
        """
        self.source_root = source_root or Path.cwd()
        self._parsed_paths: list[ParsedDataflowPath] = []

    def parse(self, sarif_content: str | dict) -> list[ParsedDataflowPath]:
        """
        Parse SARIF content and extract data flow paths.

        Args:
            sarif_content: SARIF JSON content as string or dict.

        Returns:
            List of parsed data flow paths.
        """
        # Parse JSON if string
        if isinstance(sarif_content, str):
            try:
                sarif_data = json.loads(sarif_content)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse SARIF JSON: {e}")
                return []
        else:
            sarif_data = sarif_content

        self._parsed_paths = []

        # Process each run
        for run in sarif_data.get("runs", []):
            self._parse_run(run)

        logger.info(f"Parsed {len(self._parsed_paths)} data flow paths from SARIF")
        return self._parsed_paths

    def parse_file(self, sarif_file: Path) -> list[ParsedDataflowPath]:
        """
        Parse a SARIF file.

        Args:
            sarif_file: Path to the SARIF file.

        Returns:
            List of parsed data flow paths.
        """
        if not sarif_file.exists():
            logger.error(f"SARIF file not found: {sarif_file}")
            return []

        content = sarif_file.read_text(encoding="utf-8")
        return self.parse(content)

    def _parse_run(self, run: dict[str, Any]) -> None:
        """Parse a single run from SARIF."""
        tool = run.get("tool", {}).get("driver", {})
        tool_name = tool.get("name", "CodeQL")

        # Build rule lookup
        rules = {}
        for rule in tool.get("rules", []):
            rule_id = rule.get("id", "")
            rules[rule_id] = rule

        # Process results
        for result in run.get("results", []):
            path = self._parse_result(result, rules, tool_name)
            if path:
                self._parsed_paths.append(path)

    def _parse_result(
        self,
        result: dict[str, Any],
        rules: dict[str, Any],
        tool_name: str,
    ) -> ParsedDataflowPath | None:
        """Parse a single result and extract data flow path."""
        rule_id = result.get("ruleId", "unknown")
        rule = rules.get(rule_id, {})

        # Extract code flows
        code_flows = result.get("codeFlows", [])
        if not code_flows:
            # No data flow info, create simple path from locations
            return self._create_simple_path(result, rule)

        # Use first code flow
        code_flow = code_flows[0]
        thread_flows = code_flow.get("threadFlows", [])

        if not thread_flows:
            return self._create_simple_path(result, rule)

        # Parse thread flow
        thread_flow = thread_flows[0]
        locations = thread_flow.get("locations", [])

        if not locations:
            return self._create_simple_path(result, rule)

        # Build path from thread flow locations
        path_locations = []
        for i, loc_wrapper in enumerate(locations):
            loc = loc_wrapper.get("location", {})
            path_loc = self._parse_location(loc, i)
            if path_loc:
                path_locations.append(path_loc)

        if not path_locations:
            return None

        # Identify source and sink
        source = path_locations[0] if path_locations else None
        sink = path_locations[-1] if path_locations else None

        # Mark source and sink types
        if source:
            source.node_type = "source"
        if sink and len(path_locations) > 1:
            sink.node_type = "sink"

        # Extract rule metadata
        rule_name = rule.get("shortDescription", {}).get("text", rule_id)
        severity = self._map_severity(result.get("level", "warning"))

        # Extract CWE/OWASP
        cwe = self._extract_cwe(rule)
        owasp = self._extract_owasp(rule)
        tags = rule.get("properties", {}).get("tags", [])

        # Create path
        path = ParsedDataflowPath(
            path_id=f"path_{hash(str(result)) % 1000000:06d}",
            rule_id=rule_id,
            rule_name=rule_name,
            locations=path_locations,
            source=source,
            sink=sink,
            message=result.get("message", {}).get("text", ""),
            severity=severity,
            is_complete=len(path_locations) >= 2,
            cwe=cwe,
            owasp=owasp,
            tags=tags,
        )

        return path

    def _parse_location(
        self,
        location: dict[str, Any],
        step_number: int,
    ) -> PathLocation | None:
        """Parse a single location from SARIF."""
        physical_location = location.get("physicalLocation", {})
        artifact = physical_location.get("artifactLocation", {})
        region = physical_location.get("region", {})

        file_path = artifact.get("uri", "")
        if not file_path:
            return None

        # Normalize path
        file_path = self._normalize_path(file_path)

        line = region.get("startLine", 1)
        column = region.get("startColumn")
        end_line = region.get("endLine")
        end_column = region.get("endColumn")

        # Extract snippet
        snippet = None
        snippet_region = region.get("snippet", {})
        if isinstance(snippet_region, dict):
            snippet = snippet_region.get("text")
        elif isinstance(snippet_region, str):
            snippet = snippet_region

        # Extract message
        message = location.get("message", {}).get("text", "")

        # Extract context from message (variable, expression, function)
        variable_name = self._extract_variable(message)
        expression = self._extract_expression(message)
        function_name = self._extract_function(message)

        return PathLocation(
            file_path=file_path,
            line=line,
            column=column,
            end_line=end_line,
            end_column=end_column,
            snippet=snippet,
            message=message,
            step_number=step_number,
            variable_name=variable_name,
            expression=expression,
            function_name=function_name,
        )

    def _normalize_path(self, file_path: str) -> str:
        """Normalize file path relative to source root."""
        # Remove leading slashes
        if file_path.startswith("/"):
            try:
                return str(Path(file_path).relative_to(self.source_root))
            except ValueError:
                pass

        # Remove file:// prefix
        if file_path.startswith("file://"):
            file_path = file_path[7:]

        return file_path

    def _create_simple_path(
        self,
        result: dict[str, Any],
        rule: dict[str, Any],
    ) -> ParsedDataflowPath | None:
        """Create a simple path from result locations (no codeFlows)."""
        locations = result.get("locations", [])
        if not locations:
            return None

        path_locations = []
        for i, loc_wrapper in enumerate(locations):
            loc = loc_wrapper.get("physicalLocation", {})
            path_loc = self._parse_location({"physicalLocation": loc}, i)
            if path_loc:
                path_locations.append(path_loc)

        if not path_locations:
            return None

        rule_id = result.get("ruleId", "unknown")
        rule_name = rule.get("shortDescription", {}).get("text", rule_id)

        source = path_locations[0] if path_locations else None
        sink = path_locations[-1] if len(path_locations) > 1 else None

        if source:
            source.node_type = "source"
        if sink:
            sink.node_type = "sink"

        return ParsedDataflowPath(
            path_id=f"path_{hash(str(result)) % 1000000:06d}",
            rule_id=rule_id,
            rule_name=rule_name,
            locations=path_locations,
            source=source,
            sink=sink,
            message=result.get("message", {}).get("text", ""),
            severity=self._map_severity(result.get("level", "warning")),
            is_complete=False,  # Simple paths are incomplete
        )

    def _map_severity(self, level: str) -> str:
        """Map SARIF level to severity."""
        level_map = {
            "error": "high",
            "warning": "medium",
            "note": "low",
            "none": "info",
            "recommendation": "info",
        }
        return level_map.get(level.lower(), "medium")

    def _extract_cwe(self, rule: dict[str, Any]) -> str | None:
        """Extract CWE from rule metadata."""
        # Check properties
        props = rule.get("properties", {})
        if "cwe" in props:
            return props["cwe"]
        if "CWE" in props:
            return props["CWE"]

        # Check tags
        tags = props.get("tags", [])
        for tag in tags:
            if tag.lower().startswith("cwe-"):
                return tag.upper()
            if tag.lower().startswith("cwe/"):
                return "CWE-" + tag.split("/")[-1]

        # Check rule ID
        rule_id = rule.get("id", "")
        if "cwe" in rule_id.lower():
            import re
            match = re.search(r"cwe[:/-]?(\d+)", rule_id, re.IGNORECASE)
            if match:
                return f"CWE-{match.group(1)}"

        return None

    def _extract_owasp(self, rule: dict[str, Any]) -> str | None:
        """Extract OWASP category from rule metadata."""
        props = rule.get("properties", {})
        tags = props.get("tags", [])

        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("owasp"):
                return tag.upper()

        return None

    def _extract_variable(self, message: str) -> str | None:
        """Extract variable name from message."""
        if not message:
            return None

        import re
        # Look for patterns like "variable x" or "value of x"
        match = re.search(r"variable\s+[`'\"]?(\w+)[`'\"]?", message, re.IGNORECASE)
        if match:
            return match.group(1)

        match = re.search(r"value\s+of\s+[`'\"]?(\w+)[`'\"]?", message, re.IGNORECASE)
        if match:
            return match.group(1)

        return None

    def _extract_expression(self, message: str) -> str | None:
        """Extract expression from message."""
        if not message:
            return None

        import re
        # Look for code snippets in backticks
        match = re.search(r"`([^`]+)`", message)
        if match:
            return match.group(1)

        return None

    def _extract_function(self, message: str) -> str | None:
        """Extract function name from message."""
        if not message:
            return None

        import re
        # Look for function call patterns
        match = re.search(r"function\s+[`'\"]?(\w+)[`'\"]?", message, re.IGNORECASE)
        if match:
            return match.group(1)

        match = re.search(r"call\s+to\s+[`'\"]?(\w+)[`'\"]?", message, re.IGNORECASE)
        if match:
            return match.group(1)

        # Look for method patterns like "Class.method"
        match = re.search(r"(\w+(?:\.\w+)*)\s*\(", message)
        if match:
            return match.group(1)

        return None

    def get_statistics(self) -> dict[str, Any]:
        """Get statistics about parsed paths."""
        if not self._parsed_paths:
            return {
                "total_paths": 0,
                "complete_paths": 0,
                "incomplete_paths": 0,
                "paths_with_sanitizers": 0,
                "avg_path_length": 0,
            }

        complete = sum(1 for p in self._parsed_paths if p.is_complete)
        with_sanitizers = sum(1 for p in self._parsed_paths if p.has_sanitizer)
        avg_length = sum(p.path_length for p in self._parsed_paths) / len(self._parsed_paths)

        return {
            "total_paths": len(self._parsed_paths),
            "complete_paths": complete,
            "incomplete_paths": len(self._parsed_paths) - complete,
            "paths_with_sanitizers": with_sanitizers,
            "avg_path_length": round(avg_length, 2),
            "interprocedural_paths": sum(1 for p in self._parsed_paths if p.is_interprocedural),
            "direct_flows": sum(1 for p in self._parsed_paths if p.is_direct),
        }
