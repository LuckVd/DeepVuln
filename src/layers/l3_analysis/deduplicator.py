"""
AST-Based Semantic Deduplication Module

This module implements semantic-level deduplication based on vulnerability
essence, call chains, sinks, data flow, and AST structure - NOT based on
line numbers, text content, or rule IDs.

Core Principle: Semantic Equivalence over Textual Similarity

Deduplication is based on:
- rule_id (vulnerability category)
- normalized sink (the target of the vulnerability)
- normalized source (the origin of tainted data, if available)
- function name (context of the vulnerability)
- data flow path (the route data takes)
- vulnerability category (CWE, OWASP, etc.)

NOT based on:
- Line numbers
- Raw message text
- Absolute file paths (relative paths are used)

P4-04: Semantic-Level Deduplication
- Cross-engine deduplication (Semgrep + CodeQL + Agent)
- Merge findings with same semantic hash
- Preserve highest priority finding
- Track related engines and duplicate count
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from src.core.logger.logger import get_logger


@dataclass
class DeduplicationResult:
    """
    Result of semantic deduplication.

    Contains the unique findings after deduplication and statistics
    about what was merged.
    """

    unique_findings: list[Any]
    """List of unique findings after deduplication."""

    removed_count: int = 0
    """Number of duplicate findings removed."""

    merged_groups: int = 0
    """Number of groups that were merged."""

    merge_details: list[dict[str, Any]] = field(default_factory=list)
    """Details about each merge operation."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for metadata storage."""
        return {
            "removed": self.removed_count,
            "groups": self.merged_groups,
            "unique_count": len(self.unique_findings),
            "merge_details": self.merge_details[:10],  # Limit details
        }


def normalize_code_element(element: str | None) -> str:
    """
    Normalize a code element for semantic comparison.

    This removes irrelevant differences like:
    - Whitespace variations
    - Variable name differences (anonymized)
    - Quote style differences
    - Path separators

    Args:
        element: Code element to normalize.

    Returns:
        Normalized element string.
    """
    if not element:
        return ""

    # Convert to string if needed
    text = str(element)

    # Strip whitespace
    text = text.strip()

    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text)

    # Normalize quotes
    text = text.replace('"', "'")

    # Normalize path separators
    text = text.replace('\\', '/')

    # Anonymize variable names in common patterns
    # e.g., $VAR, ${VAR}, {{VAR}} -> $X
    text = re.sub(r'\$\{?[a-zA-Z_][a-zA-Z0-9_]*\}?', '$X', text)
    text = re.sub(r'\{\{[a-zA-Z_][a-zA-Z0-9_]*\}\}', '{{X}}', text)

    # Anonymize string literals
    text = re.sub(r"'[^']*'", "'X'", text)
    text = re.sub(r'"[^"]*"', '"X"', text)

    return text.lower()


def normalize_function_name(name: str | None) -> str:
    """
    Normalize a function name for comparison.

    Args:
        name: Function name to normalize.

    Returns:
        Normalized function name.
    """
    if not name:
        return ""

    text = str(name).strip().lower()

    # Remove common prefixes
    prefixes_to_remove = ['self.', 'this.', 'cls.']
    for prefix in prefixes_to_remove:
        if text.startswith(prefix):
            text = text[len(prefix):]
            break

    return text


def normalize_file_path(path: str | None) -> str:
    """
    Normalize a file path for comparison.

    Uses relative path only, normalizes separators.

    Args:
        path: File path to normalize.

    Returns:
        Normalized file path.
    """
    if not path:
        return ""

    text = str(path).strip()

    # Normalize separators
    text = text.replace('\\', '/')

    # Remove leading ./ or /
    while text.startswith('./') or text.startswith('/'):
        text = text[1:] if text.startswith('/') else text[2:]

    return text.lower()


def extract_sink(finding: Any) -> str | None:
    """
    Extract the sink from a finding.

    The sink is the dangerous function or operation that could be exploited.

    Args:
        finding: Finding object.

    Returns:
        Sink string or None.
    """
    # Check metadata for sink
    if hasattr(finding, "metadata") and isinstance(finding.metadata, dict):
        # Try common keys
        sink = finding.metadata.get("sink")
        if sink:
            return str(sink)

        sink = finding.metadata.get("taint_sink")
        if sink:
            return str(sink)

        sink = finding.metadata.get("dangerous_function")
        if sink:
            return str(sink)

        # CodeQL specific
        sink = finding.metadata.get("codeql", {}).get("sink")
        if sink:
            return str(sink)

    # Use function name from location as fallback
    if hasattr(finding, "location"):
        loc = finding.location
        if hasattr(loc, "function") and loc.function:
            return loc.function

    return None


def extract_source(finding: Any) -> str | None:
    """
    Extract the source from a finding.

    The source is where tainted data originates.

    Args:
        finding: Finding object.

    Returns:
        Source string or None.
    """
    if hasattr(finding, "metadata") and isinstance(finding.metadata, dict):
        # Try common keys
        source = finding.metadata.get("source")
        if source:
            return str(source)

        source = finding.metadata.get("taint_source")
        if source:
            return str(source)

        # CodeQL specific
        source = finding.metadata.get("codeql", {}).get("source")
        if source:
            return str(source)

    return None


def extract_data_flow_path(finding: Any) -> str | None:
    """
    Extract the data flow path from a finding.

    Args:
        finding: Finding object.

    Returns:
        Data flow path string or None.
    """
    if hasattr(finding, "metadata") and isinstance(finding.metadata, dict):
        # Try common keys
        path = finding.metadata.get("data_flow_path")
        if path:
            return str(path)

        path = finding.metadata.get("taint_path")
        if path:
            return str(path)

        # CodeQL specific
        path = finding.metadata.get("codeql", {}).get("dataflow_path")
        if path:
            return str(path)

    return None


def extract_category(finding: Any) -> str:
    """
    Extract vulnerability category from a finding.

    Args:
        finding: Finding object.

    Returns:
        Category string (CWE, OWASP, or rule_id).
    """
    # Prefer CWE
    if hasattr(finding, "cwe") and finding.cwe:
        return f"cwe:{finding.cwe}"

    # Then OWASP
    if hasattr(finding, "owasp") and finding.owasp:
        return f"owasp:{finding.owasp}"

    # Then rule_id
    if hasattr(finding, "rule_id") and finding.rule_id:
        return f"rule:{finding.rule_id}"

    return "unknown"


def generate_ast_hash(finding: Any) -> str:
    """
    Generate a semantic hash for a finding based on AST-level attributes.

    This hash is used to identify semantically equivalent findings across
    different engines (Semgrep, CodeQL, Agent).

    Formula: hash(rule_id + normalized_sink + normalized_source +
                  normalized_function + category + file_path)

    NOT included:
    - Line numbers
    - Raw message text
    - Absolute paths

    Args:
        finding: Finding object.

    Returns:
        Semantic hash string (16 hex chars).
    """
    # Extract components
    rule_id = getattr(finding, "rule_id", None) or "unknown"

    # Get file path (relative)
    file_path = ""
    if hasattr(finding, "location"):
        loc = finding.location
        if hasattr(loc, "file"):
            file_path = normalize_file_path(loc.file)

    # Get function name
    function = ""
    if hasattr(finding, "location"):
        loc = finding.location
        if hasattr(loc, "function") and loc.function:
            function = normalize_function_name(loc.function)

    # Get sink
    sink = normalize_code_element(extract_sink(finding))

    # Get source
    source = normalize_code_element(extract_source(finding))

    # Get category
    category = extract_category(finding)

    # Get data flow path (optional)
    data_flow = normalize_code_element(extract_data_flow_path(finding))

    # Combine components
    # Note: We include file_path for same-file deduplication but not line numbers
    combined = f"{rule_id}|{file_path}|{function}|{sink}|{source}|{category}|{data_flow}"

    # Generate hash
    hash_value = hashlib.sha256(combined.encode()).hexdigest()[:16]

    return f"ast_{hash_value}"


def get_exploitability_level(exploitability: str | None) -> int:
    """
    Get numeric level for exploitability.

    Higher is more severe.

    Args:
        exploitability: Exploitability string.

    Returns:
        Numeric level (0-4).
    """
    if not exploitability:
        return 0

    normalized = str(exploitability).lower().strip()

    levels = {
        "not_exploitable": 0,
        "safe": 0,
        "unlikely": 1,
        "possible": 2,
        "likely": 3,
        "exploitable": 4,
        "confirmed": 4,
    }

    return levels.get(normalized, 2)


def get_engine_weight(source: str | None) -> float:
    """
    Get weight for an analysis engine.

    Higher weight = more reliable.

    Args:
        source: Engine source name.

    Returns:
        Engine weight (0.0-1.0).
    """
    if not source:
        return 0.5

    weights = {
        "agent": 1.0,  # Most thorough analysis
        "codeql": 0.9,  # Deep dataflow analysis
        "semgrep": 0.8,  # Pattern matching
    }

    return weights.get(str(source).lower(), 0.5)


def compare_findings_for_merge(a: Any, b: Any) -> int:
    """
    Compare two findings to determine which should be kept.

    Priority order:
    1. Higher final_score
    2. Higher engine_weight
    3. Higher exploitability

    Args:
        a: First finding.
        b: Second finding.

    Returns:
        Positive if a should be kept, negative if b should be kept.
    """
    score = 0.0

    # Compare final_score (highest priority)
    score_a = getattr(a, "final_score", None) or 0.0
    score_b = getattr(b, "final_score", None) or 0.0
    if score_a != score_b:
        return score_a - score_b

    # Compare engine_weight
    weight_a = get_engine_weight(getattr(a, "source", None))
    weight_b = get_engine_weight(getattr(b, "source", None))
    if weight_a != weight_b:
        return weight_a - weight_b

    # Compare exploitability
    exp_a = get_exploitability_level(getattr(a, "exploitability", None))
    exp_b = get_exploitability_level(getattr(b, "exploitability", None))
    if exp_a != exp_b:
        return exp_a - exp_b

    # Compare severity
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    sev_a = severity_order.get(str(getattr(a, "severity", "medium")).lower(), 2)
    sev_b = severity_order.get(str(getattr(b, "severity", "medium")).lower(), 2)
    if sev_a != sev_b:
        return sev_a - sev_b

    return 0


def merge_findings(primary: Any, secondary: Any) -> Any:
    """
    Merge secondary finding into primary finding.

    The primary finding is kept, but we record:
    - Both engines in related_engines
    - Increment duplicate_count

    Args:
        primary: The finding to keep.
        secondary: The finding being merged.

    Returns:
        The primary finding with merged metadata.
    """
    # Initialize related_engines if not present or empty
    if not hasattr(primary, "related_engines") or primary.related_engines is None:
        primary.related_engines = []  # type: ignore

    # Add primary's source if not already there
    primary_source = getattr(primary, "source", "unknown")
    if primary_source not in primary.related_engines:  # type: ignore
        primary.related_engines.append(primary_source)  # type: ignore

    # Add secondary engine
    secondary_source = getattr(secondary, "source", "unknown")
    if secondary_source not in primary.related_engines:  # type: ignore
        primary.related_engines.append(secondary_source)  # type: ignore

    # Initialize duplicate_count if not present
    if not hasattr(primary, "duplicate_count") or primary.duplicate_count is None:
        primary.duplicate_count = 1  # type: ignore
    else:
        primary.duplicate_count += 1  # type: ignore

    # Merge metadata (preserve additional context)
    if hasattr(secondary, "metadata") and isinstance(secondary.metadata, dict):
        if not hasattr(primary, "metadata") or primary.metadata is None:
            primary.metadata = {}  # type: ignore

        for key, value in secondary.metadata.items():
            # Don't overwrite existing keys
            if key not in primary.metadata:  # type: ignore
                primary.metadata[key] = value  # type: ignore

    return primary


class ASTDeduplicator:
    """
    Semantic-level deduplicator based on AST structure.

    Deduplicates findings from multiple engines (Semgrep, CodeQL, Agent)
    based on semantic equivalence rather than textual similarity.

    Key features:
    - Cross-engine deduplication
    - Preserves highest priority finding
    - Tracks related engines
    - Records duplicate count
    - No silent drops - all merges are tracked
    """

    def __init__(self, strict: bool = False):
        """
        Initialize the deduplicator.

        Args:
            strict: If True, raise exceptions on merge conflicts.
                   If False, log warnings and continue.
        """
        self.strict = strict
        self.logger = get_logger(__name__)

    def deduplicate(self, findings: list[Any]) -> DeduplicationResult:
        """
        Execute semantic deduplication on findings.

        This is the main entry point for deduplication.

        Args:
            findings: List of Finding objects to deduplicate.

        Returns:
            DeduplicationResult with unique findings and statistics.
        """
        if not findings:
            return DeduplicationResult(unique_findings=[], removed_count=0, merged_groups=0)

        self.logger.info(f"Starting semantic deduplication of {len(findings)} findings")

        # Group findings by AST hash
        hash_groups: dict[str, list[Any]] = {}
        for finding in findings:
            ast_hash = generate_ast_hash(finding)

            # Also set the ast_hash on the finding for reference
            if hasattr(finding, "metadata") and isinstance(finding.metadata, dict):
                finding.metadata["ast_hash"] = ast_hash

            if ast_hash not in hash_groups:
                hash_groups[ast_hash] = []
            hash_groups[ast_hash].append(finding)

        # Process each group
        unique_findings: list[Any] = []
        removed_count = 0
        merged_groups = 0
        merge_details = []

        for ast_hash, group in hash_groups.items():
            if len(group) == 1:
                # No duplicates for this hash
                unique_findings.append(group[0])
                continue

            # Sort group to find the best finding
            # Sort in descending order (best first)
            sorted_group = sorted(
                group,
                key=lambda f: (
                    getattr(f, "final_score", 0) or 0,
                    get_engine_weight(getattr(f, "source", None)),
                    get_exploitability_level(getattr(f, "exploitability", None)),
                ),
                reverse=True,
            )

            # Keep the best finding
            primary = sorted_group[0]

            # Merge others into primary
            for secondary in sorted_group[1:]:
                primary = merge_findings(primary, secondary)
                removed_count += 1

            unique_findings.append(primary)
            merged_groups += 1

            # Record merge details
            merge_details.append({
                "ast_hash": ast_hash,
                "kept_id": getattr(primary, "id", "unknown"),
                "kept_source": getattr(primary, "source", "unknown"),
                "merged_sources": [getattr(f, "source", "unknown") for f in sorted_group[1:]],
                "group_size": len(group),
            })

            self.logger.debug(
                f"Merged {len(group) - 1} duplicates into {getattr(primary, 'id', 'unknown')} "
                f"(sources: {[getattr(f, 'source', 'unknown') for f in group]})"
            )

        result = DeduplicationResult(
            unique_findings=unique_findings,
            removed_count=removed_count,
            merged_groups=merged_groups,
            merge_details=merge_details,
        )

        self.logger.info(
            f"Deduplication complete: {len(findings)} -> {len(unique_findings)} findings, "
            f"{removed_count} removed, {merged_groups} groups merged"
        )

        return result

    def get_duplicates(self, findings: list[Any]) -> dict[str, list[Any]]:
        """
        Find all duplicate groups without merging.

        Useful for analysis and reporting.

        Args:
            findings: List of Finding objects.

        Returns:
            Dictionary mapping AST hash to list of duplicate findings.
        """
        hash_groups: dict[str, list[Any]] = {}

        for finding in findings:
            ast_hash = generate_ast_hash(finding)
            if ast_hash not in hash_groups:
                hash_groups[ast_hash] = []
            hash_groups[ast_hash].append(finding)

        # Only return groups with duplicates
        return {h: g for h, g in hash_groups.items() if len(g) > 1}


def deduplicate_findings(
    findings: list[Any],
    strict: bool = False,
) -> DeduplicationResult:
    """
    Convenience function to deduplicate findings.

    Args:
        findings: List of Finding objects to deduplicate.
        strict: If True, raise exceptions on merge conflicts.

    Returns:
        DeduplicationResult with unique findings and statistics.
    """
    deduplicator = ASTDeduplicator(strict=strict)
    return deduplicator.deduplicate(findings)


# Module exports
__all__ = [
    "DeduplicationResult",
    "normalize_code_element",
    "normalize_function_name",
    "normalize_file_path",
    "generate_ast_hash",
    "extract_sink",
    "extract_source",
    "extract_data_flow_path",
    "extract_category",
    "get_exploitability_level",
    "get_engine_weight",
    "compare_findings_for_merge",
    "merge_findings",
    "ASTDeduplicator",
    "deduplicate_findings",
]
