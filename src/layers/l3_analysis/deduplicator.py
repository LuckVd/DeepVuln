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

# P6-17: Cluster-based deduplication
from pydantic import BaseModel


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


# =============================================================================
# P6-17: Cluster-Based Deduplication (Location + LLM)
# =============================================================================

@dataclass
class LocationCluster:
    """
    A cluster of findings at the same or nearby file location.

    Findings in the same cluster may be duplicates that need LLM judgment.
    """
    file_path: str
    """Normalized file path."""

    start_line: int
    """Start line of the cluster (minimum line number)."""

    end_line: int
    """End line of the cluster (maximum line number)."""

    findings: list[Any] = field(default_factory=list)
    """Findings in this cluster."""


class ClusterDeduplicatorConfig(BaseModel):
    """
    Configuration for cluster-based deduplication.

    P6-17: Two-stage hybrid deduplication using location clustering + LLM judgment.
    """
    line_tolerance: int = 10
    """Line number tolerance for clustering (default: 10 lines)."""

    enable_llm_dedup: bool = True
    """Whether to enable LLM-based deduplication (default: True)."""

    llm_timeout: int = 180
    """LLM timeout in seconds (default: 180, GLM-5 reasoning models can take 60+ seconds)."""

    max_cluster_size: int = 10
    """Maximum findings per cluster before splitting (default: 10)."""

    class Config:
        arbitrary_types_allowed = True


def cluster_findings_by_location(
    findings: list[Any],
    config: ClusterDeduplicatorConfig | None = None,
) -> list[LocationCluster]:
    """
    Cluster findings by file location and line number range.

    P6-17a: Location-based clustering as the first stage of hybrid deduplication.

    Algorithm:
    1. Group findings by file_path
    2. Within each file, sort by line_number
    3. Create clusters where line number difference <= line_tolerance

    Args:
        findings: List of Finding objects to cluster.
        config: Configuration for clustering behavior.

    Returns:
        List of LocationCluster objects.

    Example:
        >>> findings = [
        ...     Finding(location=Location(file="foo.java", line=10)),
        ...     Finding(location=Location(file="foo.java", line=15)),
        ...     Finding(location=Location(file="bar.java", line=100)),
        ... ]
        >>> clusters = cluster_findings_by_location(findings)
        >>> # Cluster 1: foo.java:10-15 (tolerance=10)
        >>> # Cluster 2: bar.java:100 (single finding)
    """
    config = config or ClusterDeduplicatorConfig()
    logger = get_logger(__name__)

    if not findings:
        return []

    logger.info(f"Clustering {len(findings)} findings by location")

    # Step 1: Group by file path
    from collections import defaultdict
    by_file: dict[str, list[Any]] = defaultdict(list)

    for finding in findings:
        if not hasattr(finding, "location") or finding.location is None:
            logger.debug("Finding without location, skipping")
            continue

        file_path = normalize_file_path(finding.location.file)
        by_file[file_path].append(finding)

    # Step 2 & 3: Create clusters within each file
    all_clusters: list[LocationCluster] = []

    for file_path, file_findings in by_file.items():
        # Sort by line number
        file_findings.sort(
            key=lambda f: getattr(f.location, "line", 0) if f.location else 0
        )

        # Create clusters
        current_cluster: LocationCluster | None = None

        for finding in file_findings:
            line = getattr(finding.location, "line", 0)

            if current_cluster is None:
                # Start first cluster
                current_cluster = LocationCluster(
                    file_path=file_path,
                    start_line=line,
                    end_line=line,
                    findings=[finding],
                )
            elif line - current_cluster.end_line <= config.line_tolerance:
                # Extend current cluster
                current_cluster.findings.append(finding)
                current_cluster.end_line = line
            else:
                # Start new cluster
                all_clusters.append(current_cluster)
                current_cluster = LocationCluster(
                    file_path=file_path,
                    start_line=line,
                    end_line=line,
                    findings=[finding],
                )

        # Add last cluster
        if current_cluster:
            all_clusters.append(current_cluster)

    # Log clustering statistics
    multi_clusters = [c for c in all_clusters if len(c.findings) > 1]
    logger.info(
        f"Created {len(all_clusters)} clusters: "
        f"{len(multi_clusters)} with multiple findings, "
        f"{len(all_clusters) - len(multi_clusters)} with single finding"
    )

    return all_clusters


@dataclass
class LLMClusterResult:
    """
    Result of LLM-based deduplication on a single cluster.
    """
    keep: list[Any]
    """Findings to keep (not duplicates)."""

    removed: list[Any]
    """Findings removed as duplicates."""

    reasoning: str
    """LLM's reasoning for the decision."""

    confidence: float = 0.8
    """Confidence in this decision (0-1)."""


class ClusterBasedDeduplicator:
    """
    Two-stage hybrid deduplicator using location clustering + LLM judgment.

    P6-17: Replaces ASTDeduplicator to solve cross-engine deduplication failure.

    Stage 1: Location clustering (rule-based)
        Groups findings by file_path + line_range

    Stage 2: LLM judgment (AI-based)
        For each cluster with >1 finding, LLM determines which are duplicates

    Stage 3: Preservation strategy
        - Duplicates: Keep the one with highest final_score
        - Non-duplicates: Keep all
    """

    def __init__(
        self,
        llm_client: Any = None,
        config: ClusterDeduplicatorConfig | None = None,
    ):
        """
        Initialize the cluster-based deduplicator.

        Args:
            llm_client: LLM client for judgment (optional, for testing).
            config: Configuration for deduplication behavior.
        """
        self.config = config or ClusterDeduplicatorConfig()
        self.llm_client = llm_client
        self.logger = get_logger(__name__)

    def deduplicate(self, findings: list[Any]) -> DeduplicationResult:
        """
        Execute cluster-based deduplication on findings.

        This is the main entry point compatible with ASTDeduplicator interface.

        Args:
            findings: List of Finding objects to deduplicate.

        Returns:
            DeduplicationResult with unique findings and statistics.
        """
        if not findings:
            return DeduplicationResult(unique_findings=[], removed_count=0, merged_groups=0)

        self.logger.info(
            f"Starting cluster-based deduplication of {len(findings)} findings"
        )

        # Stage 1: Cluster by location
        clusters = cluster_findings_by_location(findings, self.config)

        # Stage 2 & 3: Process each cluster
        unique_findings: list[Any] = []
        removed_count = 0
        merged_groups = 0
        merge_details: list[dict[str, Any]] = []

        for cluster in clusters:
            if len(cluster.findings) == 1:
                # Single finding - keep as is
                unique_findings.append(cluster.findings[0])
            elif not self.config.enable_llm_dedup:
                # LLM disabled - keep all in cluster
                unique_findings.extend(cluster.findings)
                self.logger.debug(
                    f"LLM dedup disabled, keeping {len(cluster.findings)} findings "
                    f"in cluster {cluster.file_path}:{cluster.start_line}-{cluster.end_line}"
                )
            else:
                # Use LLM to deduplicate this cluster
                result = self._deduplicate_cluster(cluster)
                unique_findings.extend(result.keep)
                removed_count += len(result.removed)
                if result.removed:
                    merged_groups += 1
                    merge_details.append({
                        "cluster": f"{cluster.file_path}:{cluster.start_line}-{cluster.end_line}",
                        "kept": len(result.keep),
                        "removed": len(result.removed),
                        "reasoning": result.reasoning,
                    })

        self.logger.info(
            f"Cluster deduplication complete: {len(findings)} -> {len(unique_findings)} findings, "
            f"{removed_count} removed, {merged_groups} clusters merged"
        )

        return DeduplicationResult(
            unique_findings=unique_findings,
            removed_count=removed_count,
            merged_groups=merged_groups,
            merge_details=merge_details,
        )

    def _deduplicate_cluster(self, cluster: LocationCluster) -> LLMClusterResult:
        """
        Deduplicate findings within a single cluster using LLM judgment.

        Args:
            cluster: LocationCluster with findings to deduplicate.

        Returns:
            LLMClusterResult with keep/remove lists.
        """
        if self.llm_client is None:
            # No LLM available - keep all
            self.logger.warning("No LLM client available, keeping all findings in cluster")
            return LLMClusterResult(
                keep=cluster.findings,
                removed=[],
                reasoning="No LLM client available",
                confidence=0.0,
            )

        try:
            # Build prompt for LLM
            prompt = self._build_dedup_prompt(cluster)

            # Call LLM (handle async method)
            import asyncio
            import sys
            from src.layers.l3_analysis.llm.client import LLMError

            try:
                response = asyncio.run(self.llm_client.complete(
                    prompt=prompt,
                    max_tokens=3000,
                    timeout=self.config.llm_timeout,
                ))
            except RuntimeError as e:
                # We're in an async context - use subprocess to avoid event loop conflict
                if "asyncio.run()" in str(e) or "running event loop" in str(e):
                    self.logger.warning("In async context, using subprocess for LLM call")
                    import subprocess
                    import tempfile
                    import os
                    import base64

                    # Encode the prompt as base64 to avoid escaping issues
                    prompt_b64 = base64.b64encode(prompt.encode()).decode()

                    # Create a temporary script to run the LLM call
                    script = f'''
import asyncio
import sys
import base64
sys.path.insert(0, "{os.path.abspath("/opt/projects/DeepVuln")}")

from src.core.config import load_config, get_llm_model, get_openai_config
from src.layers.l3_analysis.llm.openai_client import OpenAIClient

config = load_config()
model = get_llm_model()
openai_config = get_openai_config()

llm_client = OpenAIClient(
    model=model,
    api_key=openai_config.get("api_key"),
    base_url=openai_config.get("base_url"),
    max_tokens=3000,
    temperature=0.1,
    timeout={self.config.llm_timeout},
)

# Decode prompt
prompt_bytes = base64.b64decode("{prompt_b64}")
prompt_str = prompt_bytes.decode()

async def call_llm():
    response = await llm_client.complete(
        prompt=prompt_str,
        timeout={self.config.llm_timeout},
    )
    return response.content

result = asyncio.run(call_llm())
print(result)
'''

                    # Write to temp file and run
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                        f.write(script)
                        script_path = f.name

                    try:
                        result = subprocess.run(
                            [sys.executable, script_path],
                            capture_output=True,
                            text=True,
                            timeout=self.config.llm_timeout + 30,  # Extra buffer for subprocess overhead
                        )

                        if result.returncode != 0:
                            self.logger.error(f"Subprocess stderr: {result.stderr}")
                            raise LLMError(f"Subprocess LLM call failed: {result.stderr}")

                        # Create a mock response object
                        class MockResponse:
                            def __init__(self, content):
                                self.content = content

                        response = MockResponse(result.stdout)
                    finally:
                        # Clean up temp file
                        try:
                            os.unlink(script_path)
                        except:
                            pass
                else:
                    raise

            # Parse response (use content, not text)
            result = self._parse_llm_response(cluster.findings, response.content)

            # Log LLM response for debugging
            self.logger.info(f"LLM dedup response: {result.reasoning}")

            return result

        except Exception as e:
            self.logger.error(f"LLM deduplication failed: {e}")
            # On failure, keep all findings
            return LLMClusterResult(
                keep=cluster.findings,
                removed=[],
                reasoning=f"LLM failed: {e}",
                confidence=0.0,
            )

    def _build_dedup_prompt(self, cluster: LocationCluster) -> str:
        """
        Build a prompt for LLM to judge duplicates within a cluster.

        Args:
            cluster: LocationCluster with findings to judge.

        Returns:
            Prompt string for LLM.
        """
        findings_list = []

        for i, finding in enumerate(cluster.findings):
            # Extract key information
            engine = getattr(finding, "source", "unknown")
            rule_id = getattr(finding, "rule_id", "unknown")
            title = getattr(finding, "title", "No title")
            description = getattr(finding, "description", "")[:200]

            # Get code snippet
            snippet = ""
            if hasattr(finding, "location") and finding.location:
                snippet = getattr(finding.location, "snippet", "") or ""
                if len(snippet) > 100:
                    snippet = snippet[:100] + "..."

            findings_list.append(f"""
【检测结果 {i + 1}】
- 引擎: {engine}
- 规则: {rule_id}
- 描述: {title}: {description}
- 位置: {cluster.file_path}:{getattr(finding.location, 'line', '?') if finding.location else '?'}
- 代码: {snippet if snippet else '(无代码片段)'}
""")

        prompt = f"""你是一个安全专家，需要判断以下漏洞检测结果是否指向同一个**根本安全缺陷**。

【核心原则】关注**漏洞本质**，**参考**代码位置差异
- 即使两个检测由不同规则触发，只要它们源于**同一处未验证的用户输入**，很可能是重复
- 代码行差异是**参考因素**，不是决定性因素

这些检测结果位于同一个文件的相近位置（行号范围 {cluster.start_line}-{cluster.end_line}）。

{''.join(findings_list)}

问题：这些检测结果中，哪些是同一根本缺陷的不同检测，哪些是不同的安全缺陷？

【判断标准 - 按优先级排序】

1. 【根本原因】是否源于同一处未验证的输入？
   - 例如：两个检测都指向同一个用户参数 `ip`，这就是同一缺陷

2. 【攻击路径】数据流起点是否相同？
   - 例如：都是 `用户输入` → `字符串拼接` → `命令执行`，这就是同一缺陷

3. 【影响范围】是否影响同一个端点/函数？
   - 例如：都影响 `/ping` 接口，很可能是同一缺陷

4. 【代码位置】作为参考因素
   - 同一行或相邻行（差距<5行）：很可能是同一缺陷的不同检测面
   - 相隔较远（差距>10行）：需要仔细分析是否是不同缺陷
   - 代码位置**不能单独决定**是否合并，需要结合上述标准

【不要被以下表面差异迷惑】

- ❌ 不同的规则 ID（rule_id）- 规则只是检测方式，不是漏洞本身
- ❌ 不同的描述文字（description）- 描述角度不同不代表漏洞不同

【示例分析】

示例 1 - 应该合并（同一缺陷的不同检测）：
- 检测 A：第 37 行，规则 "java.lang.string-format-command"，"用户输入拼接到命令字符串"
- 检测 B：第 41 行，规则 "java.lang.process-injection"，"ProcessBuilder 执行用户命令"
- 判断：✅ 合并！都源于同一处未验证的 `ip` 参数，代码行相邻（4行差）

示例 2 - 不应该合并（不同的安全缺陷）：
- 检测 A：`ping` 接口的 `ip` 参数未验证
- 检测 B：`info` 接口的 `lang` 参数未验证
- 判断：❌ 不合并！两个不同的参数，两个不同的端点

示例 3 - 需要仔细分析（代码行相隔较远）：
- 检测 A：第 10 行，`password` 参数未验证
- 检测 B：第 85 行，使用同一个 `password` 参数进行数据库操作
- 判断：✅ 合并！代码行相隔较远，但都源于同一处未验证的 `password` 参数

回答格式（JSON）：
{{
  "analysis": "简要分析根本原因、数据流、影响范围和代码位置",
  "groups": [
    {{"indices": [0, 1], "reason": "同一缺陷：都是 /ping 接口的 ip 参数未验证，代码行相邻（37行和41行）"}}
  ]
}}

注意：
- 优先判断"根本原因"，代码位置作为参考因素
- 同一组的 indices 表示是同一根本缺陷的不同检测（应该合并）
- 不同组的 indices 表示是不同的根本缺陷（不应该合并）
"""

        return prompt

    def _parse_llm_response(
        self,
        findings: list[Any],
        response: str,
    ) -> LLMClusterResult:
        """
        Parse LLM response and determine which findings to keep.

        Args:
            findings: Original findings in the cluster.
            response: LLM response text.

        Returns:
            LLMClusterResult with keep/remove lists.
        """
        from src.core.utils.json_parser import robust_json_loads, JSONParseError
        import json
        import re

        try:
            # Log raw response for debugging
            self.logger.debug(f"Raw LLM response: {response[:500]}...")

            # Extract JSON from response
            response = response.strip()
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                response = response.split("```")[1].split("```")[0].strip()

            # P8-08h: Handle GLM-5 reasoning_content format
            # GLM-5 may return: {"reasoning_content": "...", "content": "{...}"}
            if "reasoning_content" in response and "content" in response:
                try:
                    # First parse the outer JSON
                    outer_data = json.loads(response)
                    if isinstance(outer_data, dict):
                        # Extract content field
                        if "content" in outer_data and isinstance(outer_data["content"], str):
                            content_str = outer_data["content"]
                            # Try to parse the inner JSON
                            try:
                                data = json.loads(content_str)
                            except json.JSONDecodeError:
                                # Content might be a JSON string with extra formatting
                                # Try to extract JSON from it
                                data = robust_json_loads(content_str)
                        else:
                            data = outer_data
                    else:
                        data = outer_data
                except json.JSONDecodeError:
                    # If outer parse fails, fall through to robust parsing
                    data = robust_json_loads(response)
            else:
                # Try to parse JSON with fault tolerance
                try:
                    data = robust_json_loads(response)
                except JSONParseError as e:
                    # P8-08h: Enhanced error handling for GLM-5
                    # Try one more extraction method for GLM-5 specific formats
                    # Sometimes GLM-5 adds reasoning before the JSON
                    if "groups" in response or "findings" in response:
                        # Extract the JSON object using regex
                        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response, re.DOTALL)
                        if json_match:
                            try:
                                data = json.loads(json_match.group(0))
                            except json.JSONDecodeError:
                                data = robust_json_loads(json_match.group(0))
                        else:
                            raise
                    else:
                        # Log the failed JSON for debugging
                        self.logger.error(f"Failed to parse LLM response: {e}")
                        self.logger.error(f"Response content: {response[:1000]}")
                        raise

            groups = data.get("groups", [])

            # Extract analysis if available
            analysis = data.get("analysis", "")

            # Build keep list (one from each group)
            keep: list[Any] = []
            removed: list[Any] = []
            reasons: list[str] = []

            for group in groups:
                indices = group.get("indices", [])
                if not indices:
                    continue

                reason = group.get("reason", "")
                reasons.append(reason)

                # Sort by final_score, keep the best one
                group_findings = [findings[i] for i in indices if i < len(findings)]

                if group_findings:
                    group_findings.sort(
                        key=lambda f: getattr(f, "final_score", 0) or 0,
                        reverse=True,
                    )

                    # Keep the best, remove the rest
                    keep.append(group_findings[0])
                    removed.extend(group_findings[1:])

                    # Update metadata on kept finding
                    if len(group_findings) > 1:
                        if not hasattr(keep[-1], "related_engines"):
                            keep[-1].related_engines = []
                        if not hasattr(keep[-1], "duplicate_count"):
                            keep[-1].duplicate_count = 1

                        # Initialize merged_findings to track all merged findings with their code snippets
                        if not hasattr(keep[-1], "merged_findings"):
                            keep[-1].merged_findings = []
                        if not hasattr(keep[-1], "metadata"):
                            keep[-1].metadata = {}

                        # Track all merged findings with their code snippets
                        for f in group_findings[1:]:
                            engine = getattr(f, "source", "unknown")
                            rule_id = getattr(f, "rule_id", "unknown")

                            # Record engine
                            if engine not in keep[-1].related_engines:
                                keep[-1].related_engines.append(engine)

                            # Record merged finding with code snippet
                            merged_info = {
                                "engine": engine,
                                "rule_id": rule_id,
                            }

                            # Add code snippet if available
                            if hasattr(f, "location") and f.location:
                                loc = f.location
                                if hasattr(loc, "snippet") and loc.snippet:
                                    merged_info["snippet"] = loc.snippet[:200]  # Limit snippet length
                                if hasattr(loc, "line"):
                                    merged_info["line"] = loc.line

                            keep[-1].merged_findings.append(merged_info)

                        keep[-1].duplicate_count = len(group_findings) - 1

            # Build reasoning string with analysis
            reasoning_parts = []
            if analysis:
                reasoning_parts.append(f"分析: {analysis}")
            if reasons:
                reasoning_parts.append(f"分组: {'; '.join(reasons)}")

            return LLMClusterResult(
                keep=keep,
                removed=removed,
                reasoning=" | ".join(reasoning_parts),
                confidence=0.8,
            )

        except Exception as e:
            self.logger.error(f"Failed to parse LLM response: {e}")
            # On parse failure, keep all findings
            return LLMClusterResult(
                keep=findings,
                removed=[],
                reasoning=f"Parse failed: {e}",
                confidence=0.0,
            )


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
    # P6-17: Cluster-based deduplication
    "LocationCluster",
    "LLMClusterResult",
    "ClusterDeduplicatorConfig",
    "ClusterBasedDeduplicator",
    "cluster_findings_by_location",
]
