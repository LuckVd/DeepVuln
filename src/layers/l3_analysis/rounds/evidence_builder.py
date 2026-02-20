"""
Evidence Chain Builder

Constructs and manages evidence chains for vulnerability candidates.
Extracts evidence from multiple sources and aggregates them into coherent chains.

This module provides a reusable builder that can be used independently
or integrated into the multi-round audit system.
"""

import uuid
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, Field

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.models import CodeLocation, Finding
from src.layers.l3_analysis.rounds.correlation import (
    Evidence,
    EvidenceChain,
    EvidenceSource,
    EvidenceType,
    VerificationStatus,
)
from src.layers.l3_analysis.rounds.dataflow import DataFlowPath, DeepAnalysisResult
from src.layers.l3_analysis.rounds.models import ConfidenceLevel, VulnerabilityCandidate


class ExportFormat(str, Enum):
    """Supported export formats for evidence chains."""

    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"


class ExploitStep(BaseModel):
    """
    A single step in an exploit scenario.

    Describes one action in a potential attack chain.
    """

    # Step info
    step_number: int = Field(..., description="Step number in the chain")
    action: str = Field(..., description="What the attacker does")
    location: CodeLocation | None = Field(default=None, description="Code location")

    # Technical details
    variable: str | None = Field(default=None, description="Variable involved")
    function: str | None = Field(default=None, description="Function involved")
    payload_example: str | None = Field(default=None, description="Example payload")

    # Impact
    impact: str | None = Field(default=None, description="Impact of this step")
    notes: str | None = Field(default=None, description="Additional notes")


class ExploitScenario(BaseModel):
    """
    A complete exploit scenario for a vulnerability.

    Describes how an attacker could potentially exploit the vulnerability,
    including the attack steps and required conditions.
    """

    # Identity
    id: str = Field(..., description="Unique scenario identifier")
    name: str = Field(..., description="Scenario name")

    # Attack details
    attack_vector: str = Field(
        default="network",
        description="How the attack is initiated",
    )
    steps: list[ExploitStep] = Field(
        default_factory=list,
        description="Steps in the exploit chain",
    )

    # Prerequisites
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Conditions required for exploitation",
    )

    # Impact assessment
    impact_description: str | None = Field(default=None, description="Impact description")
    cvss_vector: str | None = Field(default=None, description="CVSS vector if available")
    cwe_ids: list[str] = Field(default_factory=list, description="Related CWE IDs")
    cve_ids: list[str] = Field(default_factory=list, description="Related CVE IDs")

    # Confidence
    feasibility: str = Field(
        default="possible",
        description="Exploitation feasibility (trivial/easy/possible/difficult/unlikely)",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in this scenario",
    )

    # Metadata
    source: str = Field(
        default="agent",
        description="Source of this scenario (agent/manual/correlation)",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When scenario was created",
    )

    def add_step(
        self,
        action: str,
        location: CodeLocation | None = None,
        **kwargs: Any,
    ) -> ExploitStep:
        """Add a step to the exploit scenario."""
        step = ExploitStep(
            step_number=len(self.steps) + 1,
            action=action,
            location=location,
            **kwargs,
        )
        self.steps.append(step)
        return step

    def to_summary(self) -> str:
        """Get a one-line summary."""
        return f"{self.name}: {len(self.steps)} steps, {self.feasibility} feasibility"


class EvidenceChainConfig(BaseModel):
    """Configuration for evidence chain builder."""

    # Source weights
    semgrep_weight: float = Field(default=0.6, ge=0.0, le=1.0)
    codeql_weight: float = Field(default=0.8, ge=0.0, le=1.0)
    agent_weight: float = Field(default=0.9, ge=0.0, le=1.0)
    correlation_weight: float = Field(default=1.0, ge=0.0, le=1.0)

    # Confidence thresholds
    auto_confirm_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    auto_fp_threshold: float = Field(default=0.25, ge=0.0, le=1.0)

    # Limits
    max_evidence_per_chain: int = Field(default=100, ge=1)
    max_dataflow_paths: int = Field(default=10, ge=1)
    max_exploit_scenarios: int = Field(default=5, ge=1)


# Default configuration
DEFAULT_EVIDENCE_CHAIN_CONFIG = EvidenceChainConfig()


class EvidenceChainBuilder:
    """
    Builder for constructing evidence chains from vulnerability candidates.

    This class extracts evidence from multiple sources (Semgrep, CodeQL, Agent),
    aggregates them into coherent evidence chains, and provides export capabilities.

    Usage:
        builder = EvidenceChainBuilder(source_path)

        # Build from candidate
        chain = builder.build_chain(candidate)

        # Add additional evidence
        builder.add_dataflow_path(chain, dataflow_path)
        builder.add_exploit_scenario(chain, scenario)

        # Export
        markdown = builder.export_chain(chain, ExportFormat.MARKDOWN)
    """

    def __init__(
        self,
        source_path: Path | None = None,
        config: EvidenceChainConfig | None = None,
    ):
        """
        Initialize the evidence chain builder.

        Args:
            source_path: Path to source code (for context extraction).
            config: Configuration options.
        """
        self.logger = get_logger(__name__)
        self.source_path = source_path
        self.config = config or DEFAULT_EVIDENCE_CHAIN_CONFIG

        # Source weight mapping
        self._source_weights = {
            EvidenceSource.SEMGREP: self.config.semgrep_weight,
            EvidenceSource.CODEQL: self.config.codeql_weight,
            EvidenceSource.AGENT: self.config.agent_weight,
            EvidenceSource.CORRELATION: self.config.correlation_weight,
        }

    def build_chain(
        self,
        candidate: VulnerabilityCandidate,
        include_deep_results: bool = True,
    ) -> EvidenceChain:
        """
        Build an evidence chain from a vulnerability candidate.

        Args:
            candidate: The vulnerability candidate to build chain for.
            include_deep_results: Whether to include deep analysis results.

        Returns:
            A complete evidence chain.
        """
        self.logger.debug(f"Building evidence chain for candidate {candidate.id}")

        # Create new chain
        chain = EvidenceChain(
            id=f"chain-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.id,
        )

        # Extract evidence from finding
        self._extract_finding_evidence(candidate.finding, candidate.confidence, chain)

        # Extract evidence from candidate's evidence list
        self._extract_candidate_evidence(candidate, chain)

        # Extract deep analysis results
        if include_deep_results:
            self._extract_deep_results(candidate, chain)

        # Extract dataflow paths
        self._extract_dataflow_paths(candidate, chain)

        # Check consistency
        chain.check_consistency()

        self.logger.debug(
            f"Built chain with {len(chain.evidences)} evidence, "
            f"{len(chain.dataflow_paths)} paths, confidence: {chain.weighted_confidence:.0%}"
        )

        return chain

    def build_chains_batch(
        self,
        candidates: list[VulnerabilityCandidate],
        include_deep_results: bool = True,
    ) -> list[EvidenceChain]:
        """
        Build evidence chains for multiple candidates.

        Args:
            candidates: List of vulnerability candidates.
            include_deep_results: Whether to include deep analysis results.

        Returns:
            List of evidence chains.
        """
        chains = []
        for candidate in candidates:
            try:
                chain = self.build_chain(candidate, include_deep_results)
                chains.append(chain)
            except Exception as e:
                self.logger.warning(
                    f"Failed to build chain for candidate {candidate.id}: {e}"
                )
        return chains

    def add_evidence(
        self,
        chain: EvidenceChain,
        source: EvidenceSource,
        evidence_type: EvidenceType,
        content: str | None = None,
        location: CodeLocation | None = None,
        confidence: float = 0.5,
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        """
        Add evidence to an existing chain.

        Args:
            chain: The evidence chain to add to.
            source: Source of the evidence.
            evidence_type: Type of evidence.
            content: Evidence content/description.
            location: Code location if applicable.
            confidence: Confidence in this evidence.
            metadata: Additional metadata.

        Returns:
            The created evidence.
        """
        if len(chain.evidences) >= self.config.max_evidence_per_chain:
            self.logger.warning(
                f"Evidence chain {chain.id} reached max capacity"
            )
            raise ValueError("Evidence chain reached maximum capacity")

        evidence = Evidence(
            id=f"ev-{uuid.uuid4().hex[:8]}",
            source=source,
            evidence_type=evidence_type,
            location=location,
            content=content,
            confidence=confidence,
            weight=self._source_weights.get(source, 0.5),
            metadata=metadata or {},
        )

        chain.add_evidence(evidence)
        return evidence

    def add_dataflow_path(
        self,
        chain: EvidenceChain,
        path: DataFlowPath,
    ) -> None:
        """
        Add a dataflow path to an evidence chain.

        Args:
            chain: The evidence chain to add to.
            path: The dataflow path to add.
        """
        if len(chain.dataflow_paths) >= self.config.max_dataflow_paths:
            self.logger.warning(
                f"Evidence chain {chain.id} reached max dataflow paths"
            )
            return

        chain.add_dataflow_path(path)

        # Also add as evidence
        self.add_evidence(
            chain,
            source=EvidenceSource(path.analyzer) if path.analyzer in ["semgrep", "codeql", "agent"] else EvidenceSource.CODEQL,
            evidence_type=EvidenceType.DATAFLOW_PATH,
            content=path.get_summary(),
            confidence=path.path_confidence,
            metadata={
                "path_id": path.id,
                "is_complete": path.is_complete,
                "has_sanitizer": path.has_effective_sanitizer,
            },
        )

    def add_exploit_scenario(
        self,
        chain: EvidenceChain,
        scenario: ExploitScenario,
    ) -> None:
        """
        Add an exploit scenario to an evidence chain.

        Args:
            chain: The evidence chain to add to.
            scenario: The exploit scenario to add.
        """
        # Store in metadata
        if "exploit_scenarios" not in chain.metadata:
            chain.metadata["exploit_scenarios"] = []

        scenarios = chain.metadata["exploit_scenarios"]
        if len(scenarios) >= self.config.max_exploit_scenarios:
            self.logger.warning(
                f"Evidence chain {chain.id} reached max exploit scenarios"
            )
            return

        scenarios.append(scenario.model_dump())

        # Add as evidence
        self.add_evidence(
            chain,
            source=EvidenceSource.AGENT if scenario.source == "agent" else EvidenceSource.CORRELATION,
            evidence_type=EvidenceType.EXPLOIT_SCENARIO,
            content=scenario.to_summary(),
            confidence=scenario.confidence,
            metadata={
                "scenario_id": scenario.id,
                "feasibility": scenario.feasibility,
                "steps": len(scenario.steps),
                "cwe_ids": scenario.cwe_ids,
                "cve_ids": scenario.cve_ids,
            },
        )

    def add_cve_match(
        self,
        chain: EvidenceChain,
        cve_id: str,
        confidence: float,
        match_reasons: list[str] | None = None,
    ) -> Evidence:
        """
        Add a CVE pattern match to an evidence chain.

        Args:
            chain: The evidence chain to add to.
            cve_id: The CVE identifier.
            confidence: Match confidence.
            match_reasons: Reasons for the match.

        Returns:
            The created evidence.
        """
        return self.add_evidence(
            chain,
            source=EvidenceSource.CORRELATION,
            evidence_type=EvidenceType.CVE_MATCH,
            content=f"Matches CVE pattern: {cve_id}",
            confidence=confidence,
            metadata={
                "cve_id": cve_id,
                "match_reasons": match_reasons or [],
            },
        )

    def export_chain(
        self,
        chain: EvidenceChain,
        format: ExportFormat,
        include_metadata: bool = True,
    ) -> str:
        """
        Export an evidence chain to the specified format.

        Args:
            chain: The evidence chain to export.
            format: Export format.
            include_metadata: Whether to include metadata.

        Returns:
            Formatted string representation.
        """
        if format == ExportFormat.JSON:
            return self._export_json(chain, include_metadata)
        elif format == ExportFormat.MARKDOWN:
            return self._export_markdown(chain, include_metadata)
        elif format == ExportFormat.HTML:
            return self._export_html(chain, include_metadata)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def determine_status(
        self,
        chain: EvidenceChain,
    ) -> VerificationStatus:
        """
        Determine verification status based on evidence chain.

        Args:
            chain: The evidence chain to analyze.

        Returns:
            Determined verification status.
        """
        # Check for explicit false positive evidence
        for evidence in chain.evidences:
            if evidence.metadata.get("is_false_positive"):
                return VerificationStatus.FALSE_POSITIVE

        # Check for sanitizer in dataflow
        for path in chain.dataflow_paths:
            if path.has_effective_sanitizer:
                return VerificationStatus.NOT_EXPLOITABLE

        # Use confidence-based determination
        if chain.weighted_confidence >= self.config.auto_confirm_threshold:
            return VerificationStatus.CONFIRMED
        elif chain.weighted_confidence >= 0.6:
            return VerificationStatus.LIKELY
        elif chain.weighted_confidence <= self.config.auto_fp_threshold:
            return VerificationStatus.FALSE_POSITIVE

        return VerificationStatus.UNCERTAIN

    # Private methods

    def _extract_finding_evidence(
        self,
        finding: Finding,
        confidence: ConfidenceLevel,
        chain: EvidenceChain,
    ) -> None:
        """Extract evidence from the finding source."""
        confidence_value = self._map_confidence(confidence)

        if finding.source == "semgrep":
            self.add_evidence(
                chain,
                source=EvidenceSource.SEMGREP,
                evidence_type=EvidenceType.PATTERN_MATCH,
                location=finding.location,
                content=finding.description,
                confidence=confidence_value,
                metadata={
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "severity": finding.severity.value if finding.severity else None,
                },
            )

        elif finding.source == "codeql":
            self.add_evidence(
                chain,
                source=EvidenceSource.CODEQL,
                evidence_type=EvidenceType.DATAFLOW_PATH,
                location=finding.location,
                content=finding.description,
                confidence=confidence_value,
                metadata={
                    "query_id": finding.rule_id,
                    "title": finding.title,
                },
            )

        elif finding.source == "agent":
            self.add_evidence(
                chain,
                source=EvidenceSource.AGENT,
                evidence_type=EvidenceType.AGENT_ANALYSIS,
                location=finding.location,
                content=finding.description,
                confidence=confidence_value,
                metadata={
                    "title": finding.title,
                },
            )

    def _extract_candidate_evidence(
        self,
        candidate: VulnerabilityCandidate,
        chain: EvidenceChain,
    ) -> None:
        """Extract evidence from candidate's evidence list."""
        for ev_data in candidate.evidence:
            source_str = ev_data.get("source", "unknown")
            content = ev_data.get("data", {})

            # Map source string to enum
            source = self._map_source_string(source_str)
            if source is None:
                continue

            evidence_type = self._infer_evidence_type(source, content)
            confidence = 0.5
            if isinstance(content, dict):
                confidence = content.get("confidence", 0.5)

            self.add_evidence(
                chain,
                source=source,
                evidence_type=evidence_type,
                content=str(content)[:500] if content else None,
                confidence=confidence,
                metadata={"raw_data": content} if content else {},
            )

    def _extract_deep_results(
        self,
        candidate: VulnerabilityCandidate,
        chain: EvidenceChain,
    ) -> None:
        """Extract evidence from deep analysis results."""
        deep_results = candidate.metadata.get("deep_results", {})

        # CodeQL deep results
        if "codeql" in deep_results:
            codeql_data = deep_results["codeql"]
            if codeql_data.get("has_path"):
                self.add_evidence(
                    chain,
                    source=EvidenceSource.CODEQL,
                    evidence_type=EvidenceType.DATAFLOW_PATH,
                    confidence=0.8 if codeql_data.get("path_complete") else 0.6,
                    metadata={"from_deep_analysis": True},
                )

        # Agent deep results
        if "agent" in deep_results:
            agent_data = deep_results["agent"]
            if agent_data.get("confirmed"):
                self.add_evidence(
                    chain,
                    source=EvidenceSource.AGENT,
                    evidence_type=EvidenceType.AGENT_ANALYSIS,
                    confidence=0.9,
                    metadata={
                        "from_deep_analysis": True,
                        "confirmed": True,
                    },
                )
            elif agent_data.get("false_positive"):
                self.add_evidence(
                    chain,
                    source=EvidenceSource.AGENT,
                    evidence_type=EvidenceType.AGENT_ANALYSIS,
                    confidence=0.9,
                    metadata={
                        "from_deep_analysis": True,
                        "is_false_positive": True,
                    },
                )

    def _extract_dataflow_paths(
        self,
        candidate: VulnerabilityCandidate,
        chain: EvidenceChain,
    ) -> None:
        """Extract dataflow paths from candidate metadata."""
        deep_results = candidate.metadata.get("deep_results", {})
        codeql_data = deep_results.get("codeql", {})

        if "dataflow_paths" in codeql_data:
            for path_data in codeql_data["dataflow_paths"]:
                if isinstance(path_data, dict):
                    path = DataFlowPath(
                        id=path_data.get("id", f"path-{uuid.uuid4().hex[:8]}"),
                        candidate_id=candidate.id,
                        source=path_data.get("source"),
                        sink=path_data.get("sink"),
                        is_complete=path_data.get("is_complete", False),
                        analyzer="codeql",
                    )
                    try:
                        self.add_dataflow_path(chain, path)
                    except Exception as e:
                        self.logger.warning(f"Failed to add dataflow path: {e}")

    def _export_json(
        self,
        chain: EvidenceChain,
        include_metadata: bool,
    ) -> str:
        """Export chain as JSON."""
        import json

        data = chain.model_dump(
            exclude=None if include_metadata else {"metadata"},
            mode="json",
        )
        return json.dumps(data, indent=2, default=str)

    def _export_markdown(
        self,
        chain: EvidenceChain,
        include_metadata: bool,
    ) -> str:
        """Export chain as Markdown."""
        lines = [
            "# Evidence Chain Report",
            "",
            "## Summary",
            "",
            f"- **Chain ID**: {chain.id}",
            f"- **Candidate ID**: {chain.candidate_id}",
            f"- **Status**: {chain.verification_status.value}",
            f"- **Confidence**: {chain.weighted_confidence:.0%}",
            f"- **Sources**: {', '.join(s.value for s in chain.sources)}",
            f"- **Evidence Count**: {len(chain.evidences)}",
            "",
            "## Evidence Items",
            "",
        ]

        for i, evidence in enumerate(chain.evidences, 1):
            lines.append(f"### {i}. [{evidence.source.value}] {evidence.evidence_type.value}")
            lines.append("")
            if evidence.location:
                lines.append(f"- **Location**: {evidence.location.to_display()}")
            if evidence.content:
                lines.append(f"- **Content**: {evidence.content[:200]}")
            lines.append(f"- **Confidence**: {evidence.confidence:.0%}")
            lines.append("")

        if chain.dataflow_paths:
            lines.append("## Data Flow Paths")
            lines.append("")
            for path in chain.dataflow_paths:
                lines.append(f"- {path.get_summary()}")
            lines.append("")

        if not chain.consistent:
            lines.append("## Conflicts")
            lines.append("")
            for conflict in chain.conflicts:
                lines.append(f"- {conflict}")
            lines.append("")

        # Exploit scenarios
        if include_metadata and "exploit_scenarios" in chain.metadata:
            scenarios = chain.metadata["exploit_scenarios"]
            if scenarios:
                lines.append("## Exploit Scenarios")
                lines.append("")
                for scenario_data in scenarios:
                    lines.append(f"### {scenario_data.get('name', 'Unknown')}")
                    lines.append("")
                    lines.append(f"- **Feasibility**: {scenario_data.get('feasibility', 'unknown')}")
                    lines.append(f"- **Steps**: {len(scenario_data.get('steps', []))}")
                    if scenario_data.get("cwe_ids"):
                        lines.append(f"- **CWEs**: {', '.join(scenario_data['cwe_ids'])}")
                    lines.append("")

        return "\n".join(lines)

    def _export_html(
        self,
        chain: EvidenceChain,
        include_metadata: bool,
    ) -> str:
        """Export chain as HTML."""
        # Convert markdown to basic HTML
        md = self._export_markdown(chain, include_metadata)

        # Simple markdown to HTML conversion
        html = md.replace("\n", "<br>\n")
        html = html.replace("# ", "<h1>").replace("## ", "<h2>").replace("### ", "<h3>")
        html = html.replace("**", "<strong>").replace("- ", "<li>")
        html = html.replace("<h1>", "<h1>").replace("<h2>", "<h2>").replace("<h3>", "<h3>")

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Evidence Chain Report - {chain.id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 1px solid #ccc; }}
        h3 {{ color: #888; }}
        li {{ margin-left: 20px; }}
    </style>
</head>
<body>
{html}
</body>
</html>"""

    def _map_confidence(self, level: ConfidenceLevel) -> float:
        """Map confidence level enum to float."""
        mapping = {
            ConfidenceLevel.HIGH: 0.85,
            ConfidenceLevel.MEDIUM: 0.6,
            ConfidenceLevel.LOW: 0.3,
        }
        return mapping.get(level, 0.5)

    def _map_source_string(self, source: str) -> EvidenceSource | None:
        """Map source string to enum."""
        mapping = {
            "semgrep": EvidenceSource.SEMGREP,
            "codeql": EvidenceSource.CODEQL,
            "agent": EvidenceSource.AGENT,
            "manual": EvidenceSource.MANUAL,
            "correlation": EvidenceSource.CORRELATION,
        }
        return mapping.get(source.lower())

    def _infer_evidence_type(
        self,
        source: EvidenceSource,
        content: dict,
    ) -> EvidenceType:
        """Infer evidence type from source and content."""
        if source == EvidenceSource.SEMGREP:
            return EvidenceType.PATTERN_MATCH
        elif source == EvidenceSource.CODEQL:
            return EvidenceType.DATAFLOW_PATH
        elif source == EvidenceSource.AGENT:
            return EvidenceType.AGENT_ANALYSIS

        if isinstance(content, dict):
            if content.get("dataflow_path"):
                return EvidenceType.DATAFLOW_PATH
            if content.get("sanitizer"):
                return EvidenceType.SANITIZER_DETECTED
            if content.get("code_snippet"):
                return EvidenceType.CODE_SNIPPET

        return EvidenceType.PATTERN_MATCH
