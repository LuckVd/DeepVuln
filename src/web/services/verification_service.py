"""Verification Service - P14-02.

This service wraps the CLI's exploitability verification functionality
for use in the web service.

It integrates:
- RoundFourExecutor for exploitability verification
- CodeQL dataflow analysis
- Attack surface results
- LLM-assisted assessment
"""

import logging
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from src.layers.l3_analysis.rounds.round_four import (
    RoundFourExecutor,
    ExploitabilityStatus,
    ExploitabilityResult,
)
from src.layers.l3_analysis.llm.client import LLMClient
from src.layers.l3_analysis.models import Finding, SeverityLevel
from src.layers.l1_intelligence.attack_surface.models import (
    AttackSurfaceReport,
)


logger = logging.getLogger(__name__)


class ExploitabilityRating(str, Enum):
    """Exploitability rating for web API responses."""
    EXPLOITABLE = "exploitable"
    LIKELY = "likely"
    NOT_EXPLOITABLE = "not_exploitable"


class VerificationService:
    """Service for verifying vulnerability exploitability (P14-02).

    This service wraps RoundFourExecutor and provides:
    1. Conversion between web and CLI Finding models
    2. Async verification methods
    3. Integration with scan workflow
    4. CodeQL dataflow analysis
    5. Attack surface result integration
    """

    def __init__(
        self,
        source_path: Path,
        llm_client: Optional[LLMClient] = None,
        attack_surface_report: Optional[AttackSurfaceReport] = None,
        codeql_findings: Optional[list[Finding]] = None,
        enable_llm_assessment: bool = True,
    ):
        """Initialize the verification service.

        Args:
            source_path: Path to source code
            llm_client: Optional LLM client for AI-assisted assessment
            attack_surface_report: Pre-computed attack surface from P14-01
            codeql_findings: CodeQL scan results for dataflow analysis
            enable_llm_assessment: Whether to use LLM for NEEDS_REVIEW cases
        """
        self.source_path = source_path
        self.llm_client = llm_client
        self.attack_surface_report = attack_surface_report
        self.codeql_findings = codeql_findings or []
        self.enable_llm_assessment = enable_llm_assessment and llm_client is not None

        # Initialize the executor
        self.executor = RoundFourExecutor(
            source_path=source_path,
            llm_client=llm_client,
            enable_llm_assessment=enable_llm_assessment,
            attack_surface_report=attack_surface_report,
            codeql_results=codeql_findings,
        )

        logger.info(
            f"VerificationService initialized: llm={'enabled' if enable_llm_assessment else 'disabled'}, "
            f"codeql_results={len(codeql_findings) if codeql_findings else 0}, "
            f"attack_surface={'present' if attack_surface_report else 'none'}"
        )

    async def verify_finding(
        self,
        finding: Finding,
    ) -> ExploitabilityResult:
        """Verify a single finding's exploitability.

        Args:
            finding: The CLI Finding to verify

        Returns:
            ExploitabilityResult with verification details
        """
        # Import VulnerabilityCandidate locally to avoid circular imports
        from src.layers.l3_analysis.rounds.models import VulnerabilityCandidate, ConfidenceLevel
        import uuid

        # Create a candidate wrapper
        candidate = VulnerabilityCandidate(
            id=str(uuid.uuid4())[:8],
            finding=finding,
            confidence=ConfidenceLevel.MEDIUM,
            discovered_in_round=1,
        )

        # Verify exploitability
        result = await self.executor._verify_exploitability(candidate)

        logger.info(
            f"Verified finding {finding.id}: status={result.status.value}, "
            f"confidence={result.confidence:.2f}"
        )

        return result

    async def verify_findings_batch(
        self,
        findings: list[Finding],
        max_concurrent: int = 3,
    ) -> dict[str, ExploitabilityResult]:
        """Verify multiple findings in batch.

        Args:
            findings: List of CLI Findings to verify
            max_concurrent: Maximum concurrent verifications (default 3)

        Returns:
            Dictionary mapping finding_id to ExploitabilityResult
        """
        import asyncio

        results = {}

        # Process in batches to control concurrency
        for i in range(0, len(findings), max_concurrent):
            batch = findings[i:i + max_concurrent]
            tasks = [self.verify_finding(f) for f in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for finding, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Error verifying finding {finding.id}: {result}")
                    # Create a fallback result
                    results[finding.id] = ExploitabilityResult(
                        finding_id=finding.id,
                        status=ExploitabilityStatus.NEEDS_REVIEW,
                        confidence=0.1,
                        reasoning=f"Verification error: {str(result)}",
                    )
                else:
                    results[finding.id] = result

        logger.info(f"Verified {len(results)} findings in batch")
        return results

    def convert_web_finding_to_cli_finding(
        self,
        web_finding: dict[str, Any],
    ) -> Finding:
        """Convert a web finding dict to CLI Finding model.

        Args:
            web_finding: Web finding dict from database

        Returns:
            CLI Finding instance
        """
        from src.layers.l3_analysis.models import FindingLocation

        # Create FindingLocation
        location = FindingLocation(
            file=web_finding.get("file_path", ""),
            line=web_finding.get("line_start", 0),
            column=web_finding.get("column_start", 0),
            end_line=web_finding.get("line_end", web_finding.get("line_start", 0)),
            end_column=web_finding.get("column_end", 0),
            snippet=web_finding.get("evidence", ""),
            function=web_finding.get("function_name"),
        )

        # Map severity
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        severity = severity_map.get(
            web_finding.get("severity", "medium").lower(),
            SeverityLevel.MEDIUM
        )

        # Create Finding
        finding = Finding(
            id=web_finding.get("id", str(web_finding.get("finding_id", ""))),
            rule_id=web_finding.get("vuln_type", "unknown"),
            title=web_finding.get("title", "Unknown vulnerability"),
            description=web_finding.get("description"),
            severity=severity,
            location=location,
            confidence=web_finding.get("confidence", 0.5),
            cwe=web_finding.get("metadata", {}).get("cwe") if web_finding.get("metadata") else None,
            owasp=web_finding.get("metadata", {}).get("owasp") if web_finding.get("metadata") else None,
            fix_suggestion=web_finding.get("remediation"),
            snippet=web_finding.get("evidence", ""),
        )

        # Add metadata
        if web_finding.get("metadata"):
            finding.metadata = web_finding["metadata"]

        # Add engine info
        finding.metadata = finding.metadata or {}
        finding.metadata["engine"] = web_finding.get("engine", "unknown")

        return finding

    def create_exploitability_dict(
        self,
        result: ExploitabilityResult,
    ) -> dict[str, Any]:
        """Create a dict representation of exploitability result for storage.

        Args:
            result: ExploitabilityResult from verification

        Returns:
            Dict suitable for JSON storage in database
        """
        return {
            "status": result.status.value,
            "rating": self._map_status_to_rating(result.status),
            "confidence": result.confidence,
            "is_entry_point": result.is_entry_point,
            "entry_point_type": result.entry_point_type,
            "is_user_controlled": result.is_user_controlled,
            "data_source_type": result.data_source_type,
            "prerequisites": result.prerequisites,
            "reasoning": result.reasoning,
            "severity_adjustment": {
                "original": result.severity_adjustment.original_severity.value if result.severity_adjustment else None,
                "adjusted": result.severity_adjustment.adjusted_severity.value if result.severity_adjustment else None,
                "reason": result.severity_adjustment.reason if result.severity_adjustment else None,
            } if result.severity_adjustment else None,
            "analyzed_at": result.analyzed_at.isoformat() if result.analyzed_at else None,
        }

    def _map_status_to_rating(
        self,
        status: ExploitabilityStatus,
    ) -> str:
        """Map ExploitabilityStatus to simplified rating.

        Args:
            status: The detailed status

        Returns:
            Simplified rating string
        """
        rating_map = {
            ExploitabilityStatus.EXPLOITABLE: ExploitabilityRating.EXPLOITABLE,
            ExploitabilityStatus.CONDITIONAL: ExploitabilityRating.LIKELY,
            ExploitabilityStatus.UNLIKELY: ExploitabilityRating.NOT_EXPLOITABLE,
            ExploitabilityStatus.NOT_EXPLOITABLE: ExploitabilityRating.NOT_EXPLOITABLE,
            ExploitabilityStatus.NEEDS_REVIEW: ExploitabilityRating.NOT_EXPLOITABLE,
        }
        return rating_map.get(status, ExploitabilityRating.NOT_EXPLOITABLE)


def create_verification_service(
    source_path: Path,
    llm_client: Optional[LLMClient] = None,
    attack_surface_report: Optional[AttackSurfaceReport] = None,
    codeql_findings: Optional[list[Finding]] = None,
    enable_llm_assessment: bool = True,
) -> VerificationService:
    """Factory function to create a VerificationService.

    Args:
        source_path: Path to source code
        llm_client: Optional LLM client for AI-assisted assessment
        attack_surface_report: Pre-computed attack surface from P14-01
        codeql_findings: CodeQL scan results for dataflow analysis
        enable_llm_assessment: Whether to use LLM for NEEDS_REVIEW cases

    Returns:
        Configured VerificationService instance
    """
    return VerificationService(
        source_path=source_path,
        llm_client=llm_client,
        attack_surface_report=attack_surface_report,
        codeql_findings=codeql_findings,
        enable_llm_assessment=enable_llm_assessment,
    )
