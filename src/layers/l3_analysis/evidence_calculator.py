"""
Evidence Strength Calculator

P6-03: Calculate evidence strength for vulnerability findings based on
anti-hallucination rules and multi-engine correlation.

Integration Point: Called after deduplication in adjudication.py

Based on:
- /opt/AI/code-audit/references/core/anti_hallucination.md
- /opt/AI/code-audit/references/checklists/coverage_matrix.md
"""

import logging
from pathlib import Path
from typing import Any

from src.layers.l3_analysis.models import (
    EvidenceStrength,
    Finding,
    FindingType,
    HallucinationCheckResult,
)

logger = logging.getLogger(__name__)


def calculate_evidence_strength(
    findings: list[Finding],
    source_path: Path,
) -> tuple[list[Finding], dict[str, int]]:
    """
    Calculate evidence strength for all findings.

    This function should be called AFTER deduplication, when related_engines
    and duplicate_count fields are already populated.

    Args:
        findings: Deduplicated Finding list (related_engines already set)
        source_path: Source code path (for file verification)

    Returns:
        Tuple of (updated_findings, strength_counts)
        - updated_findings: Findings with evidence_strength populated
        - strength_counts: Dict with counts per strength level
    """
    counts: dict[str, int] = {
        "strong": 0,
        "medium": 0,
        "weak": 0,
        "speculative": 0,
    }

    for finding in findings:
        # 1. Perform hallucination check
        hallucination_check = _verify_finding(finding, source_path)
        finding.hallucination_check = hallucination_check

        # 2. Force SPECULATIVE for certain conditions
        if finding.type == FindingType.SUSPICIOUS:
            finding.evidence_strength = EvidenceStrength.SPECULATIVE
            finding.evidence_details = {
                "reason": "suspicious_type",
                "description": "Finding type is SUSPICIOUS, forcing speculative evidence",
            }
            counts["speculative"] += 1
            logger.debug(
                f"Finding {finding.id}: SPECULATIVE (suspicious type)"
            )
            continue

        if finding.confidence < 0.5:
            finding.evidence_strength = EvidenceStrength.SPECULATIVE
            finding.evidence_details = {
                "reason": "low_confidence",
                "confidence": finding.confidence,
                "description": f"Confidence {finding.confidence:.2f} < 0.5, forcing speculative",
            }
            counts["speculative"] += 1
            logger.debug(
                f"Finding {finding.id}: SPECULATIVE (low confidence {finding.confidence:.2f})"
            )
            continue

        if hallucination_check.has_failure:
            finding.evidence_strength = EvidenceStrength.SPECULATIVE
            finding.evidence_details = {
                "reason": "hallucination_check_failed",
                "check_result": hallucination_check.to_dict(),
                "description": "Hallucination check failed, forcing speculative",
            }
            counts["speculative"] += 1
            logger.warning(
                f"Finding {finding.id}: SPECULATIVE (hallucination check failed) - "
                f"file={hallucination_check.file_path}, "
                f"exists={hallucination_check.file_exists}, "
                f"line_valid={hallucination_check.line_number_valid}"
            )
            continue

        # 3. Check for STRONG evidence conditions
        related_engines = getattr(finding, "related_engines", []) or []
        duplicate_count = getattr(finding, "duplicate_count", 0) or 0

        # Multi-engine cross-validation (2+ engines)
        if len(related_engines) >= 2:
            finding.evidence_strength = EvidenceStrength.STRONG
            finding.evidence_details = {
                "reason": "multi_engine",
                "engines": related_engines,
                "description": f"Detected by {len(related_engines)} engines: {related_engines}",
            }
            counts["strong"] += 1
            logger.debug(
                f"Finding {finding.id}: STRONG (multi-engine: {related_engines})"
            )
            continue

        # Multiple detections merged (2+ duplicates)
        if duplicate_count >= 2:
            finding.evidence_strength = EvidenceStrength.STRONG
            finding.evidence_details = {
                "reason": "multiple_detections",
                "count": duplicate_count,
                "description": f"Merged from {duplicate_count} duplicate findings",
            }
            counts["strong"] += 1
            logger.debug(
                f"Finding {finding.id}: STRONG (multiple detections: {duplicate_count})"
            )
            continue

        # High confidence + all validations passed
        if finding.confidence >= 0.9 and hallucination_check.all_passed:
            finding.evidence_strength = EvidenceStrength.STRONG
            finding.evidence_details = {
                "reason": "high_confidence_verified",
                "confidence": finding.confidence,
                "description": f"High confidence ({finding.confidence:.2f}) with all validations passed",
            }
            counts["strong"] += 1
            logger.debug(
                f"Finding {finding.id}: STRONG (high confidence {finding.confidence:.2f})"
            )
            continue

        # 4. Check for MEDIUM evidence conditions
        if finding.confidence >= 0.8:
            finding.evidence_strength = EvidenceStrength.MEDIUM
            finding.evidence_details = {
                "reason": "high_confidence",
                "confidence": finding.confidence,
                "description": f"High confidence ({finding.confidence:.2f}) single engine detection",
            }
            counts["medium"] += 1
            logger.debug(
                f"Finding {finding.id}: MEDIUM (confidence {finding.confidence:.2f})"
            )
            continue

        # Merged at least once
        if duplicate_count >= 1:
            finding.evidence_strength = EvidenceStrength.MEDIUM
            finding.evidence_details = {
                "reason": "merged_finding",
                "count": duplicate_count,
                "description": f"Merged from {duplicate_count} duplicate finding",
            }
            counts["medium"] += 1
            logger.debug(
                f"Finding {finding.id}: MEDIUM (merged: {duplicate_count})"
            )
            continue

        # 5. Default: WEAK evidence
        finding.evidence_strength = EvidenceStrength.WEAK
        finding.evidence_details = {
            "reason": "default",
            "confidence": finding.confidence,
            "description": f"Moderate confidence ({finding.confidence:.2f}) single engine detection",
        }
        counts["weak"] += 1
        logger.debug(
            f"Finding {finding.id}: WEAK (default, confidence {finding.confidence:.2f})"
        )

    logger.info(
        f"Evidence strength calculated: strong={counts['strong']}, "
        f"medium={counts['medium']}, weak={counts['weak']}, "
        f"speculative={counts['speculative']}"
    )

    return findings, counts


def _verify_finding(
    finding: Finding,
    source_path: Path,
) -> HallucinationCheckResult:
    """
    Perform anti-hallucination verification on a finding.

    Based on code-audit anti_hallucination.md rules:
    - Rule 1: File existence verification
    - Rule 3: Line number validity verification

    Args:
        finding: Finding to verify
        source_path: Project source path

    Returns:
        HallucinationCheckResult with verification details
    """
    file_path = finding.location.file
    full_path = source_path / file_path

    # Rule 1: File existence
    file_exists = full_path.exists()

    # Rule 3: Line number validity
    line_number_valid = True
    actual_line_count = None

    if file_exists:
        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            actual_line_count = len(content.splitlines())
            reported_line = finding.location.line
            # Line number should be 1-indexed and within file bounds
            line_number_valid = 1 <= reported_line <= actual_line_count
        except Exception as e:
            logger.debug(f"Error reading file {full_path}: {e}")
            line_number_valid = False

    return HallucinationCheckResult(
        file_exists=file_exists,
        line_number_valid=line_number_valid,
        file_path=file_path,
        actual_line_count=actual_line_count,
        reported_line=finding.location.line,
    )
