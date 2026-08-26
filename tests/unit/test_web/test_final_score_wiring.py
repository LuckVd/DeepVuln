"""Regression tests for audit finding A4: final_score must be assigned
before adjudication consumes it.

Before the fix, ``assign_scores_to_findings`` had zero production callers,
so every finding's ``final_score`` stayed ``None`` and
``ClusterBasedDeduplicator``'s "keep highest final_score" tie-break degraded
to arbitrary order.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.layers.l3_analysis.models import (
    CodeLocation,
    EvidenceStrength,
    Finding,
    FindingType,
    ScanResult,
    SeverityLevel,
)
from src.web.services.scan_orchestrator import ScanOrchestrator


def _orch() -> ScanOrchestrator:
    """Lightweight orchestrator (no DB / no LLM) for unit tests."""
    return ScanOrchestrator(
        scan_id=1, source_path="/tmp", scan_config={}, progress_callback=MagicMock()
    )


def _finding(**overrides) -> Finding:
    base = dict(
        id="finding-1",
        rule_id="rule-x",
        type=FindingType.VULNERABILITY,
        severity=SeverityLevel.HIGH,
        confidence=0.8,
        title="SQL injection",
        description="desc",
        location=CodeLocation(file="app.py", line=12, function="get_user"),
        source="semgrep",
        cwe="CWE-89",
        evidence_strength=EvidenceStrength.MEDIUM,
    )
    base.update(overrides)
    return Finding(**base)


def _async_progress() -> MagicMock:
    cb = MagicMock()
    cb.broadcast_event = AsyncMock()
    cb.on_warning = AsyncMock()
    return cb


@pytest.mark.asyncio
class TestFinalScoreWiredIntoAdjudication:
    async def test_adjudication_assigns_final_score(self):
        """After adjudication every surviving finding carries a final_score."""
        orch = _orch()
        orch.progress_callback = _async_progress()
        orch.scan_results = {
            "semgrep": ScanResult(
                source_path="/tmp",
                engine="semgrep",
                findings=[_finding()],
                total_findings=1,
            )
        }

        await orch._run_adjudication()

        survivors = [f for r in orch.scan_results.values() for f in r.findings]
        assert survivors, "expected at least one surviving finding"
        for finding in survivors:
            assert finding.final_score is not None, (
                "final_score must be assigned before dedup/report consume it"
            )

    async def test_llm_dedup_group_keeps_highest_final_score(self):
        """When the LLM groups duplicates, final_score picks the survivor.

        (No-LLM mode keeps every cluster member by design, so this exercises
        _parse_llm_response directly.)
        """
        from src.layers.l3_analysis.deduplicator import (
            ClusterBasedDeduplicator,
            ClusterDeduplicatorConfig,
        )

        dedup = ClusterBasedDeduplicator(
            config=ClusterDeduplicatorConfig(enable_llm_dedup=True),
            llm_client=None,
        )
        low = _finding(id="low-dup", confidence=0.3)
        high = _finding(id="high-dup", confidence=0.95)

        # Assign scores exactly like the wired adjudication step does.
        from src.core.final_score import assign_scores_to_findings

        assign_scores_to_findings([low, high], sort=False)

        assert high.final_score > low.final_score
        assert low.final_score is not None and high.final_score is not None

        response = (
            '```json\n{"groups": [{"indices": [0, 1], '
            '"reason": "same sink"}]}\n```'
        )
        result = dedup._parse_llm_response([low, high], response)

        kept_ids = {f.id for f in result.keep}
        removed_ids = {f.id for f in result.removed}
        assert kept_ids == {"high-dup"}
        assert removed_ids == {"low-dup"}
