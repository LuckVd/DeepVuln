"""Shared, mutable state passed across pipeline phases."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ScanContext:
    """Cross-phase shared state.

    Replaces the ad-hoc local dicts (CLI's 1000+ line ``result`` dict) and the
    sprawling ``self`` attributes (Web orchestrator) with a single typed
    carrier. Phases read/write fields here; the pipeline itself is stateless
    beyond phase ordering.
    """

    scan_id: str | int
    source_path: Path
    config: dict[str, Any] = field(default_factory=dict)

    # Intermediate artifacts (populated by phases)
    tech_stack: dict[str, Any] | None = None
    attack_surface_report: Any | None = None
    engines: dict[str, Any] = field(default_factory=dict)
    scan_results: dict[str, Any] = field(default_factory=dict)
    all_findings: list[Any] = field(default_factory=list)
    verified_findings: list[Any] = field(default_factory=list)
    adjudication_summary: dict[str, Any] | None = None
    rounds_session: Any | None = None  # multi-round AuditSession product

    # Accounting
    total_tokens: int = 0
    adversarial_tokens: int = 0
    errors: list[str] = field(default_factory=list)

    # Escape hatch for adapter-specific data not worth a dedicated field.
    extra: dict[str, Any] = field(default_factory=dict)
