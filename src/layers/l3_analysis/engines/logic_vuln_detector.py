"""LogicVulnerabilityDetector — AI 补漏逻辑漏洞 (E5).

Static engines (semgrep/AST/taint) and the broad Agent audit routinely miss
*logic* flaws: missing authorization, auth bypass, IDOR, business-logic
abuse, and injection too context-dependent for rules. This detector is the
AI supplement that closes that gap — but only within a strict, limited scope
to control false positives:

- It feeds the LLM **only** entry-point-reachable source regions (selected
  from the pre-computed attack surface report). Internal-only code is never
  audited here.
- It enforces a three-element hard-evidence contract (missing_check /
  entry_point / attack_path) at the prompt *and* parse layer; ungrounded
  findings are dropped.
- Emitted findings carry ``source="logic_vuln"`` with
  ``evidence_strength=SPECULATIVE`` and confidence capped at
  :attr:`MAX_CONFIDENCE`, so downstream adjudication treats them as
  low-confidence signals until corroborated.

The detector reuses the same LLM client + prompt build/parse infrastructure
as ``RoundFourExecutor._llm_assisted_assessment``.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Protocol

from src.core.logger.logger import get_logger
from src.core.models.attack_surface import AttackSurfaceReport, EntryPointType
from src.layers.l3_analysis.models import (
    CodeLocation,
    EvidenceStrength,
    Finding,
    FindingType,
    SeverityLevel,
)
from src.layers.l3_analysis.prompts.logic_vuln import (
    build_logic_vuln_prompt,
    parse_logic_vuln_response,
)

# Map the attack-surface EntryPointType to a short label for the prompt.
_ENTRY_TYPE_LABEL = {
    EntryPointType.HTTP: "HTTP",
    EntryPointType.RPC: "RPC",
    EntryPointType.GRPC: "gRPC",
    EntryPointType.MQ: "MQ",
    EntryPointType.CRON: "SCHEDULED",
    EntryPointType.FILE: "FILE",
    EntryPointType.WEBSOCKET: "WEBSOCKET",
    EntryPointType.CLI: "CLI",
}

_SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
}

# CWE hints per category (best-effort; the LLM may supply its own).
_CATEGORY_CWE = {
    "missing_authorization": "CWE-862",
    "auth_bypass": "CWE-287",
    "idor": "CWE-639",
    "business_logic": "CWE-840",
    "complex_injection": "CWE-74",
}


class LLMClientProtocol(Protocol):
    """Minimal LLM client contract (mirrors RoundFourExecutor's protocol)."""

    async def complete_with_context(
        self,
        system_prompt: str,
        user_prompt: str,
        context: list[dict[str, str]] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Generate a completion. The response exposes ``.content``."""
        ...


class LogicVulnerabilityDetector:
    """AI supplement pass that discovers logic vulnerabilities static tools miss.

    Limited-scope + hard-evidence design keeps false positives in check. See the
    module docstring for the full contract.
    """

    SOURCE = "logic_vuln"
    # Findings are AI-only signals; cap confidence so adjudication weighs them
    # below statically-grounded findings until corroborated.
    MAX_CONFIDENCE = 0.6
    DEFAULT_MAX_ENTRY_POINTS = 50

    def __init__(
        self,
        source_path: Path,
        llm_client: LLMClientProtocol | None,
        attack_surface_report: AttackSurfaceReport | None = None,
        *,
        config: dict[str, Any] | None = None,
        max_entry_points: int = DEFAULT_MAX_ENTRY_POINTS,
    ) -> None:
        self.logger = get_logger(__name__)
        self.source_path = Path(source_path)
        self._llm_client = llm_client
        self._report = attack_surface_report
        self._config = config or {}
        self._max_entry_points = max(1, max_entry_points)

    # ------------------------------------------------------------------
    # Region selection (limited scope)
    # ------------------------------------------------------------------
    def select_entry_regions(self) -> list[dict[str, Any]]:
        """Select entry-point-reachable source regions to audit.

        Entry points are grouped by file (multiple handlers in one file become
        a single region to avoid re-reading/re-auditing the same code). Files
        that cannot be read are skipped. The number of regions is capped at
        ``max_entry_points``.

        Returns:
            List of region dicts: ``{file, line, entry_point_type, handlers,
            code, language}``.
        """
        if not self._report or not self._report.entry_points:
            return []

        # Group entry points by file, preserving first-seen type/line.
        grouped: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        for entry in self._report.entry_points:
            file_key = entry.file
            if file_key not in grouped:
                grouped[file_key] = {
                    "file": file_key,
                    "line": entry.line,
                    "entry_point_type": _ENTRY_TYPE_LABEL.get(entry.type, entry.type.value),
                    "handlers": [],
                }
                order.append(file_key)
            grouped[file_key]["handlers"].append(
                {"handler": entry.handler, "path": entry.path}
            )

        regions: list[dict[str, Any]] = []
        for file_key in order:
            if len(regions) >= self._max_entry_points:
                break
            meta = grouped[file_key]
            code = self._read_source(file_key)
            if code is None:
                self.logger.debug(f"logic_vuln: skip unreadable entry file {file_key}")
                continue
            meta["code"] = code
            meta["language"] = _guess_language(file_key)
            regions.append(meta)
        return regions

    def _read_source(self, file_key: str) -> str | None:
        """Read a source file by attack-surface-relative key, else None."""
        candidates = [self.source_path / file_key]
        if not (self.source_path / file_key).is_absolute():
            # Some detectors record absolute paths.
            candidates.append(Path(file_key))
        for candidate in candidates:
            try:
                if candidate.exists() and candidate.is_file():
                    return candidate.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                self.logger.debug(f"logic_vuln: read failed for {candidate}: {exc}")
        return None

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    async def discover(self) -> list[Finding]:
        """Run logic-vulnerability discovery over entry-reachable regions.

        Returns:
            Grounded findings tagged ``source="logic_vuln"``. Empty when no
            attack surface, no LLM client, or no regions are available.
        """
        if not self._llm_client:
            self.logger.debug("logic_vuln: no LLM client, skipping")
            return []
        if not self._report or not self._report.entry_points:
            self.logger.debug("logic_vuln: no attack surface, skipping")
            return []

        regions = self.select_entry_regions()
        if not regions:
            self.logger.info("logic_vuln: no readable entry-point regions to audit")
            return []

        self.logger.info(
            f"logic_vuln: auditing {len(regions)} entry-point region(s) "
            f"({self._report.total_entry_points} entry points total)"
        )

        findings: list[Finding] = []
        for region in regions:
            try:
                raw_findings = await self._assess_region(region)
            except Exception as exc:  # noqa: BLE001 — one bad region must not abort the scan
                self.logger.warning(
                    f"logic_vuln: assessment failed for {region.get('file')}: {exc}"
                )
                continue
            for raw in raw_findings:
                findings.append(self._to_finding(raw, region))

        self.logger.info(f"logic_vuln: produced {len(findings)} grounded finding(s)")
        return findings

    async def _assess_region(self, region: dict[str, Any]) -> list[dict[str, Any]]:
        """Call the LLM for one region and return parsed raw findings."""
        system_prompt, user_prompt = build_logic_vuln_prompt([region])
        response = await self._llm_client.complete_with_context(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            context=None,
            temperature=0.1,  # low temperature for consistent, grounded output
            max_tokens=2000,
        )
        text = response.content if hasattr(response, "content") else str(response)
        return parse_logic_vuln_response(text)

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------
    def _to_finding(self, raw: dict[str, Any], region: dict[str, Any]) -> Finding:
        """Convert a grounded raw finding dict into a Finding model."""
        category = str(raw.get("category", "business_logic"))
        severity_str = str(raw.get("severity", "medium")).lower()
        severity = _SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)

        confidence = float(raw.get("confidence", 0.5))
        confidence = max(0.0, min(self.MAX_CONFIDENCE, confidence))

        file_path = str(raw.get("file") or region.get("file") or "unknown")
        line = int(raw.get("line") or region.get("line") or 0)

        # Build a grounded description that surfaces the required evidence so
        # downstream adjudication/users can audit the claim.
        description = self._build_description(raw, category)

        return Finding(
            id=f"logic-vuln-{uuid.uuid4().hex[:8]}",
            rule_id=f"logic-vuln:{category}",
            type=FindingType.VULNERABILITY,
            severity=severity,
            confidence=confidence,
            title=str(raw.get("title", "Logic vulnerability")),
            description=description,
            location=CodeLocation(
                file=file_path,
                line=line,
                function=raw.get("function"),
            ),
            source=self.SOURCE,
            cwe=raw.get("cwe") or _CATEGORY_CWE.get(category),
            tags=["logic_vuln", category],
            evidence_strength=EvidenceStrength.SPECULATIVE,
            metadata={
                "engine": self.SOURCE,
                "category": category,
                "missing_check": raw.get("missing_check"),
                "entry_point": raw.get("entry_point"),
                "attack_path": raw.get("attack_path"),
            },
        )

    @staticmethod
    def _build_description(raw: dict[str, Any], category: str) -> str:
        """Compose a human-readable, evidence-grounded description."""
        parts = [str(raw.get("description", "Logic vulnerability detected.")).strip()]
        parts.append(f"\n[Category] {category}")
        if raw.get("missing_check"):
            parts.append(f"[Missing check] {raw['missing_check']}")
        if raw.get("entry_point"):
            parts.append(f"[Entry point] {raw['entry_point']}")
        if raw.get("attack_path"):
            parts.append(f"[Attack path] {raw['attack_path']}")
        return "\n".join(parts)


def _guess_language(file_path: str) -> str:
    """Best-effort language hint for the prompt code fence."""
    suffix = Path(file_path).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".kt": "kotlin",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
    }.get(suffix, "")
