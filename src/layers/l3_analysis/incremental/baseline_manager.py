"""
Baseline Manager - Manage historical vulnerability baselines.

Tracks vulnerabilities across scans to distinguish new issues from
previously detected ones and identify fixed vulnerabilities.
"""

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class VulnerabilityStatus(str, Enum):
    """Status of a vulnerability in the baseline."""

    NEW = "new"  # Newly detected in this scan
    PERSISTENT = "persistent"  # Previously detected, still present
    FIXED = "fixed"  # Previously detected, now resolved
    REGRESSED = "regressed"  # Was fixed, now reappeared
    MUTATED = "mutated"  # Same vuln but location/properties changed


@dataclass
class VulnerabilityBaseline:
    """
    Baseline record for a single vulnerability.

    Stores historical information for tracking vulnerability lifecycle.
    """

    # Unique identifier (stable across scans)
    vuln_id: str

    # Original detection info
    rule_id: str | None = None
    cwe: str | None = None
    title: str = ""
    severity: str = "medium"
    confidence: float = 0.8

    # Location
    file_path: str = ""
    line_start: int = 0
    line_end: int | None = None
    function_name: str | None = None
    code_snippet: str | None = None

    # Content hash for change detection
    content_hash: str = ""

    # Lifecycle tracking
    first_detected: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    first_seen_commit: str | None = None
    last_seen_commit: str | None = None
    fix_commit: str | None = None

    # Status history
    status_history: list[dict[str, Any]] = field(default_factory=list)

    # Metadata
    source: str = ""  # semgrep, codeql, agent
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "vuln_id": self.vuln_id,
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "function_name": self.function_name,
            "code_snippet": self.code_snippet,
            "content_hash": self.content_hash,
            "first_detected": self.first_detected.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "first_seen_commit": self.first_seen_commit,
            "last_seen_commit": self.last_seen_commit,
            "fix_commit": self.fix_commit,
            "status_history": self.status_history,
            "source": self.source,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VulnerabilityBaseline":
        """Create from dictionary."""
        return cls(
            vuln_id=data["vuln_id"],
            rule_id=data.get("rule_id"),
            cwe=data.get("cwe"),
            title=data.get("title", ""),
            severity=data.get("severity", "medium"),
            confidence=data.get("confidence", 0.8),
            file_path=data.get("file_path", ""),
            line_start=data.get("line_start", 0),
            line_end=data.get("line_end"),
            function_name=data.get("function_name"),
            code_snippet=data.get("code_snippet"),
            content_hash=data.get("content_hash", ""),
            first_detected=datetime.fromisoformat(data["first_detected"])
            if data.get("first_detected")
            else datetime.now(UTC),
            last_seen=datetime.fromisoformat(data["last_seen"])
            if data.get("last_seen")
            else datetime.now(UTC),
            first_seen_commit=data.get("first_seen_commit"),
            last_seen_commit=data.get("last_seen_commit"),
            fix_commit=data.get("fix_commit"),
            status_history=data.get("status_history", []),
            source=data.get("source", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class BaselineDiff:
    """Result of comparing current findings with baseline."""

    # Counts
    new_count: int = 0
    persistent_count: int = 0
    fixed_count: int = 0
    regressed_count: int = 0
    mutated_count: int = 0

    # Actual findings
    new_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    persistent_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    fixed_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    regressed_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    mutated_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)

    # Statistics
    baseline_total: int = 0
    current_total: int = 0
    comparison_time: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def total_changes(self) -> int:
        """Get total number of changes."""
        return self.new_count + self.fixed_count + self.regressed_count + self.mutated_count

    @property
    def net_change(self) -> int:
        """Get net change in vulnerability count."""
        return self.new_count + self.regressed_count - self.fixed_count

    def get_summary(self) -> str:
        """Get a summary of the diff."""
        parts = []

        if self.new_count > 0:
            parts.append(f"+{self.new_count} new")
        if self.fixed_count > 0:
            parts.append(f"-{self.fixed_count} fixed")
        if self.regressed_count > 0:
            parts.append(f"+{self.regressed_count} regressed")

        if not parts:
            return "No changes from baseline"

        return " | ".join(parts)


class BaselineManager:
    """
    Manages vulnerability baselines for incremental analysis.

    Stores historical vulnerability data and compares new findings
    against the baseline to identify new, fixed, and regressed issues.
    """

    def __init__(
        self,
        baseline_path: str | Path,
        project_hash: str | None = None,
        auto_save: bool = True,
    ):
        """
        Initialize the baseline manager.

        Args:
            baseline_path: Path to store baseline data.
            project_hash: Optional hash to identify the project.
            auto_save: Automatically save changes to disk.
        """
        self.baseline_path = Path(baseline_path)
        self.project_hash = project_hash or "default"
        self.auto_save = auto_save

        # Baseline storage
        self.baselines: dict[str, VulnerabilityBaseline] = {}
        # Index by file for quick lookup
        self.file_index: dict[str, list[str]] = {}  # file_path -> [vuln_ids]
        # Index by rule for quick lookup
        self.rule_index: dict[str, list[str]] = {}  # rule_id -> [vuln_ids]

        self._loaded = False
        self._dirty = False

        # Ensure directory exists
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_baseline_file(self) -> Path:
        """Get the baseline file path for this project."""
        return self.baseline_path.parent / f"{self.project_hash}_baseline.json"

    def _compute_finding_hash(
        self,
        file_path: str,
        line_start: int,
        rule_id: str | None,
        code_snippet: str | None,
    ) -> str:
        """
        Compute a hash for a finding to identify it uniquely.

        Uses file, line, rule, and code snippet for identification.
        """
        content = f"{file_path}:{line_start}:{rule_id or 'unknown'}"
        if code_snippet:
            content += f":{code_snippet[:100]}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _index_baseline(self, baseline: VulnerabilityBaseline) -> None:
        """Add baseline to indices."""
        # File index
        if baseline.file_path not in self.file_index:
            self.file_index[baseline.file_path] = []
        if baseline.vuln_id not in self.file_index[baseline.file_path]:
            self.file_index[baseline.file_path].append(baseline.vuln_id)

        # Rule index
        if baseline.rule_id:
            if baseline.rule_id not in self.rule_index:
                self.rule_index[baseline.rule_id] = []
            if baseline.vuln_id not in self.rule_index[baseline.rule_id]:
                self.rule_index[baseline.rule_id].append(baseline.vuln_id)

    def _remove_from_index(self, baseline: VulnerabilityBaseline) -> None:
        """Remove baseline from indices."""
        if baseline.file_path in self.file_index:
            if baseline.vuln_id in self.file_index[baseline.file_path]:
                self.file_index[baseline.file_path].remove(baseline.vuln_id)

        if baseline.rule_id and baseline.rule_id in self.rule_index:
            if baseline.vuln_id in self.rule_index[baseline.rule_id]:
                self.rule_index[baseline.rule_id].remove(baseline.vuln_id)

    async def load(self) -> bool:
        """
        Load baseline from disk.

        Returns:
            True if baseline was loaded successfully.
        """
        baseline_file = self._get_baseline_file()

        if not baseline_file.exists():
            logger.info(f"No baseline file found at {baseline_file}")
            self._loaded = True
            return False

        try:
            content = await asyncio.to_thread(baseline_file.read_text, encoding="utf-8")
            data = json.loads(content)

            self.baselines.clear()
            self.file_index.clear()
            self.rule_index.clear()

            for vuln_data in data.get("vulnerabilities", []):
                baseline = VulnerabilityBaseline.from_dict(vuln_data)
                self.baselines[baseline.vuln_id] = baseline
                self._index_baseline(baseline)

            self._loaded = True
            self._dirty = False

            logger.info(f"Loaded {len(self.baselines)} vulnerabilities from baseline")
            return True

        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return False

    async def save(self) -> bool:
        """
        Save baseline to disk.

        Returns:
            True if baseline was saved successfully.
        """
        baseline_file = self._get_baseline_file()

        try:
            data = {
                "project_hash": self.project_hash,
                "version": "1.0",
                "updated_at": datetime.now(UTC).isoformat(),
                "total_vulnerabilities": len(self.baselines),
                "vulnerabilities": [b.to_dict() for b in self.baselines.values()],
            }

            content = json.dumps(data, indent=2, ensure_ascii=False)
            await asyncio.to_thread(baseline_file.write_text, content, encoding="utf-8")

            self._dirty = False
            logger.info(f"Saved {len(self.baselines)} vulnerabilities to baseline")
            return True

        except Exception as e:
            logger.error(f"Failed to save baseline: {e}")
            return False

    def get_baseline_for_file(self, file_path: str) -> list[VulnerabilityBaseline]:
        """Get all baseline vulnerabilities for a file."""
        vuln_ids = self.file_index.get(file_path, [])
        return [self.baselines[vid] for vid in vuln_ids if vid in self.baselines]

    def get_baseline_for_rule(self, rule_id: str) -> list[VulnerabilityBaseline]:
        """Get all baseline vulnerabilities for a rule."""
        vuln_ids = self.rule_index.get(rule_id, [])
        return [self.baselines[vid] for vid in vuln_ids if vid in self.baselines]

    def compare(
        self,
        current_findings: list[dict[str, Any]],
        current_commit: str | None = None,
    ) -> BaselineDiff:
        """
        Compare current findings with baseline.

        Args:
            current_findings: List of current vulnerability findings.
            current_commit: Current commit hash.

        Returns:
            BaselineDiff with comparison results.
        """
        diff = BaselineDiff()
        diff.baseline_total = len(self.baselines)
        diff.current_total = len(current_findings)

        # Track which baseline vulns were seen
        seen_baseline_ids: set[str] = set()

        # Index current findings by their hash
        current_by_hash: dict[str, dict[str, Any]] = {}
        for finding in current_findings:
            finding_hash = self._compute_finding_hash(
                finding.get("file_path", finding.get("location", {}).get("file", "")),
                finding.get("line_start", finding.get("location", {}).get("line", 0)),
                finding.get("rule_id"),
                finding.get("code_snippet", finding.get("location", {}).get("snippet")),
            )
            current_by_hash[finding_hash] = finding

        # Check each current finding against baseline
        for finding_hash, finding in current_by_hash.items():
            file_path = finding.get("file_path", finding.get("location", {}).get("file", ""))
            line_start = finding.get("line_start", finding.get("location", {}).get("line", 0))

            # Look for matching baseline
            matched_baseline: VulnerabilityBaseline | None = None
            file_baselines = self.get_baseline_for_file(file_path)

            for baseline in file_baselines:
                # Check if this is the same vulnerability
                if baseline.content_hash == finding_hash:
                    matched_baseline = baseline
                    break

                # Fallback: same rule and nearby line
                if (
                    baseline.rule_id == finding.get("rule_id")
                    and abs(baseline.line_start - line_start) <= 5
                ):
                    matched_baseline = baseline
                    break

            if matched_baseline:
                seen_baseline_ids.add(matched_baseline.vuln_id)

                # Check if it was previously fixed (regression)
                if matched_baseline.fix_commit:
                    diff.regressed_count += 1
                    diff.regressed_vulnerabilities.append({
                        "finding": finding,
                        "baseline": matched_baseline.to_dict(),
                        "status": VulnerabilityStatus.REGRESSED.value,
                    })
                else:
                    # Persistent vulnerability
                    diff.persistent_count += 1
                    diff.persistent_vulnerabilities.append({
                        "finding": finding,
                        "baseline": matched_baseline.to_dict(),
                        "status": VulnerabilityStatus.PERSISTENT.value,
                    })

                    # Update last seen
                    matched_baseline.last_seen = datetime.now(UTC)
                    matched_baseline.last_seen_commit = current_commit
            else:
                # New vulnerability
                diff.new_count += 1
                diff.new_vulnerabilities.append({
                    "finding": finding,
                    "status": VulnerabilityStatus.NEW.value,
                })

        # Find fixed vulnerabilities (in baseline but not in current)
        for vuln_id, baseline in self.baselines.items():
            if vuln_id not in seen_baseline_ids:
                # Was not seen in current scan
                if not baseline.fix_commit:
                    # Not previously marked as fixed
                    diff.fixed_count += 1
                    diff.fixed_vulnerabilities.append({
                        "baseline": baseline.to_dict(),
                        "status": VulnerabilityStatus.FIXED.value,
                    })

                    # Mark as fixed
                    baseline.fix_commit = current_commit
                    baseline.status_history.append({
                        "status": VulnerabilityStatus.FIXED.value,
                        "timestamp": datetime.now(UTC).isoformat(),
                        "commit": current_commit,
                    })

        logger.info(
            f"Baseline comparison: {diff.new_count} new, "
            f"{diff.persistent_count} persistent, "
            f"{diff.fixed_count} fixed, "
            f"{diff.regressed_count} regressed"
        )

        if self.auto_save and diff.total_changes > 0:
            self._dirty = True

        return diff

    def update_baseline(
        self,
        findings: list[dict[str, Any]],
        commit_hash: str | None = None,
        merge_mode: bool = True,
    ) -> int:
        """
        Update baseline with new findings.

        Args:
            findings: List of current vulnerability findings.
            commit_hash: Current commit hash.
            merge_mode: If True, merge with existing; if False, replace.

        Returns:
            Number of new vulnerabilities added.
        """
        if not merge_mode:
            self.baselines.clear()
            self.file_index.clear()
            self.rule_index.clear()

        added_count = 0

        for finding in findings:
            file_path = finding.get("file_path", finding.get("location", {}).get("file", ""))
            line_start = finding.get("line_start", finding.get("location", {}).get("line", 0))
            rule_id = finding.get("rule_id")
            code_snippet = finding.get("code_snippet", finding.get("location", {}).get("snippet"))

            finding_hash = self._compute_finding_hash(
                file_path, line_start, rule_id, code_snippet
            )

            # Check if already in baseline
            if finding_hash in self.baselines:
                # Update last seen
                baseline = self.baselines[finding_hash]
                baseline.last_seen = datetime.now(UTC)
                baseline.last_seen_commit = commit_hash
                continue

            # Create new baseline entry
            baseline = VulnerabilityBaseline(
                vuln_id=finding_hash,
                rule_id=rule_id,
                cwe=finding.get("cwe"),
                title=finding.get("title", ""),
                severity=finding.get("severity", "medium"),
                confidence=finding.get("confidence", 0.8),
                file_path=file_path,
                line_start=line_start,
                line_end=finding.get("line_end", finding.get("location", {}).get("end_line")),
                function_name=finding.get("function_name", finding.get("location", {}).get("function")),
                code_snippet=code_snippet,
                content_hash=finding_hash,
                first_seen_commit=commit_hash,
                last_seen_commit=commit_hash,
                source=finding.get("source", ""),
                metadata=finding.get("metadata", {}),
            )

            self.baselines[finding_hash] = baseline
            self._index_baseline(baseline)
            added_count += 1

        if added_count > 0:
            self._dirty = True

        logger.info(f"Updated baseline: added {added_count} new vulnerabilities")
        return added_count

    def mark_false_positive(
        self,
        vuln_id: str,
        reason: str | None = None,
    ) -> bool:
        """
        Mark a vulnerability as false positive.

        Args:
            vuln_id: Vulnerability ID to mark.
            reason: Optional reason for the false positive.

        Returns:
            True if successfully marked.
        """
        if vuln_id not in self.baselines:
            return False

        baseline = self.baselines[vuln_id]
        baseline.status_history.append({
            "status": "false_positive",
            "timestamp": datetime.now(UTC).isoformat(),
            "reason": reason,
        })
        baseline.metadata["false_positive"] = True
        baseline.metadata["false_positive_reason"] = reason

        self._dirty = True
        return True

    def get_statistics(self) -> dict[str, Any]:
        """Get baseline statistics."""
        if not self.baselines:
            return {
                "total": 0,
                "by_severity": {},
                "by_source": {},
                "oldest": None,
                "newest": None,
            }

        by_severity: dict[str, int] = {}
        by_source: dict[str, int] = {}
        oldest: datetime | None = None
        newest: datetime | None = None

        for baseline in self.baselines.values():
            # By severity
            sev = baseline.severity
            by_severity[sev] = by_severity.get(sev, 0) + 1

            # By source
            src = baseline.source or "unknown"
            by_source[src] = by_source.get(src, 0) + 1

            # Dates
            if oldest is None or baseline.first_detected < oldest:
                oldest = baseline.first_detected
            if newest is None or baseline.first_detected > newest:
                newest = baseline.first_detected

        return {
            "total": len(self.baselines),
            "by_severity": by_severity,
            "by_source": by_source,
            "oldest": oldest.isoformat() if oldest else None,
            "newest": newest.isoformat() if newest else None,
            "files_affected": len(self.file_index),
            "rules_triggered": len(self.rule_index),
        }

    def cleanup_fixed(
        self,
        days_old: int = 30,
    ) -> int:
        """
        Remove old fixed vulnerabilities from baseline.

        Args:
            days_old: Remove fixed vulns older than this many days.

        Returns:
            Number of vulnerabilities removed.
        """
        cutoff = datetime.now(UTC).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        cutoff = cutoff.replace(day=cutoff.day - days_old)

        to_remove = []
        for vuln_id, baseline in self.baselines.items():
            if baseline.fix_commit and baseline.last_seen < cutoff:
                to_remove.append(vuln_id)

        for vuln_id in to_remove:
            baseline = self.baselines.pop(vuln_id)
            self._remove_from_index(baseline)

        if to_remove:
            self._dirty = True
            logger.info(f"Cleaned up {len(to_remove)} old fixed vulnerabilities")

        return len(to_remove)
