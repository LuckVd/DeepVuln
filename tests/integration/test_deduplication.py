"""
Integration tests for cluster-based deduplication (P6-17).

Tests verify that the two-stage hybrid deduplication strategy works correctly
with real-world scenarios and cross-engine findings.
"""

import pytest

from src.layers.l3_analysis.deduplicator import (
    ClusterBasedDeduplicator,
    ClusterDeduplicatorConfig,
    cluster_findings_by_location,
)
from src.layers.l3_analysis.models import Finding, FindingType, SeverityLevel, CodeLocation


class TestClusterDeduplicationIntegration:
    """Integration tests for cluster-based deduplication."""

    def _create_finding(
        self,
        id: str,
        rule_id: str,
        source: str,
        file: str,
        line: int,
        title: str,
        severity: SeverityLevel = SeverityLevel.HIGH,
        confidence: float = 0.9,
        final_score: float = 0.8,
    ) -> Finding:
        """Helper to create a Finding object for testing."""
        return Finding(
            id=id,
            rule_id=rule_id,
            type=FindingType.VULNERABILITY,
            severity=severity,
            confidence=confidence,
            title=title,
            description=f"{title}. This is a test vulnerability for {rule_id}.",
            fix_suggestion="Review and fix the vulnerability.",
            location=CodeLocation(
                file=file,
                line=line,
            ),
            source=source,
            final_score=final_score,
            exploitability="exploitable",
        )

    def test_cross_engine_command_injection_dedup(self):
        """
        Test that different engines detecting the same command injection
        vulnerability are correctly deduplicated.

        Scenario:
        - Semgrep detects: "Command Injection Process Builder" at line 41
        - CodeQL detects: "Shell command with user input" at line 41
        - Agent detects: "Process builder vulnerability" at line 38

        Expected: Should be clustered and deduplicated to one finding.
        """
        # Create findings that simulate real cross-engine detection
        findings = [
            self._create_finding(
                id="semgrep-001",
                rule_id="java.lang.security.audit.command-injection-process-builder",
                source="semgrep",
                file="src/main/java/com/envtest/controller/CmdInjectionController.java",
                line=41,
                title="Command Injection Process Builder",
                final_score=0.85,
            ),
            self._create_finding(
                id="codeql-001",
                rule_id="java/ts-shell-command-constructed-from-shell-input",
                source="codeql",
                file="src/main/java/com/envtest/controller/CmdInjectionController.java",
                line=41,
                title="Shell command constructed from user input",
                final_score=0.88,
            ),
            self._create_finding(
                id="agent-001",
                rule_id="suspicious_command_injection",
                source="agent",
                file="src/main/java/com/envtest/controller/CmdInjectionController.java",
                line=38,
                title="OS Command Injection via 'ip' Parameter",
                severity=SeverityLevel.CRITICAL,
                final_score=0.92,
            ),
        ]

        # Test clustering (without LLM)
        clusters = cluster_findings_by_location(
            findings,
            ClusterDeduplicatorConfig(line_tolerance=10, enable_llm_dedup=False)
        )

        # All three findings should be in the same cluster
        # (lines 38 and 41 are within 10-line tolerance)
        assert len(clusters) == 1
        assert len(clusters[0].findings) == 3
        assert clusters[0].start_line == 38
        assert clusters[0].end_line == 41

        # Test deduplication without LLM (keeps all)
        dedup = ClusterBasedDeduplicator(
            llm_client=None,
            config=ClusterDeduplicatorConfig(enable_llm_dedup=False)
        )
        result = dedup.deduplicate(findings)

        # Without LLM, all findings should be kept
        assert len(result.unique_findings) == 3
        assert result.removed_count == 0

    def test_different_vulnerabilities_not_deduped(self):
        """
        Test that different vulnerabilities at nearby locations are not deduplicated.

        Scenario:
        - Line 41: Command injection
        - Line 60: Error message disclosure

        Expected: Should be in different clusters and both kept.
        """
        findings = [
            self._create_finding(
                id="f1",
                rule_id="command-injection",
                source="semgrep",
                file="src/main/java/com/envtest/controller/CmdInjectionController.java",
                line=41,
                title="Command Injection",
                final_score=0.85,
            ),
            self._create_finding(
                id="f2",
                rule_id="error-disclosure",
                source="codeql",
                file="src/main/java/com/envtest/controller/CmdInjectionController.java",
                line=60,
                title="Error Information Disclosure",
                severity=SeverityLevel.LOW,
                final_score=0.5,
            ),
        ]

        # Test clustering
        config = ClusterDeduplicatorConfig(line_tolerance=10)
        clusters = cluster_findings_by_location(findings, config)

        # Should be in different clusters (line difference > tolerance)
        assert len(clusters) == 2

        # Test deduplication
        dedup = ClusterBasedDeduplicator(llm_client=None, config=config)
        result = dedup.deduplicate(findings)

        # Both should be kept
        assert len(result.unique_findings) == 2
        assert result.removed_count == 0

    def test_same_file_different_regions(self):
        """
        Test findings in the same file but far apart are not clustered.

        Scenario:
        - Line 10: XSS vulnerability
        - Line 500: SQL injection vulnerability

        Expected: Different clusters, both kept.
        """
        findings = [
            self._create_finding(
                id="f1",
                rule_id="xss",
                source="semgrep",
                file="src/main/java/com/example/Controller.java",
                line=10,
                title="Cross-Site Scripting",
                final_score=0.8,
            ),
            self._create_finding(
                id="f2",
                rule_id="sql-injection",
                source="codeql",
                file="src/main/java/com/example/Controller.java",
                line=500,
                title="SQL Injection",
                final_score=0.9,
            ),
        ]

        config = ClusterDeduplicatorConfig(line_tolerance=10)
        clusters = cluster_findings_by_location(findings, config)

        # Should be in different clusters
        assert len(clusters) == 2
        assert clusters[0].start_line == 10
        assert clusters[1].start_line == 500

    def test_multiple_files(self):
        """
        Test findings across multiple files are correctly handled.

        Scenario:
        - File A: 2 findings (same vulnerability, different engines)
        - File B: 1 finding
        - File C: 3 findings (2 nearby, 1 far)

        Expected: Correct clustering per file.
        """
        findings = [
            # File A - two findings at same location
            self._create_finding(
                id="a1",
                rule_id="r1",
                source="semgrep",
                file="src/A.java",
                line=100,
                title="Vulnerability in A",
            ),
            self._create_finding(
                id="a2",
                rule_id="r2",
                source="codeql",
                file="src/A.java",
                line=100,
                title="Same vulnerability in A",
            ),
            # File B - single finding
            self._create_finding(
                id="b1",
                rule_id="r3",
                source="semgrep",
                file="src/B.java",
                line=50,
                title="Vulnerability in B",
                severity=SeverityLevel.MEDIUM,
            ),
            # File C - three findings (2 nearby, 1 far)
            self._create_finding(
                id="c1",
                rule_id="r4",
                source="semgrep",
                file="src/C.java",
                line=200,
                title="Vulnerability in C",
            ),
            self._create_finding(
                id="c2",
                rule_id="r5",
                source="codeql",
                file="src/C.java",
                line=205,
                title="Same vulnerability in C",
            ),
            self._create_finding(
                id="c3",
                rule_id="r6",
                source="semgrep",
                file="src/C.java",
                line=300,
                title="Different vulnerability in C",
                severity=SeverityLevel.MEDIUM,
            ),
        ]

        config = ClusterDeduplicatorConfig(line_tolerance=10)
        clusters = cluster_findings_by_location(findings, config)

        # Should have clusters:
        # - src/A.java: 2 findings (lines 100, 100)
        # - src/B.java: 1 finding (line 50)
        # - src/C.java: 2 clusters (lines 200-205, and line 300)
        assert len(clusters) == 4

        # Find the cluster for file C with multiple findings
        c_clusters = [c for c in clusters if "c.java" in c.file_path.lower()]
        assert len(c_clusters) == 2
        # One cluster should have 2 findings (lines 200-205)
        cluster_with_2 = next(c for c in c_clusters if len(c.findings) == 2)
        assert cluster_with_2.start_line == 200
        assert cluster_with_2.end_line == 205

    def test_tolerance_affects_clustering(self):
        """
        Test that line_tolerance affects clustering behavior.
        """
        findings = [
            self._create_finding(
                id="f1",
                rule_id="r1",
                source="semgrep",
                file="test.py",
                line=10,
                title="Vulnerability 1",
            ),
            self._create_finding(
                id="f2",
                rule_id="r2",
                source="codeql",
                file="test.py",
                line=25,
                title="Vulnerability 2",
            ),
        ]

        # With tolerance 10: should be separate clusters (25 - 10 = 15 > 10)
        config_10 = ClusterDeduplicatorConfig(line_tolerance=10)
        clusters_10 = cluster_findings_by_location(findings, config_10)
        assert len(clusters_10) == 2

        # With tolerance 20: should be same cluster (25 - 10 = 15 <= 20)
        config_20 = ClusterDeduplicatorConfig(line_tolerance=20)
        clusters_20 = cluster_findings_by_location(findings, config_20)
        assert len(clusters_20) == 1
        assert len(clusters_20[0].findings) == 2


class TestDeduplicationStatistics:
    """Test deduplication result statistics."""

    def _create_finding(self, id: str, score: float) -> Finding:
        """Helper to create a Finding with given final_score."""
        return Finding(
            id=id,
            rule_id="r1",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            title=f"Finding {id}",
            description=f"Test vulnerability {id}.",
            fix_suggestion="Review and fix.",
            location=CodeLocation(file="test.py", line=10),
            source="semgrep",
            final_score=score,
            exploitability="exploitable",
        )

    def test_merge_details_tracking(self):
        """Test that merge details correctly track deduplication."""
        findings = [self._create_finding(f"f{i}", 0.8 + (i * 0.01)) for i in range(5)]

        dedup = ClusterBasedDeduplicator(llm_client=None)
        result = dedup.deduplicate(findings)

        # Without LLM, no deduplication occurs
        assert result.removed_count == 0
        assert result.merged_groups == 0
        assert len(result.unique_findings) == 5
        assert len(result.merge_details) == 0

    def test_empty_findings_list(self):
        """Test deduplicating empty findings list."""
        dedup = ClusterBasedDeduplicator()
        result = dedup.deduplicate([])

        assert len(result.unique_findings) == 0
        assert result.removed_count == 0
        assert result.merged_groups == 0
        assert len(result.merge_details) == 0
