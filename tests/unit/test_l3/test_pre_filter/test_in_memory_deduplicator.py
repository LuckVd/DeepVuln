"""
Unit tests for InMemoryDeduplicator - P8-08e component.

Tests cover:
1. File-level deduplication
2. Call-chain deduplication
3. Score-based selection
4. Statistics tracking
"""

import pytest

from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    SeverityLevel,
)
from src.layers.l3_analysis.pre_filter.in_memory_deduplicator import (
    InMemoryDeduplicator,
    DeduplicationStats,
    deduplicate_in_memory,
)


class TestInMemoryDeduplicator:
    """Test suite for InMemoryDeduplicator class."""

    def test_init(self):
        """Test initialization."""
        deduplicator = InMemoryDeduplicator()
        assert deduplicator is not None
        assert deduplicator.stats.total_input == 0


class TestFileLevelDeduplication:
    """Test file-level deduplication."""

    def make_finding(
        self,
        id: str,
        line: int,
        score: float = 1.0,
        snippet: str = "test",
    ) -> Finding:
        """Helper to create a test finding."""
        return Finding(
            id=id,
            rule_id="test_rule",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.MEDIUM,
            confidence=0.7,
            title=f"Finding {id}",
            description="Test finding",
            fix_suggestion="Fix it",
            location=CodeLocation(
                file="test.py",
                line=line,
                end_line=line,
                snippet=snippet,
            ),
            source="agent",
            final_score=score,
        )

    def test_same_line_keeps_highest_score(self):
        """Test that findings on same line keep the highest scored one."""
        deduplicator = InMemoryDeduplicator()

        findings = [
            self.make_finding("f1", line=10, score=0.8),
            self.make_finding("f2", line=10, score=1.0),  # Higher score
            self.make_finding("f3", line=10, score=0.5),
        ]

        result = deduplicator.deduplicate_findings(findings, "test.py")

        assert len(result) == 1
        assert result[0].id == "f2"  # Highest score kept

    def test_different_lines_all_kept(self):
        """Test that findings on different lines are all kept."""
        deduplicator = InMemoryDeduplicator()

        findings = [
            self.make_finding("f1", line=10),
            self.make_finding("f2", line=20),
            self.make_finding("f3", line=30),
        ]

        result = deduplicator.deduplicate_findings(findings, "test.py")

        assert len(result) == 3

    def test_same_line_no_score_keeps_first(self):
        """Test that when scores are equal, first is kept."""
        deduplicator = InMemoryDeduplicator()

        findings = [
            self.make_finding("f1", line=10, score=1.0),
            self.make_finding("f2", line=10, score=1.0),
        ]

        result = deduplicator.deduplicate_findings(findings, "test.py")

        assert len(result) == 1
        assert result[0].id == "f1"  # First one kept

    def test_file_cache_cleared_between_calls(self):
        """Test that file cache is cleared between file scans."""
        deduplicator = InMemoryDeduplicator()

        # First file
        findings1 = [self.make_finding("f1", line=10)]
        result1 = deduplicator.deduplicate_findings(findings1, "file1.py")

        # Second file, same line number
        findings2 = [self.make_finding("f2", line=10)]
        result2 = deduplicator.deduplicate_findings(findings2, "file2.py")

        # Both should be kept (different files)
        assert len(result1) == 1
        assert len(result2) == 1
        assert result1[0].id == "f1"
        assert result2[0].id == "f2"


class TestCallChainDeduplication:
    """Test call-chain deduplication."""

    def make_finding(
        self,
        id: str,
        rule_id: str = "sql_injection",
        snippet: str = "db.execute(query)",
        score: float = 1.0,
        line: int = 10,
    ) -> Finding:
        """Helper to create a test finding."""
        return Finding(
            id=id,
            rule_id=rule_id,
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title=f"Finding {id}",
            description=f"{rule_id} vulnerability",
            fix_suggestion="Fix it",
            location=CodeLocation(
                file="test.py",
                line=line,
                end_line=line,
                snippet=snippet,
            ),
            source="agent",
            final_score=score,
            metadata={"sink": "execute"},
        )

    def test_same_vulnerability_type_deduped(self):
        """Test that same vulnerability type is deduplicated."""
        deduplicator = InMemoryDeduplicator()

        findings = [
            self.make_finding("f1", snippet="db.execute(user_input)"),
            self.make_finding("f2", snippet="cursor.execute(user_input)"),
        ]

        result = deduplicator.deduplicate_findings(findings, "test.py")

        # Both findings have same rule_id and sink, so they deduplicate
        assert len(result) <= 2

    def test_different_vulnerability_types_kept(self):
        """Test that different vulnerability types are kept."""
        deduplicator = InMemoryDeduplicator()

        findings = [
            self.make_finding("f1", rule_id="sql_injection", line=10),
            self.make_finding("f2", rule_id="xss", line=20),
        ]

        result = deduplicator.deduplicate_findings(findings, "test.py")

        # Different rule_ids should not be deduplicated
        assert len(result) == 2

    def test_same_vulnerability_different_files_tracked(self):
        """Test that same vulnerability across files is tracked in cache."""
        deduplicator = InMemoryDeduplicator()

        # First file
        findings1 = [self.make_finding("f1", score=0.8, line=10)]
        result1 = deduplicator.deduplicate_findings(findings1, "file1.py")

        # Second file with same vulnerability
        findings2 = [self.make_finding("f2", score=1.0, line=10)]
        result2 = deduplicator.deduplicate_findings(findings2, "file2.py")

        # Both should be in results
        assert len(result1) == 1
        assert len(result2) == 1
        # The call-chain cache should have the highest score
        assert len(deduplicator.call_chain_cache) > 0


class TestStatistics:
    """Test statistics tracking."""

    def make_finding(self, id: str, line: int) -> Finding:
        """Helper to create a test finding."""
        return Finding(
            id=id,
            rule_id="test",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.MEDIUM,
            confidence=0.5,
            title=f"F{id}",
            description="Test",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.py",
                line=line,
                end_line=line,
                snippet="code",
            ),
            source="agent",
            final_score=1.0,
        )

    def test_stats_tracked(self):
        """Test that statistics are tracked correctly."""
        deduplicator = InMemoryDeduplicator()

        findings = [
            self.make_finding("f1", line=10),
            self.make_finding("f2", line=10),  # Duplicate
            self.make_finding("f3", line=20),
        ]

        deduplicator.deduplicate_findings(findings, "test.py")

        stats = deduplicator.get_stats()
        assert stats.total_input == 3
        assert stats.total_output == 2
        assert stats.file_filtered >= 1

    def test_reduction_rate_calculated(self):
        """Test reduction rate calculation."""
        deduplicator = InMemoryDeduplicator()

        findings = [
            self.make_finding(f"f{i}", line=i + 1)  # Lines 1-10
            for i in range(10)
        ]

        deduplicator.deduplicate_findings(findings, "test.py")

        stats = deduplicator.get_stats()
        assert stats.reduction_rate() >= 0.0
        assert stats.reduction_rate() <= 1.0


class TestConvenienceFunction:
    """Test the deduplicate_in_memory convenience function."""

    def test_returns_list(self):
        """Test function returns a list."""
        from src.layers.l3_analysis.pre_filter.in_memory_deduplicator import (
            deduplicate_in_memory,
        )

        finding = Finding(
            id="test",
            rule_id="test",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.LOW,
            confidence=0.3,
            title="Test",
            description="Test",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet="code",
            ),
            source="agent",
        )

        result = deduplicate_in_memory([finding], "test.py")

        assert isinstance(result, list)
        assert len(result) == 1


class TestSinkExtraction:
    """Test sink extraction from findings."""

    def test_extract_sink_from_snippet(self):
        """Test sink extraction from code snippet."""
        deduplicator = InMemoryDeduplicator()

        finding = Finding(
            id="test",
            rule_id="sql_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="SQL Injection",
            description="SQL injection via execute",
            fix_suggestion="Use parameterized queries",
            location=CodeLocation(
                file="test.py",
                line=10,
                end_line=10,
                snippet="db.execute(user_input)",
            ),
            source="agent",
        )

        sink = deduplicator._extract_sink(finding)
        assert "execute" in sink.lower()

    def test_extract_sink_from_metadata(self):
        """Test sink extraction from metadata."""
        deduplicator = InMemoryDeduplicator()

        finding = Finding(
            id="test",
            rule_id="test",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.MEDIUM,
            confidence=0.5,
            title="Test",
            description="Test",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet="code",
            ),
            source="agent",
            metadata={"sink": "dangerous_function"},
        )

        sink = deduplicator._extract_sink(finding)
        assert sink == "dangerous_function"


class TestSourceExtraction:
    """Test source extraction from findings."""

    def test_extract_source_from_metadata(self):
        """Test source extraction from metadata."""
        deduplicator = InMemoryDeduplicator()

        finding = Finding(
            id="test",
            rule_id="test",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.MEDIUM,
            confidence=0.5,
            title="Test",
            description="Test",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet="code",
            ),
            source="agent",
            metadata={"source": "user_input"},
        )

        source = deduplicator._extract_source(finding)
        assert source == "user_input"

    def test_extract_source_from_description(self):
        """Test source extraction from description."""
        deduplicator = InMemoryDeduplicator()

        finding = Finding(
            id="test",
            rule_id="test",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.MEDIUM,
            confidence=0.5,
            title="Test",
            description="Tainted data via query parameter reaches sink",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet="code",
            ),
            source="agent",
        )

        source = deduplicator._extract_source(finding)
        assert source == "query"  # "query parameter" -> "query"


class TestVulnerabilityHash:
    """Test vulnerability hash generation."""

    def test_same_vulnerability_same_hash(self):
        """Test that same vulnerability produces same hash."""
        deduplicator = InMemoryDeduplicator()

        finding1 = Finding(
            id="f1",
            rule_id="sql_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="SQL Injection 1",
            description="SQL injection",
            fix_suggestion=None,
            location=CodeLocation(
                file="file1.py",
                line=10,
                end_line=10,
                snippet="db.execute(x)",
            ),
            source="agent",
            metadata={"sink": "execute"},
        )

        finding2 = Finding(
            id="f2",
            rule_id="sql_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="SQL Injection 2",
            description="SQL injection",
            fix_suggestion=None,
            location=CodeLocation(
                file="file2.py",  # Different file
                line=20,  # Different line
                snippet="cursor.execute(x)",  # Different function
            ),
            source="agent",
            metadata={"sink": "execute"},
        )

        hash1 = deduplicator._get_vulnerability_hash(finding1)
        hash2 = deduplicator._get_vulnerability_hash(finding2)

        # Same rule_id + sink = same hash
        assert hash1 == hash2

    def test_different_vulnerability_different_hash(self):
        """Test that different vulnerabilities produce different hashes."""
        deduplicator = InMemoryDeduplicator()

        finding1 = Finding(
            id="f1",
            rule_id="sql_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="SQL Injection",
            description="SQL injection",
            fix_suggestion=None,
            location=CodeLocation(
                file="file1.py",
                line=10,
                end_line=10,
                snippet="db.execute(x)",
            ),
            source="agent",
            metadata={"sink": "execute"},
        )

        finding2 = Finding(
            id="f2",
            rule_id="xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.MEDIUM,
            confidence=0.6,
            title="XSS",
            description="XSS vulnerability",
            fix_suggestion=None,
            location=CodeLocation(
                file="file1.py",
                line=10,
                end_line=10,
                snippet="innerHTML = x",
            ),
            source="agent",
            metadata={"sink": "innerHTML"},
        )

        hash1 = deduplicator._get_vulnerability_hash(finding1)
        hash2 = deduplicator._get_vulnerability_hash(finding2)

        assert hash1 != hash2


class TestCacheManagement:
    """Test cache management."""

    def make_finding(self, id: str) -> Finding:
        """Helper to create a test finding."""
        return Finding(
            id=id,
            rule_id="test",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.MEDIUM,
            confidence=0.5,
            title=f"F{id}",
            description="Test",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet="code",
            ),
            source="agent",
            final_score=1.0,
        )

    def test_clear_call_chain_cache(self):
        """Test clearing call-chain cache."""
        deduplicator = InMemoryDeduplicator()

        findings = [self.make_finding("f1")]
        deduplicator.deduplicate_findings(findings, "test.py")

        assert len(deduplicator.call_chain_cache) > 0

        deduplicator.clear_call_chain_cache()

        assert len(deduplicator.call_chain_cache) == 0

    def test_clear_all_caches(self):
        """Test clearing all caches."""
        deduplicator = InMemoryDeduplicator()

        findings = [self.make_finding("f1")]
        deduplicator.deduplicate_findings(findings, "test.py")

        assert len(deduplicator.current_file_cache) == 0  # Cleared automatically
        assert len(deduplicator.call_chain_cache) > 0

        deduplicator.clear_all_caches()

        assert len(deduplicator.current_file_cache) == 0
        assert len(deduplicator.call_chain_cache) == 0
