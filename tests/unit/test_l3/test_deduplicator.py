"""Unit tests for AST-Based Semantic Deduplication module."""

import pytest

from src.layers.l3_analysis.deduplicator import (
    DeduplicationResult,
    normalize_code_element,
    normalize_function_name,
    normalize_file_path,
    generate_ast_hash,
    extract_sink,
    extract_source,
    extract_data_flow_path,
    extract_category,
    get_exploitability_level,
    get_engine_weight,
    compare_findings_for_merge,
    merge_findings,
    ASTDeduplicator,
    deduplicate_findings,
)


class MockFinding:
    """Mock Finding object for testing."""

    def __init__(
        self,
        finding_id="test-001",
        rule_id="rule-001",
        source="semgrep",
        severity="high",
        final_score=0.8,
        exploitability="exploitable",
        final_status="exploitable",
        location=None,
        metadata=None,
        cwe=None,
        owasp=None,
    ):
        self.id = finding_id
        self.rule_id = rule_id
        self.source = source
        self.severity = severity
        self.final_score = final_score
        self.exploitability = exploitability
        self.final_status = final_status
        self.location = location or MockLocation()
        self.metadata = metadata or {}
        self.cwe = cwe
        self.owasp = owasp
        self.related_engines = []
        self.duplicate_count = 0


class MockLocation:
    """Mock Location object for testing."""

    def __init__(self, file="test.py", line=10, function="process_input"):
        self.file = file
        self.line = line
        self.function = function


# ============================================================
# Test DeduplicationResult
# ============================================================

class TestDeduplicationResult:
    """Test DeduplicationResult dataclass."""

    def test_create_result(self):
        """Test creating result."""
        result = DeduplicationResult(
            unique_findings=[MockFinding()],
            removed_count=5,
            merged_groups=3,
        )
        assert len(result.unique_findings) == 1
        assert result.removed_count == 5
        assert result.merged_groups == 3

    def test_to_dict(self):
        """Test converting to dictionary."""
        result = DeduplicationResult(
            unique_findings=[MockFinding(), MockFinding()],
            removed_count=3,
            merged_groups=2,
        )
        d = result.to_dict()
        assert d["removed"] == 3
        assert d["groups"] == 2
        assert d["unique_count"] == 2

    def test_empty_result(self):
        """Test empty result."""
        result = DeduplicationResult(unique_findings=[])
        assert len(result.unique_findings) == 0
        assert result.removed_count == 0


# ============================================================
# Test Normalization Functions
# ============================================================

class TestNormalizeCodeElement:
    """Test normalize_code_element function."""

    def test_normalize_whitespace(self):
        """Test whitespace normalization."""
        assert normalize_code_element("  hello   world  ") == "hello world"

    def test_normalize_quotes(self):
        """Test quote normalization."""
        assert normalize_code_element('"test"') == "'x'"

    def test_normalize_variables(self):
        """Test variable name anonymization."""
        assert normalize_code_element("$USER_INPUT") == "$x"
        assert normalize_code_element("${variable}") == "$x"
        assert normalize_code_element("{{template_var}}") == "{{x}}"

    def test_normalize_empty(self):
        """Test empty input."""
        assert normalize_code_element(None) == ""
        assert normalize_code_element("") == ""

    def test_normalize_case(self):
        """Test case normalization."""
        assert normalize_code_element("EXEC") == "exec"


class TestNormalizeFunctionName:
    """Test normalize_function_name function."""

    def test_remove_self_prefix(self):
        """Test removing self. prefix."""
        assert normalize_function_name("self.process") == "process"

    def test_remove_this_prefix(self):
        """Test removing this. prefix."""
        assert normalize_function_name("this.handle") == "handle"

    def test_remove_cls_prefix(self):
        """Test removing cls. prefix."""
        assert normalize_function_name("cls.validate") == "validate"

    def test_normalize_empty(self):
        """Test empty input."""
        assert normalize_function_name(None) == ""
        assert normalize_function_name("") == ""

    def test_normalize_case(self):
        """Test case normalization."""
        assert normalize_function_name("ProcessInput") == "processinput"


class TestNormalizeFilePath:
    """Test normalize_file_path function."""

    def test_normalize_separators(self):
        """Test path separator normalization."""
        assert normalize_file_path("path\\to\\file.py") == "path/to/file.py"

    def test_remove_leading_dot_slash(self):
        """Test removing leading ./"""
        assert normalize_file_path("./src/file.py") == "src/file.py"

    def test_remove_leading_slash(self):
        """Test removing leading /"""
        assert normalize_file_path("/home/user/file.py") == "home/user/file.py"

    def test_normalize_empty(self):
        """Test empty input."""
        assert normalize_file_path(None) == ""
        assert normalize_file_path("") == ""


# ============================================================
# Test Extract Functions
# ============================================================

class TestExtractSink:
    """Test extract_sink function."""

    def test_extract_from_metadata_sink(self):
        """Test extracting sink from metadata."""
        finding = MockFinding(metadata={"sink": "eval()"})
        assert extract_sink(finding) == "eval()"

    def test_extract_from_metadata_taint_sink(self):
        """Test extracting from taint_sink."""
        finding = MockFinding(metadata={"taint_sink": "exec()"})
        assert extract_sink(finding) == "exec()"

    def test_extract_from_location_function(self):
        """Test extracting from location function."""
        finding = MockFinding()
        assert extract_sink(finding) == "process_input"

    def test_extract_none(self):
        """Test when no sink available."""
        finding = MockFinding()
        finding.location.function = None
        finding.metadata = {}
        assert extract_sink(finding) is None


class TestExtractSource:
    """Test extract_source function."""

    def test_extract_from_metadata_source(self):
        """Test extracting source from metadata."""
        finding = MockFinding(metadata={"source": "request.params"})
        assert extract_source(finding) == "request.params"

    def test_extract_from_metadata_taint_source(self):
        """Test extracting from taint_source."""
        finding = MockFinding(metadata={"taint_source": "user_input"})
        assert extract_source(finding) == "user_input"

    def test_extract_none(self):
        """Test when no source available."""
        finding = MockFinding(metadata={})
        assert extract_source(finding) is None


class TestExtractDataFlowPath:
    """Test extract_data_flow_path function."""

    def test_extract_data_flow_path(self):
        """Test extracting data flow path."""
        finding = MockFinding(metadata={"data_flow_path": "a -> b -> c"})
        assert extract_data_flow_path(finding) == "a -> b -> c"

    def test_extract_taint_path(self):
        """Test extracting taint path."""
        finding = MockFinding(metadata={"taint_path": "input -> sanitize -> output"})
        assert extract_data_flow_path(finding) == "input -> sanitize -> output"

    def test_extract_none(self):
        """Test when no path available."""
        finding = MockFinding(metadata={})
        assert extract_data_flow_path(finding) is None


class TestExtractCategory:
    """Test extract_category function."""

    def test_extract_cwe(self):
        """Test extracting CWE."""
        finding = MockFinding(cwe="CWE-79")
        assert extract_category(finding) == "cwe:CWE-79"

    def test_extract_owasp(self):
        """Test extracting OWASP."""
        finding = MockFinding(owasp="A03:2021")
        assert extract_category(finding) == "owasp:A03:2021"

    def test_extract_rule_id(self):
        """Test extracting rule_id as fallback."""
        finding = MockFinding(cwe=None, owasp=None, rule_id="xss-rule")
        assert extract_category(finding) == "rule:xss-rule"

    def test_extract_unknown(self):
        """Test unknown category."""
        finding = MockFinding(cwe=None, owasp=None, rule_id=None)
        assert extract_category(finding) == "unknown"


# ============================================================
# Test AST Hash Generation
# ============================================================

class TestGenerateAstHash:
    """Test generate_ast_hash function."""

    def test_generate_basic(self):
        """Test basic hash generation."""
        finding = MockFinding()
        hash1 = generate_ast_hash(finding)
        assert hash1.startswith("ast_")
        assert len(hash1) == 20  # "ast_" + 16 hex chars

    def test_same_finding_same_hash(self):
        """Test same finding produces same hash."""
        finding = MockFinding()
        hash1 = generate_ast_hash(finding)
        hash2 = generate_ast_hash(finding)
        assert hash1 == hash2

    def test_different_rule_different_hash(self):
        """Test different rule_id produces different hash."""
        finding1 = MockFinding(rule_id="rule-001")
        finding2 = MockFinding(rule_id="rule-002")
        hash1 = generate_ast_hash(finding1)
        hash2 = generate_ast_hash(finding2)
        assert hash1 != hash2

    def test_different_file_different_hash(self):
        """Test different file produces different hash."""
        finding1 = MockFinding(location=MockLocation(file="a.py"))
        finding2 = MockFinding(location=MockLocation(file="b.py"))
        hash1 = generate_ast_hash(finding1)
        hash2 = generate_ast_hash(finding2)
        assert hash1 != hash2

    def test_same_semantic_same_hash(self):
        """Test semantically equivalent findings have same hash."""
        # Same rule, file, function, sink
        finding1 = MockFinding(
            rule_id="xss-rule",
            location=MockLocation(file="api.py", function="handle"),
            metadata={"sink": "response.write"},
        )
        finding2 = MockFinding(
            rule_id="xss-rule",
            location=MockLocation(file="api.py", function="handle"),
            metadata={"sink": "response.write"},
        )
        hash1 = generate_ast_hash(finding1)
        hash2 = generate_ast_hash(finding2)
        assert hash1 == hash2

    def test_different_line_same_hash(self):
        """Test different line numbers don't affect hash."""
        finding1 = MockFinding(location=MockLocation(file="test.py", line=10))
        finding2 = MockFinding(location=MockLocation(file="test.py", line=100))
        hash1 = generate_ast_hash(finding1)
        hash2 = generate_ast_hash(finding2)
        # Same hash because line number is not part of hash
        assert hash1 == hash2


# ============================================================
# Test Helper Functions
# ============================================================

class TestGetExploitabilityLevel:
    """Test get_exploitability_level function."""

    def test_exploitable_level(self):
        """Test exploitable is highest."""
        assert get_exploitability_level("exploitable") == 4
        assert get_exploitability_level("confirmed") == 4

    def test_not_exploitable_level(self):
        """Test not_exploitable is lowest."""
        assert get_exploitability_level("not_exploitable") == 0
        assert get_exploitability_level("safe") == 0

    def test_intermediate_levels(self):
        """Test intermediate levels."""
        assert get_exploitability_level("unlikely") == 1
        assert get_exploitability_level("possible") == 2
        assert get_exploitability_level("likely") == 3

    def test_none_level(self):
        """Test None returns 0."""
        assert get_exploitability_level(None) == 0

    def test_unknown_level(self):
        """Test unknown returns default."""
        assert get_exploitability_level("unknown") == 2


class TestGetEngineWeight:
    """Test get_engine_weight function."""

    def test_agent_weight(self):
        """Test agent has highest weight."""
        assert get_engine_weight("agent") == 1.0

    def test_codeql_weight(self):
        """Test codeql weight."""
        assert get_engine_weight("codeql") == 0.9

    def test_semgrep_weight(self):
        """Test semgrep weight."""
        assert get_engine_weight("semgrep") == 0.8

    def test_unknown_weight(self):
        """Test unknown engine returns default."""
        assert get_engine_weight("unknown") == 0.5

    def test_none_weight(self):
        """Test None returns default."""
        assert get_engine_weight(None) == 0.5


class TestCompareFindingsForMerge:
    """Test compare_findings_for_merge function."""

    def test_higher_score_wins(self):
        """Test higher final_score wins."""
        a = MockFinding(final_score=0.9)
        b = MockFinding(final_score=0.5)
        assert compare_findings_for_merge(a, b) > 0

    def test_higher_engine_weight_wins(self):
        """Test higher engine weight wins when scores equal."""
        a = MockFinding(final_score=0.8, source="agent")
        b = MockFinding(final_score=0.8, source="semgrep")
        assert compare_findings_for_merge(a, b) > 0

    def test_higher_exploitability_wins(self):
        """Test higher exploitability wins when others equal."""
        a = MockFinding(final_score=0.8, source="semgrep", exploitability="exploitable")
        b = MockFinding(final_score=0.8, source="semgrep", exploitability="possible")
        assert compare_findings_for_merge(a, b) > 0

    def test_equal_findings(self):
        """Test equal findings return 0."""
        a = MockFinding()
        b = MockFinding()
        assert compare_findings_for_merge(a, b) == 0


class TestMergeFindings:
    """Test merge_findings function."""

    def test_merge_adds_related_engine(self):
        """Test merge adds secondary engine to related_engines."""
        primary = MockFinding(source="semgrep")
        secondary = MockFinding(source="codeql")
        result = merge_findings(primary, secondary)
        assert "semgrep" in result.related_engines
        assert "codeql" in result.related_engines

    def test_merge_increments_duplicate_count(self):
        """Test merge increments duplicate_count."""
        primary = MockFinding()
        secondary = MockFinding()
        result = merge_findings(primary, secondary)
        assert result.duplicate_count == 1

    def test_merge_multiple(self):
        """Test merging multiple findings."""
        primary = MockFinding(source="agent")
        secondary1 = MockFinding(source="semgrep")
        secondary2 = MockFinding(source="codeql")
        result = merge_findings(primary, secondary1)
        result = merge_findings(result, secondary2)
        assert result.duplicate_count == 2
        assert len(result.related_engines) == 3

    def test_merge_preserves_metadata(self):
        """Test merge preserves metadata."""
        primary = MockFinding(metadata={"key1": "value1"})
        secondary = MockFinding(metadata={"key2": "value2"})
        result = merge_findings(primary, secondary)
        assert result.metadata.get("key1") == "value1"
        assert result.metadata.get("key2") == "value2"


# ============================================================
# Test ASTDeduplicator
# ============================================================

class TestASTDeduplicator:
    """Test ASTDeduplicator class."""

    def test_empty_findings(self):
        """Test empty findings."""
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate([])
        assert len(result.unique_findings) == 0
        assert result.removed_count == 0

    def test_single_finding(self):
        """Test single finding."""
        finding = MockFinding()
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate([finding])
        assert len(result.unique_findings) == 1
        assert result.removed_count == 0

    def test_no_duplicates(self):
        """Test no duplicates."""
        findings = [
            MockFinding(finding_id="f1", rule_id="r1"),
            MockFinding(finding_id="f2", rule_id="r2"),
            MockFinding(finding_id="f3", rule_id="r3"),
        ]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert len(result.unique_findings) == 3
        assert result.removed_count == 0

    def test_cross_engine_dedup(self):
        """Test cross-engine deduplication."""
        # Same semantic finding from different engines
        findings = [
            MockFinding(
                finding_id="f1",
                source="semgrep",
                rule_id="xss-rule",
                location=MockLocation(file="api.py", function="handle"),
                metadata={"sink": "response.write"},
                final_score=0.7,
            ),
            MockFinding(
                finding_id="f2",
                source="codeql",
                rule_id="xss-rule",
                location=MockLocation(file="api.py", function="handle"),
                metadata={"sink": "response.write"},
                final_score=0.8,
            ),
            MockFinding(
                finding_id="f3",
                source="agent",
                rule_id="xss-rule",
                location=MockLocation(file="api.py", function="handle"),
                metadata={"sink": "response.write"},
                final_score=0.9,
            ),
        ]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert len(result.unique_findings) == 1
        assert result.removed_count == 2
        assert result.merged_groups == 1

    def test_keeps_highest_score(self):
        """Test keeps finding with highest score."""
        findings = [
            MockFinding(
                finding_id="f1",
                source="semgrep",
                rule_id="r1",
                location=MockLocation(file="a.py"),
                final_score=0.5,
            ),
            MockFinding(
                finding_id="f2",
                source="semgrep",
                rule_id="r1",
                location=MockLocation(file="a.py"),
                final_score=0.9,
            ),
        ]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert len(result.unique_findings) == 1
        assert result.unique_findings[0].id == "f2"

    def test_keeps_higher_engine_weight(self):
        """Test keeps finding with higher engine weight when scores equal."""
        findings = [
            MockFinding(
                finding_id="f1",
                source="semgrep",
                rule_id="r1",
                location=MockLocation(file="a.py"),
                final_score=0.8,
            ),
            MockFinding(
                finding_id="f2",
                source="agent",
                rule_id="r1",
                location=MockLocation(file="a.py"),
                final_score=0.8,
            ),
        ]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert len(result.unique_findings) == 1
        assert result.unique_findings[0].id == "f2"  # agent wins

    def test_keeps_higher_exploitability(self):
        """Test keeps finding with higher exploitability when others equal."""
        findings = [
            MockFinding(
                finding_id="f1",
                source="semgrep",
                rule_id="r1",
                location=MockLocation(file="a.py"),
                final_score=0.8,
                exploitability="possible",
            ),
            MockFinding(
                finding_id="f2",
                source="semgrep",
                rule_id="r1",
                location=MockLocation(file="a.py"),
                final_score=0.8,
                exploitability="exploitable",
            ),
        ]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert len(result.unique_findings) == 1
        assert result.unique_findings[0].id == "f2"

    def test_different_vulnerabilities_not_merged(self):
        """Test different vulnerabilities are not merged."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="xss-rule",
                location=MockLocation(file="a.py", function="func1"),
            ),
            MockFinding(
                finding_id="f2",
                rule_id="sqli-rule",
                location=MockLocation(file="a.py", function="func2"),
            ),
        ]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert len(result.unique_findings) == 2

    def test_different_lines_same_semantic_merged(self):
        """Test different line numbers but same semantic are merged."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="xss-rule",
                location=MockLocation(file="a.py", line=10, function="handle"),
            ),
            MockFinding(
                finding_id="f2",
                rule_id="xss-rule",
                location=MockLocation(file="a.py", line=50, function="handle"),
            ),
        ]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert len(result.unique_findings) == 1
        assert result.removed_count == 1

    def test_related_engines_tracked(self):
        """Test related engines are tracked."""
        findings = [
            MockFinding(
                finding_id="f1",
                source="semgrep",
                rule_id="r1",
                location=MockLocation(file="a.py"),
            ),
            MockFinding(
                finding_id="f2",
                source="codeql",
                rule_id="r1",
                location=MockLocation(file="a.py"),
            ),
        ]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert len(result.unique_findings[0].related_engines) == 2

    def test_duplicate_count_tracked(self):
        """Test duplicate count is tracked."""
        findings = [
            MockFinding(
                finding_id="f1",
                source="semgrep",
                rule_id="r1",
                location=MockLocation(file="a.py"),
            ),
            MockFinding(
                finding_id="f2",
                source="codeql",
                rule_id="r1",
                location=MockLocation(file="a.py"),
            ),
            MockFinding(
                finding_id="f3",
                source="agent",
                rule_id="r1",
                location=MockLocation(file="a.py"),
            ),
        ]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert result.unique_findings[0].duplicate_count == 2

    def test_get_duplicates(self):
        """Test get_duplicates method."""
        findings = [
            MockFinding(
                finding_id="f1",
                source="semgrep",
                rule_id="r1",
                location=MockLocation(file="a.py"),
            ),
            MockFinding(
                finding_id="f2",
                source="codeql",
                rule_id="r1",
                location=MockLocation(file="a.py"),
            ),
            MockFinding(
                finding_id="f3",
                rule_id="r2",
                location=MockLocation(file="b.py"),
            ),
        ]
        deduplicator = ASTDeduplicator()
        duplicates = deduplicator.get_duplicates(findings)
        assert len(duplicates) == 1  # Only one group has duplicates


# ============================================================
# Test Convenience Function
# ============================================================

class TestDeduplicateFindings:
    """Test deduplicate_findings convenience function."""

    def test_basic_deduplication(self):
        """Test basic deduplication."""
        findings = [
            MockFinding(finding_id="f1", rule_id="r1"),
            MockFinding(finding_id="f2", rule_id="r1"),
        ]
        result = deduplicate_findings(findings)
        assert isinstance(result, DeduplicationResult)

    def test_strict_mode(self):
        """Test strict mode parameter."""
        findings = [MockFinding()]
        result = deduplicate_findings(findings, strict=True)
        assert len(result.unique_findings) == 1


# ============================================================
# Test Edge Cases
# ============================================================

class TestEdgeCases:
    """Test edge cases."""

    def test_large_batch(self):
        """Test large batch of findings."""
        findings = [
            MockFinding(
                finding_id=f"f{i}",
                rule_id=f"r{i % 10}",
                location=MockLocation(file=f"file{i % 5}.py"),
            )
            for i in range(100)
        ]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert len(result.unique_findings) > 0
        assert result.unique_findings[0].metadata.get("ast_hash") is not None

    def test_missing_attributes(self):
        """Test finding with missing attributes."""
        finding = MockFinding()
        finding.rule_id = None
        finding.location = None
        finding.metadata = None
        # Should not raise
        hash_val = generate_ast_hash(finding)
        assert hash_val.startswith("ast_")

    def test_unicode_handling(self):
        """Test unicode in findings."""
        finding = MockFinding(
            metadata={"sink": "eval('用户输入')"},
        )
        # Should not raise
        hash_val = generate_ast_hash(finding)
        assert hash_val.startswith("ast_")

    def test_merge_details_limited(self):
        """Test merge details are limited in to_dict."""
        findings = []
        for i in range(20):
            findings.append(MockFinding(
                finding_id=f"f{i}",
                rule_id="r1",
                location=MockLocation(file="a.py"),
            ))

        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        d = result.to_dict()
        assert len(d["merge_details"]) <= 10


# ============================================================
# Test Integration with Metadata
# ============================================================

class TestMetadataIntegration:
    """Test metadata integration."""

    def test_ast_hash_stored_in_metadata(self):
        """Test AST hash is stored in finding metadata."""
        findings = [MockFinding()]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert "ast_hash" in result.unique_findings[0].metadata

    def test_merge_details_in_result(self):
        """Test merge details are in result."""
        findings = [
            MockFinding(
                finding_id="f1",
                source="semgrep",
                rule_id="r1",
                location=MockLocation(file="a.py"),
            ),
            MockFinding(
                finding_id="f2",
                source="codeql",
                rule_id="r1",
                location=MockLocation(file="a.py"),
            ),
        ]
        deduplicator = ASTDeduplicator()
        result = deduplicator.deduplicate(findings)
        assert len(result.merge_details) == 1
        assert result.merge_details[0]["group_size"] == 2

    def test_result_to_dict_for_metadata(self):
        """Test result to_dict for metadata storage."""
        result = DeduplicationResult(
            unique_findings=[MockFinding()],
            removed_count=5,
            merged_groups=3,
        )
        d = result.to_dict()
        assert "removed" in d
        assert "groups" in d
        assert "unique_count" in d
