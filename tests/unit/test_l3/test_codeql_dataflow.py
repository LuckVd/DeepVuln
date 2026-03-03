"""
Tests for CodeQL Dataflow Analysis Components.

Tests the new CodeQL dataflow analysis module including:
- QueryGenerator: CodeQL query template generation
- SARIFParser: SARIF output parsing with codeFlows
- CodeQLDataflowExecutor: Query execution
- SanitizerDetector: Sanitizer detection and evaluation
- DataflowAnalyzer: High-level coordination
"""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from src.layers.l3_analysis.codeql import (
    CodeQLDataflowExecutor,
    DataflowResult,
    DataflowAnalysisConfig,
    QueryGenerator,
    SARIFParser,
    ParsedDataflowPath,
    PathLocation,
    SanitizerDetector,
    SanitizerMatch,
    SanitizerEffectiveness,
    TaintTrackingConfig,
    SourceDefinition,
    SinkDefinition,
    VulnerabilityCategory,
    generate_taint_tracking_query,
)
from src.layers.l3_analysis.rounds.dataflow_analyzer import (
    DataflowAnalyzer,
    DataflowAnalysisResult,
)


# ============================================================
# QueryGenerator Tests
# ============================================================

class TestQueryGenerator:
    """Tests for QueryGenerator class."""

    def test_default_init(self):
        """Test default initialization."""
        gen = QueryGenerator()
        assert gen.language == "python"

    def test_custom_language_init(self):
        """Test initialization with custom language."""
        gen = QueryGenerator(language="java")
        assert gen.language == "java"

    def test_generate_from_finding_sql(self):
        """Test generating config from SQL injection finding."""
        gen = QueryGenerator()
        finding = MagicMock()
        finding.title = "SQL Injection vulnerability"
        finding.location = MagicMock()
        finding.location.file = "app.py"
        finding.location.line = 10
        finding.location.function = "get_user"
        finding.location.snippet = "cursor.execute(query)"
        finding.severity = MagicMock(value="high")
        finding.cwe = "CWE-89"
        finding.tags = ["sql", "security"]

        config = gen.generate_from_finding(finding)
        assert config.language == "python"
        assert config.source is not None
        assert config.sink is not None

    def test_generate_from_finding_xss(self):
        """Test generating config from XSS finding."""
        gen = QueryGenerator()
        finding = MagicMock()
        finding.title = "Cross-site Scripting vulnerability"
        finding.location = MagicMock()
        finding.location.file = "app.py"
        finding.location.line = 20
        finding.location.function = "render_template"
        finding.location.snippet = "return render_template('page.html', data=user_input)"
        finding.severity = MagicMock(value="medium")
        finding.cwe = "CWE-79"
        finding.tags = ["xss"]

        config = gen.generate_from_finding(finding)
        assert config.source is not None
        assert config.sink is not None

    def test_infer_category(self):
        """Test vulnerability category inference."""
        gen = QueryGenerator()

        # SQL injection
        finding = MagicMock()
        finding.title = "SQL Injection"
        finding.tags = []
        assert gen._infer_category(finding) == VulnerabilityCategory.SQL_INJECTION

        # XSS
        finding.title = "XSS vulnerability"
        assert gen._infer_category(finding) == VulnerabilityCategory.XSS

        # Command injection
        finding.title = "OS Command Injection"
        assert gen._infer_category(finding) == VulnerabilityCategory.COMMAND_INJECTION

    def test_generate_source_from_finding(self):
        """Test source generation from finding."""
        gen = QueryGenerator()
        finding = MagicMock()
        finding.title = "SQL Injection"
        finding.location = MagicMock()
        finding.location.file = "app.py"
        finding.location.line = 10
        finding.location.function = "get_user"
        finding.location.snippet = "user_id = request.args.get('id')"
        finding.tags = ["sql"]

        source = gen._generate_source(finding, VulnerabilityCategory.SQL_INJECTION, "python")
        assert source is not None
        assert source.category in ("http_param", "user_input")

    def test_generate_sink_from_finding(self):
        """Test sink generation from finding."""
        gen = QueryGenerator()
        finding = MagicMock()
        finding.title = "SQL Injection"
        finding.location = MagicMock()
        finding.location.file = "app.py"
        finding.location.line = 20
        finding.location.function = "execute_query"
        finding.location.snippet = "cursor.execute(query)"
        finding.tags = ["sql"]

        sink = gen._generate_sink(finding, VulnerabilityCategory.SQL_INJECTION, "python")
        assert sink is not None
        # Sink category is derived from vulnerability category
        assert sink.category in ("sql_query", "sql_injection")


class TestSourceDefinition:
    """Tests for SourceDefinition dataclass."""

    def test_default_source(self):
        """Test default source definition."""
        source = SourceDefinition(
            name="test_source",
            category="http_param",
        )
        assert source.name == "test_source"
        assert source.category == "http_param"

    def test_to_codeql_python(self):
        """Test CodeQL generation for Python."""
        source = SourceDefinition(
            name="user_input",
            category="http_param",
            parameter_name="id",
        )
        code = source.to_codeql("python")
        assert "isSource" in code

    def test_to_codeql_java(self):
        """Test CodeQL generation for Java."""
        source = SourceDefinition(
            name="request_param",
            category="http_param",
        )
        code = source.to_codeql("java")
        assert "isSource" in code


class TestSinkDefinition:
    """Tests for SinkDefinition dataclass."""

    def test_default_sink(self):
        """Test default sink definition."""
        sink = SinkDefinition(
            name="test_sink",
            category="sql_query",
        )
        assert sink.name == "test_sink"
        assert sink.category == "sql_query"

    def test_to_codeql_python(self):
        """Test CodeQL generation for Python."""
        sink = SinkDefinition(
            name="sql_exec",
            category="sql_query",
            function_name="execute",
        )
        code = sink.to_codeql("python")
        assert "isSink" in code


class TestTaintTrackingConfig:
    """Tests for TaintTrackingConfig dataclass."""

    def test_default_config(self):
        """Test default configuration."""
        config = TaintTrackingConfig(
            query_id="test-001",
            query_name="Test Query",
            source=SourceDefinition(
                name="test_source",
                category="http_param",
            ),
            sink=SinkDefinition(
                name="test_sink",
                category="sql_query",
            ),
            language="python",
        )
        assert config.query_id == "test-001"
        assert config.language == "python"
        assert config.additional_steps == []
        assert config.sanitizers == []


# ============================================================
# SARIFParser Tests
# ============================================================

class TestSARIFParser:
    """Tests for SARIFParser class."""

    def test_default_init(self):
        """Test default initialization."""
        parser = SARIFParser()
        assert parser.source_root is not None

    def test_parse_empty_sarif(self):
        """Test parsing empty SARIF."""
        parser = SARIFParser()
        paths = parser.parse({"runs": []})
        assert paths == []

    def test_parse_simple_result(self):
        """Test parsing simple result without codeFlows."""
        parser = SARIFParser()
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "CodeQL", "rules": []}},
                "results": [{
                    "ruleId": "test-rule",
                    "message": {"text": "Test finding"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "test.py"},
                            "region": {"startLine": 10}
                        }
                    }]
                }]
            }]
        }
        paths = parser.parse(sarif)
        assert len(paths) == 1
        assert paths[0].rule_id == "test-rule"

    def test_parse_with_code_flows(self):
        """Test parsing SARIF with codeFlows."""
        parser = SARIFParser()
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "CodeQL", "rules": []}},
                "results": [{
                    "ruleId": "test-rule",
                    "message": {"text": "Test dataflow"},
                    "codeFlows": [{
                        "threadFlows": [{
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "source.py"},
                                            "region": {"startLine": 5}
                                        },
                                        "message": {"text": "source"}
                                    }
                                },
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "sink.py"},
                                            "region": {"startLine": 20}
                                        },
                                        "message": {"text": "sink"}
                                    }
                                }
                            ]
                        }]
                    }]
                }]
            }]
        }
        paths = parser.parse(sarif)
        assert len(paths) == 1
        assert len(paths[0].locations) == 2
        assert paths[0].is_complete is True
        assert paths[0].source.node_type == "source"
        assert paths[0].sink.node_type == "sink"

    def test_path_location_to_code_location(self):
        """Test PathLocation conversion to CodeLocation."""
        loc = PathLocation(
            file_path="test.py",
            line=10,
            column=5,
            snippet="x = y",
            function_name="test_func",
        )
        code_loc = loc.to_code_location()
        assert code_loc.file == "test.py"
        assert code_loc.line == 10
        assert code_loc.column == 5
        assert code_loc.snippet == "x = y"
        assert code_loc.function == "test_func"

    def test_extract_cwe_from_tags(self):
        """Test CWE extraction from tags."""
        parser = SARIFParser()
        rule = {
            "properties": {
                "tags": ["cwe-89", "sql-injection"]
            }
        }
        cwe = parser._extract_cwe(rule)
        assert cwe == "CWE-89"

    def test_severity_mapping(self):
        """Test SARIF level to severity mapping."""
        parser = SARIFParser()
        assert parser._map_severity("error") == "high"
        assert parser._map_severity("warning") == "medium"
        assert parser._map_severity("note") == "low"

    def test_statistics(self):
        """Test statistics calculation."""
        parser = SARIFParser()
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "CodeQL", "rules": []}},
                "results": [
                    {
                        "ruleId": "r1",
                        "codeFlows": [{
                            "threadFlows": [{
                                "locations": [
                                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}},
                                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 2}}}}
                                ]
                            }]
                        }]
                    },
                    {
                        "ruleId": "r2",
                        "codeFlows": [{
                            "threadFlows": [{
                                "locations": [
                                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "b.py"}, "region": {"startLine": 1}}}}
                                ]
                            }]
                        }]
                    }
                ]
            }]
        }
        paths = parser.parse(sarif)
        stats = parser.get_statistics()
        assert stats["total_paths"] == 2
        assert stats["complete_paths"] == 1  # Only one has 2+ locations


class TestParsedDataflowPath:
    """Tests for ParsedDataflowPath dataclass."""

    def test_path_properties(self):
        """Test path properties."""
        path = ParsedDataflowPath(
            path_id="test-path",
            rule_id="test-rule",
            rule_name="Test Rule",
            locations=[
                PathLocation(file_path="a.py", line=1, function_name="func_a"),
                PathLocation(file_path="a.py", line=5, function_name="func_b"),
                PathLocation(file_path="a.py", line=10, function_name="func_b"),
            ],
        )
        assert path.path_length == 3
        assert path.is_direct is False
        assert path.is_interprocedural is True

    def test_direct_flow(self):
        """Test direct flow detection."""
        path = ParsedDataflowPath(
            path_id="test",
            rule_id="r1",
            rule_name="Test",
            locations=[
                PathLocation(file_path="a.py", line=1),
                PathLocation(file_path="a.py", line=2),
            ],
        )
        assert path.is_direct is True

    def test_get_intermediate_nodes(self):
        """Test getting intermediate nodes."""
        path = ParsedDataflowPath(
            path_id="test",
            rule_id="r1",
            rule_name="Test",
            locations=[
                PathLocation(file_path="a.py", line=1),
                PathLocation(file_path="a.py", line=5),
                PathLocation(file_path="a.py", line=10),
            ],
        )
        intermediate = path.get_intermediate_nodes()
        assert len(intermediate) == 1
        assert intermediate[0].line == 5


# ============================================================
# SanitizerDetector Tests
# ============================================================

class TestSanitizerDetector:
    """Tests for SanitizerDetector class."""

    def test_default_init(self):
        """Test default initialization."""
        detector = SanitizerDetector()
        assert detector.language == "python"

    def test_detect_html_escape(self):
        """Test detecting HTML escape sanitizers."""
        detector = SanitizerDetector()
        code = "html.escape(user_input)"
        sanitizers = detector.detect_in_snippet(code)
        assert len(sanitizers) > 0
        assert sanitizers[0].category == "html_encode"

    def test_detect_bleach_clean(self):
        """Test detecting bleach.clean sanitizer."""
        detector = SanitizerDetector()
        code = "bleach.clean(user_input)"
        sanitizers = detector.detect_in_snippet(code)
        assert len(sanitizers) > 0
        assert sanitizers[0].category == "html_encode"
        assert sanitizers[0].effectiveness == SanitizerEffectiveness.FULL

    def test_detect_prepared_statement(self):
        """Test detecting prepared statement."""
        detector = SanitizerDetector()
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])'
        sanitizers = detector.detect_in_snippet(code)
        # Should detect parameterized query pattern
        assert len(sanitizers) > 0

    def test_detect_shlex_quote(self):
        """Test detecting shlex.quote for command injection."""
        detector = SanitizerDetector()
        code = "shlex.quote(user_input)"
        sanitizers = detector.detect_in_snippet(code)
        assert len(sanitizers) > 0
        assert sanitizers[0].category == "command_escape"

    def test_detect_in_path(self):
        """Test detecting sanitizers in a path."""
        detector = SanitizerDetector()
        path_nodes = [
            {"snippet": "user_input = request.args.get('id')", "line": 1},
            {"snippet": "safe_input = html.escape(user_input)", "line": 2},
            {"snippet": "return render_template('result.html', data=safe_input)", "line": 3},
        ]
        sanitizers = detector.detect_in_path(path_nodes)
        assert len(sanitizers) > 0

    def test_evaluate_effectiveness_sql(self):
        """Test evaluating sanitizer effectiveness for SQL injection."""
        detector = SanitizerDetector()
        sanitizers = [
            SanitizerMatch(
                name="prepared_stmt",
                category="prepared_stmt",
                location=MagicMock(),
                effectiveness=SanitizerEffectiveness.FULL,
            )
        ]
        is_effective, reason = detector.evaluate_effectiveness(sanitizers, "sql_injection")
        assert is_effective is True
        assert "Effective" in reason

    def test_evaluate_effectiveness_partial(self):
        """Test evaluating partial sanitizers."""
        detector = SanitizerDetector()
        sanitizers = [
            SanitizerMatch(
                name="sql_escape",
                category="sql_escape",
                location=MagicMock(),
                effectiveness=SanitizerEffectiveness.PARTIAL,
                bypass_conditions=["Encoding issues"],
            )
        ]
        is_effective, reason = detector.evaluate_effectiveness(sanitizers, "sql_injection")
        assert is_effective is False
        assert "bypass" in reason.lower()

    def test_no_relevant_sanitizers(self):
        """Test when no relevant sanitizers found."""
        detector = SanitizerDetector()
        sanitizers = [
            SanitizerMatch(
                name="html_encode",
                category="html_encode",
                location=MagicMock(),
                effectiveness=SanitizerEffectiveness.FULL,
            )
        ]
        is_effective, reason = detector.evaluate_effectiveness(sanitizers, "sql_injection")
        assert is_effective is False
        assert "No sanitizers relevant" in reason

    def test_get_statistics(self):
        """Test statistics calculation."""
        detector = SanitizerDetector()
        sanitizers = [
            SanitizerMatch(
                name="s1",
                category="html_encode",
                location=MagicMock(),
                effectiveness=SanitizerEffectiveness.FULL,
            ),
            SanitizerMatch(
                name="s2",
                category="sql_escape",
                location=MagicMock(),
                effectiveness=SanitizerEffectiveness.PARTIAL,
            ),
        ]
        stats = detector.get_statistics(sanitizers)
        assert stats["total"] == 2
        assert stats["fully_effective_count"] == 1
        assert "html_encode" in stats["by_category"]
        assert "partial" in stats["by_effectiveness"]

    def test_javascript_sanitizers(self):
        """Test detecting JavaScript sanitizers."""
        detector = SanitizerDetector(language="javascript")
        code = "DOMPurify.sanitize(userInput)"
        sanitizers = detector.detect_in_snippet(code)
        assert len(sanitizers) > 0
        assert sanitizers[0].category == "html_encode"

    def test_java_sanitizers(self):
        """Test detecting Java sanitizers."""
        detector = SanitizerDetector(language="java")
        code = "PreparedStatement stmt = conn.prepareStatement(sql)"
        sanitizers = detector.detect_in_snippet(code)
        assert len(sanitizers) > 0


# ============================================================
# CodeQLDataflowExecutor Tests
# ============================================================

class TestCodeQLDataflowExecutor:
    """Tests for CodeQLDataflowExecutor class."""

    def test_default_init(self):
        """Test default initialization."""
        executor = CodeQLDataflowExecutor()
        assert executor.codeql_path == "codeql"
        assert executor.timeout == 300

    def test_custom_init(self):
        """Test custom initialization."""
        executor = CodeQLDataflowExecutor(
            codeql_path="/custom/codeql",
            database_path=Path("/db"),
            timeout=600,
        )
        assert executor.codeql_path == "/custom/codeql"
        assert executor.database_path == Path("/db")
        assert executor.timeout == 600

    @pytest.mark.asyncio
    async def test_is_available_not_installed(self):
        """Test availability check when not installed."""
        executor = CodeQLDataflowExecutor(codeql_path="nonexistent_codeql")
        available = await executor.is_available()
        assert available is False

    def test_dataflow_result_to_dict(self):
        """Test DataflowResult serialization."""
        result = DataflowResult(
            query_id="test-001",
            query_name="Test Query",
            source_path="/src",
            language="python",
            total_paths=5,
            complete_paths=3,
        )
        d = result.to_dict()
        assert d["query_id"] == "test-001"
        assert d["total_paths"] == 5
        assert d["complete_paths"] == 3

    def test_map_source_type(self):
        """Test source type mapping."""
        executor = CodeQLDataflowExecutor()
        from src.layers.l3_analysis.rounds.dataflow import SourceType

        assert executor._map_source_type("http_param") == SourceType.HTTP_PARAM
        assert executor._map_source_type("http_header") == SourceType.HTTP_HEADER
        assert executor._map_source_type("file_input") == SourceType.FILE_INPUT

    def test_map_sink_type(self):
        """Test sink type mapping."""
        executor = CodeQLDataflowExecutor()
        from src.layers.l3_analysis.rounds.dataflow import SinkType

        assert executor._map_sink_type("sql_query") == SinkType.SQL_QUERY
        assert executor._map_sink_type("command_exec") == SinkType.COMMAND_EXEC
        assert executor._map_sink_type("file_write") == SinkType.FILE_WRITE

    def test_infer_sanitizer_type(self):
        """Test sanitizer type inference."""
        executor = CodeQLDataflowExecutor()
        from src.layers.l3_analysis.rounds.dataflow import SanitizerType

        assert executor._infer_sanitizer_type("html.escape(x)") == SanitizerType.HTML_ENCODE
        assert executor._infer_sanitizer_type("int(x)") == SanitizerType.TYPE_CAST


class TestDataflowAnalysisConfig:
    """Tests for DataflowAnalysisConfig dataclass."""

    def test_default_config(self):
        """Test default configuration."""
        config = DataflowAnalysisConfig()
        assert config.codeql_path == "codeql"
        assert config.language == "python"
        assert config.timeout == 300
        assert config.max_concurrent_queries == 3

    def test_custom_config(self):
        """Test custom configuration."""
        config = DataflowAnalysisConfig(
            codeql_path="/custom/codeql",
            database_path=Path("/db"),
            language="java",
            timeout=600,
        )
        assert config.codeql_path == "/custom/codeql"
        assert config.database_path == Path("/db")
        assert config.language == "java"
        assert config.timeout == 600


# ============================================================
# DataflowAnalyzer Tests
# ============================================================

class TestDataflowAnalyzer:
    """Tests for DataflowAnalyzer class."""

    @pytest.fixture
    def config(self):
        """Create test configuration."""
        return DataflowAnalysisConfig(
            codeql_path="codeql",
            database_path=None,  # No database for tests
            language="python",
        )

    def test_init(self, config):
        """Test initialization."""
        analyzer = DataflowAnalyzer(config)
        assert analyzer.config == config
        assert analyzer.query_generator is not None
        assert analyzer.executor is not None
        assert analyzer.sanitizer_detector is not None

    @pytest.mark.asyncio
    async def test_initialize_without_database(self, config):
        """Test initialization fails without database."""
        analyzer = DataflowAnalyzer(config)
        result = await analyzer.initialize()
        assert result is False

    def test_confidence_to_str(self, config):
        """Test confidence conversion."""
        analyzer = DataflowAnalyzer(config)

        from enum import Enum
        class TestConfidence(Enum):
            HIGH = "high"
            MEDIUM = "medium"
            LOW = "low"

        assert analyzer._confidence_to_str(TestConfidence.HIGH) == "high"
        assert analyzer._confidence_to_str("medium") == "medium"

    def test_infer_vulnerability_type(self, config):
        """Test vulnerability type inference."""
        analyzer = DataflowAnalyzer(config)

        # Create mock candidate with SQL injection
        candidate = MagicMock()
        finding = MagicMock()
        finding.title = "SQL Injection vulnerability"
        finding.tags = ["sql", "security"]
        candidate.finding = finding

        vuln_type = analyzer._infer_vulnerability_type(candidate)
        assert vuln_type == "sql_injection"

    def test_infer_source_type(self, config):
        """Test source type inference."""
        analyzer = DataflowAnalyzer(config)

        finding = MagicMock()
        finding.title = "SQL Injection in user input"
        source_type = analyzer._infer_source_type(finding)
        assert source_type.value in ["http_param", "user_input"]

    def test_infer_sink_type(self, config):
        """Test sink type inference."""
        analyzer = DataflowAnalyzer(config)

        finding = MagicMock()
        finding.title = "SQL Injection vulnerability"
        sink_type = analyzer._infer_sink_type(finding)
        assert sink_type.value == "sql_query"

    def test_select_primary_path(self, config):
        """Test primary path selection."""
        analyzer = DataflowAnalyzer(config)

        from src.layers.l3_analysis.rounds.dataflow import DataFlowPath

        # Create mock paths
        path1 = MagicMock(spec=DataFlowPath)
        path1.is_complete = True
        path1.path_nodes = [1, 2, 3]

        path2 = MagicMock(spec=DataFlowPath)
        path2.is_complete = True
        path2.path_nodes = [1, 2, 3, 4, 5]

        path3 = MagicMock(spec=DataFlowPath)
        path3.is_complete = False
        path3.path_nodes = [1]

        # Should select complete path with most nodes
        selected = analyzer._select_primary_path([path1, path2, path3])
        assert selected == path2

    def test_update_confidence_complete_path(self, config):
        """Test confidence update with complete path."""
        analyzer = DataflowAnalyzer(config)

        candidate = MagicMock()
        candidate.confidence = MagicMock(value="medium")

        result = DataflowAnalysisResult(
            candidate_id="test",
            finding_id="f1",
        )
        result.has_complete_path = True
        result.has_effective_sanitizer = False

        analyzer._update_confidence(candidate, result)
        assert result.updated_confidence == "high"

    def test_update_confidence_with_sanitizer(self, config):
        """Test confidence update with effective sanitizer."""
        analyzer = DataflowAnalyzer(config)

        candidate = MagicMock()
        candidate.confidence = MagicMock(value="high")

        result = DataflowAnalysisResult(
            candidate_id="test",
            finding_id="f1",
        )
        result.has_complete_path = True
        result.has_effective_sanitizer = True

        analyzer._update_confidence(candidate, result)
        assert result.updated_confidence == "low"


class TestDataflowAnalysisResult:
    """Tests for DataflowAnalysisResult dataclass."""

    def test_default_result(self):
        """Test default result."""
        result = DataflowAnalysisResult(
            candidate_id="test",
            finding_id="f1",
        )
        assert result.dataflow_paths == []
        assert result.success is True
        assert result.has_complete_path is False

    def test_to_dict(self):
        """Test serialization."""
        result = DataflowAnalysisResult(
            candidate_id="test",
            finding_id="f1",
            has_complete_path=True,
            has_effective_sanitizer=False,
            original_confidence="high",
            updated_confidence="high",
        )
        d = result.to_dict()
        assert d["candidate_id"] == "test"
        assert d["has_complete_path"] is True
        assert d["original_confidence"] == "high"


# ============================================================
# Integration Tests
# ============================================================

class TestIntegration:
    """Integration tests for dataflow components."""

    def test_query_generation_to_string(self):
        """Test query generation produces valid output."""
        gen = QueryGenerator()
        finding = MagicMock()
        finding.title = "SQL Injection vulnerability"
        finding.location = MagicMock()
        finding.location.file = "app.py"
        finding.location.line = 10
        finding.location.function = "get_user"
        finding.location.snippet = "cursor.execute(query)"
        finding.severity = MagicMock(value="high")
        finding.cwe = "CWE-89"
        finding.tags = ["sql", "security"]

        config = gen.generate_from_finding(finding)
        query = generate_taint_tracking_query(config)

        # Check query has essential components
        assert "select" in query.lower()
        assert "from" in query.lower()
        assert "where" in query.lower()

    def test_sarif_parsing_end_to_end(self):
        """Test complete SARIF parsing flow."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "version": "2.0.0",
                        "rules": [{
                            "id": "py/sql-injection",
                            "shortDescription": {"text": "SQL Injection"},
                            "properties": {"tags": ["cwe-89", "sql-injection"]}
                        }]
                    }
                },
                "results": [{
                    "ruleId": "py/sql-injection",
                    "message": {"text": "Detected SQL injection"},
                    "level": "error",
                    "codeFlows": [{
                        "threadFlows": [{
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 10, "snippet": {"text": "user_id = request.args.get('id')"}}
                                        },
                                        "message": {"text": "user-controlled source"}
                                    }
                                },
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 15, "snippet": {"text": "cursor.execute(query)"}}
                                        },
                                        "message": {"text": "tainted data used in SQL query"}
                                    }
                                }
                            ]
                        }]
                    }]
                }]
            }]
        }

        parser = SARIFParser()
        paths = parser.parse(sarif)

        assert len(paths) == 1
        assert paths[0].is_complete is True
        assert paths[0].cwe == "CWE-89"
        assert paths[0].severity == "high"
        assert len(paths[0].locations) == 2

    def test_sanitizer_detection_in_flow(self):
        """Test sanitizer detection in a data flow."""
        detector = SanitizerDetector()

        # Simulate a data flow path
        path_nodes = [
            {"file_path": "app.py", "line": 10, "snippet": "user_input = request.args.get('q')"},
            {"file_path": "app.py", "line": 11, "snippet": "safe_input = html.escape(user_input)"},
            {"file_path": "app.py", "line": 12, "snippet": "return f'<div>{safe_input}</div>'"},
        ]

        sanitizers = detector.detect_in_path(path_nodes)
        is_effective, reason = detector.evaluate_effectiveness(sanitizers, "xss")

        assert len(sanitizers) > 0
        assert is_effective is True
