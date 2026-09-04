"""Regression tests for audit 2026-09 fix: SARIF codeFlows must be converted
into finding metadata (has_dataflow / sources / path).

Before the fix, ``_convert_sarif_result_to_finding`` dropped all codeFlow
data, so the CODEQL confirming-evidence dimension of the multi-dim scorer
could never see has_source=True even with CodeQL installed. Also verifies
``round_four._extract_codeql_dataflow_dict`` derives has_sink from real path
evidence instead of hardcoding True.
"""

from pathlib import Path

import pytest

from src.layers.l3_analysis.engines.codeql import CodeQLEngine


def _sarif_result(code_flows=None, level="warning", rule_id="java/xss"):
    result = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": "Cross-site scripting"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": "App.java"},
                "region": {"startLine": 12},
            }
        }],
    }
    if code_flows is not None:
        result["codeFlows"] = code_flows
    return result


def _flow(source_file, source_line, sink_file, sink_line):
    return [{
        "threadFlows": [{
            "locations": [
                {"location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": source_file},
                        "region": {"startLine": source_line},
                    },
                    "message": {"text": "user input"},
                }},
                {"location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": sink_file},
                        "region": {"startLine": sink_line},
                    },
                    "message": {"text": "dangerous call"},
                }},
            ]
        }]
    }]


@pytest.fixture
def engine():
    return CodeQLEngine(codeql_path="/usr/bin/codeql")


class TestSarifDataflowExtraction:
    def test_codeflow_populates_dataflow_metadata(self, engine):
        result = _sarif_result(code_flows=_flow("App.java", 5, "App.java", 12))
        finding = engine._convert_sarif_result_to_finding(result, "codeql", Path("/src"))
        assert finding is not None
        meta = finding.metadata
        assert meta["has_dataflow"] is True
        assert len(meta["sources"]) == 1
        assert meta["sources"][0]["file"] == "App.java"
        assert len(meta["path"]) == 2

    def test_no_codeflow_yields_no_dataflow(self, engine):
        result = _sarif_result(code_flows=[])
        finding = engine._convert_sarif_result_to_finding(result, "codeql", Path("/src"))
        assert finding is not None
        meta = finding.metadata
        assert meta["has_dataflow"] is False
        assert meta["sources"] == []
        # Backward compatibility keys must remain.
        assert meta["sarif_level"] == "warning"
        assert meta["tool_name"] == "codeql"

    def test_single_location_codeflow_not_dataflow(self, engine):
        partial = [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": {
                "artifactLocation": {"uri": "App.java"},
                "region": {"startLine": 1},
            }}}
        ]}]}]
        result = _sarif_result(code_flows=partial)
        finding = engine._convert_sarif_result_to_finding(result, "codeql", Path("/src"))
        assert finding.metadata["has_dataflow"] is False


class TestExtractCodeqlDataflowDict:
    def test_full_path_gives_source_and_sink(self, engine):
        from src.layers.l3_analysis.models import Finding, CodeLocation, SeverityLevel
        from src.layers.l3_analysis.rounds.round_four import RoundFourExecutor

        f = Finding(
            id="codeql-x",
            source="codeql",
            rule_id="xss",
            title="XSS",
            description="d",
            severity=SeverityLevel.HIGH,
            location=CodeLocation(file="App.java", line=12),
            metadata={
                "has_dataflow": True,
                "sources": [{"file": "App.java", "line": 5}],
                "path": [{"file": "App.java", "line": 5}, {"file": "App.java", "line": 12}],
            },
        )
        r4 = RoundFourExecutor(source_path=Path("/src"))
        r4._codeql_index = {"App.java:12": f}
        candidate = _candidate(f)
        d = r4._extract_codeql_dataflow_dict(candidate)
        assert d is not None
        assert d["has_source"] is True
        assert d["has_sink"] is True
        assert d["path_length"] == 2

    def test_bare_alert_without_path_is_not_sink(self, engine):
        from src.layers.l3_analysis.models import Finding, CodeLocation, SeverityLevel
        from src.layers.l3_analysis.rounds.round_four import RoundFourExecutor

        f = Finding(
            id="codeql-x",
            source="codeql",
            rule_id="xss",
            title="XSS",
            description="d",
            severity=SeverityLevel.HIGH,
            location=CodeLocation(file="App.java", line=12),
            metadata={"sarif_level": "warning"},
        )
        r4 = RoundFourExecutor(source_path=Path("/src"))
        r4._codeql_index = {"App.java:12": f}
        candidate = _candidate(f)
        d = r4._extract_codeql_dataflow_dict(candidate)
        # A bare alert is not dataflow-grade evidence: has_sink must not be
        # hardcoded True.
        assert d is not None
        assert d["has_source"] is False
        assert d["has_sink"] is False


def _candidate(finding):
    from src.layers.l3_analysis.rounds.models import ConfidenceLevel, VulnerabilityCandidate

    return VulnerabilityCandidate(
        id="c1",
        finding=finding,
        confidence=ConfidenceLevel.HIGH,
        discovered_in_round=1,
    )