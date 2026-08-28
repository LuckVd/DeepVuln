"""Phase 20 P-A2: ApplicabilityGate 单元测试.

覆盖：信号收集 → 逐类判定 → fail-open 降级 → gated_classes / 规则关键词 /
finding 匹配。全部确定性（无 LLM、无网络）。
"""

from pathlib import Path

import pytest

from src.core.applicability_gate import (
    GATE_CONFIDENCE_THRESHOLD,
    ApplicabilityGate,
    GateReport,
    finding_matches_gated_class,
)
from src.core.models.attack_surface import AttackSurfaceReport, EntryPoint, EntryPointType


def _report_with(entries: list[EntryPoint]) -> AttackSurfaceReport:
    report = AttackSurfaceReport(source_path="/tmp/project")
    for ep in entries:
        report.add_entry_point(ep)
    return report


def _http(file: str = "app.py", **kwargs) -> EntryPoint:
    return EntryPoint(type=EntryPointType.HTTP, path="/x", handler="h", file=file, **kwargs)


class TestNoSurfaceFailClosedToOpen:
    """零攻击面 → web 类被裁，但无前提要求的类永不裁。"""

    def test_empty_project_gates_web_classes(self) -> None:
        report = _report_with([])
        gate = ApplicabilityGate(tech_stack={}, attack_surface=report, enable_probes=False)
        result = gate.evaluate()
        gated = result.gated_classes()
        for cls in ("xss", "ssrf", "open_redirect", "path_traversal", "authn_bypass", "authz_idor"):
            assert cls in gated

    def test_command_injection_never_gated(self) -> None:
        gate = ApplicabilityGate(tech_stack={}, attack_surface=None, enable_probes=False)
        result = gate.evaluate()
        assert "command_injection" not in result.gated_classes()
        decision = result.decision_for("command_injection")
        assert decision.applicable is True

    def test_none_attack_surface_fails_open(self) -> None:
        """攻击面报告完全缺失（resume 场景）≠ 确认没有面 → 不确定，放行。"""
        gate = ApplicabilityGate(tech_stack={}, attack_surface=None, enable_probes=False)
        result = gate.evaluate()
        assert result.signals.attack_surface_available is False
        assert "xss" not in result.gated_classes()
        assert result.decision_for("xss").applicable is None
        assert "authn_bypass" not in result.gated_classes()
        assert "ssrf" not in result.gated_classes()

    def test_empty_report_still_gates_web_classes(self) -> None:
        """报告存在但零入口点 = 确认无面 → 正常裁剪。"""
        gate = ApplicabilityGate(
            tech_stack={}, attack_surface=_report_with([]), enable_probes=False
        )
        result = gate.evaluate()
        assert result.signals.attack_surface_available is True
        assert "xss" in result.gated_classes()


class TestHttpProject:
    def test_http_without_auth_gates_auth_classes(self) -> None:
        """Codebuddy Gate 场景：有 web 面但无任何认证机制 → 越权/认证绕过不适用."""
        report = _report_with([_http()])
        gate = ApplicabilityGate(tech_stack={}, attack_surface=report, enable_probes=False)
        result = gate.evaluate()
        assert "authn_bypass" in result.gated_classes()
        assert "authz_idor" in result.gated_classes()
        # web 类保持适用
        assert "xss" not in result.gated_classes()
        assert result.decision_for("xss").applicable is True

    def test_http_with_auth_middleware_keeps_auth_classes(self) -> None:
        report = _report_with([_http(middleware=["auth_session"])])
        gate = ApplicabilityGate(tech_stack={}, attack_surface=report, enable_probes=False)
        result = gate.evaluate()
        assert "authn_bypass" not in result.gated_classes()
        assert "authz_idor" not in result.gated_classes()
        assert result.decision_for("authz_idor").evidence

    def test_auth_required_endpoint_is_signal(self) -> None:
        report = _report_with([_http(auth_required=True)])
        gate = ApplicabilityGate(tech_stack={}, attack_surface=report, enable_probes=False)
        result = gate.evaluate()
        assert "authz_idor" not in result.gated_classes()

    def test_no_http_gates_web_classes_entirely(self) -> None:
        report = _report_with(
            [EntryPoint(type=EntryPointType.CRON, path="c", handler="h", file="c.py")]
        )
        gate = ApplicabilityGate(tech_stack={}, attack_surface=report, enable_probes=False)
        result = gate.evaluate()
        assert "xss" in result.gated_classes()
        assert "ssrf" in result.gated_classes()
        assert "file_upload" in result.gated_classes()


class TestTechStackSignals:
    def test_database_signal_keeps_sqli_applicable(self) -> None:
        gate = ApplicabilityGate(
            tech_stack={"databases": ["postgres"]}, attack_surface=None, enable_probes=False
        )
        result = gate.evaluate()
        assert "sqli" not in result.gated_classes()
        assert "postgres" in result.decision_for("sqli").evidence

    def test_no_database_gates_sqli(self) -> None:
        gate = ApplicabilityGate(tech_stack={}, attack_surface=None, enable_probes=False)
        result = gate.evaluate()
        assert "sqli" in result.gated_classes()


class TestProbes:
    def test_crypto_probe_keeps_crypto_applicable(self, tmp_path: Path) -> None:
        (tmp_path / "hash.go").write_text('package main\nimport "crypto/md5"\n')
        gate = ApplicabilityGate(
            tech_stack={}, attack_surface=None, source_path=tmp_path, enable_probes=True
        )
        result = gate.evaluate()
        assert "crypto_misuse" not in result.gated_classes()

    def test_no_crypto_gates_crypto_class(self, tmp_path: Path) -> None:
        (tmp_path / "main.go").write_text("package main\nfunc main() {}\n")
        gate = ApplicabilityGate(
            tech_stack={}, attack_surface=None, source_path=tmp_path, enable_probes=True
        )
        result = gate.evaluate()
        assert "crypto_misuse" in result.gated_classes()

    def test_sql_probe_hit_by_import(self, tmp_path: Path) -> None:
        (tmp_path / "store.py").write_text("import sqlalchemy\ndef q(): pass\n")
        gate = ApplicabilityGate(
            tech_stack={}, attack_surface=None, source_path=tmp_path, enable_probes=True
        )
        result = gate.evaluate()
        assert result.signals.probe_hits.get("sql") == 1
        assert "sqli" not in result.gated_classes()

    def test_probe_skips_vendor_directories(self, tmp_path: Path) -> None:
        vendor = tmp_path / "vendor" / "x"
        vendor.mkdir(parents=True)
        (vendor / "crypto.go").write_text('import "crypto/md5"\n')
        gate = ApplicabilityGate(
            tech_stack={}, attack_surface=None, source_path=tmp_path, enable_probes=True
        )
        result = gate.evaluate()
        assert result.signals.probe_hits.get("crypto", 0) == 0

    def test_missing_source_path_fail_open_on_probes(self) -> None:
        gate = ApplicabilityGate(
            tech_stack={}, attack_surface=None,
            source_path=Path("/nonexistent/xyz"), enable_probes=True,
        )
        result = gate.evaluate()  # 不应抛异常
        assert set(result.signals.probe_hits.values()) == {0}


class TestFailOpen:
    def test_low_confidence_negative_demoted_to_uncertain(self) -> None:
        decision = ApplicabilityGate._decide("xss", False, 0.5, "weak signal")
        assert decision.applicable is None
        assert decision.is_gated is False

    def test_uncertain_never_gated(self) -> None:
        decision = ApplicabilityGate._decide("xss", None, 0.0, "unknown")
        assert decision.is_gated is False

    def test_gating_requires_threshold(self) -> None:
        assert GATE_CONFIDENCE_THRESHOLD >= 0.7

    def test_gate_exception_fail_open(self, tmp_path: Path, monkeypatch) -> None:
        gate = ApplicabilityGate(tech_stack={}, attack_surface=None, enable_probes=False)
        monkeypatch.setattr(
            ApplicabilityGate, "_collect_signals", lambda self: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        # evaluate() 内部不捕获 collect_signals 异常——编排层负责 fail-open；
        # 这里只验证异常是确定性抛出的（契约：编排层 except 后不启用门控）。
        with pytest.raises(RuntimeError):
            gate.evaluate()


class TestConvergenceHelpers:
    def test_disabled_rule_keywords_dedup(self) -> None:
        decisions = [
            ApplicabilityGate._decide("sqli", False, 0.8, "no db"),
            ApplicabilityGate._decide("xss", False, 0.9, "no http"),
        ]
        report = GateReport(decisions)
        kws = report.disabled_rule_keywords()
        assert "sqli" in kws and "xss" in kws
        assert len(kws) == len(set(kws))

    def test_finding_match_agent_rule_id(self) -> None:
        assert finding_matches_gated_class("sql_injection", ["sqli"]) == "sqli"

    def test_finding_match_semgrep_rule_id(self) -> None:
        assert (
            finding_matches_gated_class(
                "go.lang.security.audit.sqli.tainted-sql-string", ["sqli"]
            )
            == "sqli"
        )

    def test_finding_match_no_false_positive(self) -> None:
        assert finding_matches_gated_class("xss_reflected", ["sqli"]) is None
        assert finding_matches_gated_class(None, ["sqli"]) is None
        assert finding_matches_gated_class("anything", []) is None

    def test_summary_shape(self) -> None:
        decisions = [ApplicabilityGate._decide("sqli", False, 0.8, "no db")]
        report = GateReport(decisions)
        summary = report.to_summary()
        assert summary["gated_classes"] == ["sqli"]
        assert summary["decisions"][0]["vuln_class"] == "sqli"
