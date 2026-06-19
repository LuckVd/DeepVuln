"""Tests for logic-vuln discovery prompts (E5: AI 补漏逻辑漏洞).

These tests pin the prompt module contract:
- ``build_logic_vuln_prompt`` returns a (system, user) tuple.
- ``parse_logic_vuln_response`` enforces the anti-false-positive three-element
  hard-evidence requirement (missing_check / entry_point / attack_path) and
  drops findings that lack it. Malformed input yields an empty list.
"""

import json

import pytest

from src.layers.l3_analysis.prompts.logic_vuln import (
    build_logic_vuln_prompt,
    parse_logic_vuln_response,
)


def _finding(**overrides) -> dict:
    base = {
        "title": "Missing authorization on user lookup",
        "category": "missing_authorization",
        "severity": "high",
        "confidence": 0.7,
        "file": "app.py",
        "line": 12,
        "function": "get_user",
        "missing_check": "No ownership check on user_id before returning the record",
        "entry_point": "GET /api/users/{id} -> get_user",
        "attack_path": "Attacker swaps {id} for another user's id; record returned unchecked",
        "description": "IDOR via missing authorization.",
        "cwe": "CWE-862",
    }
    base.update(overrides)
    return base


class TestBuildLogicVulnPrompt:
    def test_returns_system_and_user_strings(self) -> None:
        regions = [
            {
                "file": "app.py",
                "line": 1,
                "entry_point_type": "HTTP",
                "handler": "get_user",
                "code": "def get_user(id): return db.get(id)",
            }
        ]
        system, user = build_logic_vuln_prompt(regions)
        assert isinstance(system, str) and system.strip()
        assert isinstance(user, str) and user.strip()

    def test_system_prompt_states_scope_and_evidence_rule(self) -> None:
        system, _ = build_logic_vuln_prompt([])
        # Limited scope + anti-FP contract must be visible to the model.
        assert "entry point" in system.lower()
        assert "authorization" in system.lower() or "auth" in system.lower()
        assert "missing_check" in system or "missing check" in system.lower()

    def test_user_prompt_embeds_entry_point_code(self) -> None:
        regions = [
            {
                "file": "app.py",
                "line": 5,
                "entry_point_type": "HTTP",
                "handler": "delete_user",
                "code": "MARKER_CODE_FRAGMENT",
            }
        ]
        _, user = build_logic_vuln_prompt(regions)
        assert "MARKER_CODE_FRAGMENT" in user
        assert "delete_user" in user

    def test_long_code_is_truncated(self) -> None:
        big = "x = 1\n" * 5000  # ~30KB
        regions = [
            {
                "file": "app.py",
                "line": 1,
                "entry_point_type": "HTTP",
                "handler": "h",
                "code": big,
            }
        ]
        _, user = build_logic_vuln_prompt(regions, max_code_length=1000)
        assert len(user) < len(big)
        assert "MARKER_CODE_FRAGMENT" not in user  # sanity


class TestParseLogicVulnResponse:
    def test_valid_response_returns_findings(self) -> None:
        payload = json.dumps({"findings": [_finding(), _finding(title="Second", line=20)]})
        result = parse_logic_vuln_response(payload)
        assert len(result) == 2
        assert result[0]["missing_check"]
        assert result[1]["title"] == "Second"

    def test_drops_finding_missing_attack_path(self) -> None:
        # Missing one of the three required evidence fields → dropped.
        bad = _finding(attack_path="")
        payload = json.dumps({"findings": [bad, _finding(title="Good")]})
        result = parse_logic_vuln_response(payload)
        assert len(result) == 1
        assert result[0]["title"] == "Good"

    def test_drops_finding_missing_missing_check(self) -> None:
        bad = _finding(missing_check="   ")  # whitespace-only
        payload = json.dumps({"findings": [bad]})
        assert parse_logic_vuln_response(payload) == []

    def test_drops_finding_missing_entry_point(self) -> None:
        bad = _finding(entry_point=None)  # type: ignore[arg-type]
        payload = json.dumps({"findings": [bad]})
        assert parse_logic_vuln_response(payload) == []

    def test_accepts_bare_list(self) -> None:
        payload = json.dumps([_finding(), _finding(title="B")])
        result = parse_logic_vuln_response(payload)
        assert len(result) == 2

    def test_accepts_single_object(self) -> None:
        payload = json.dumps(_finding())
        result = parse_logic_vuln_response(payload)
        assert len(result) == 1

    def test_strips_markdown_code_fence(self) -> None:
        payload = "```json\n" + json.dumps({"findings": [_finding()]}) + "\n```"
        result = parse_logic_vuln_response(payload)
        assert len(result) == 1

    def test_malformed_text_returns_empty(self) -> None:
        assert parse_logic_vuln_response("not json at all") == []

    def test_empty_findings_key(self) -> None:
        assert parse_logic_vuln_response(json.dumps({"findings": []})) == []

    def test_clamps_confidence_into_range(self) -> None:
        f = _finding(confidence=5.0)  # out of [0,1]
        result = parse_logic_vuln_response(json.dumps({"findings": [f]}))
        assert len(result) == 1
        assert 0.0 <= result[0]["confidence"] <= 1.0

    @pytest.mark.parametrize(
        "category",
        [
            "missing_authorization",
            "auth_bypass",
            "idor",
            "business_logic",
            "complex_injection",
        ],
    )
    def test_accepts_all_v1_categories(self, category: str) -> None:
        f = _finding(category=category)
        result = parse_logic_vuln_response(json.dumps({"findings": [f]}))
        assert len(result) == 1
        assert result[0]["category"] == category
