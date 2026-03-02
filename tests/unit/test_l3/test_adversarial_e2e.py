"""
End-to-End tests for Adversarial Verification System.

Tests the complete verification flow from finding input to result output,
including real-world scenarios and edge cases.
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from typing import Any

from src.layers.l3_analysis.verification.adversarial import (
    AdversarialVerifier,
    AdversarialVerifierConfig,
)
from src.layers.l3_analysis.verification.models import (
    VerdictType,
)

from .conftest_adversarial import (
    MultiResponseMockLLMClient,
    MockLLMClient,
    build_attacker_response,
    build_defender_response,
    build_arbiter_response,
)


class TestEndToEndScenarios:
    """End-to-end test scenarios."""

    @pytest.mark.asyncio
    async def test_scenario_clear_sqli_vulnerability(self):
        """
        Scenario: Clear SQL Injection vulnerability
        Expected: CONFIRMED in single round
        """
        finding = {
            "id": "e2e-sqli-001",
            "type": "sql_injection",
            "severity": "critical",
            "title": "SQL Injection in Login",
            "description": "User credentials directly concatenated into query",
            "location": "auth/login.py:45",
            "code_snippet": '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    return db.execute(query)
''',
            "language": "python",
        }

        responses = [
            # Round 1
            build_attacker_response(
                confidence=0.98,
                strength="definitive",
                claim="Critical SQL injection in authentication",
                evidence=[
                    "Both username and password directly interpolated",
                    "No sanitization whatsoever",
                    "Classic authentication bypass possible",
                ],
                poc_code="admin'--",
                exploitation_steps=[
                    "1. POST /login with username=admin'--",
                    "2. Query becomes: SELECT * FROM users WHERE username = 'admin'--' AND ...",
                    "3. Password check is commented out, login as admin",
                ],
            ),
            build_defender_response(
                confidence=0.1,
                strength="weak",
                claim="Cannot find any defense",
                evidence=[],
                reasoning="No sanitizers or validation detected in code",
            ),
            build_arbiter_response(
                verdict="confirmed",
                confidence=0.98,
                attacker_strength=0.98,
                defender_strength=0.1,
                summary="Critical SQL injection confirmed with working auth bypass",
                recommended_action="fix",
                priority="critical",
            ),
        ]

        mock_client = MultiResponseMockLLMClient(responses)
        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=finding,
            code_context=finding["code_snippet"],
        )

        assert result.verdict.verdict == VerdictType.CONFIRMED
        assert result.verdict.confidence >= 0.9
        assert result.rounds_completed == 1
        assert result.max_rounds_reached is False
        assert result.verdict.priority == "critical"

    @pytest.mark.asyncio
    async def test_scenario_parameterized_query_false_positive(self):
        """
        Scenario: Flagged as SQLi but uses parameterized query
        Expected: FALSE_POSITIVE in single round
        """
        finding = {
            "id": "e2e-fp-001",
            "type": "sql_injection",
            "severity": "high",
            "title": "Potential SQL Injection",
            "description": "Flagged due to SQL query construction",
            "location": "db/queries.py:30",
            "code_snippet": '''
def get_user(user_id: int) -> User:
    query = "SELECT * FROM users WHERE id = %s"
    cursor = db.cursor()
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
''',
            "language": "python",
        }

        responses = [
            # Round 1
            build_attacker_response(
                confidence=0.3,
                strength="weak",
                claim="Cannot construct working PoC",
                evidence=["SQL query exists but uses parameterization"],
                reasoning="The %s placeholder prevents direct injection",
            ),
            build_defender_response(
                confidence=0.98,
                strength="definitive",
                claim="This is a false positive - parameterized query",
                evidence=[
                    "Uses %s placeholder for parameterization",
                    "user_id passed as tuple to execute()",
                    "This is the recommended secure pattern",
                ],
                sanitizers_found=["%s placeholder", "tuple parameterization"],
            ),
            build_arbiter_response(
                verdict="false_positive",
                confidence=0.95,
                attacker_strength=0.3,
                defender_strength=0.98,
                summary="False positive - uses secure parameterized query pattern",
                recommended_action="ignore",
                priority="low",
            ),
        ]

        mock_client = MultiResponseMockLLMClient(responses)
        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=finding,
            code_context=finding["code_snippet"],
        )

        assert result.verdict.verdict == VerdictType.FALSE_POSITIVE
        assert result.verdict.confidence >= 0.9
        assert result.rounds_completed == 1
        assert result.max_rounds_reached is False

    @pytest.mark.asyncio
    async def test_scenario_orm_with_edge_case(self):
        """
        Scenario: ORM usage with potential edge case
        Expected: CONDITIONAL or multiple rounds
        """
        finding = {
            "id": "e2e-orm-001",
            "type": "sql_injection",
            "severity": "medium",
            "title": "Potential ORM Injection",
            "description": "Raw SQL in ORM context",
            "location": "models/user.py:55",
            "code_snippet": '''
def search_users(query: str) -> list[User]:
    # Using raw SQL in Django ORM
    return User.objects.raw(
        f"SELECT * FROM users WHERE name LIKE '%{query}%'"
    )
''',
            "language": "python",
        }

        responses = [
            # Round 1 - close debate
            build_attacker_response(
                confidence=0.7,
                strength="strong",
                claim="Raw SQL with f-string is injectable",
                evidence=["f-string in raw() SQL", "LIKE clause with user input"],
                poc_code="%' OR '1'='1",
            ),
            build_defender_response(
                confidence=0.6,
                strength="moderate",
                claim="Django ORM may provide some protection",
                evidence=["Using Django ORM", "raw() method"],
                sanitizers_found=["Django ORM context"],
            ),
            build_arbiter_response(
                verdict="needs_review",
                confidence=0.5,
                attacker_strength=0.7,
                defender_strength=0.6,
                summary="Need more context about Django raw() behavior",
            ),
            # Round 2 - attacker strengthens case
            build_attacker_response(
                confidence=0.85,
                strength="strong",
                claim="Django raw() does NOT escape f-strings",
                evidence=[
                    "Django documentation confirms raw() doesn't escape",
                    "f-string interpolation happens before raw()",
                    "This is a known Django anti-pattern",
                ],
                counter_arguments=["Django ORM context doesn't apply to raw() f-strings"],
            ),
            build_defender_response(
                confidence=0.5,
                strength="moderate",
                claim="Still uncertain about actual exploitability",
                evidence=["Maybe Django has some protection"],
            ),
            build_arbiter_response(
                verdict="confirmed",
                confidence=0.8,
                attacker_strength=0.85,
                defender_strength=0.5,
                summary="Confirmed - raw() with f-string is injectable",
            ),
        ]

        mock_client = MultiResponseMockLLMClient(responses)
        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=finding,
            code_context=finding["code_snippet"],
        )

        assert result.rounds_completed == 2
        assert result.verdict.verdict == VerdictType.CONFIRMED
        assert result.max_rounds_reached is False

    @pytest.mark.asyncio
    async def test_scenario_xss_with_partial_defense(self):
        """
        Scenario: XSS with partial escaping
        Expected: CONDITIONAL or NEEDS_REVIEW (both indicate uncertainty)
        """
        finding = {
            "id": "e2e-xss-001",
            "type": "xss",
            "severity": "medium",
            "title": "Potential XSS in Template",
            "description": "User input in template context",
            "location": "templates/comment.html:20",
            "code_snippet": '''
<div class="comment">
    <h3>{{ user_name | escape }}</h3>
    <p>{{ user_comment }}</p>  <!-- escape missing here -->
</div>
''',
            "language": "html",
        }

        responses = [
            build_attacker_response(
                confidence=0.8,
                strength="strong",
                claim="XSS in user_comment field",
                evidence=[
                    "user_comment not escaped",
                    "user_name is escaped but not user_comment",
                ],
                poc_code="<script>alert(1)</script>",
            ),
            build_defender_response(
                confidence=0.7,
                strength="strong",
                claim="Template framework may auto-escape",
                evidence=[
                    "Using template engine ({{ }} syntax)",
                    "Many templates auto-escape by default",
                ],
                framework_protections=["Template auto-escape"],
            ),
            build_arbiter_response(
                verdict="conditional",
                confidence=0.7,
                attacker_strength=0.8,
                defender_strength=0.7,
                summary="Potentially exploitable depending on template configuration",
                conditions=["If auto-escape is disabled for this template"],
            ),
        ]

        mock_client = MultiResponseMockLLMClient(responses)
        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=finding,
            code_context=finding["code_snippet"],
        )

        # Either CONDITIONAL or NEEDS_REVIEW is acceptable for uncertain cases
        assert result.verdict.verdict in [VerdictType.CONDITIONAL, VerdictType.NEEDS_REVIEW]

    @pytest.mark.asyncio
    async def test_scenario_max_rounds_indecisive(self):
        """
        Scenario: Debate continues without resolution
        Expected: NEEDS_REVIEW with max_rounds_reached
        """
        finding = {
            "id": "e2e-indecisive-001",
            "type": "sql_injection",
            "severity": "medium",
            "title": "Ambiguous SQL Pattern",
            "description": "Complex query construction",
            "location": "db/complex.py:100",
            "code_snippet": '''
def dynamic_query(table: str, filters: dict):
    base = f"SELECT * FROM {table}"
    conditions = []
    for key, value in filters.items():
        conditions.append(f"{key} = %s")
    query = base + " WHERE " + " AND ".join(conditions)
    return execute(query, list(filters.values()))
''',
            "language": "python",
        }

        responses = []
        for _ in range(3):  # 3 rounds of indecisive debate
            responses.extend([
                build_attacker_response(
                    confidence=0.6,
                    strength="moderate",
                    claim="Table name injection possible",
                    evidence=["Table name from user input", "Key names from dict keys"],
                ),
                build_defender_response(
                    confidence=0.55,
                    strength="moderate",
                    claim="Values are parameterized",
                    evidence=["Values use %s placeholder", "Only table/column names are dynamic"],
                ),
                build_arbiter_response(
                    verdict="needs_review",
                    confidence=0.5,
                    attacker_strength=0.6,
                    defender_strength=0.55,
                    summary="Debate continues - need more analysis",
                ),
            ])

        mock_client = MultiResponseMockLLMClient(responses)
        config = AdversarialVerifierConfig(max_rounds=3)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=finding,
            code_context=finding["code_snippet"],
        )

        assert result.rounds_completed == 3
        assert result.max_rounds_reached is True
        assert result.verdict.verdict == VerdictType.NEEDS_REVIEW


class TestSessionReporting:
    """Tests for session-level reporting."""

    @pytest.mark.asyncio
    async def test_full_session_with_multiple_findings(self):
        """Test a full session with multiple findings of different types."""
        findings = [
            {
                "id": "session-sqli-001",
                "type": "sql_injection",
                "severity": "critical",
                "title": "SQL Injection",
                "description": "Test",
                "location": "test.py:1",
                "code_snippet": 'query = f"SELECT * FROM {table}"',
                "language": "python",
            },
            {
                "id": "session-xss-001",
                "type": "xss",
                "severity": "medium",
                "title": "XSS",
                "description": "Test",
                "location": "test.py:2",
                "code_snippet": "<div>{{ input }}</div>",
                "language": "html",
            },
            {
                "id": "session-fp-001",
                "type": "sql_injection",
                "severity": "high",
                "title": "False Positive",
                "description": "Test",
                "location": "test.py:3",
                "code_snippet": 'cursor.execute("SELECT * FROM users WHERE id = %s", (id,))',
                "language": "python",
            },
        ]

        # Responses for all findings (3 calls each)
        responses = [
            # Finding 1: Confirmed
            build_attacker_response(0.9),
            build_defender_response(0.2),
            build_arbiter_response("confirmed", 0.9, 0.9, 0.2),
            # Finding 2: Conditional
            build_attacker_response(0.7),
            build_defender_response(0.6),
            build_arbiter_response("conditional", 0.6, 0.7, 0.6),
            # Finding 3: False Positive
            build_attacker_response(0.2),
            build_defender_response(0.95),
            build_arbiter_response("false_positive", 0.95, 0.2, 0.95),
        ]

        mock_client = MultiResponseMockLLMClient(responses)
        config = AdversarialVerifierConfig(max_rounds=1)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        session = await verifier.verify_findings(
            findings=findings,
            source_path="/test/project",
        )

        # Check session stats
        assert session.total_findings == 3
        assert session.confirmed == 1
        assert session.false_positives == 1
        assert session.conditional == 1
        assert session.needs_review == 0

        # Check statistics
        stats = verifier.get_statistics(session)
        assert stats["total"] == 3
        assert stats["confirmed_rate"] == pytest.approx(1/3, rel=0.1)
        assert stats["false_positive_rate"] == pytest.approx(1/3, rel=0.1)

        # Check report
        report = verifier.format_session_report(session)
        # Report uses finding type, which is "sql_injection" not "SQL Injection"
        assert "sql_injection" in report.lower()
        assert "xss" in report.lower()
        assert "CONFIRMED" in report
        assert "FALSE_POSITIVE" in report
        assert "CONDITIONAL" in report

    @pytest.mark.asyncio
    async def test_session_with_all_needs_review(self):
        """Test session where all findings need review."""
        findings = [
            {
                "id": f"review-{i}",
                "type": "sql_injection",
                "severity": "medium",
                "title": f"Test {i}",
                "description": "Test",
                "location": f"test.py:{i}",
                "code_snippet": "test code",
                "language": "python",
            }
            for i in range(5)
        ]

        responses = []
        for _ in findings:
            responses.extend([
                build_attacker_response(0.5),
                build_defender_response(0.5),
                build_arbiter_response("needs_review", 0.5, 0.5, 0.5),
            ])

        mock_client = MultiResponseMockLLMClient(responses)
        config = AdversarialVerifierConfig(max_rounds=1)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        session = await verifier.verify_findings(
            findings=findings,
            source_path="/test/project",
        )

        assert session.needs_review == 5
        assert session.confirmed == 0
        assert session.false_positives == 0

        stats = session.get_summary()
        assert stats["confirmed_rate"] == 0.0
        assert stats["false_positive_rate"] == 0.0


class TestEdgeCases:
    """Edge case tests."""

    @pytest.mark.asyncio
    async def test_empty_code_context(self):
        """Test with empty code context."""
        finding = {
            "id": "edge-001",
            "type": "sql_injection",
            "severity": "high",
            "title": "Test",
            "description": "Test",
            "location": "test.py:1",
            "language": "python",
        }

        responses = [
            build_attacker_response(0.3, strength="weak"),
            build_defender_response(0.3, strength="weak"),
            build_arbiter_response("needs_review", 0.3, 0.3, 0.3),
        ]

        mock_client = MultiResponseMockLLMClient(responses)
        config = AdversarialVerifierConfig()
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=finding,
            code_context="",  # Empty
        )

        assert result is not None
        assert result.verdict is not None

    @pytest.mark.asyncio
    async def test_very_long_code_context(self):
        """Test with very long code context."""
        finding = {
            "id": "edge-002",
            "type": "sql_injection",
            "severity": "high",
            "title": "Test",
            "description": "Test",
            "location": "test.py:1",
            "language": "python",
        }

        # Very long code context
        long_context = "def test():\n    pass\n" * 1000

        responses = [
            build_attacker_response(0.5),
            build_defender_response(0.5),
            build_arbiter_response("needs_review", 0.5, 0.5, 0.5),
        ]

        mock_client = MultiResponseMockLLMClient(responses)
        config = AdversarialVerifierConfig(max_context_length=4000)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=finding,
            code_context=long_context,
        )

        # Should handle truncation gracefully
        assert result is not None

    @pytest.mark.asyncio
    async def test_unicode_in_code(self):
        """Test with unicode characters in code."""
        finding = {
            "id": "edge-003",
            "type": "sql_injection",
            "severity": "high",
            "title": "Test",
            "description": "Test",
            "location": "test.py:1",
            "code_snippet": 'query = f"SELECT * FROM 用户 WHERE 名字 = {name}"',
            "language": "python",
        }

        responses = [
            build_attacker_response(0.8),
            build_defender_response(0.3),
            build_arbiter_response("confirmed", 0.8, 0.8, 0.3),
        ]

        mock_client = MultiResponseMockLLMClient(responses)
        config = AdversarialVerifierConfig()
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=finding,
            code_context=finding["code_snippet"],
        )

        assert result.verdict.verdict == VerdictType.CONFIRMED

    @pytest.mark.asyncio
    async def test_llm_returns_invalid_json(self):
        """Test handling of invalid JSON from LLM."""
        finding = {
            "id": "edge-004",
            "type": "sql_injection",
            "severity": "high",
            "title": "Test",
            "description": "Test",
            "location": "test.py:1",
            "code_snippet": "test code",
            "language": "python",
        }

        # Return invalid JSON, then valid fallback
        responses = [
            "This is not valid JSON at all",
            '{"claim": "Defense", "confidence": 0.3, "evidence": [], "reasoning": "", "strength": "weak"}',
            '{"verdict": "needs_review", "confidence": 0.3, "summary": "LLM error", "reasoning": "", "attacker_strength": 0.1, "defender_strength": 0.3}',
        ]

        mock_client = MultiResponseMockLLMClient(responses)
        config = AdversarialVerifierConfig(use_heuristic_fallback=True)
        verifier = AdversarialVerifier(llm_client=mock_client, config=config)

        result = await verifier.verify_finding(
            finding=finding,
            code_context="test",
        )

        # Should use fallback/heuristic
        assert result is not None
        assert result.verdict is not None
