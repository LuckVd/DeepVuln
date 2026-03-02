"""
Test fixtures for Adversarial Verification tests.

Provides common fixtures and utilities for testing the adversarial
verification system.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock
from typing import Any

from src.layers.l3_analysis.verification.models import (
    AdversarialVerdict,
    ArgumentStrength,
    TriggerConditions,
    VerificationArgument,
    VerdictType,
)


class MockLLMClient:
    """Mock LLM client for testing."""

    def __init__(self, response_content: str = "{}"):
        self.response_content = response_content
        self.call_count = 0
        self.call_history = []
        self.last_system_prompt = None
        self.last_user_prompt = None

    async def complete_with_context(self, system_prompt: str, user_prompt: str):
        """Mock the complete_with_context method."""
        self.call_count += 1
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        self.call_history.append({
            "call": self.call_count,
            "system_prompt": system_prompt[:200],
            "user_prompt": user_prompt[:500],
        })

        response = MagicMock()
        response.content = self.response_content
        return response


class MultiResponseMockLLMClient:
    """Mock LLM client that returns different responses based on call count."""

    def __init__(self, responses: list[str]):
        self.responses = responses
        self.call_count = 0
        self.call_history = []

    async def complete_with_context(self, system_prompt: str, user_prompt: str):
        """Return the next response in sequence."""
        if self.call_count >= len(self.responses):
            # Return a default response if we run out
            response = MagicMock()
            response.content = json.dumps({
                "verdict": "needs_review",
                "confidence": 0.5,
                "summary": "Default response",
                "reasoning": "Ran out of prepared responses",
                "attacker_strength": 0.5,
                "defender_strength": 0.5,
            })
            self.call_count += 1
            return response

        response = MagicMock()
        response.content = self.responses[self.call_count]
        self.call_history.append({
            "call": self.call_count,
            "system_prompt": system_prompt[:200],
            "user_prompt": user_prompt[:500],
        })
        self.call_count += 1
        return response


@pytest.fixture
def mock_llm_client():
    """Create a basic mock LLM client."""
    return MockLLMClient()


@pytest.fixture
def sample_sql_injection_finding():
    """Sample SQL injection vulnerability finding."""
    return {
        "id": "sqli-001",
        "type": "sql_injection",
        "severity": "high",
        "title": "SQL Injection in User Query",
        "description": "User input directly concatenated into SQL query without sanitization",
        "location": "app/db.py:42",
        "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_input}"',
        "dataflow": "user_input → query → db.execute()",
        "attack_surface": "HTTP GET parameter",
        "language": "python",
        "cwe": "CWE-89",
    }


@pytest.fixture
def sample_xss_finding():
    """Sample XSS vulnerability finding."""
    return {
        "id": "xss-001",
        "type": "xss",
        "severity": "medium",
        "title": "Cross-Site Scripting in Comment",
        "description": "User input rendered without escaping",
        "location": "app/templates/comment.html:15",
        "code_snippet": '<div>{{ user_comment }}</div>',
        "language": "python",
    }


@pytest.fixture
def sample_command_injection_finding():
    """Sample command injection vulnerability finding."""
    return {
        "id": "cmdi-001",
        "type": "command_injection",
        "severity": "critical",
        "title": "Command Injection in Ping Utility",
        "description": "User input directly passed to os.system",
        "location": "app/utils/ping.py:23",
        "code_snippet": 'os.system(f"ping -c 1 {hostname}")',
        "language": "python",
    }


@pytest.fixture
def sample_false_positive_finding():
    """Sample false positive finding (parameterized query)."""
    return {
        "id": "fp-001",
        "type": "sql_injection",
        "severity": "high",
        "title": "Potential SQL Injection",
        "description": "Flagged as SQL injection but uses parameterized query",
        "location": "app/db.py:50",
        "code_snippet": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "language": "python",
    }


@pytest.fixture
def sample_code_context():
    """Sample code context for testing."""
    return '''
def get_user_by_id(user_id: str) -> User:
    """Get user by ID from database.

    Args:
        user_id: The user ID from HTTP request

    Returns:
        User object or None
    """
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = db.execute(query)
    if result:
        return User.from_row(result)
    return None
'''


@pytest.fixture
def attacker_argument_strong():
    """Strong attacker argument."""
    return VerificationArgument(
        role="attacker",
        claim="This SQL injection is directly exploitable",
        evidence=[
            "User input directly concatenated into SQL query",
            "No parameterization or sanitization",
            "f-string interpolation allows arbitrary SQL",
        ],
        reasoning="The f-string interpolation in the query construction allows an attacker to inject arbitrary SQL code.",
        strength=ArgumentStrength.DEFINITIVE,
        confidence=0.95,
        counter_arguments=[
            "Some might argue input validation exists - but we see no evidence of it",
        ],
        poc_code="1' OR '1'='1",
        poc_type="http_request",
        exploitation_steps=[
            "1. Send GET /api/user?id=1'%20OR%20'1'='1",
            "2. Query becomes: SELECT * FROM users WHERE id = 1' OR '1'='1",
            "3. Returns all users instead of single user",
        ],
        prerequisites=[],
    )


@pytest.fixture
def defender_argument_strong():
    """Strong defender argument."""
    return VerificationArgument(
        role="defender",
        claim="This is NOT exploitable due to parameterized query",
        evidence=[
            "Query uses %s placeholder for parameterization",
            "user_id passed as tuple parameter to execute()",
            "This is the recommended secure pattern",
        ],
        reasoning="The code uses parameterized queries which prevent SQL injection by separating code from data.",
        strength=ArgumentStrength.DEFINITIVE,
        confidence=0.95,
        counter_arguments=[
            "Attacker might claim WAF bypass - but parameterization is WAF-independent",
        ],
        sanitizers_found=["%s placeholder", "tuple parameterization"],
        validation_checks=[],
        framework_protections=["Python DB-API parameterization"],
        exploitation_barriers=[
            "Parameterized queries treat all input as data, never as code",
        ],
        false_positive_reasons=[
            "This is a well-known secure coding pattern",
            "The detection tool flagged it incorrectly",
        ],
    )


@pytest.fixture
def defender_argument_weak():
    """Weak defender argument."""
    return VerificationArgument(
        role="defender",
        claim="This might not be exploitable",
        evidence=["Maybe there's validation somewhere"],
        reasoning="There could be validation we don't see.",
        strength=ArgumentStrength.WEAK,
        confidence=0.3,
        counter_arguments=[],
        sanitizers_found=[],
        validation_checks=[],
        framework_protections=[],
    )


@pytest.fixture
def confirmed_verdict():
    """Confirmed verdict."""
    return AdversarialVerdict(
        verdict=VerdictType.CONFIRMED,
        confidence=0.9,
        summary="Vulnerability confirmed - working PoC provided",
        reasoning="Attacker provides definitive evidence with working PoC, defender cannot demonstrate effective mitigations.",
        attacker_strength=0.9,
        defender_strength=0.3,
        recommended_action="fix",
        priority="critical",
        key_factors=["Working PoC", "No effective defenses", "Direct user input"],
    )


@pytest.fixture
def needs_review_verdict():
    """Needs review verdict."""
    return AdversarialVerdict(
        verdict=VerdictType.NEEDS_REVIEW,
        confidence=0.5,
        summary="Cannot determine - requires manual review",
        reasoning="Both sides have similar strength. Need more context.",
        attacker_strength=0.55,
        defender_strength=0.5,
        recommended_action="review",
        priority="medium",
        key_factors=["Close debate", "Need more context"],
    )


# Response builders for convenience
def build_attacker_response(confidence: float = 0.8, strength: str = "strong", **kwargs) -> str:
    """Build a mock attacker response JSON."""
    response = {
        "claim": kwargs.get("claim", f"Attacker claim with {confidence} confidence"),
        "confidence": confidence,
        "evidence": kwargs.get("evidence", ["Evidence 1", "Evidence 2"]),
        "reasoning": kwargs.get("reasoning", "Attacker reasoning"),
        "strength": strength,
        "counter_arguments": kwargs.get("counter_arguments", []),
    }
    if confidence > 0.7:
        response["poc_code"] = kwargs.get("poc_code", "1' OR '1'='1")
        response["poc_type"] = kwargs.get("poc_type", "http_request")
        response["exploitation_steps"] = kwargs.get("exploitation_steps", ["Step 1", "Step 2"])
    response["prerequisites"] = kwargs.get("prerequisites", [])
    return json.dumps(response)


def build_defender_response(confidence: float = 0.7, strength: str = "moderate", **kwargs) -> str:
    """Build a mock defender response JSON."""
    response = {
        "claim": kwargs.get("claim", f"Defender claim with {confidence} confidence"),
        "confidence": confidence,
        "evidence": kwargs.get("evidence", ["Defense 1"]),
        "reasoning": kwargs.get("reasoning", "Defender reasoning"),
        "strength": strength,
        "sanitizers_found": kwargs.get("sanitizers_found", []),
        "validation_checks": kwargs.get("validation_checks", []),
        "framework_protections": kwargs.get("framework_protections", []),
        "exploitation_barriers": kwargs.get("exploitation_barriers", []),
        "counter_arguments": kwargs.get("counter_arguments", []),
    }
    return json.dumps(response)


def build_arbiter_response(
    verdict: str = "confirmed",
    confidence: float = 0.8,
    attacker_strength: float = 0.8,
    defender_strength: float = 0.3,
    **kwargs
) -> str:
    """Build a mock arbiter response JSON."""
    response = {
        "verdict": verdict,
        "confidence": confidence,
        "summary": kwargs.get("summary", f"Verdict: {verdict}"),
        "reasoning": kwargs.get("reasoning", "Arbiter reasoning"),
        "attacker_strength": attacker_strength,
        "defender_strength": defender_strength,
        "conditions": kwargs.get("conditions", []),
        "recommended_action": kwargs.get("recommended_action", "fix" if verdict == "confirmed" else "review"),
        "priority": kwargs.get("priority", "high"),
        "key_factors": kwargs.get("key_factors", ["Factor 1"]),
    }
    return json.dumps(response)
