"""Regression tests for audit 2026-09 fix: WebSocket endpoint authentication.

The WS endpoint used to sit behind the router-level HTTPBearer dependency —
invisible to browsers during the handshake — while the frontend already sent
the JWT as ``token`` query param that the backend never read. The endpoint
now lives on a dedicated router and authenticates via query params.
"""

from types import SimpleNamespace

import pytest

from src.web.api.v1.scans import _authenticate_websocket


class _FakeWebSocket:
    def __init__(self, query_params: dict[str, str] | None = None):
        self.query_params = query_params or {}


class _FakeSettings:
    def __init__(self, auth_enabled=True, jwt_secret="s", jwt_algorithm="HS256",
                 api_key_enabled=False):
        self.auth_enabled = auth_enabled
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.api_key_enabled = api_key_enabled

    def get_api_keys(self):
        return ["static-key-1"]


@pytest.fixture
def patch_settings(monkeypatch):
    def _apply(settings):
        monkeypatch.setattr(
            "src.web.api.v1.scans.get_security_settings", lambda: settings
        )
    return _apply


@pytest.mark.asyncio
async def test_dev_mode_allows_without_token(monkeypatch):
    monkeypatch.setattr(
        "src.web.api.v1.scans.get_security_settings",
        lambda: _FakeSettings(auth_enabled=False),
    )
    assert await _authenticate_websocket(_FakeWebSocket(), None) is True


@pytest.mark.asyncio
async def test_auth_enabled_requires_token(monkeypatch):
    monkeypatch.setattr(
        "src.web.api.v1.scans.get_security_settings",
        lambda: _FakeSettings(),
    )
    # verify_token patched to return None (invalid / missing token)
    monkeypatch.setattr(
        "src.web.api.v1.scans.verify_token", lambda *a, **k: None
    )
    assert await _authenticate_websocket(_FakeWebSocket(), None) is False
    assert await _authenticate_websocket(_FakeWebSocket({"token": "garbage"}), "garbage") is False


@pytest.mark.asyncio
async def test_valid_jwt_token_allows(monkeypatch):
    monkeypatch.setattr(
        "src.web.api.v1.scans.get_security_settings",
        lambda: _FakeSettings(),
    )
    monkeypatch.setattr(
        "src.web.api.v1.scans.verify_token", lambda *a, **k: {"sub": "1"}
    )

    class _Session:
        class _Result:
            def scalar_one_or_none(self):
                return SimpleNamespace(id=1, is_active=True)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def execute(self, *a, **k):
            return self._Result()

    monkeypatch.setattr("src.web.models.database.get_session_local", lambda: _Session)
    assert await _authenticate_websocket(_FakeWebSocket({"token": "good"}), "good") is True


@pytest.mark.asyncio
async def test_inactive_user_rejected(monkeypatch):
    monkeypatch.setattr(
        "src.web.api.v1.scans.get_security_settings",
        lambda: _FakeSettings(),
    )
    monkeypatch.setattr(
        "src.web.api.v1.scans.verify_token", lambda *a, **k: {"sub": "1"}
    )

    class _Session:
        class _Result:
            def scalar_one_or_none(self):
                return SimpleNamespace(id=1, is_active=False)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def execute(self, *a, **k):
            return self._Result()

    monkeypatch.setattr("src.web.models.database.get_session_local", lambda: _Session)
    assert await _authenticate_websocket(_FakeWebSocket({"token": "good"}), "good") is False


@pytest.mark.asyncio
async def test_api_key_allows_when_enabled(monkeypatch):
    monkeypatch.setattr(
        "src.web.api.v1.scans.get_security_settings",
        lambda: _FakeSettings(api_key_enabled=True),
    )
    monkeypatch.setattr(
        "src.web.api.v1.scans.verify_token", lambda *a, **k: None
    )
    assert await _authenticate_websocket(
        _FakeWebSocket({"api_key": "static-key-1"}), None
    ) is True
    assert await _authenticate_websocket(
        _FakeWebSocket({"api_key": "wrong"}), None
    ) is False