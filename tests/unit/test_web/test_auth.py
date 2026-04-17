"""Unit tests for authentication service and API endpoints."""

import pytest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from src.web.services.auth_service import (
    authenticate,
    change_password,
    create_access_token,
    hash_password,
    seed_default_user,
    verify_password,
    verify_token,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SECRET = "test-secret-key"
ALGORITHM = "HS256"


def _make_user(**overrides):
    """Create a mock User object."""
    defaults = dict(
        id=1,
        username="admin",
        password_hash=hash_password("deepvuln"),
        must_change_password=True,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# Service-level tests
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    """Tests for password hashing and verification."""

    def test_hash_and_verify_success(self):
        hashed = hash_password("mypassword")
        assert verify_password("mypassword", hashed)

    def test_hash_and_verify_wrong_password(self):
        hashed = hash_password("mypassword")
        assert not verify_password("wrongpassword", hashed)

    def test_different_hashes_for_same_password(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # bcrypt uses random salt


class TestJWT:
    """Tests for JWT token creation and verification."""

    def test_create_and_verify_token(self):
        token = create_access_token(user_id=1, must_change_password=True, secret=SECRET)
        payload = verify_token(token, SECRET)
        assert payload is not None
        assert payload["sub"] == "1"
        assert payload["must_change_password"] is True

    def test_verify_expired_token(self):
        token = create_access_token(
            user_id=1, must_change_password=False, secret=SECRET, expire_minutes=-1
        )
        payload = verify_token(token, SECRET)
        assert payload is None

    def test_verify_invalid_token(self):
        payload = verify_token("invalid.token.here", SECRET)
        assert payload is None

    def test_verify_token_wrong_secret(self):
        token = create_access_token(user_id=1, must_change_password=False, secret=SECRET)
        payload = verify_token(token, "wrong-secret")
        assert payload is None

    def test_token_contains_user_id(self):
        token = create_access_token(user_id=42, must_change_password=False, secret=SECRET)
        payload = verify_token(token, SECRET)
        assert payload["sub"] == "42"


class TestAuthenticate:
    """Tests for user authentication."""

    @pytest.mark.asyncio
    async def test_authenticate_success(self):
        user = _make_user()
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = user
        db.execute = AsyncMock(return_value=result_mock)

        authenticated = await authenticate(db, "admin", "deepvuln")
        assert authenticated is not None
        assert authenticated.username == "admin"

    @pytest.mark.asyncio
    async def test_authenticate_wrong_password(self):
        user = _make_user()
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = user
        db.execute = AsyncMock(return_value=result_mock)

        authenticated = await authenticate(db, "admin", "wrongpassword")
        assert authenticated is None

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self):
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=result_mock)

        authenticated = await authenticate(db, "nonexistent", "password")
        assert authenticated is None

    @pytest.mark.asyncio
    async def test_authenticate_inactive_user(self):
        user = _make_user(is_active=False)
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = user
        db.execute = AsyncMock(return_value=result_mock)

        authenticated = await authenticate(db, "admin", "deepvuln")
        assert authenticated is None


class TestChangePassword:
    """Tests for password change."""

    @pytest.mark.asyncio
    async def test_change_password_updates_hash(self):
        original_hash = hash_password("old")
        user = _make_user(password_hash=original_hash)
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = user
        db.execute = AsyncMock(return_value=result_mock)
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        updated = await change_password(db, 1, "newpassword123")
        assert updated.password_hash != original_hash
        assert verify_password("newpassword123", updated.password_hash)

    @pytest.mark.asyncio
    async def test_change_password_clears_flag(self):
        user = _make_user(must_change_password=True)
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = user
        db.execute = AsyncMock(return_value=result_mock)
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        updated = await change_password(db, 1, "newpassword123")
        assert updated.must_change_password is False

    @pytest.mark.asyncio
    async def test_change_password_user_not_found(self):
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=result_mock)

        with pytest.raises(ValueError, match="not found"):
            await change_password(db, 999, "newpassword123")


class TestSeedDefaultUser:
    """Tests for default user seeding."""

    @pytest.mark.asyncio
    async def test_seed_creates_admin(self):
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = None  # No existing admin
        db.execute = AsyncMock(return_value=result_mock)
        db.commit = AsyncMock()

        await seed_default_user(db)
        db.add.assert_called_once()
        db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_seed_idempotent(self):
        existing_user = _make_user()
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = existing_user
        db.execute = AsyncMock(return_value=result_mock)

        await seed_default_user(db)
        db.add.assert_not_called()
        db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_seed_default_password_is_deepvuln(self):
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=result_mock)
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        await seed_default_user(db)
        added_user = db.add.call_args[0][0]
        assert verify_password("deepvuln", added_user.password_hash)
        assert added_user.must_change_password is True
        assert added_user.username == "admin"
