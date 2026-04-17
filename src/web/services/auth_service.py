"""Authentication service – login, JWT, password management, user seeding."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.models.user import User

logger = logging.getLogger(__name__)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its bcrypt hash."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8") if isinstance(hashed_password, str) else hashed_password,
    )


def hash_password(password: str) -> str:
    """Hash a plain password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


async def authenticate(db: AsyncSession, username: str, password: str) -> Optional[User]:
    """Authenticate a user by username and password.

    Returns the User object on success, None on failure.
    """
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()

    if user is None:
        return None
    if not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None

    return user


def create_access_token(
    user_id: int,
    must_change_password: bool,
    secret: str,
    algorithm: str = "HS256",
    expire_minutes: int = 1440,
) -> str:
    """Create a signed JWT access token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "must_change_password": must_change_password,
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def verify_token(token: str, secret: str, algorithm: str = "HS256") -> Optional[dict[str, Any]]:
    """Decode and verify a JWT token.

    Returns the payload dict on success, None on failure.
    """
    try:
        payload = jwt.decode(token, secret, algorithms=[algorithm])
        return payload
    except JWTError:
        return None


async def change_password(db: AsyncSession, user_id: int, new_password: str) -> User:
    """Change a user's password and clear the must_change_password flag."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise ValueError(f"User {user_id} not found")

    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    user.updated_at = datetime.utcnow()
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def seed_default_user(db: AsyncSession) -> None:
    """Ensure the default admin user exists.

    Called at application startup. Idempotent — does nothing if admin already exists.
    """
    result = await db.execute(select(User).where(User.username == "admin"))
    existing = result.scalar_one_or_none()

    if existing is not None:
        logger.info("Default admin user already exists (id=%s)", existing.id)
        return

    user = User(
        username="admin",
        password_hash=hash_password("deepvuln"),
        must_change_password=True,
        is_active=True,
    )
    db.add(user)
    await db.commit()

    logger.info("Default admin user created (id=%s)", user.id)
