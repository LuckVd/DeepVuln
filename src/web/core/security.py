"""Security utilities for API authentication and authorization."""

import hmac
from typing import Optional, Any

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from src.web.models.user import User

# Lazy initialization - will be set when config is loaded
_api_key_header: Optional[APIKeyHeader] = None
_bearer_scheme = HTTPBearer(auto_error=False)


class SecurityDepends:
    """Helper for dependency injection of settings."""

    def __init__(self, settings_class: Any):
        self.settings_class = settings_class

    def __call__(self) -> Any:
        return self.settings_class()


def get_api_key_header() -> APIKeyHeader:
    """Get the API key header scheme (lazy initialization)."""
    global _api_key_header
    if _api_key_header is None:
        from src.web.core.config import get_security_settings
        _api_key_header = APIKeyHeader(
            name=get_security_settings().api_key_header,
            auto_error=False
        )
    return _api_key_header


async def verify_api_key(
    api_key: Optional[str] = Security(get_api_key_header),
) -> bool:
    """
    Verify API key from request header.

    Returns True if authentication is disabled or key is valid.
    Raises HTTPException if key is invalid.
    """
    from src.web.core.config import get_security_settings
    settings = get_security_settings()

    # Skip verification if disabled
    if not settings.api_key_enabled:
        return True

    # Get valid API keys
    valid_keys = settings.get_api_keys()

    # Check if API key is provided
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key is missing. Provide it via X-API-Key header.",
        )

    # Validate API key (constant-time comparison to prevent timing attacks)
    if not any(hmac.compare_digest(api_key, k) for k in valid_keys):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key.",
        )

    return True


async def require_api_key(
    verified: bool = Security(verify_api_key),
) -> None:
    """
    Dependency to require API key authentication.

    Usage:
        @router.get("/protected")
        async def protected_endpoint(_: None = Depends(require_api_key)):
            ...
    """
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication failed",
        )


# Optional API key verification (for endpoints that work with or without auth)
async def optional_api_key(
    api_key: Optional[str] = Security(get_api_key_header),
) -> Optional[str]:
    """
    Verify API key if provided, but don't require it.

    Returns the API key if valid, None otherwise.
    """
    from src.web.core.config import get_security_settings
    settings = get_security_settings()

    if not settings.api_key_enabled:
        return None

    if api_key is None:
        return None

    valid_keys = settings.get_api_keys()
    if any(hmac.compare_digest(api_key, k) for k in valid_keys):
        return api_key

    return None


# ---------------------------------------------------------------------------
# JWT-based authentication
# ---------------------------------------------------------------------------

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
) -> User:
    """
    Dependency to get the current authenticated user from JWT Bearer token.

    Raises HTTPException 401 if no valid token is provided.
    """
    from src.web.core.config import get_security_settings
    from src.web.services.auth_service import verify_token

    settings = get_security_settings()

    if not settings.auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication is disabled",
        )

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(
        credentials.credentials,
        settings.jwt_secret,
        settings.jwt_algorithm,
    )

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    # Fetch user from database
    from src.web.models.database import get_session_local
    from sqlalchemy import select

    session_local = get_session_local()
    async with session_local() as session:
        result = await session.execute(select(User).where(User.id == int(user_id)))
        user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user
