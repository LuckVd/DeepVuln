"""Security utilities for API authentication and authorization."""

import hmac
from typing import Optional, Any

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

# Lazy initialization - will be set when config is loaded
_api_key_header: Optional[APIKeyHeader] = None


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
