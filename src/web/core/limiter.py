"""Global rate limiter (slowapi).

The limiter is created once at import time. Its ``enabled`` flag honors
``SecuritySettings.rate_limit_enabled`` so it no-ops transparently when rate
limiting is disabled, while still letting endpoints be decorated unconditionally.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

from src.web.core.config import get_security_settings

_settings = get_security_settings()

limiter = Limiter(
    key_func=get_remote_address,
    enabled=_settings.rate_limit_enabled,
)
