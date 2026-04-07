"""FastAPI dependency injection providers."""

from src.web.models.database import get_db as _get_db

# Re-export the get_db function from database.py
# This ensures we always use the initialized AsyncSessionLocal
get_db = _get_db
