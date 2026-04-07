"""v1 API package initialization."""

from fastapi import APIRouter

from src.web.api.v1.api import router

__all__ = ["router"]
