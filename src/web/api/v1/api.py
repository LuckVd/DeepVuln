"""API v1 router initialization."""

from fastapi import APIRouter

from src.web.api.v1 import scans, stats

# Create API v1 router
router = APIRouter()

# Include sub-routers
router.include_router(scans.router, tags=["scans"])
router.include_router(stats.router, tags=["stats"])
