"""API v1 router initialization."""

from fastapi import APIRouter

from src.web.api.v1 import projects, scans

# Create API v1 router
router = APIRouter()

# Include sub-routers
router.include_router(projects.router, tags=["projects"])
router.include_router(scans.router, tags=["scans"])
