"""API v1 router initialization."""

from fastapi import APIRouter

from src.web.api.v1 import auth, scans, stats, llm_configs, system_settings

# Create API v1 router
router = APIRouter()

# Include sub-routers
router.include_router(auth.router, tags=["auth"])
router.include_router(scans.router, tags=["scans"])
router.include_router(stats.router, tags=["stats"])
router.include_router(llm_configs.router, tags=["llm-configs"])
router.include_router(system_settings.router, tags=["system-settings"])
