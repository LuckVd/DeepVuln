"""Unit tests for Scan API endpoints."""

from unittest.mock import AsyncMock

import pytest
from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.main import app


@pytest.fixture
def mock_db():
    """Create mock database session."""
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def client(mock_db):
    """Create test client with mocked database and disabled auth."""
    from fastapi.testclient import TestClient
    from src.web.api import deps
    from src.web.core import security

    # Override database dependency
    async def get_db_override():
        yield mock_db

    # Override auth dependencies
    async def require_api_key_override():
        pass  # Skip auth check

    async def optional_api_key_override():
        return None  # Return None for optional auth

    app.dependency_overrides[deps.get_db] = get_db_override
    app.dependency_overrides[security.require_api_key] = require_api_key_override
    app.dependency_overrides[security.optional_api_key] = optional_api_key_override

    client = TestClient(app)

    yield client

    # Clean up
    app.dependency_overrides = {}


class TestAPIRoutesRegistered:
    """Tests that all scan API routes are properly registered."""

    def test_routes_registered(self):
        """Test that all scan routes are registered."""
        routes = [route.path for route in app.routes if hasattr(route, "path")]
        assert "/api/v1/scans" in routes
        assert "/api/v1/scans/{scan_id}" in routes
        assert "/api/v1/scans/{scan_id}/progress" in routes
        assert "/api/v1/scans/{scan_id}/phases" in routes
        assert "/api/v1/scans/{scan_id}/events" in routes
        assert "/api/v1/scans/{scan_id}/agent-conversation" in routes
        assert "/api/v1/scans/{scan_id}/current-file" in routes
        assert "/api/v1/scans/{scan_id}/findings" in routes
        assert "/api/v1/scans/{scan_id}/report" in routes


class TestRequestBodyValidation:
    """Tests for request body validation."""

    def test_create_scan_missing_project_id(self, client):
        """Test that project_id is required."""
        response = client.post(
            "/api/v1/scans",
            json={"scan_type": "full"}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_scan_missing_scan_type(self, client):
        """Test that scan_type is required."""
        response = client.post(
            "/api/v1/scans",
            json={"project_id": 1}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_scan_invalid_scan_type(self, client):
        """Test that invalid scan_type is rejected."""
        response = client.post(
            "/api/v1/scans",
            json={"project_id": 1, "scan_type": "invalid"}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestPaginationValidation:
    """Tests for pagination parameter validation."""

    def test_invalid_page_zero(self, client):
        """Test that page=0 is rejected."""
        response = client.get("/api/v1/scans?page=0")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_invalid_page_negative(self, client):
        """Test that negative page is rejected."""
        response = client.get("/api/v1/scans?page=-1")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_invalid_page_size_too_large(self, client):
        """Test that page_size > 1000 is rejected."""
        response = client.get("/api/v1/scans?page_size=1001")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_invalid_scan_limit_too_large(self, client):
        """Test that scan limit > 500 is rejected (for agent-conversation)."""
        response = client.get("/api/v1/scans/1/agent-conversation?limit=501")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_invalid_events_page_size_too_large(self, client):
        """Test that events page_size > 1000 is rejected."""
        response = client.get("/api/v1/scans/1/events?page_size=1001")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
