"""Unit tests for Project API endpoints."""

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


class TestPaginationValidation:
    """Tests for pagination parameter validation."""

    def test_invalid_page_zero(self, client):
        """Test that page=0 is rejected."""
        response = client.get("/api/v1/projects?page=0")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_invalid_page_negative(self, client):
        """Test that negative page is rejected."""
        response = client.get("/api/v1/projects?page=-1")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_invalid_page_size_too_large(self, client):
        """Test that page_size > 1000 is rejected."""
        response = client.get("/api/v1/projects?page_size=1001")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_invalid_page_size_zero(self, client):
        """Test that page_size=0 is rejected."""
        response = client.get("/api/v1/projects?page_size=0")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_invalid_scan_limit_too_large(self, client):
        """Test that scan limit > 500 is rejected."""
        response = client.get("/api/v1/projects/1/scans?limit=501")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestRequestBodyValidation:
    """Tests for request body validation."""

    def test_create_project_missing_name(self, client):
        """Test that name is required."""
        response = client.post(
            "/api/v1/projects",
            json={"source_type": "local", "source_path": "/tmp"}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_project_missing_source_type(self, client):
        """Test that source_type is required."""
        response = client.post(
            "/api/v1/projects",
            json={"name": "test", "source_path": "/tmp"}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_project_invalid_source_type(self, client):
        """Test that invalid source_type is rejected."""
        response = client.post(
            "/api/v1/projects",
            json={"name": "test", "source_type": "invalid", "source_path": "/tmp"}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_project_name_too_long(self, client):
        """Test that name > 255 chars is rejected."""
        response = client.post(
            "/api/v1/projects",
            json={"name": "a" * 256, "source_type": "local", "source_path": "/tmp"}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_project_name_empty(self, client):
        """Test that empty name is rejected."""
        response = client.post(
            "/api/v1/projects",
            json={"name": "", "source_type": "local", "source_path": "/tmp"}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_project_valid_source_local(self, client):
        """Test that 'local' source type is accepted."""
        response = client.post(
            "/api/v1/projects",
            json={"name": "test", "source_type": "local", "source_path": "/tmp"}
        )
        # Validation passes (will get DB error)
        assert response.status_code not in [
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_404_NOT_FOUND
        ]

    def test_create_project_valid_source_git(self, client):
        """Test that 'git' source type is accepted."""
        response = client.post(
            "/api/v1/projects",
            json={"name": "test", "source_type": "git", "source_path": "https://github.com/test/repo"}
        )
        assert response.status_code not in [
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_404_NOT_FOUND
        ]

    def test_create_project_valid_source_zip(self, client):
        """Test that 'zip' source type is accepted."""
        response = client.post(
            "/api/v1/projects",
            json={"name": "test", "source_type": "zip", "source_path": "/tmp/project.zip"}
        )
        assert response.status_code not in [
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_404_NOT_FOUND
        ]


class TestAPIRoutesRegistered:
    """Tests that all API routes are properly registered."""

    def test_routes_registered(self):
        """Test that all project routes are registered."""
        routes = [route.path for route in app.routes if hasattr(route, "path")]
        assert "/api/v1/projects" in routes
        assert "/api/v1/projects/{project_id}" in routes
        assert "/api/v1/projects/{project_id}/scans" in routes
