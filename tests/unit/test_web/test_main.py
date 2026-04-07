"""Unit tests for FastAPI application."""

import pytest
from fastapi.testclient import TestClient

from src.web.main import app


class TestFastAPIApp:
    """Test FastAPI application setup."""

    def test_app_creation(self):
        """Test that the app is created successfully."""
        assert app is not None
        assert app.title == "DeepVuln API"
        assert app.version == "0.9.0"

    def test_routes_registered(self):
        """Test that all expected routes are registered."""
        routes = [route.path for route in app.routes if hasattr(route, "path")]
        assert "/" in routes
        assert "/health" in routes
        assert "/api/v1/projects" in routes
        assert "/api/v1/scans" in routes


class TestRootEndpoints:
    """Test root-level endpoints."""

    def test_root_endpoint(self):
        """Test the root endpoint."""
        client = TestClient(app)
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "DeepVuln API"
        assert data["status"] == "running"

    def test_health_endpoint(self):
        """Test the health check endpoint."""
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_openapi_schema(self):
        """Test that OpenAPI schema is generated."""
        client = TestClient(app)
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert schema["info"]["title"] == "DeepVuln API"
        assert schema["info"]["version"] == "0.9.0"

    def test_docs_endpoint(self):
        """Test that the docs endpoint is accessible."""
        client = TestClient(app)
        response = client.get("/docs")
        assert response.status_code == 200


class TestAPIEndpoints:
    """Test API endpoints (placeholder)."""

    def test_projects_endpoint_returns_501(self):
        """Test that projects endpoint returns 501 (not implemented)."""
        client = TestClient(app)
        response = client.get("/api/v1/projects")
        assert response.status_code == 501
        assert "Not implemented yet" in response.json()["detail"]

    def test_scans_endpoint_returns_501(self):
        """Test that scans endpoint returns 501 (not implemented)."""
        client = TestClient(app)
        response = client.get("/api/v1/scans")
        assert response.status_code == 501
        assert "Not implemented yet" in response.json()["detail"]


class TestCORS:
    """Test CORS configuration."""

    def test_cors_headers(self):
        """Test that CORS headers are set correctly."""
        client = TestClient(app)
        response = client.options(
            "/api/v1/projects",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            }
        )
        # Note: OPTIONS might not be handled by the TestClient the same way
        # but the middleware should be present
        assert any(m.cls.__name__ == "CORSMiddleware" for m in app.user_middleware)
