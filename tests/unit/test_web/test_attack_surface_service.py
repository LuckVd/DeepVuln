"""Unit tests for AttackSurfaceService.

P14-01a: AttackSurfaceService 单元测试
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from src.core.models.attack_surface import (
    AttackSurfaceReport,
    EntryPoint,
    EntryPointType,
    HTTPMethod,
    DetectionSource,
)
from src.layers.l3_analysis.llm.client import LLMClient
from src.web.services.attack_surface_service import (
    AttackSurfaceService,
    AttackSurfaceDetectionConfig,
    DetectionMode,
    create_attack_surface_service,
)


@pytest.fixture
def mock_llm_client():
    """Mock LLM client."""
    client = MagicMock(spec=LLMClient)
    return client


@pytest.fixture
def mock_source_path(tmp_path):
    """Create a temporary source directory with test files."""
    # Create a simple Python file with an HTTP endpoint
    test_file = tmp_path / "app.py"
    test_file.write_text("""
from flask import Flask, request

app = Flask(__name__)

@app.route('/api/users', methods=['GET'])
def get_users():
    return {'users': []}

@app.route('/api/users/<int:id>', methods=['GET', 'PUT'])
def get_user(id):
    return {'user': id}
""")
    return tmp_path


@pytest.fixture
def attack_surface_service(mock_llm_client):
    """Create AttackSurfaceService instance."""
    return AttackSurfaceService(llm_client=mock_llm_client)


class TestAttackSurfaceDetectionConfig:
    """Tests for AttackSurfaceDetectionConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = AttackSurfaceDetectionConfig()
        assert config.mode == DetectionMode.STATIC
        assert config.llm_model == "deepseek-chat"
        assert config.max_files == 50
        assert config.max_batch_chars == 25000
        assert config.static_only is False

    def test_static_only_config(self):
        """Test static-only configuration."""
        config = AttackSurfaceDetectionConfig(static_only=True)
        assert config.mode == DetectionMode.STATIC
        assert config.static_only is True

    def test_llm_full_config(self):
        """Test LLM-full configuration."""
        config = AttackSurfaceDetectionConfig(mode=DetectionMode.LLM_FULL)
        assert config.mode == DetectionMode.LLM_FULL
        assert config.static_only is False

    def test_parallel_config(self):
        """Test parallel detection configuration."""
        config = AttackSurfaceDetectionConfig(mode=DetectionMode.PARALLEL)
        assert config.mode == DetectionMode.PARALLEL


class TestAttackSurfaceService:
    """Tests for AttackSurfaceService."""

    def test_init_without_llm(self):
        """Test initialization without LLM client."""
        service = AttackSurfaceService()
        assert service.llm_client is None
        assert service._detector is None

    def test_init_with_llm(self, mock_llm_client):
        """Test initialization with LLM client."""
        service = AttackSurfaceService(llm_client=mock_llm_client)
        assert service.llm_client is mock_llm_client
        assert service._detector is None

    def test_get_detector_creates_instance(self, attack_surface_service):
        """Test that _get_detector creates detector instance."""
        config = AttackSurfaceDetectionConfig()
        detector = attack_surface_service._get_detector(config)
        assert detector is not None
        assert attack_surface_service._detector is not None

    @pytest.mark.asyncio
    async def test_detect_static_mode(
        self, attack_surface_service, mock_source_path
    ):
        """Test static detection mode."""
        config = AttackSurfaceDetectionConfig(mode=DetectionMode.STATIC)

        with patch.object(
            attack_surface_service, '_get_detector'
        ) as mock_get_detector:
            mock_detector = MagicMock()
            mock_report = AttackSurfaceReport(source_path=str(mock_source_path))
            mock_report.files_scanned = 1
            mock_get_detector.return_value = mock_detector

            mock_detector.detect.return_value = mock_report

            result = await attack_surface_service.detect(
                mock_source_path, config
            )

            assert result == mock_report
            mock_detector.detect.assert_called_once_with(
                mock_source_path, None
            )

    @pytest.mark.asyncio
    async def test_detect_with_none_config_uses_static(
        self, attack_surface_service, mock_source_path
    ):
        """Test that None config defaults to static mode."""
        with patch.object(
            attack_surface_service, '_detect_static'
        ) as mock_static:
            mock_report = AttackSurfaceReport(source_path=str(mock_source_path))
            mock_static.return_value = mock_report

            result = await attack_surface_service.detect(mock_source_path)

            assert result == mock_report
            mock_static.assert_called_once()

    def test_get_http_endpoints(self, attack_surface_service):
        """Test getting HTTP endpoints from report."""
        report = AttackSurfaceReport(source_path="/test")

        http_ep = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.GET,
            path="/api/test",
            handler="test_handler",
            file="test.py",
            line=10,
        )
        report.add_entry_point(http_ep)

        rpc_ep = EntryPoint(
            type=EntryPointType.RPC,
            path="TestService",
            handler="test_method",
            file="test.proto",
            line=5,
        )
        report.add_entry_point(rpc_ep)

        service = AttackSurfaceService()
        http_endpoints = service.get_http_endpoints(report)

        assert len(http_endpoints) == 1
        assert http_endpoints[0].type == EntryPointType.HTTP

    def test_get_unauthenticated_endpoints(self, attack_surface_service):
        """Test getting unauthenticated endpoints."""
        report = AttackSurfaceReport(source_path="/test")

        auth_ep = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.GET,
            path="/api/protected",
            handler="protected_handler",
            file="test.py",
            line=10,
            auth_required=True,
        )
        report.add_entry_point(auth_ep)

        unauth_ep = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.GET,
            path="/api/public",
            handler="public_handler",
            file="test.py",
            line=20,
            auth_required=False,
        )
        report.add_entry_point(unauth_ep)

        service = AttackSurfaceService()
        unauth_endpoints = service.get_unauthenticated_endpoints(report)

        assert len(unauth_endpoints) == 1
        assert unauth_endpoints[0].path == "/api/public"

    def test_get_summary(self, attack_surface_service):
        """Test getting summary from report."""
        report = AttackSurfaceReport(source_path="/test")

        http_ep = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.GET,
            path="/api/test",
            handler="test_handler",
            file="test.py",
            line=10,
            detection_source=DetectionSource.STATIC,
        )
        report.add_entry_point(http_ep)

        service = AttackSurfaceService()
        summary = service.get_summary(report)

        assert summary["total_entry_points"] == 1
        assert summary["http_endpoints"] == 1
        assert summary["static_found"] == 1

    def test_create_finding_context(self, attack_surface_service):
        """Test creating finding context from report."""
        report = AttackSurfaceReport(source_path="/test")
        report.frameworks_detected = ["flask"]

        http_ep = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.GET,
            path="/api/test",
            handler="test_handler",
            file="test.py",
            line=10,
            auth_required=False,
            detection_source=DetectionSource.STATIC,
        )
        report.add_entry_point(http_ep)

        service = AttackSurfaceService()
        context = service.create_finding_context(report)

        assert "attack_surface" in context
        assert context["attack_surface"]["total_entry_points"] == 1
        assert context["attack_surface"]["http_endpoints"] == 1
        assert context["attack_surface"]["unauthenticated_count"] == 1
        assert "detection_sources" in context
        assert context["detection_sources"]["static_found"] == 1
        assert context["frameworks"] == ["flask"]
        assert "entry_points" in context
        assert len(context["entry_points"]) == 1


class TestCreateAttackSurfaceService:
    """Tests for factory function."""

    def test_create_service_without_llm(self):
        """Test creating service without LLM client."""
        service = create_attack_surface_service()
        assert isinstance(service, AttackSurfaceService)
        assert service.llm_client is None

    def test_create_service_with_llm(self, mock_llm_client):
        """Test creating service with LLM client."""
        service = create_attack_surface_service(llm_client=mock_llm_client)
        assert isinstance(service, AttackSurfaceService)
        assert service.llm_client is mock_llm_client
