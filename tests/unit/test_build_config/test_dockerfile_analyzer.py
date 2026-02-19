"""Unit tests for Dockerfile analyzer."""

import tempfile
from pathlib import Path

import pytest

from src.layers.l1_intelligence.build_config.analyzers.dockerfile_analyzer import DockerfileAnalyzer
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    SecurityRisk,
)


class TestDockerfileAnalyzer:
    """Tests for DockerfileAnalyzer."""

    @pytest.fixture
    def analyzer(self) -> DockerfileAnalyzer:
        """Create analyzer instance."""
        return DockerfileAnalyzer()

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_analyze_empty_directory(self, analyzer: DockerfileAnalyzer, temp_dir: Path) -> None:
        """Test analyzing empty directory."""
        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        assert len(findings) == 0

    def test_detect_root_user(self, analyzer: DockerfileAnalyzer, temp_dir: Path) -> None:
        """Test detection of USER root."""
        dockerfile_content = """
FROM python:3.11
USER root
RUN apt-get update
"""
        (temp_dir / "Dockerfile").write_text(dockerfile_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find root user issue
        root_findings = [f for f in findings if "root" in f.title.lower()]
        assert len(root_findings) >= 1

    def test_detect_missing_user(self, analyzer: DockerfileAnalyzer, temp_dir: Path) -> None:
        """Test detection of missing USER instruction."""
        dockerfile_content = """
FROM python:3.11
RUN apt-get update
CMD ["python"]
"""
        (temp_dir / "Dockerfile").write_text(dockerfile_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should warn about missing USER
        user_findings = [f for f in findings if "USER" in f.title]
        assert len(user_findings) >= 1

    def test_detect_add_with_url(self, analyzer: DockerfileAnalyzer, temp_dir: Path) -> None:
        """Test detection of ADD with URL."""
        dockerfile_content = """
FROM alpine:3.18
ADD https://example.com/script.sh /script.sh
"""
        (temp_dir / "Dockerfile").write_text(dockerfile_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find ADD with URL issue
        add_findings = [f for f in findings if "ADD" in f.title]
        assert len(add_findings) >= 1

    def test_detect_sensitive_env(self, analyzer: DockerfileAnalyzer, temp_dir: Path) -> None:
        """Test detection of sensitive ENV variables."""
        dockerfile_content = """
FROM python:3.11
ENV DATABASE_PASSWORD=SuperSecret123
ENV API_KEY=secret_api_key
"""
        (temp_dir / "Dockerfile").write_text(dockerfile_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find sensitive ENV
        env_findings = [f for f in findings if "ENV" in f.title]
        assert len(env_findings) >= 1

    def test_detect_curl_pipe_bash(self, analyzer: DockerfileAnalyzer, temp_dir: Path) -> None:
        """Test detection of curl | bash pattern."""
        dockerfile_content = """
FROM alpine:3.18
RUN curl https://example.com/install.sh | bash
"""
        (temp_dir / "Dockerfile").write_text(dockerfile_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find curl | bash issue
        curl_findings = [f for f in findings if "curl" in f.title.lower()]
        assert len(curl_findings) >= 1

    def test_detect_latest_tag(self, analyzer: DockerfileAnalyzer, temp_dir: Path) -> None:
        """Test detection of latest tag."""
        dockerfile_content = """
FROM python:latest
RUN apt-get update
"""
        (temp_dir / "Dockerfile").write_text(dockerfile_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find latest tag issue
        latest_findings = [f for f in findings if "latest" in f.title.lower()]
        assert len(latest_findings) >= 1

    def test_detect_chmod_777(self, analyzer: DockerfileAnalyzer, temp_dir: Path) -> None:
        """Test detection of chmod 777."""
        dockerfile_content = """
FROM alpine:3.18
RUN chmod 777 /app
"""
        (temp_dir / "Dockerfile").write_text(dockerfile_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find chmod issue
        chmod_findings = [f for f in findings if "chmod" in f.title.lower()]
        assert len(chmod_findings) >= 1

    def test_secure_dockerfile(self, analyzer: DockerfileAnalyzer, temp_dir: Path) -> None:
        """Test that secure Dockerfile has minimal findings."""
        dockerfile_content = """
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m appuser
USER appuser

WORKDIR /app
COPY --chown=appuser:appuser . .

HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1
CMD ["python", "app.py"]
"""
        (temp_dir / "Dockerfile").write_text(dockerfile_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should have minimal findings (maybe just INFO level)
        high_findings = [f for f in findings if f.risk_level in (SecurityRisk.HIGH, SecurityRisk.CRITICAL)]
        assert len(high_findings) == 0

    def test_dockerfile_with_extension(self, analyzer: DockerfileAnalyzer, temp_dir: Path) -> None:
        """Test detection of Dockerfile.* patterns."""
        dockerfile_content = """
FROM python:3.11
USER root
"""
        (temp_dir / "Dockerfile.prod").write_text(dockerfile_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should scan Dockerfile.prod
        assert len(report.scanned_files) == 1

    def test_expose_sensitive_port(self, analyzer: DockerfileAnalyzer, temp_dir: Path) -> None:
        """Test detection of sensitive port exposure."""
        dockerfile_content = """
FROM alpine:3.18
EXPOSE 22
"""
        (temp_dir / "Dockerfile").write_text(dockerfile_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find SSH port exposure
        port_findings = [f for f in findings if "port" in f.title.lower()]
        assert len(port_findings) >= 1
