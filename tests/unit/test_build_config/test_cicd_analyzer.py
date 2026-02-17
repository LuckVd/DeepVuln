"""Unit tests for CI/CD analyzer."""

import tempfile
from pathlib import Path

import pytest

from src.layers.l1_intelligence.build_config.analyzers.cicd_analyzer import CICDAnalyzer
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    FindingCategory,
    SecurityRisk,
)


class TestCICDAnalyzer:
    """Tests for CICDAnalyzer."""

    @pytest.fixture
    def analyzer(self) -> CICDAnalyzer:
        """Create analyzer instance."""
        return CICDAnalyzer()

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_analyze_empty_directory(self, analyzer: CICDAnalyzer, temp_dir: Path) -> None:
        """Test analyzing empty directory."""
        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        assert len(findings) == 0

    def test_analyze_github_actions_with_secret(
        self, analyzer: CICDAnalyzer, temp_dir: Path
    ) -> None:
        """Test detection of hardcoded secrets in GitHub Actions."""
        workflow_dir = temp_dir / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)

        workflow_content = """
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      API_KEY: "sk-1234567890abcdefghijklmnop"
    steps:
      - uses: actions/checkout@v3
      - run: echo "Building"
"""
        (workflow_dir / "ci.yml").write_text(workflow_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find hardcoded secret
        secret_findings = [f for f in findings if "secret" in f.title.lower() or "API_KEY" in f.title]
        assert len(secret_findings) >= 1

    def test_github_actions_safe_secrets(self, analyzer: CICDAnalyzer, temp_dir: Path) -> None:
        """Test that GitHub Secrets references are not flagged."""
        workflow_dir = temp_dir / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)

        workflow_content = """
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      API_KEY: ${{ secrets.API_KEY }}
      DATABASE_URL: ${{ secrets.DATABASE_URL }}
    steps:
      - uses: actions/checkout@v3
"""
        (workflow_dir / "ci.yml").write_text(workflow_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should not flag secrets references
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRETS]
        assert len(secret_findings) == 0

    def test_pull_request_target_danger(self, analyzer: CICDAnalyzer, temp_dir: Path) -> None:
        """Test detection of dangerous pull_request_target pattern."""
        workflow_dir = temp_dir / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)

        workflow_content = """
name: CI
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
        (workflow_dir / "ci.yml").write_text(workflow_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find dangerous pattern
        danger_findings = [f for f in findings if "pull_request_target" in f.title.lower()]
        assert len(danger_findings) >= 1

    def test_script_injection(self, analyzer: CICDAnalyzer, temp_dir: Path) -> None:
        """Test detection of potential script injection."""
        workflow_dir = temp_dir / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)

        workflow_content = """
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.body }}"
"""
        (workflow_dir / "ci.yml").write_text(workflow_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find injection risk
        injection_findings = [f for f in findings if "injection" in f.title.lower()]
        assert len(injection_findings) >= 1

    def test_gitlab_ci_with_secret(self, analyzer: CICDAnalyzer, temp_dir: Path) -> None:
        """Test detection of secrets in GitLab CI."""
        gitlab_ci_content = """
stages:
  - build

build:
  stage: build
  variables:
    DATABASE_PASSWORD: "SuperSecretPassword123"
  script:
    - echo "Building"
"""
        (temp_dir / ".gitlab-ci.yml").write_text(gitlab_ci_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find hardcoded secret
        secret_findings = [f for f in findings if "secret" in f.title.lower() or "PASSWORD" in f.title]
        assert len(secret_findings) >= 1

    def test_jenkinsfile_with_credential(self, analyzer: CICDAnalyzer, temp_dir: Path) -> None:
        """Test detection of credentials in Jenkinsfile."""
        jenkinsfile_content = """
pipeline {
    agent any
    environment {
        API_KEY = 'sk-1234567890abcdefghijkl'
    }
    stages {
        stage('Build') {
            steps {
                sh 'echo Building'
            }
        }
    }
}
"""
        (temp_dir / "Jenkinsfile").write_text(jenkinsfile_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find hardcoded credential
        cred_findings = [f for f in findings if "credential" in f.title.lower()]
        assert len(cred_findings) >= 1

    def test_circleci_with_secret(self, analyzer: CICDAnalyzer, temp_dir: Path) -> None:
        """Test detection of secrets in CircleCI."""
        circleci_dir = temp_dir / ".circleci"
        circleci_dir.mkdir()

        circleci_content = """
version: 2.1
jobs:
  build:
    docker:
      - image: python:3.11
    environment:
      API_KEY: "secret_api_key_12345"
    steps:
      - checkout
"""
        (circleci_dir / "config.yml").write_text(circleci_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find hardcoded secret
        secret_findings = [f for f in findings if "secret" in f.title.lower() or "API_KEY" in f.title]
        assert len(secret_findings) >= 1

    def test_safe_github_actions(self, analyzer: CICDAnalyzer, temp_dir: Path) -> None:
        """Test that safe GitHub Actions workflow has no findings."""
        workflow_dir = temp_dir / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)

        workflow_content = """
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest
"""
        (workflow_dir / "ci.yml").write_text(workflow_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should have no high/critical findings
        high_findings = [f for f in findings if f.risk_level in (SecurityRisk.HIGH, SecurityRisk.CRITICAL)]
        assert len(high_findings) == 0

    def test_multiple_workflow_files(self, analyzer: CICDAnalyzer, temp_dir: Path) -> None:
        """Test scanning multiple workflow files."""
        workflow_dir = temp_dir / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)

        # Create multiple workflow files
        (workflow_dir / "ci.yml").write_text("""
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      SECRET: "hardcoded_secret_123"
    steps:
      - run: echo "CI"
""")

        (workflow_dir / "deploy.yml").write_text("""
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      API_KEY: "another_hardcoded_key"
    steps:
      - run: echo "Deploy"
""")

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should scan both files
        assert len(report.scanned_files) == 2

        # Should find secrets in both
        secret_findings = [f for f in findings if f.category == FindingCategory.CI_CD]
        assert len(secret_findings) >= 2
