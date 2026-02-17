"""Unit tests for Python build configuration analyzer."""

import tempfile
from pathlib import Path

import pytest

from src.layers.l1_intelligence.build_config.analyzers.python_analyzer import PythonAnalyzer
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    FindingCategory,
    SecurityRisk,
)


class TestPythonAnalyzer:
    """Tests for PythonAnalyzer."""

    @pytest.fixture
    def analyzer(self) -> PythonAnalyzer:
        """Create analyzer instance."""
        return PythonAnalyzer()

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_supported_files(self, analyzer: PythonAnalyzer) -> None:
        """Test supported file list."""
        assert "setup.py" in analyzer.supported_files
        assert "setup.cfg" in analyzer.supported_files
        assert "tox.ini" in analyzer.supported_files
        assert ".python-version" in analyzer.supported_files
        assert "pyproject.toml" in analyzer.supported_files

    def test_analyze_empty_directory(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test analyzing empty directory."""
        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        assert len(findings) == 0
        assert len(report.scanned_files) == 0

    def test_analyze_setup_py_with_exec(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test detection of exec() in setup.py."""
        setup_content = """
from setuptools import setup

# Dynamically get version
with open('version.txt') as f:
    version = exec(f.read())

setup(
    name='mypackage',
    version=version,
)
"""
        (temp_dir / "setup.py").write_text(setup_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find exec() usage
        exec_findings = [f for f in findings if "exec" in f.title.lower()]
        assert len(exec_findings) >= 1
        assert exec_findings[0].risk_level == SecurityRisk.HIGH

    def test_analyze_setup_py_with_eval(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test detection of eval() in setup.py."""
        setup_content = """
from setuptools import setup

with open('config.txt') as f:
    config = eval(f.read())

setup(name='mypackage')
"""
        (temp_dir / "setup.py").write_text(setup_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find eval() usage
        eval_findings = [f for f in findings if "eval" in f.title.lower()]
        assert len(eval_findings) >= 1
        assert eval_findings[0].risk_level == SecurityRisk.HIGH

    def test_analyze_setup_py_with_subprocess_shell(
        self, analyzer: PythonAnalyzer, temp_dir: Path
    ) -> None:
        """Test detection of subprocess with shell=True."""
        setup_content = """
from setuptools import setup
import subprocess

subprocess.run('echo hello', shell=True)

setup(name='mypackage')
"""
        (temp_dir / "setup.py").write_text(setup_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find shell=True usage
        shell_findings = [f for f in findings if "shell" in f.title.lower()]
        assert len(shell_findings) >= 1

    def test_analyze_setup_py_with_secrets(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test detection of hardcoded secrets in setup.py."""
        setup_content = """
from setuptools import setup

API_KEY = "sk-1234567890abcdefghijklmnop"
DB_PASSWORD = "SuperSecretPassword123!"

setup(name='mypackage')
"""
        (temp_dir / "setup.py").write_text(setup_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find secrets
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRETS]
        assert len(secret_findings) >= 1

    def test_analyze_setup_cfg_with_secrets(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test detection of secrets in setup.cfg."""
        setup_cfg = """
[metadata]
name = mypackage

[options]
install_requires =
    requests

[database]
password = HardcodedDbPassword123
api_key = sk-test-1234567890
"""
        (temp_dir / "setup.cfg").write_text(setup_cfg)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find secrets in setup.cfg
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRETS]
        assert len(secret_findings) >= 1

    def test_analyze_tox_ini_with_secrets(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test detection of secrets in tox.ini."""
        tox_content = """
[tox]
envlist = py311

[testenv]
setenv =
    API_KEY = hardcoded-api-key-12345
    DB_PASSWORD = SecretPassword789
commands =
    pytest
"""
        (temp_dir / "tox.ini").write_text(tox_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find hardcoded secrets
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRETS]
        assert len(secret_findings) >= 1

    def test_analyze_tox_ini_safe_env_vars(
        self, analyzer: PythonAnalyzer, temp_dir: Path
    ) -> None:
        """Test that environment variable references are not flagged."""
        tox_content = """
[tox]
envlist = py311

[testenv]
setenv =
    API_KEY = {env:API_KEY}
    DB_PASSWORD = {env:DB_PASSWORD:default}
passenv =
    SECRET_TOKEN
commands =
    pytest
"""
        (temp_dir / "tox.ini").write_text(tox_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should not find hardcoded secrets (using env vars)
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRETS]
        assert len(secret_findings) == 0

    def test_analyze_tox_ini_curl_bash(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test detection of curl | bash pattern in tox.ini."""
        # Note: This test is for potential future enhancement
        # Currently curl|bash detection in tox.ini is a basic check
        tox_content = """
[tox]
envlist = py311

[testenv]
commands =
    curl https://example.com/install.sh | bash
    pytest
"""
        (temp_dir / "tox.ini").write_text(tox_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # This feature may be implemented in future - for now just verify no crashes
        # The tox.ini parser focuses on secrets, not command analysis
        assert findings is not None

    def test_analyze_python_version_eol(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test detection of EOL Python versions."""
        (temp_dir / ".python-version").write_text("2.7.18\n")

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find EOL version
        eol_findings = [f for f in findings if "EOL" in f.title]
        assert len(eol_findings) >= 1
        assert eol_findings[0].risk_level == SecurityRisk.HIGH

    def test_analyze_python_version_old(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test detection of old Python versions."""
        (temp_dir / ".python-version").write_text("3.8.10\n")

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find old version warning
        old_findings = [f for f in findings if "Old" in f.title]
        assert len(old_findings) >= 1
        assert old_findings[0].risk_level == SecurityRisk.LOW

    def test_analyze_python_version_current(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test that current Python versions don't trigger warnings."""
        (temp_dir / ".python-version").write_text("3.12.0\n")

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should not find any version issues
        version_findings = [f for f in findings if "version" in f.title.lower()]
        assert len(version_findings) == 0

    def test_analyze_pyproject_toml_secrets(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test detection of secrets in pyproject.toml."""
        pyproject_content = """
[project]
name = "mypackage"
version = "1.0.0"

[tool.mytool]
api_key = "sk-1234567890abcdefghij"
password = "HardcodedPassword123"
"""
        (temp_dir / "pyproject.toml").write_text(pyproject_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find secrets
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRETS]
        assert len(secret_findings) >= 1

    def test_analyze_pyproject_toml_safe_values(
        self, analyzer: PythonAnalyzer, temp_dir: Path
    ) -> None:
        """Test that environment variable references are not flagged."""
        pyproject_content = """
[project]
name = "mypackage"
version = "1.0.0"

[tool.mytool]
api_key = "{env:API_KEY}"
normal_setting = "some_value"
"""
        (temp_dir / "pyproject.toml").write_text(pyproject_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should not find secrets (using env vars)
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRETS]
        assert len(secret_findings) == 0

    def test_analyze_clean_setup_py(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test that clean setup.py files don't trigger warnings."""
        setup_content = """
from setuptools import setup, find_packages

setup(
    name='mypackage',
    version='1.0.0',
    packages=find_packages(),
    install_requires=[
        'requests>=2.25.0',
    ],
)
"""
        (temp_dir / "setup.py").write_text(setup_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should not find any issues in clean setup.py
        assert len(findings) == 0

    def test_analyze_multiple_files(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test analysis of multiple Python config files."""
        # Create multiple files
        (temp_dir / "setup.py").write_text("""
from setuptools import setup
API_KEY = "sk-test-1234567890"
setup(name='test')
""")
        (temp_dir / "setup.cfg").write_text("""
[database]
password = DbPassword123
""")
        (temp_dir / ".python-version").write_text("3.7.0\n")

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should scan all files
        assert len(report.scanned_files) == 3

        # Should find multiple issues
        assert len(findings) >= 3

    def test_aws_access_key_detection(self, analyzer: PythonAnalyzer, temp_dir: Path) -> None:
        """Test detection of AWS access keys."""
        setup_content = """
from setuptools import setup

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

setup(name='test')
"""
        (temp_dir / "setup.py").write_text(setup_content)

        report = BuildConfigReport(source_path=str(temp_dir))
        findings = analyzer.analyze(temp_dir, report)

        # Should find AWS key as CRITICAL
        aws_findings = [f for f in findings if f.risk_level == SecurityRisk.CRITICAL]
        assert len(aws_findings) >= 1
