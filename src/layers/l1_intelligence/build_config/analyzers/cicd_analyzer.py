"""CI/CD configuration security analyzer."""

import re
from pathlib import Path

from src.layers.l1_intelligence.build_config.base import BaseConfigAnalyzer
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    FindingCategory,
    SecurityFinding,
    SecurityRisk,
)


class CICDAnalyzer(BaseConfigAnalyzer):
    """Analyzer for CI/CD configuration files."""

    supported_files = [
        # GitHub Actions
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        # GitLab CI
        ".gitlab-ci.yml",
        ".gitlab-ci/*.yml",
        # CircleCI
        ".circleci/config.yml",
        # Jenkins
        "Jenkinsfile",
        "jenkinsfile",
        "*.jenkinsfile",
        # Azure Pipelines
        "azure-pipelines.yml",
        ".azure-pipelines/*.yml",
        # Travis CI
        ".travis.yml",
        # Bitbucket Pipelines
        "bitbucket-pipelines.yml",
    ]
    category_name = "ci_cd"

    # Sensitive environment variable patterns
    SENSITIVE_VAR_PATTERNS = {
        "password": re.compile(r"(?i)(?:password|passwd|pwd)", re.IGNORECASE),
        "secret": re.compile(r"(?i)(?:secret|token|key)", re.IGNORECASE),
        "credential": re.compile(r"(?i)(?:credential|auth)", re.IGNORECASE),
        "api_key": re.compile(r"(?i)(?:api[_-]?key|apikey)", re.IGNORECASE),
    }

    def __init__(self) -> None:
        """Initialize CI/CD analyzer."""
        super().__init__()

    def analyze(self, source_path: Path, report: BuildConfigReport) -> list[SecurityFinding]:
        """Analyze CI/CD configuration files for security issues.

        Args:
            source_path: Path to the source code.
            report: Report to add findings to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        cicd_files = self._find_cicd_files(source_path)
        if not cicd_files:
            return findings

        for cicd_file in cicd_files:
            report.scanned_files.append(str(cicd_file))
            file_findings = self._analyze_cicd_file(cicd_file)
            findings.extend(file_findings)

        return findings

    def _find_cicd_files(self, source_path: Path) -> list[Path]:
        """Find all CI/CD configuration files.

        Args:
            source_path: Source root path.

        Returns:
            List of CI/CD file paths.
        """
        files: list[Path] = []

        # GitHub Actions
        workflows_dir = source_path / ".github" / "workflows"
        if workflows_dir.exists():
            for f in workflows_dir.glob("*.yml"):
                if not self._should_skip_path(f):
                    files.append(f)
            for f in workflows_dir.glob("*.yaml"):
                if not self._should_skip_path(f):
                    files.append(f)

        # GitLab CI
        gitlab_ci = source_path / ".gitlab-ci.yml"
        if gitlab_ci.exists():
            files.append(gitlab_ci)

        for f in (source_path / ".gitlab-ci").glob("*.yml"):
            if not self._should_skip_path(f):
                files.append(f)

        # CircleCI
        circleci = source_path / ".circleci" / "config.yml"
        if circleci.exists():
            files.append(circleci)

        # Jenkins
        for name in ["Jenkinsfile", "jenkinsfile"]:
            jenkinsfile = source_path / name
            if jenkinsfile.exists():
                files.append(jenkinsfile)

        for f in source_path.glob("*.jenkinsfile"):
            if not self._should_skip_path(f):
                files.append(f)

        # Azure Pipelines
        azure_pipelines = source_path / "azure-pipelines.yml"
        if azure_pipelines.exists():
            files.append(azure_pipelines)

        for f in (source_path / ".azure-pipelines").glob("*.yml"):
            if not self._should_skip_path(f):
                files.append(f)

        # Travis CI
        travis = source_path / ".travis.yml"
        if travis.exists():
            files.append(travis)

        # Bitbucket Pipelines
        bitbucket = source_path / "bitbucket-pipelines.yml"
        if bitbucket.exists():
            files.append(bitbucket)

        return list(set(files))

    def _analyze_cicd_file(self, cicd_file: Path) -> list[SecurityFinding]:
        """Analyze a CI/CD configuration file.

        Args:
            cicd_file: Path to the CI/CD file.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        content = self._safe_read_file(cicd_file)
        if not content:
            return findings

        source_file = str(cicd_file)
        filename = cicd_file.name

        # Determine CI/CD type
        if ".github" in str(cicd_file):
            findings.extend(self._analyze_github_actions(content, source_file))
        elif ".gitlab" in str(cicd_file):
            findings.extend(self._analyze_gitlab_ci(content, source_file))
        elif "circleci" in str(cicd_file).lower():
            findings.extend(self._analyze_circleci(content, source_file))
        elif "jenkins" in filename.lower():
            findings.extend(self._analyze_jenkins(content, source_file))
        else:
            # Generic analysis
            findings.extend(self._analyze_generic_ci(content, source_file))

        return findings

    def _analyze_github_actions(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Analyze GitHub Actions workflow.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Check for hardcoded secrets in env
        env_pattern = re.compile(r"^\s*(\w+)\s*:\s*['\"]([^'\"]{10,})['\"]", re.MULTILINE)
        for match in env_pattern.finditer(content):
            var_name = match.group(1)
            var_value = match.group(2)
            line_num = content[:match.start()].count("\n") + 1

            if self._is_sensitive_var(var_name) and not self._is_placeholder(var_value):
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.CI_CD,
                        risk_level=SecurityRisk.HIGH,
                        title=f"Hardcoded secret in GitHub Actions: {var_name}",
                        description=f"Environment variable '{var_name}' contains hardcoded value.",
                        file_path=source_file,
                        line_start=line_num,
                        evidence=f"{var_name}: ***",
                        recommendation="Use GitHub Secrets instead of hardcoded values. "
                        "Reference with ${{ secrets.SECRET_NAME }}",
                        references=[
                            "https://docs.github.com/en/actions/security-guides/encrypted-secrets"
                        ],
                        cwe="CWE-798",
                    )
                )

        # Check for pull_request_target with checkout (potential security issue)
        if "pull_request_target" in content and "actions/checkout" in content:
            findings.append(
                SecurityFinding(
                    category=FindingCategory.CI_CD,
                    risk_level=SecurityRisk.HIGH,
                    title="Dangerous workflow pattern: pull_request_target with checkout",
                    description="Using pull_request_target with actions/checkout can expose repository secrets "
                    "to untrusted code from forks.",
                    file_path=source_file,
                    recommendation="Avoid using pull_request_target with checkout, or use persist-credentials: false "
                    "and be very careful with subsequent steps.",
                    references=[
                        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
                    ],
                    cwe="CWE-829",
                )
            )

        # Check for script injection in run steps
        script_injection_pattern = re.compile(r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment)\.(?:body|title)|github\.head_ref)\s*\}\}")
        for match in script_injection_pattern.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(
                SecurityFinding(
                    category=FindingCategory.CI_CD,
                    risk_level=SecurityRisk.HIGH,
                    title="Potential script injection in workflow",
                    description="Workflow uses user-controlled context in a potentially unsafe way.",
                    file_path=source_file,
                    line_start=line_num,
                    evidence=match.group(0),
                    recommendation="Sanitize user input or use environment files instead of interpolation.",
                    references=[
                        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
                    ],
                    cwe="CWE-94",
                )
            )

        return findings

    def _analyze_gitlab_ci(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Analyze GitLab CI configuration.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Check for hardcoded variables
        var_pattern = re.compile(r"^\s*(\w+)\s*:\s*['\"]([^'\"]{10,})['\"]", re.MULTILINE)
        for match in var_pattern.finditer(content):
            var_name = match.group(1)
            var_value = match.group(2)
            line_num = content[:match.start()].count("\n") + 1

            if self._is_sensitive_var(var_name) and not self._is_placeholder(var_value):
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.CI_CD,
                        risk_level=SecurityRisk.HIGH,
                        title=f"Hardcoded secret in GitLab CI: {var_name}",
                        description=f"Variable '{var_name}' contains hardcoded value.",
                        file_path=source_file,
                        line_start=line_num,
                        evidence=f"{var_name}: ***",
                        recommendation="Use GitLab CI/CD Variables or Vault integration.",
                        references=[
                            "https://docs.gitlab.com/ee/ci/variables/"
                        ],
                        cwe="CWE-798",
                    )
                )

        return findings

    def _analyze_circleci(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Analyze CircleCI configuration.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Check for hardcoded environment variables
        env_pattern = re.compile(r"^\s*(\w+)\s*:\s*['\"]([^'\"]{10,})['\"]", re.MULTILINE)
        for match in env_pattern.finditer(content):
            var_name = match.group(1)
            var_value = match.group(2)
            line_num = content[:match.start()].count("\n") + 1

            if self._is_sensitive_var(var_name) and not self._is_placeholder(var_value):
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.CI_CD,
                        risk_level=SecurityRisk.HIGH,
                        title=f"Hardcoded secret in CircleCI: {var_name}",
                        description=f"Environment variable '{var_name}' contains hardcoded value.",
                        file_path=source_file,
                        line_start=line_num,
                        evidence=f"{var_name}: ***",
                        recommendation="Use CircleCI Contexts or environment variables in project settings.",
                        references=[
                            "https://circleci.com/docs/env-vars/"
                        ],
                        cwe="CWE-798",
                    )
                )

        return findings

    def _analyze_jenkins(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Analyze Jenkinsfile.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Check for hardcoded credentials
        cred_pattern = re.compile(r"(?:password|secret|token|key)\s*[=:]\s*['\"]([^'\"]{10,})['\"]", re.IGNORECASE)
        for match in cred_pattern.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            value = match.group(1)

            if not self._is_placeholder(value):
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.CI_CD,
                        risk_level=SecurityRisk.HIGH,
                        title="Hardcoded credential in Jenkinsfile",
                        description="Jenkinsfile contains hardcoded credential.",
                        file_path=source_file,
                        line_start=line_num,
                        evidence=match.group(0)[:50] + "...",
                        recommendation="Use Jenkins Credentials Plugin with withCredentials block.",
                        references=[
                            "https://www.jenkins.io/doc/book/using/using-credentials/"
                        ],
                        cwe="CWE-798",
                    )
                )

        return findings

    def _analyze_generic_ci(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Generic CI/CD analysis.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Look for common secret patterns
        for var_type, pattern in self.SENSITIVE_VAR_PATTERNS.items():
            # Find variable assignments
            var_pattern = re.compile(
                rf"(?:export\s+)?(\w*{pattern.pattern}\w*)\s*[=:]\s*['\"]([^'\"]{{10,}})['\"]",
                re.IGNORECASE | re.MULTILINE
            )

            for match in var_pattern.finditer(content):
                var_name = match.group(1)
                var_value = match.group(2)
                line_num = content[:match.start()].count("\n") + 1

                if not self._is_placeholder(var_value):
                    findings.append(
                        SecurityFinding(
                            category=FindingCategory.CI_CD,
                            risk_level=SecurityRisk.HIGH,
                            title=f"Hardcoded secret in CI/CD config: {var_name}",
                            description=f"Configuration contains hardcoded {var_type}.",
                            file_path=source_file,
                            line_start=line_num,
                            evidence=f"{var_name}: ***",
                            recommendation="Use CI/CD platform's secrets management or external vault.",
                            references=[],
                            cwe="CWE-798",
                        )
                    )

        return findings

    def _is_sensitive_var(self, var_name: str) -> bool:
        """Check if variable name suggests sensitive data.

        Args:
            var_name: Variable name.

        Returns:
            True if variable name is sensitive.
        """
        var_lower = var_name.lower()
        sensitive_keywords = [
            "password", "passwd", "pwd", "secret", "token", "key",
            "credential", "auth", "api_key", "apikey", "private",
            "access_key", "secret_key", "database_url"
        ]
        return any(kw in var_lower for kw in sensitive_keywords)

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder or variable reference.

        Args:
            value: Value to check.

        Returns:
            True if value is a placeholder.
        """
        if not value:
            return True

        placeholders = [
            "${{",           # GitHub Actions
            "${",            # Shell/variable
            "$(",            # Command substitution
            "secrets.",      # GitHub Secrets
            "env.",          # Environment variable
            "vault.",        # Vault reference
            "<",             # Placeholder
            "your_",         # Placeholder prefix
            "example",       # Example value
            "changeme",      # Placeholder
            "xxx",           # Placeholder
        ]

        value_lower = value.lower()
        return any(ph.lower() in value_lower for ph in placeholders)
