"""Python build configuration security analyzer."""

import re
from pathlib import Path

from src.layers.l1_intelligence.build_config.base import BaseConfigAnalyzer
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    FindingCategory,
    SecurityFinding,
    SecurityRisk,
)


class PythonAnalyzer(BaseConfigAnalyzer):
    """Analyzer for Python build configuration files."""

    supported_files = [
        "setup.py",
        "setup.cfg",
        "tox.ini",
        ".python-version",
        "pyproject.toml",  # Extended analysis beyond dependency scanning
    ]
    category_name = "python_config"

    # Patterns for detecting hardcoded secrets
    SECRET_PATTERNS = {
        "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "aws_secret": re.compile(r"(?i)aws[_-]?secret[_-]?(access)?[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9/+=]{40}['\"]"),
        "generic_secret": re.compile(
            r"(?:password|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
            re.IGNORECASE
        ),
        "base64_secret": re.compile(r"['\"][A-Za-z0-9+/]{40,}={0,2}['\"]"),
    }

    # Dangerous setup.py patterns
    DANGEROUS_SETUP_PATTERNS = {
        "exec": re.compile(r"\bexec\s*\(", re.IGNORECASE),
        "eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
        "subprocess_shell": re.compile(r"subprocess\..*shell\s*=\s*True", re.IGNORECASE),
        "os_system": re.compile(r"os\.system\s*\(", re.IGNORECASE),
        "download_exec": re.compile(
            r"(?:urllib|requests)\..*(?:download|get).*\n.*(?:exec|eval|subprocess)",
            re.IGNORECASE | re.DOTALL
        ),
    }

    # Sensitive tox configuration
    TOX_SENSITIVE_PATTERNS = {
        "password": re.compile(r"password\s*=\s*[^\s$]+", re.IGNORECASE),
        "secret": re.compile(r"secret\s*=\s*[^\s$]+", re.IGNORECASE),
        "token": re.compile(r"token\s*=\s*[^\s$]+", re.IGNORECASE),
        "api_key": re.compile(r"api[_-]?key\s*=\s*[^\s$]+", re.IGNORECASE),
    }

    def __init__(self) -> None:
        """Initialize Python analyzer."""
        super().__init__()

    def analyze(self, source_path: Path, report: BuildConfigReport) -> list[SecurityFinding]:
        """Analyze Python build files for security issues.

        Args:
            source_path: Path to the source code.
            report: Report to add findings to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        python_files = self.find_files(source_path)
        if not python_files:
            return findings

        for file_path in python_files:
            report.scanned_files.append(str(file_path))
            file_findings = self._analyze_file(file_path, report)
            findings.extend(file_findings)

        return findings

    def _analyze_file(self, file_path: Path, report: BuildConfigReport) -> list[SecurityFinding]:
        """Analyze a single Python build file.

        Args:
            file_path: Path to the file.
            report: Report to add findings to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        content = self._safe_read_file(file_path)
        if not content:
            return findings

        source_file = str(file_path)
        filename = file_path.name

        if filename == "setup.py":
            findings.extend(self._analyze_setup_py(content, source_file))
        elif filename == "setup.cfg":
            findings.extend(self._analyze_setup_cfg(content, source_file))
        elif filename == "tox.ini":
            findings.extend(self._analyze_tox_ini(content, source_file))
        elif filename == ".python-version":
            findings.extend(self._analyze_python_version(content, source_file))
        elif filename == "pyproject.toml":
            findings.extend(self._analyze_pyproject_toml(content, source_file))

        return findings

    def _analyze_setup_py(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Analyze setup.py for security issues.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Check for dangerous code execution patterns
        for pattern_name, pattern in self.DANGEROUS_SETUP_PATTERNS.items():
            for match in pattern.finditer(content):
                # Get line number
                line_num = content[:match.start()].count("\n") + 1

                if pattern_name == "exec":
                    findings.append(
                        SecurityFinding(
                            category=FindingCategory.PYTHON_CONFIG,
                            risk_level=SecurityRisk.HIGH,
                            title="Dynamic code execution in setup.py",
                            description="setup.py uses exec() which can execute arbitrary code during installation. "
                            "This is a potential supply chain attack vector.",
                            file_path=source_file,
                            line_start=line_num,
                            evidence=match.group(0),
                            recommendation="Avoid dynamic code execution in setup.py. Use static configuration "
                            "or move complex logic to a separate build script.",
                            references=[
                                "https://packaging.python.org/en/latest/guides/installing-using-setup-py/",
                                "https://peps.python.org/pep-0517/",
                            ],
                            cwe="CWE-94",
                        )
                    )
                elif pattern_name == "eval":
                    findings.append(
                        SecurityFinding(
                            category=FindingCategory.PYTHON_CONFIG,
                            risk_level=SecurityRisk.HIGH,
                            title="Dynamic code evaluation in setup.py",
                            description="setup.py uses eval() which can execute arbitrary code during installation.",
                            file_path=source_file,
                            line_start=line_num,
                            evidence=match.group(0),
                            recommendation="Avoid eval() in setup.py. Use ast.literal_eval() for safe parsing "
                            "or static configuration.",
                            references=[],
                            cwe="CWE-95",
                        )
                    )
                elif pattern_name == "subprocess_shell":
                    findings.append(
                        SecurityFinding(
                            category=FindingCategory.PYTHON_CONFIG,
                            risk_level=SecurityRisk.MEDIUM,
                            title="Shell execution in setup.py",
                            description="setup.py uses subprocess with shell=True which can be vulnerable to "
                            "command injection.",
                            file_path=source_file,
                            line_start=line_num,
                            evidence=match.group(0),
                            recommendation="Use subprocess without shell=True and pass arguments as a list.",
                            references=[],
                            cwe="CWE-78",
                        )
                    )
                elif pattern_name == "os_system":
                    findings.append(
                        SecurityFinding(
                            category=FindingCategory.PYTHON_CONFIG,
                            risk_level=SecurityRisk.MEDIUM,
                            title="os.system() call in setup.py",
                            description="setup.py uses os.system() which can be vulnerable to command injection.",
                            file_path=source_file,
                            line_start=line_num,
                            evidence=match.group(0),
                            recommendation="Use subprocess module with proper argument handling instead of os.system().",
                            references=[],
                            cwe="CWE-78",
                        )
                    )

        # Check for hardcoded secrets
        findings.extend(self._detect_secrets(content, source_file, "setup.py"))

        return findings

    def _analyze_setup_cfg(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Analyze setup.cfg for security issues.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Check for hardcoded secrets in setup.cfg
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            # Check for sensitive key-value pairs
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip().lower()
                value = value.strip()

                if self._is_sensitive_property(key) and value and not self._is_placeholder(value):
                    findings.append(
                        SecurityFinding(
                            category=FindingCategory.SECRETS,
                            risk_level=SecurityRisk.HIGH,
                            title=f"Sensitive configuration in setup.cfg: {key}",
                            description=f"setup.cfg contains potentially sensitive configuration for '{key}'.",
                            file_path=source_file,
                            line_start=line_num,
                            evidence=line[:80],
                            recommendation="Move sensitive values to environment variables or a separate "
                            "configuration file excluded from version control.",
                            references=[],
                            cwe="CWE-798",
                        )
                    )

        return findings

    def _analyze_tox_ini(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Analyze tox.ini for security issues.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Check for hardcoded secrets in tox.ini
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            # Check for sensitive configurations
            for pattern_name, pattern in self.TOX_SENSITIVE_PATTERNS.items():
                match = pattern.search(line)
                if match:
                    # Check if value is a placeholder/variable
                    value = match.group(0).split("=", 1)[1].strip() if "=" in match.group(0) else ""
                    if not self._is_placeholder(value):
                        findings.append(
                            SecurityFinding(
                                category=FindingCategory.SECRETS,
                                risk_level=SecurityRisk.MEDIUM,
                                title=f"Hardcoded secret in tox.ini: {pattern_name}",
                                description=f"tox.ini contains hardcoded {pattern_name} that should be externalized.",
                                file_path=source_file,
                                line_start=line_num,
                                evidence=line[:80],
                                recommendation="Use environment variable substitution in tox.ini: "
                                "{env:VARIABLE_NAME}",
                                references=[
                                    "https://tox.wiki/en/latest/config.html#substitution"
                                ],
                                cwe="CWE-798",
                            )
                        )

        # Check for dangerous commands in commands section
        in_commands = False
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()

            if stripped.startswith("[") and "commands" in stripped.lower():
                in_commands = True
            elif stripped.startswith("["):
                in_commands = False

            if in_commands and stripped:
                # Check for curl | sh patterns
                if "curl" in stripped.lower() and ("sh" in stripped.lower() or "bash" in stripped.lower()):
                    findings.append(
                        SecurityFinding(
                            category=FindingCategory.PYTHON_CONFIG,
                            risk_level=SecurityRisk.HIGH,
                            title="Unsafe curl | bash pattern in tox.ini",
                            description="tox.ini uses curl piped to shell which is a potential security risk.",
                            file_path=source_file,
                            line_start=line_num,
                            evidence=stripped[:80],
                            recommendation="Download files separately and verify checksums before execution.",
                            references=[],
                            cwe="CWE-829",
                        )
                    )

        return findings

    def _analyze_python_version(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Analyze .python-version for security considerations.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        version = content.strip()

        # Check for EOL Python versions
        eol_versions = {
            "2.7": "2020-01-01",
            "3.5": "2020-09-30",
            "3.6": "2021-12-23",
            "3.7": "2023-06-27",
        }

        for eol_version, eol_date in eol_versions.items():
            if version.startswith(eol_version):
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.PYTHON_CONFIG,
                        risk_level=SecurityRisk.HIGH,
                        title=f"EOL Python version: {version}",
                        description=f"Python {eol_version} reached end-of-life on {eol_date} and no longer "
                        "receives security updates.",
                        file_path=source_file,
                        evidence=f"Python {version}",
                        recommendation=f"Upgrade to a supported Python version (3.11+ recommended).",
                        references=[
                            "https://devguide.python.org/versions/",
                        ],
                    )
                )

        # Check for very old 3.x versions
        old_versions = ["3.8", "3.9"]
        for old_version in old_versions:
            if version.startswith(old_version):
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.PYTHON_CONFIG,
                        risk_level=SecurityRisk.LOW,
                        title=f"Old Python version: {version}",
                        description=f"Python {old_version} is aging. Consider upgrading for latest security features.",
                        file_path=source_file,
                        evidence=f"Python {version}",
                        recommendation="Consider upgrading to Python 3.11+ for latest security features and "
                        "performance improvements.",
                        references=[],
                    )
                )
                break

        return findings

    def _analyze_pyproject_toml(self, content: str, source_file: str) -> list[SecurityFinding]:
        """Analyze pyproject.toml for extended security issues.

        Note: Basic dependency scanning is done by dependency_scanner.
        This focuses on build system and tool configuration.

        Args:
            content: File content.
            source_file: Source file path.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Check for hardcoded secrets in pyproject.toml
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()

            # Skip comments
            if line.startswith("#"):
                continue

            # Look for key = "value" patterns with sensitive keys
            if "=" in line and ('"' in line or "'" in line):
                key_part, _, value_part = line.partition("=")
                key = key_part.strip().lower()
                value = value_part.strip()

                if self._is_sensitive_property(key):
                    # Extract actual value
                    value_match = re.search(r"['\"]([^'\"]+)['\"]", value)
                    if value_match and not self._is_placeholder(value_match.group(1)):
                        findings.append(
                            SecurityFinding(
                                category=FindingCategory.SECRETS,
                                risk_level=SecurityRisk.HIGH,
                                title=f"Hardcoded secret in pyproject.toml: {key}",
                                description=f"pyproject.toml contains hardcoded sensitive value for '{key}'.",
                                file_path=source_file,
                                line_start=line_num,
                                evidence=line[:80],
                                recommendation="Use environment variables or a separate configuration file "
                                "for sensitive values.",
                                references=[],
                                cwe="CWE-798",
                            )
                        )

        # Check for suspicious build-system requires
        if "[build-system]" in content:
            # Extract build-system section
            in_build_system = False
            build_system_lines: list[str] = []
            for line in content.splitlines():
                if line.strip().startswith("[build-system]"):
                    in_build_system = True
                elif line.strip().startswith("[") and in_build_system:
                    break
                elif in_build_system:
                    build_system_lines.append(line)

            build_system_content = "\n".join(build_system_lines)

            # Check for requires with suspicious packages
            suspicious_packages = [
                "eval", "exec", "subprocess-call", "os-cmd"
            ]
            for pkg in suspicious_packages:
                if pkg in build_system_content.lower():
                    findings.append(
                        SecurityFinding(
                            category=FindingCategory.PYTHON_CONFIG,
                            risk_level=SecurityRisk.HIGH,
                            title="Suspicious build-system dependency",
                            description=f"build-system requires contains suspicious package: {pkg}. "
                            "This could indicate a supply chain attack.",
                            file_path=source_file,
                            evidence=build_system_content[:200],
                            recommendation="Review build-system requires carefully. Only use trusted packages.",
                            references=[
                                "https://peps.python.org/pep-0517/",
                            ],
                            cwe="CWE-829",
                        )
                    )

        return findings

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder or variable reference.

        Args:
            value: Value to check.

        Returns:
            True if value is a placeholder.
        """
        if not value:
            return True
        value = value.strip()
        if not value:
            return True

        # Common placeholder patterns
        placeholders = [
            "{env:",           # tox/env var syntax
            "${",              # shell variable
            "$(",              # shell command substitution
            "os.environ",      # Python os.environ
            "os.getenv",       # Python os.getenv
            "environ.",        # Environment access
            "<",               # XML-like placeholder
            "your_",           # Common placeholder prefix
            "xxx",             # Common placeholder
            "***",             # Masked value
            "changeme",        # Common placeholder
            "placeholder",     # Common placeholder
            "example",         # Common placeholder
        ]

        value_lower = value.lower()
        for ph in placeholders:
            if ph.lower() in value_lower:
                return True

        return False

    def _detect_secrets(self, content: str, source_file: str, context: str) -> list[SecurityFinding]:
        """Detect hardcoded secrets in content.

        Args:
            content: File content.
            source_file: Source file path.
            context: Context description (e.g., "setup.py").

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        for pattern_name, pattern in self.SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1

                # Skip if inside a comment
                line = content.splitlines()[line_num - 1] if line_num > 0 else ""
                if line.strip().startswith("#"):
                    continue

                # Determine risk level
                if pattern_name in ("aws_access_key", "aws_secret"):
                    risk = SecurityRisk.CRITICAL
                else:
                    risk = SecurityRisk.HIGH

                findings.append(
                    SecurityFinding(
                        category=FindingCategory.SECRETS,
                        risk_level=risk,
                        title=f"Hardcoded secret detected in {context}",
                        description=f"Potential {pattern_name.replace('_', ' ')} found in {context}.",
                        file_path=source_file,
                        line_start=line_num,
                        evidence=match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0),
                        recommendation="Remove hardcoded secrets and use environment variables or "
                        "a secrets management solution.",
                        references=[],
                        cwe="CWE-798",
                    )
                )

        return findings
