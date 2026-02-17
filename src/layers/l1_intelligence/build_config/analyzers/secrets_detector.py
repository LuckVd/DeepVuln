"""Generic secrets detector for all file types."""

import re
from pathlib import Path

from src.layers.l1_intelligence.build_config.base import BaseConfigAnalyzer
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    FindingCategory,
    SecurityFinding,
    SecurityRisk,
)


class SecretsDetector(BaseConfigAnalyzer):
    """Generic detector for hardcoded secrets across all files."""

    # Files to scan for secrets
    supported_files = [
        # Config files
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.staging",
        "config.ini",
        "config.json",
        "settings.json",
        "credentials.json",
        # Shell scripts
        ".sh",
        ".bash",
        ".zsh",
        # Other potential secret containers
        ".yaml",
        ".yml",
    ]

    # Also scan common code files
    code_extensions = {
        ".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
        ".jsx", ".tsx", ".vue", ".cs", ".swift", ".kt"
    }

    category_name = "secrets"

    # Secret patterns with confidence levels
    SECRET_PATTERNS = {
        # High confidence - specific formats
        "aws_access_key_id": {
            "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
            "risk": SecurityRisk.CRITICAL,
            "description": "AWS Access Key ID",
        },
        "aws_secret_access_key": {
            "pattern": re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]"),
            "risk": SecurityRisk.CRITICAL,
            "description": "AWS Secret Access Key",
        },
        "github_token": {
            "pattern": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
            "risk": SecurityRisk.CRITICAL,
            "description": "GitHub Personal Access Token",
        },
        "github_oauth": {
            "pattern": re.compile(r"gho_[a-zA-Z0-9]{36}"),
            "risk": SecurityRisk.CRITICAL,
            "description": "GitHub OAuth Token",
        },
        "github_app_token": {
            "pattern": re.compile(r"(?:ghu|ghs)_[a-zA-Z0-9]{36}"),
            "risk": SecurityRisk.CRITICAL,
            "description": "GitHub App Token",
        },
        "slack_token": {
            "pattern": re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9]{24}"),
            "risk": SecurityRisk.CRITICAL,
            "description": "Slack Token",
        },
        "stripe_api_key": {
            "pattern": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
            "risk": SecurityRisk.CRITICAL,
            "description": "Stripe Live API Key",
        },
        "stripe_publishable_key": {
            "pattern": re.compile(r"pk_live_[0-9a-zA-Z]{24}"),
            "risk": SecurityRisk.HIGH,
            "description": "Stripe Publishable Key",
        },
        "google_api_key": {
            "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
            "risk": SecurityRisk.CRITICAL,
            "description": "Google API Key",
        },
        "google_oauth": {
            "pattern": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
            "risk": SecurityRisk.HIGH,
            "description": "Google OAuth Client ID",
        },
        "private_key": {
            "pattern": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
            "risk": SecurityRisk.CRITICAL,
            "description": "Private Key",
        },
        "jwt_secret": {
            "pattern": re.compile(r"(?i)jwt[_-]?(?:secret|key|token)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9\-_]{32,}['\"]"),
            "risk": SecurityRisk.HIGH,
            "description": "JWT Secret",
        },
        # Medium confidence - generic patterns
        "generic_password": {
            "pattern": re.compile(r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
            "risk": SecurityRisk.HIGH,
            "description": "Hardcoded Password",
        },
        "generic_api_key": {
            "pattern": re.compile(r"(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9\-_]{20,}['\"]"),
            "risk": SecurityRisk.HIGH,
            "description": "API Key",
        },
        "generic_secret": {
            "pattern": re.compile(r"(?i)(?:secret|token|auth)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9\-_]{20,}['\"]"),
            "risk": SecurityRisk.HIGH,
            "description": "Secret/Token",
        },
        # Lower confidence - potential issues
        "connection_string": {
            "pattern": re.compile(r"(?i)(?:mysql|postgres|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"),
            "risk": SecurityRisk.HIGH,
            "description": "Database Connection String with Credentials",
        },
        "base64_secret": {
            "pattern": re.compile(r"['\"][A-Za-z0-9+/]{40,}={0,2}['\"]"),
            "risk": SecurityRisk.MEDIUM,
            "description": "Potential Base64-encoded Secret",
        },
    }

    # Patterns to ignore (false positives)
    IGNORE_PATTERNS = [
        re.compile(r"^\s*#", re.MULTILINE),  # Comments
        re.compile(r"^\s*//", re.MULTILINE),  # C-style comments
        re.compile(r"^\s*\*", re.MULTILINE),  # Doc comments
        re.compile(r"example", re.IGNORECASE),
        re.compile(r"placeholder", re.IGNORECASE),
        re.compile(r"changeme", re.IGNORECASE),
        re.compile(r"your[_-]?(?:key|secret|password|token)", re.IGNORECASE),
        re.compile(r"xxx+"),
        re.compile(r"\*\*\*+"),
        re.compile(r"<[^>]+>"),  # Placeholders like <API_KEY>
        re.compile(r"\$\{[^}]+\}"),  # Variable references
        re.compile(r"env\s*\.\s*\w+", re.IGNORECASE),  # Environment variable access
        re.compile(r"os\.environ", re.IGNORECASE),
        re.compile(r"process\.env", re.IGNORECASE),
    ]

    def __init__(self) -> None:
        """Initialize secrets detector."""
        super().__init__()

    def analyze(self, source_path: Path, report: BuildConfigReport) -> list[SecurityFinding]:
        """Analyze files for hardcoded secrets.

        Args:
            source_path: Path to the source code.
            report: Report to add findings to.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        # Find all relevant files
        files_to_scan = self._find_all_files(source_path)

        for file_path in files_to_scan:
            report.scanned_files.append(str(file_path))
            file_findings = self._scan_file(file_path)
            findings.extend(file_findings)

        return findings

    def _find_all_files(self, source_path: Path) -> list[Path]:
        """Find all files to scan for secrets.

        Args:
            source_path: Source root path.

        Returns:
            List of files to scan.
        """
        files: list[Path] = []

        # Find .env files and similar
        env_patterns = [".env", ".env.local", ".env.development", ".env.production", ".env.staging"]
        for pattern in env_patterns:
            for f in source_path.rglob(pattern):
                if not self._should_skip_path(f):
                    files.append(f)

        # Find other config files
        config_patterns = ["config.ini", "config.json", "settings.json", "credentials.json"]
        for pattern in config_patterns:
            for f in source_path.rglob(pattern):
                if not self._should_skip_path(f):
                    files.append(f)

        # Find files with specific extensions
        extension_patterns = ["*.yaml", "*.yml", "*.sh", "*.bash", "*.zsh", "*.pem", "*.key"]
        for pattern in extension_patterns:
            for f in source_path.rglob(pattern):
                if not self._should_skip_path(f):
                    files.append(f)

        # Find credentials and secrets files
        cred_patterns = ["credentials*", "secrets*"]
        for pattern in cred_patterns:
            for f in source_path.rglob(pattern):
                if not self._should_skip_path(f) and f not in files:
                    files.append(f)

        return list(set(files))

    def _scan_file(self, file_path: Path) -> list[SecurityFinding]:
        """Scan a file for secrets.

        Args:
            file_path: Path to the file.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []

        content = self._safe_read_file(file_path)
        if not content:
            return findings

        source_file = str(file_path)

        # Check each pattern
        for pattern_name, pattern_info in self.SECRET_PATTERNS.items():
            pattern = pattern_info["pattern"]
            risk = pattern_info["risk"]
            description = pattern_info["description"]

            for match in pattern.finditer(content):
                # Get line number
                line_num = content[:match.start()].count("\n") + 1
                line = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                # Check if this is a false positive
                if self._is_false_positive(line, match.group(0)):
                    continue

                findings.append(
                    SecurityFinding(
                        category=FindingCategory.SECRETS,
                        risk_level=risk,
                        title=f"{description} detected",
                        description=f"Potential {description.lower()} found in file. "
                        "This could lead to credential exposure.",
                        file_path=source_file,
                        line_start=line_num,
                        evidence=self._mask_secret(match.group(0)),
                        recommendation="Remove hardcoded secrets and use environment variables, "
                        "a secrets manager, or encrypted configuration.",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                        ],
                        cwe="CWE-798",
                    )
                )

        return findings

    def _is_false_positive(self, line: str, match: str) -> bool:
        """Check if a match is likely a false positive.

        Args:
            line: The line containing the match.
            match: The matched string.

        Returns:
            True if likely a false positive.
        """
        # Check if line is a comment
        stripped_line = line.strip()
        if stripped_line.startswith(("#", "//", "*", "<!--", "/*")):
            return True

        # Check ignore patterns
        for ignore_pattern in self.IGNORE_PATTERNS:
            if ignore_pattern.search(match) or ignore_pattern.search(line):
                return True

        # Check for common placeholder patterns in the match
        match_lower = match.lower()
        placeholders = [
            "example", "placeholder", "changeme", "your_key", "your_secret",
            "xxx", "***", "dummy", "sample", "test", "fake"
        ]
        if any(ph in match_lower for ph in placeholders):
            return True

        return False

    def _mask_secret(self, secret: str) -> str:
        """Mask a secret for safe display.

        Args:
            secret: The secret string.

        Returns:
            Masked version of the secret.
        """
        if len(secret) <= 10:
            return "*" * len(secret)

        # Show first 4 and last 4 characters
        return f"{secret[:4]}...{secret[-4:]}"

    def _should_skip_path(self, path: Path) -> bool:
        """Check if path should be skipped.

        Args:
            path: Path to check.

        Returns:
            True if path should be skipped.
        """
        # Call parent method first
        if super()._should_skip_path(path):
            return True

        # Skip common non-source directories (only directories, not files)
        skip_dirs = {
            "node_modules", "venv", ".venv", "env",
            "__pycache__", ".git", ".hg", ".svn",
            "dist", "build", "target", "vendor",
            ".gradle", ".idea", ".mvn", ".tox",
            ".pytest_cache", ".mypy_cache",
            "site-packages", "eggs", ".eggs",
        }

        # Check if any parent directory is in skip_dirs
        for parent in path.parents:
            if parent.name in skip_dirs:
                return True

        # Check if path itself is a directory that should be skipped
        if path.is_dir() and path.name in skip_dirs:
            return True

        # Skip binary files
        binary_extensions = {
            ".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe",
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
            ".pdf", ".zip", ".tar", ".gz", ".rar",
            ".mp3", ".mp4", ".wav", ".avi", ".mov",
            ".db", ".sqlite", ".sqlite3",
        }
        if path.suffix.lower() in binary_extensions:
            return True

        # Skip lock files (usually contain many hashes that trigger false positives)
        if "lock" in path.name.lower():
            return True

        return False
