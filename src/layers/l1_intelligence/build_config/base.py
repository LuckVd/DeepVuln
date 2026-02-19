"""Base class for build configuration analyzers."""

from abc import ABC, abstractmethod
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.build_config.models import (
    BuildConfigReport,
    SecurityFinding,
)


class BaseConfigAnalyzer(ABC):
    """Base class for all configuration analyzers."""

    # Files this analyzer can handle
    supported_files: list[str] = []
    category_name: str = "general"

    def __init__(self) -> None:
        """Initialize the analyzer."""
        self.logger = get_logger(self.__class__.__name__)

    def can_analyze(self, file_path: Path) -> bool:
        """Check if this analyzer can handle the file.

        Args:
            file_path: Path to the file.

        Returns:
            True if this analyzer can handle the file.
        """
        return file_path.name in self.supported_files

    @abstractmethod
    def analyze(self, source_path: Path, report: BuildConfigReport) -> list[SecurityFinding]:
        """Analyze the source path for security issues.

        Args:
            source_path: Path to the source code.
            report: Report to add findings to.

        Returns:
            List of security findings.
        """
        pass

    def find_files(self, source_path: Path) -> list[Path]:
        """Find supported configuration files in the source path.

        Args:
            source_path: Path to the source code.

        Returns:
            List of found configuration files.
        """
        found: list[Path] = []
        for pattern in self.supported_files:
            # Check root level first
            root_file = source_path / pattern
            if root_file.exists():
                found.append(root_file)

            # Also check subdirectories
            for f in source_path.rglob(pattern):
                if self._should_skip_path(f):
                    continue
                if f not in found:
                    found.append(f)

        return found

    def _should_skip_path(self, path: Path) -> bool:
        """Check if path should be skipped.

        Args:
            path: Path to check.

        Returns:
            True if path should be skipped.
        """
        skip_dirs = {
            "node_modules",
            "venv",
            ".venv",
            "env",
            "__pycache__",
            ".git",
            "dist",
            "build",
            "target",
            "vendor",
            ".gradle",
            ".idea",
            ".mvn",
        }
        # Check parent directories only (not the file itself)
        for part in path.parent.parts:
            if part in skip_dirs:
                return True
        return False

    def _safe_read_file(self, file_path: Path) -> str | None:
        """Safely read file contents.

        Args:
            file_path: Path to the file.

        Returns:
            File contents or None on error.
        """
        try:
            return file_path.read_text(encoding="utf-8")
        except Exception as e:
            self.logger.warning(f"Failed to read {file_path}: {e}")
            return None

    def _is_sensitive_property(self, key: str) -> bool:
        """Check if a property name suggests sensitive data.

        Args:
            key: Property name.

        Returns:
            True if the property might contain sensitive data.
        """
        sensitive_keywords = {
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_key",
            "secret_key",
            "private_key",
            "credential",
            "auth",
            "login",
            "db_password",
            "database_password",
            "jdbc_password",
            "smtp_password",
            "mail_password",
            "keystore",
            "truststore",
            "encryption",
            "salt",
        }
        key_lower = key.lower()
        return any(kw in key_lower for kw in sensitive_keywords)

    def _is_sensitive_value(self, value: str) -> bool:
        """Check if a value looks like sensitive data.

        Args:
            value: Property value.

        Returns:
            True if the value looks like sensitive data.
        """
        # Skip empty or placeholder values
        if not value or len(value) < 8:
            return False

        # Skip common placeholders
        placeholders = {
            "${",
            "#{",
            "@",
            "changeme",
            "placeholder",
            "example",
            "xxx",
            "****",
            "<set",
            "your_",
        }
        value_lower = value.lower()
        if any(ph in value_lower for ph in placeholders):
            return False

        # Check for patterns that look like secrets
        import re

        # Base64-like strings (long alphanumeric)
        if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", value):
            return True

        # Hex strings (like API keys)
        if re.match(r"^[a-fA-F0-9]{20,}$", value):
            return True

        # UUID-like strings
        if re.match(r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-", value):
            return True

        return False
