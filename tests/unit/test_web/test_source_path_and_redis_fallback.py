"""Regression tests for audit 2026-09 fix: local source_path validation and
CelerySettings Redis URL fallback.

The scanner previously accepted any local path, letting an authenticated
user mirror arbitrary server files back into scan reports (/etc, secrets…).
Also: the WebSocket pub/sub bridge used CELERY_REDIS_URL (unset in the
compose stacks) and silently lost events; it now falls back to the broker.
"""

from pathlib import Path

import pytest

from src.web.models.schemas import ScanCreate


class TestLocalSourcePathValidation:
    def test_denies_sensitive_system_paths(self):
        for bad in ("/etc", "/etc/passwd", "/proc/1/environ", "/root/.ssh",
                    "/sys/kernel", "/boot/grub", "/var/lib", "/dev/sda"):
            with pytest.raises(Exception) as exc:
                ScanCreate(
                    name="t", source_type="local",
                    source_path=bad, scan_type="full",
                )
            assert "敏感系统路径" in str(exc.value) or "不存在" in str(exc.value)

    def test_denies_nonexistent_path(self):
        with pytest.raises(Exception) as exc:
            ScanCreate(
                name="t", source_type="local",
                source_path="/no/such/dir/xyz", scan_type="full",
            )
        assert "不存在或不是目录" in str(exc.value)

    def test_allows_existing_non_sensitive_dir(self):
        s = ScanCreate(
            name="t", source_type="local",
            source_path="/opt/pro/DeepVuln/benchmarks/mini", scan_type="full",
        )
        assert s.source_path == "/opt/pro/DeepVuln/benchmarks/mini"

    def test_git_source_skips_local_validation(self):
        s = ScanCreate(
            name="t", source_type="git",
            source_path="https://github.com/owner/repo.git", scan_type="full",
        )
        assert s.source_type == "git"

    def test_zip_source_skips_local_validation(self):
        # ZIP scans store the archive path with source_type=zip; the local
        # validator must not reject them.
        s = ScanCreate(
            name="t", source_type="zip",
            source_path="/opt/pro/DeepVuln/uploads/abc.zip", scan_type="full",
        )
        assert s.source_type == "zip"

    def test_allowlist_env_enforced(self, monkeypatch):
        monkeypatch.setenv("DEEPVULN_WEB_LOCAL_SCAN_ROOTS", "/opt/pro/DeepVuln,/srv/code")
        from src.web.core.config import WebSettings

        w = WebSettings()
        assert w.local_scan_roots == "/opt/pro/DeepVuln,/srv/code"
        assert w.local_scan_roots_list == ["/opt/pro/DeepVuln", "/srv/code"]


class TestCeleryRedisUrlFallback:
    def test_explicit_redis_url_wins(self):
        from src.web.core.celery_app import CelerySettings

        s = CelerySettings(
            redis_url="redis://redis:6379/5",
            broker_url="redis://redis:6379/0",
        )
        assert s.effective_redis_url == "redis://redis:6379/5"

    def test_default_redis_url_falls_back_to_broker(self):
        from src.web.core.celery_app import CelerySettings

        # This is exactly the broken compose scenario: broker configured,
        # redis_url left at default localhost.
        s = CelerySettings(broker_url="redis://redis:6379/0")
        assert s.effective_redis_url == "redis://redis:6379/0"

    def test_single_instance_default(self):
        from src.web.core.celery_app import CelerySettings

        s = CelerySettings()
        assert s.effective_redis_url == "redis://localhost:6379/0"