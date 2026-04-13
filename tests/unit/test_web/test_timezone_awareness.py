"""Tests for timezone-aware datetime handling across the API.

Ensures all API-returned ISO 8601 timestamps carry UTC timezone info
so that JavaScript `new Date()` parses them correctly regardless of
the browser / server local timezone.

Strategy: database stores naive UTC datetime (TIMESTAMP WITHOUT TIME ZONE);
the serialization layer (Pydantic schemas + API helper) adds UTC offset
at output time.
"""

from datetime import datetime, timezone

import pytest


def _has_utc_offset(iso_str: str) -> bool:
    """Check if an ISO 8601 string carries UTC offset info (+00:00 or Z)."""
    return iso_str.endswith("+00:00") or iso_str.endswith("Z")


# ---------------------------------------------------------------------------
# 1. API helper _iso() produces timezone-aware strings from naive datetimes
# ---------------------------------------------------------------------------

class TestApiIsoHelper:
    """Verify the _iso() helper in scans.py adds UTC offset."""

    def test_iso_helper_naive_datetime(self):
        from src.web.api.v1.scans import _iso

        naive = datetime(2026, 4, 12, 5, 50, 51)
        result = _iso(naive)
        assert _has_utc_offset(result), (
            f"Expected UTC offset in serialized datetime, got: {result}"
        )
        assert "+00:00" in result

    def test_iso_helper_none(self):
        from src.web.api.v1.scans import _iso

        assert _iso(None) is None

    def test_iso_helper_aware_datetime(self):
        from src.web.api.v1.scans import _iso

        aware = datetime(2026, 4, 12, 5, 50, 51, tzinfo=timezone.utc)
        result = _iso(aware)
        assert _has_utc_offset(result)


# ---------------------------------------------------------------------------
# 2. Pydantic schema serialization produces timezone-aware JSON
# ---------------------------------------------------------------------------

class TestPydanticSchemaTimezone:
    """Pydantic model_dump(mode='json') must produce UTC-aware ISO strings
    even when fed naive datetimes (the UtcDateTime serializer handles this)."""

    def test_scan_response_naive_datetime_gets_offset(self):
        """Naive datetime passed to ScanResponse should gain UTC offset on serialization."""
        from src.web.models.schemas import ScanResponse

        naive_dt = datetime(2026, 4, 12, 5, 50, 51)
        resp = ScanResponse(
            id=1,
            name="test-scan",
            source_type="local",
            source_path="/tmp/test",
            status="completed",
            scan_type="full",
            created_at=naive_dt,
            started_at=naive_dt,
            completed_at=naive_dt,
        )
        dumped = resp.model_dump(mode="json")
        assert _has_utc_offset(dumped["created_at"]), (
            f"Expected UTC offset in created_at, got: {dumped['created_at']}"
        )
        assert _has_utc_offset(dumped["started_at"]), (
            f"Expected UTC offset in started_at, got: {dumped['started_at']}"
        )
        assert _has_utc_offset(dumped["completed_at"]), (
            f"Expected UTC offset in completed_at, got: {dumped['completed_at']}"
        )

    def test_scan_response_aware_datetime_keeps_offset(self):
        from src.web.models.schemas import ScanResponse

        aware_dt = datetime(2026, 4, 12, 5, 50, 51, tzinfo=timezone.utc)
        resp = ScanResponse(
            id=1,
            name="test-scan",
            source_type="local",
            source_path="/tmp/test",
            status="completed",
            scan_type="full",
            created_at=aware_dt,
        )
        dumped = resp.model_dump(mode="json")
        assert _has_utc_offset(dumped["created_at"])

    def test_progress_response_naive_datetime_gets_offset(self):
        from src.web.models.schemas import ScanProgressResponse

        naive_dt = datetime(2026, 4, 12, 5, 50, 51)
        resp = ScanProgressResponse(
            scan_id=1,
            status="running",
            progress_percent=50,
            current_phase="l3_agent",
            started_at=naive_dt,
            estimated_completion=naive_dt,
        )
        dumped = resp.model_dump(mode="json")
        assert _has_utc_offset(dumped["started_at"]), (
            f"Expected UTC offset in started_at, got: {dumped['started_at']}"
        )
        assert _has_utc_offset(dumped["estimated_completion"]), (
            f"Expected UTC offset in estimated_completion, got: {dumped['estimated_completion']}"
        )

    def test_finding_response_created_at_has_offset(self):
        from src.web.models.schemas import FindingResponse

        naive_dt = datetime(2026, 4, 12, 5, 50, 51)
        resp = FindingResponse(
            id=1,
            scan_id=1,
            vuln_type="sql_injection",
            severity="high",
            file_path="src/main.py",
            line_start=1,
            title="test",
            engine="agent",
            status="pending",
            created_at=naive_dt,
        )
        dumped = resp.model_dump(mode="json")
        assert _has_utc_offset(dumped["created_at"]), (
            f"Expected UTC offset, got: {dumped['created_at']}"
        )

    def test_scan_event_response_created_at_has_offset(self):
        from src.web.models.schemas import ScanEventResponse

        naive_dt = datetime(2026, 4, 12, 5, 50, 51)
        resp = ScanEventResponse(
            id=1,
            scan_id=1,
            event_type="info",
            message="test",
            created_at=naive_dt,
        )
        dumped = resp.model_dump(mode="json")
        assert _has_utc_offset(dumped["created_at"]), (
            f"Expected UTC offset, got: {dumped['created_at']}"
        )

    def test_control_responses_have_offset(self):
        """Pause/Resume/Cancel responses should also have UTC offset."""
        from src.web.models.schemas import PauseScanResponse, CancelScanResponse

        naive_dt = datetime(2026, 4, 12, 5, 50, 51)

        pause = PauseScanResponse(
            scan_id=1, status="paused",
            checkpoint_saved=True, paused_at=naive_dt, can_resume=True,
        )
        assert _has_utc_offset(pause.model_dump(mode="json")["paused_at"])

        cancel = CancelScanResponse(
            scan_id=1, status="cancelled",
            cancelled_at=naive_dt, cleanup_started=True,
        )
        assert _has_utc_offset(cancel.model_dump(mode="json")["cancelled_at"])


# ---------------------------------------------------------------------------
# 3. Raw isoformat() still lacks offset (documents why the helper is needed)
# ---------------------------------------------------------------------------

class TestRawIsoformatBehaviour:
    """Document that raw .isoformat() on naive datetime lacks offset."""

    def test_naive_isoformat_no_offset(self):
        dt = datetime(2026, 4, 12, 5, 50, 51)
        assert not _has_utc_offset(dt.isoformat())

    def test_aware_isoformat_has_offset(self):
        dt = datetime(2026, 4, 12, 5, 50, 51, tzinfo=timezone.utc)
        assert _has_utc_offset(dt.isoformat())
