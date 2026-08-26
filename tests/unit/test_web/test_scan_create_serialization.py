"""Regression test for audit finding A5: ScanConfig must be serialized
to a plain dict before being stored in the Scan JSON column.

Before the fix, ``ScanExecutor.create_scan`` stored the pydantic
``ScanCreate.config`` (a ``ScanConfig``) directly on ``Scan.config``, which
made every REST ``POST /scans`` fail with
``TypeError: Object of type ScanConfig is not JSON serializable``.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.web.models.scan import Scan
from src.web.models.schemas import ScanCreate
from src.web.services.scan_executor import ScanExecutor


@pytest.fixture
def executor():
    """ScanExecutor with constructor dependencies patched out."""
    with (
        patch("src.web.services.scan_executor.ScanRepository"),
        patch("src.web.services.scan_executor.ScanPhaseRepository"),
        patch("src.web.services.scan_executor.ScanEventRepository"),
        patch("src.web.services.scan_executor.FindingRepository"),
        patch("src.web.services.scan_executor.get_checkpoint_service"),
    ):
        yield ScanExecutor()


@pytest.mark.asyncio
async def test_create_scan_stores_config_as_dict(executor):
    """REST scan creation must persist config as a JSON-safe dict."""
    scan_create = ScanCreate(
        name="audit-a5-regression",
        source_type="local",
        source_path="/tmp/target",
        scan_type="base",
        # Explicit non-default config to prove real values survive the round trip.
        config={"engines": ["semgrep", "ast"], "adversarial": True},
    )

    captured = {}

    async def fake_repo_create(db, obj_in):
        captured["obj_in"] = obj_in
        return obj_in

    fake_session = MagicMock()
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=None)
    fake_session.commit = AsyncMock()
    fake_session.refresh = AsyncMock()

    with (
        patch(
            "src.web.services.scan_executor.get_session_local",
            return_value=lambda: fake_session,
        ),
    ):
        executor.scan_repo.create = AsyncMock(side_effect=fake_repo_create)
        executor._create_initial_phases = AsyncMock()
        created = await executor.create_scan(scan_create)

    assert created is captured["obj_in"]
    assert isinstance(captured["obj_in"].config, dict), (
        "config must be a JSON-safe dict, not a pydantic model"
    )
    assert captured["obj_in"].config["engines"] == ["semgrep", "ast"]
    assert captured["obj_in"].config["adversarial"] is True
