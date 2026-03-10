"""Tests for CLI main module."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from src.cli.main import clean, git, local, main, run_interactive_fetch


class TestMainCommand:
    """Test main CLI command."""

    def test_version_flag(self) -> None:
        """Test version flag."""
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    @patch("src.cli.main.run_interactive_mode")
    def test_interactive_flag(self, mock_interactive: MagicMock) -> None:
        """Test interactive flag."""
        runner = CliRunner()
        runner.invoke(main, ["--interactive"])
        mock_interactive.assert_called_once()

    @patch("src.cli.main.run_interactive_mode")
    def test_default_interactive(self, mock_interactive: MagicMock) -> None:
        """Test default behavior (interactive mode)."""
        runner = CliRunner()
        runner.invoke(main, [])
        mock_interactive.assert_called_once()


class TestGitCommand:
    """Test git subcommand."""

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    @patch("src.cli.main.show_summary")
    def test_git_basic(
        self,
        mock_summary: MagicMock,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
    ) -> None:
        """Test basic git command."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": "/test/path"}
        }

        runner = CliRunner()
        result = runner.invoke(git, ["--url", "https://github.com/user/repo.git"])

        assert result.exit_code == 0
        mock_banner.assert_called_once()
        mock_summary.assert_called_once()

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    def test_git_with_branch(
        self,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
    ) -> None:
        """Test git command with branch."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": "/test/path"}
        }

        runner = CliRunner()
        result = runner.invoke(
            git,
            ["--url", "https://github.com/user/repo.git", "--branch", "develop"],
        )

        assert result.exit_code == 0

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    def test_git_with_tag(
        self,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
    ) -> None:
        """Test git command with tag."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": "/test/path"}
        }

        runner = CliRunner()
        result = runner.invoke(
            git,
            ["--url", "https://github.com/user/repo.git", "--tag", "v1.0.0"],
        )

        assert result.exit_code == 0

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    def test_git_with_commit(
        self,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
    ) -> None:
        """Test git command with commit."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": "/test/path"}
        }

        runner = CliRunner()
        result = runner.invoke(
            git,
            ["--url", "https://github.com/user/repo.git", "--commit", "abc12345"],
        )

        assert result.exit_code == 0

    def test_git_missing_url(self) -> None:
        """Test git command without URL."""
        runner = CliRunner()
        result = runner.invoke(git, [])
        assert result.exit_code != 0


class TestLocalCommand:
    """Test local subcommand."""

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    @patch("src.cli.main.show_summary")
    def test_local_basic(
        self,
        mock_summary: MagicMock,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test basic local command."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": str(tmp_path)}
        }

        runner = CliRunner()
        result = runner.invoke(local, ["--path", str(tmp_path)])

        assert result.exit_code == 0
        mock_banner.assert_called_once()
        mock_summary.assert_called_once()

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_banner")
    def test_local_no_copy(
        self,
        mock_banner: MagicMock,
        mock_fetch: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test local command without copy."""
        mock_fetch.return_value = {
            "result": {"success": True, "source_path": str(tmp_path)}
        }

        runner = CliRunner()
        result = runner.invoke(local, ["--path", str(tmp_path), "--no-copy"])

        assert result.exit_code == 0

    def test_local_missing_path(self) -> None:
        """Test local command without path."""
        runner = CliRunner()
        result = runner.invoke(local, [])
        assert result.exit_code != 0

    def test_local_invalid_path(self) -> None:
        """Test local command with invalid path."""
        runner = CliRunner()
        result = runner.invoke(local, ["--path", "/nonexistent/path"])
        assert result.exit_code != 0


class TestCleanCommand:
    """Test clean subcommand."""

    @patch("src.cli.main.AssetFetcher")
    @patch("src.cli.main.show_banner")
    @patch("src.cli.main.show_success")
    def test_clean(
        self,
        mock_success: MagicMock,
        mock_banner: MagicMock,
        mock_fetcher_class: MagicMock,
    ) -> None:
        """Test clean command."""
        mock_fetcher = MagicMock()
        mock_fetcher.cleanup_all.return_value = 5
        mock_fetcher_class.return_value = mock_fetcher

        runner = CliRunner()
        result = runner.invoke(clean, [])

        assert result.exit_code == 0
        mock_banner.assert_called_once()
        mock_fetcher.cleanup_all.assert_called_once()
        mock_success.assert_called_once()


class TestRunInteractiveFetch:
    """Test interactive fetch function."""

    @patch("src.cli.main.execute_fetch")
    @patch("src.cli.main.show_summary")
    @patch("src.cli.main.get_git_config")
    @patch("src.cli.main.select_source_type")
    def test_git_fetch_success(
        self,
        mock_select: MagicMock,
        mock_config: MagicMock,
        mock_summary: MagicMock,
        mock_execute: MagicMock,
    ) -> None:
        """Test successful Git fetch."""
        mock_select.return_value = "git"
        mock_config.return_value = {
            "repo_url": "https://github.com/user/repo.git",
            "git_ref": None,
            "depth": 1,
            "workspace_name": None,
        }
        mock_execute.return_value = {"result": {"success": True}}

        result = run_interactive_fetch()

        assert result is not None
        mock_summary.assert_called_once()

    @patch("src.cli.main.show_summary")
    @patch("src.cli.main.get_local_config")
    @patch("src.cli.main.select_source_type")
    def test_local_fetch_success(
        self,
        mock_select: MagicMock,
        mock_config: MagicMock,
        mock_summary: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test successful local fetch."""
        mock_select.return_value = "local"
        mock_config.return_value = {
            "local_path": tmp_path,
            "copy_to_workspace": True,
            "workspace_name": None,
        }

        with patch("src.cli.main.execute_fetch") as mock_execute:
            mock_execute.return_value = {"result": {"success": True}}
            result = run_interactive_fetch()

        assert result is not None

    @patch("src.cli.main.select_source_type")
    def test_cancelled_selection(
        self,
        mock_select: MagicMock,
    ) -> None:
        """Test cancelled source selection."""
        mock_select.return_value = None
        result = run_interactive_fetch()
        assert result is None

    @patch("src.cli.main.get_git_config")
    @patch("src.cli.main.select_source_type")
    def test_cancelled_config(
        self,
        mock_select: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        """Test cancelled configuration."""
        mock_select.return_value = "git"
        mock_config.return_value = {}
        result = run_interactive_fetch()
        assert result is None


# =============================================================================
# P6-01: Scan Status Model Tests
# =============================================================================


class TestScanStatusModel:
    """Test P6-01 scan status model and helper functions."""

    def test_scan_status_enum_values(self) -> None:
        """Test ScanStatus enum has correct values."""
        from src.layers.l3_analysis.models import ScanStatus

        assert ScanStatus.COMPLETE_SUCCESS.value == "complete_success"
        assert ScanStatus.PARTIAL_SUCCESS.value == "partial_success"
        assert ScanStatus.DEGRADED_SUCCESS.value == "degraded_success"
        assert ScanStatus.FAILED.value == "failed"

    def test_failed_engine_info_model(self) -> None:
        """Test FailedEngineInfo model."""
        from src.layers.l3_analysis.models import FailedEngineInfo

        info = FailedEngineInfo(
            name="codeql",
            error_type="analyze_failed",
            message="All language scans failed",
            languages=["typescript", "javascript"],
            is_core_engine=True,
        )

        assert info.name == "codeql"
        assert info.error_type == "analyze_failed"
        assert info.languages == ["typescript", "javascript"]
        assert info.is_core_engine is True

    def test_collect_failed_engines_all_success(self) -> None:
        """Test _collect_failed_engines when all engines succeed."""
        from src.cli.main import _collect_failed_engines

        phases = {
            "semgrep": {"success": True, "findings_count": 10},
            "codeql": {"success": True, "findings_count": 5},
            "agent": {"success": True, "findings_count": 3},
        }

        result = _collect_failed_engines(
            phases=phases,
            unavailable_engines=[],
            requested_engines=["semgrep", "codeql", "agent"],
        )

        assert result == []

    def test_collect_failed_engines_codeql_failed(self) -> None:
        """Test _collect_failed_engines when CodeQL fails."""
        from src.cli.main import _collect_failed_engines

        phases = {
            "semgrep": {"success": True, "findings_count": 10},
            "codeql": {
                "success": False,
                "error": "All language scans failed. Languages attempted: typescript, javascript",
                "codeql_lang": ["typescript", "javascript"],
            },
            "agent": {"success": True, "findings_count": 3},
        }

        result = _collect_failed_engines(
            phases=phases,
            unavailable_engines=[],
            requested_engines=["semgrep", "codeql", "agent"],
        )

        assert len(result) == 1
        assert result[0]["name"] == "codeql"
        assert result[0]["is_core_engine"] is True
        assert result[0]["languages"] == ["typescript", "javascript"]
        assert result[0]["error_type"] == "analyze_failed"

    def test_collect_failed_engines_unavailable(self) -> None:
        """Test _collect_failed_engines with unavailable engines."""
        from src.cli.main import _collect_failed_engines

        phases = {
            "semgrep": {"success": True, "findings_count": 10},
        }

        result = _collect_failed_engines(
            phases=phases,
            unavailable_engines=["codeql"],
            requested_engines=["semgrep", "codeql"],
        )

        # Should include codeql as unavailable
        assert len(result) == 1
        assert result[0]["name"] == "codeql"
        assert result[0]["error_type"] == "unavailable"

    def test_determine_scan_status_complete_success(self) -> None:
        """Test _determine_scan_status returns complete_success when all succeed."""
        from src.cli.main import _determine_scan_status

        phases = {
            "semgrep": {"success": True},
            "codeql": {"success": True},
            "agent": {"success": True},
        }

        result = _determine_scan_status(
            phases=phases,
            failed_engines=[],
            has_valid_findings=True,
            requested_engines=["semgrep", "codeql", "agent"],
        )

        assert result == "complete_success"

    def test_determine_scan_status_degraded_success(self) -> None:
        """Test _determine_scan_status returns degraded_success when CodeQL fails but others succeed."""
        from src.cli.main import _determine_scan_status

        phases = {
            "semgrep": {"success": True, "findings_count": 10},
            "codeql": {"success": False, "error": "Failed"},
            "agent": {"success": True, "findings_count": 3},
        }

        failed_engines = [{
            "name": "codeql",
            "error_type": "analyze_failed",
            "message": "Failed",
            "is_core_engine": True,
        }]

        result = _determine_scan_status(
            phases=phases,
            failed_engines=failed_engines,
            has_valid_findings=True,
            requested_engines=["semgrep", "codeql", "agent"],
        )

        assert result == "degraded_success"

    def test_determine_scan_status_failed(self) -> None:
        """Test _determine_scan_status returns failed when all engines fail."""
        from src.cli.main import _determine_scan_status

        phases = {
            "semgrep": {"success": False, "error": "Failed"},
            "codeql": {"success": False, "error": "Failed"},
            "agent": {"success": False, "error": "Failed"},
        }

        failed_engines = [
            {"name": "semgrep", "error_type": "engine_failed", "is_core_engine": False},
            {"name": "codeql", "error_type": "engine_failed", "is_core_engine": True},
            {"name": "agent", "error_type": "engine_failed", "is_core_engine": False},
        ]

        result = _determine_scan_status(
            phases=phases,
            failed_engines=failed_engines,
            has_valid_findings=False,
            requested_engines=["semgrep", "codeql", "agent"],
        )

        assert result == "failed"

    def test_determine_scan_status_no_phases(self) -> None:
        """Test _determine_scan_status returns failed when no phases executed."""
        from src.cli.main import _determine_scan_status

        result = _determine_scan_status(
            phases={},
            failed_engines=[],
            has_valid_findings=False,
            requested_engines=[],
        )

        assert result == "failed"


class TestExportFullScanResult:
    """Test P6-01 export function includes status."""

    def test_export_includes_status_complete(self, tmp_path: Path) -> None:
        """Test export includes status for complete success."""
        from src.cli.main import _export_full_scan_result

        result = {
            "status": "complete_success",
            "source_path": "/test/path",
            "start_time": "2026-03-11T00:00:00",
            "end_time": "2026-03-11T00:01:00",
            "primary_language": "python",
            "phases": {"semgrep": {"success": True, "findings_count": 5}},
            "statistics": {"total_findings": 5, "verified_count": 5},
            "failed_engines": [],
            "all_findings": [],
            "errors": [],
        }

        export_file = tmp_path / "report.txt"
        _export_full_scan_result(result, str(export_file), {})

        content = export_file.read_text()
        assert "Status: COMPLETE SUCCESS" in content
        assert "COVERAGE WARNING" not in content

    def test_export_includes_status_degraded(self, tmp_path: Path) -> None:
        """Test export includes status for degraded success with warning."""
        from src.cli.main import _export_full_scan_result

        result = {
            "status": "degraded_success",
            "source_path": "/test/path",
            "start_time": "2026-03-11T00:00:00",
            "end_time": "2026-03-11T00:01:00",
            "primary_language": "typescript",
            "phases": {
                "semgrep": {"success": True, "findings_count": 10},
                "codeql": {"success": False, "error": "Failed"},
            },
            "statistics": {"total_findings": 10, "verified_count": 10},
            "failed_engines": [{
                "name": "codeql",
                "error_type": "analyze_failed",
                "message": "All language scans failed",
                "languages": ["typescript"],
                "is_core_engine": True,
            }],
            "all_findings": [],
            "errors": [],
        }

        export_file = tmp_path / "report.txt"
        _export_full_scan_result(result, str(export_file), {})

        content = export_file.read_text()
        assert "Status: DEGRADED SUCCESS" in content
        assert "COVERAGE WARNING" in content
        assert "Core evidence engine" in content
        assert "Failed Engines" in content
        assert "codeql" in content

    def test_export_includes_failed_engines_details(self, tmp_path: Path) -> None:
        """Test export includes detailed failed engine info."""
        from src.cli.main import _export_full_scan_result

        result = {
            "status": "degraded_success",
            "source_path": "/test/path",
            "start_time": "2026-03-11T00:00:00",
            "end_time": "2026-03-11T00:01:00",
            "primary_language": "javascript",
            "phases": {
                "semgrep": {"success": True, "findings_count": 5},
                "codeql": {"success": False, "error": "Failed"},
            },
            "statistics": {"total_findings": 5, "verified_count": 5},
            "failed_engines": [{
                "name": "codeql",
                "error_type": "analyze_failed",
                "message": "All language scans failed. Languages attempted: typescript, javascript",
                "languages": ["typescript", "javascript"],
                "is_core_engine": True,
            }],
            "all_findings": [],
            "errors": [],
        }

        export_file = tmp_path / "report.txt"
        _export_full_scan_result(result, str(export_file), {})

        content = export_file.read_text()
        assert "Failed Engines" in content
        assert "codeql [CORE]" in content
        assert "Languages: typescript, javascript" in content
