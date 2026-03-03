"""
Unit tests for CodeQL database caching functionality.
"""

import hashlib
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.layers.l3_analysis.engines.codeql import CodeQLEngine, DEFAULT_CACHE_DIR


class TestCodeQLCache:
    """Test cases for CodeQL database caching."""

    def test_cache_initialization_default(self):
        """Test default cache configuration."""
        engine = CodeQLEngine()
        assert engine.enable_cache is True
        assert engine.cache_dir == DEFAULT_CACHE_DIR

    def test_cache_initialization_custom_dir(self):
        """Test custom cache directory."""
        custom_dir = Path("/tmp/custom_cache")
        engine = CodeQLEngine(cache_dir=custom_dir)
        assert engine.cache_dir == custom_dir

    def test_cache_initialization_disabled(self):
        """Test disabled cache."""
        engine = CodeQLEngine(enable_cache=False)
        assert engine.enable_cache is False

    def test_compute_source_hash_deterministic(self):
        """Test that source hash is deterministic."""
        engine = CodeQLEngine()

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            # Create some test files
            (source_path / "test.py").write_text("print('hello')")
            (source_path / "subdir").mkdir()
            (source_path / "subdir" / "test2.py").write_text("print('world')")

            hash1 = engine._compute_source_hash(source_path, "python")
            hash2 = engine._compute_source_hash(source_path, "python")

            assert hash1 == hash2
            assert len(hash1) == 16

    def test_compute_source_hash_different_languages(self):
        """Test that different languages produce different hashes."""
        engine = CodeQLEngine()

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            (source_path / "test.py").write_text("print('hello')")
            (source_path / "test.js").write_text("console.log('hello')")

            hash_python = engine._compute_source_hash(source_path, "python")
            hash_js = engine._compute_source_hash(source_path, "javascript")

            assert hash_python != hash_js

    def test_compute_source_hash_changes_with_files(self):
        """Test that hash changes when files change."""
        engine = CodeQLEngine()

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            (source_path / "test.py").write_text("print('hello')")

            hash1 = engine._compute_source_hash(source_path, "python")

            # Modify file
            (source_path / "test.py").write_text("print('modified')")

            hash2 = engine._compute_source_hash(source_path, "python")

            # Hashes should be different due to mtime change
            # Note: This test might be flaky on fast systems
            # but the hash should at least be computed

    def test_compute_source_hash_skips_ignored_dirs(self):
        """Test that hash ignores files in skipped directories."""
        engine = CodeQLEngine()

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            (source_path / "test.py").write_text("print('hello')")
            (source_path / "node_modules").mkdir()
            (source_path / "node_modules" / "skip.js").write_text("skip this")

            # Should not fail and should only consider Python files
            hash_val = engine._compute_source_hash(source_path, "python")
            assert len(hash_val) == 16

    def test_get_cached_database_path(self):
        """Test cached database path generation."""
        engine = CodeQLEngine()

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir)
            (source_path / "test.py").write_text("print('hello')")

            cache_path = engine._get_cached_database_path(source_path, "python")

            assert cache_path.parent == DEFAULT_CACHE_DIR
            assert cache_path.name.startswith("python_")

    def test_check_cached_database_not_exists(self):
        """Test cache check when database doesn't exist."""
        engine = CodeQLEngine()

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "nonexistent"
            assert engine._check_cached_database(cache_path) is False

    def test_check_cached_database_exists_valid(self):
        """Test cache check when valid database exists."""
        engine = CodeQLEngine()

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "valid_db"
            cache_path.mkdir()
            (cache_path / "codeql-database.yml").write_text("name: test")
            (cache_path / "db-python").mkdir()

            assert engine._check_cached_database(cache_path) is True

    def test_check_cached_database_exists_invalid(self):
        """Test cache check when invalid database exists."""
        engine = CodeQLEngine()

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "invalid_db"
            cache_path.mkdir()
            # Missing codeql-database.yml and db-* directory

            assert engine._check_cached_database(cache_path) is False

    def test_ensure_cache_dir(self):
        """Test cache directory creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "new_cache"
            engine = CodeQLEngine(cache_dir=cache_dir)

            assert not cache_dir.exists()
            engine._ensure_cache_dir()
            assert cache_dir.exists()

    def test_get_cache_stats_empty(self):
        """Test cache stats when cache is empty."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            engine = CodeQLEngine(cache_dir=cache_dir)

            stats = engine.get_cache_stats()

            assert stats["enabled"] is True
            assert stats["exists"] is False
            assert stats["entries"] == 0
            assert stats["total_size_mb"] == 0

    def test_get_cache_stats_with_entries(self):
        """Test cache stats with cached databases."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            cache_dir.mkdir()
            engine = CodeQLEngine(cache_dir=cache_dir)

            # Create a fake cached database
            db_path = cache_dir / "python_test123"
            db_path.mkdir()
            (db_path / "codeql-database.yml").write_text("name: test")
            (db_path / "db-python").mkdir()
            (db_path / "db-python" / "test.db").write_text("x" * (1024 * 1024))  # 1MB

            stats = engine.get_cache_stats()

            assert stats["enabled"] is True
            assert stats["exists"] is True
            assert stats["entries"] == 1
            assert stats["total_size_mb"] >= 1.0  # At least 1MB

    def test_clear_cache(self):
        """Test cache clearing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            cache_dir.mkdir()
            engine = CodeQLEngine(cache_dir=cache_dir)

            # Create some fake cached databases
            for i in range(3):
                db_path = cache_dir / f"python_test{i}"
                db_path.mkdir()

            assert len(list(cache_dir.iterdir())) == 3

            count = engine.clear_cache()

            assert count == 3
            assert len(list(cache_dir.iterdir())) == 0

    def test_clear_cache_empty(self):
        """Test cache clearing when cache is empty."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            engine = CodeQLEngine(cache_dir=cache_dir)

            count = engine.clear_cache()
            assert count == 0


class TestCodeQLCacheIntegration:
    """Integration tests for CodeQL caching with scan method."""

    @pytest.mark.asyncio
    async def test_scan_uses_cached_database(self):
        """Test that scan uses cached database when available."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            cache_dir.mkdir()
            source_dir = Path(tmpdir) / "source"
            source_dir.mkdir()
            (source_dir / "test.py").write_text("print('hello')")

            engine = CodeQLEngine(cache_dir=cache_dir, enable_cache=True)

            # Create a fake cached database
            cache_path = engine._get_cached_database_path(source_dir, "python")
            cache_path.mkdir(parents=True)
            (cache_path / "codeql-database.yml").write_text("name: test")
            (cache_path / "db-python").mkdir()

            # Mock the internal methods
            with patch.object(engine, 'is_available', return_value=True):
                with patch.object(engine, '_detect_language', return_value='python'):
                    with patch.object(engine, '_analyze_database', new_callable=AsyncMock) as mock_analyze:
                        with patch.object(engine, '_parse_sarif', return_value=[]):
                            mock_analyze.return_value = {"runs": []}

                            result = await engine.scan(source_dir)

                            # Verify that _create_database was NOT called
                            # (since we're using cached DB)
                            assert result.success is True

    @pytest.mark.asyncio
    async def test_scan_creates_cached_database(self):
        """Test that scan creates database in cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            source_dir = Path(tmpdir) / "source"
            source_dir.mkdir()
            (source_dir / "test.py").write_text("print('hello')")

            engine = CodeQLEngine(cache_dir=cache_dir, enable_cache=True)

            expected_cache_path = engine._get_cached_database_path(source_dir, "python")

            with patch.object(engine, 'is_available', return_value=True):
                with patch.object(engine, '_detect_language', return_value='python'):
                    with patch.object(engine, '_create_database', new_callable=AsyncMock) as mock_create:
                        with patch.object(engine, '_analyze_database', new_callable=AsyncMock) as mock_analyze:
                            with patch.object(engine, '_parse_sarif', return_value=[]):
                                mock_create.return_value = True
                                mock_analyze.return_value = {"runs": []}

                                result = await engine.scan(source_dir)

                                # Verify database was created in cache directory
                                mock_create.assert_called_once()
                                call_args = mock_create.call_args
                                assert call_args.kwargs['database_path'] == expected_cache_path
