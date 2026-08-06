"""
Edge-case and boundary tests for parse_database_standalone.

Focuses on graceful degradation under failure conditions — clear errors,
no silent data loss, no hangs — rather than happy-path correctness.
"""

import time
import tracemalloc
from unittest.mock import patch

import pytest

from main import parse_database_standalone

EMPTY_DB_ERROR = "Extracted database file is empty or unreadable"
CORRUPTED_DB_PATTERN = r"corrupted or incomplete"

# Parser uses batch_size=500; cancel after one progress tick stops after first batch.
PARSER_BATCH_SIZE = 500

# Performance ceiling for 50k-row synthetic fixture (adjust if hardware differs).
LARGE_DB_TIME_LIMIT_SECONDS = 30
LARGE_DB_MEMORY_CEILING_BYTES = 200 * 1024 * 1024  # 200 MB


def _parse(db_path, **kwargs):
    """Parse with time.sleep patched out unless kwargs override behavior."""
    with patch("main.time.sleep"):
        return parse_database_standalone(str(db_path), **kwargs)


class TestEmptyDatabase:
    def test_parse_database_zero_byte_file_raises_empty_or_unreadable(self, empty_db):
        with pytest.raises(RuntimeError, match=EMPTY_DB_ERROR):
            _parse(empty_db)


class TestValidEmptyDatabase:
    def test_parse_database_valid_empty_schema_returns_empty_list(
        self, valid_empty_db
    ):
        messages, total_records, wal_recovery = _parse(valid_empty_db)

        assert messages == []
        assert total_records == 0
        assert wal_recovery["wal_present"] is False
        assert wal_recovery["recovered_message_count"] == 0


class TestMissingWalSidecar:
    def test_parse_database_missing_wal_sidecar_reports_wal_absent(
        self, db_missing_wal_reference
    ):
        start = time.perf_counter()
        messages, total_records, wal_recovery = _parse(db_missing_wal_reference)
        elapsed = time.perf_counter() - start

        assert wal_recovery["wal_present"] is False
        assert wal_recovery["wal_hash"] is None
        assert wal_recovery["recovered_message_count"] == 0
        assert total_records == 1
        assert len(messages) == 1
        assert elapsed < 2.0, "Missing WAL sidecar should not introduce delay"


class TestCorruptedDatabase:
    def test_parse_database_corrupted_file_raises_runtime_error_with_no_partial_data(
        self, corrupted_db
    ):
        with pytest.raises(RuntimeError, match=CORRUPTED_DB_PATTERN) as exc_info:
            _parse(corrupted_db)

        assert "corrupted or incomplete" in str(exc_info.value).lower()


class TestLargeDatabasePerformance:
    @pytest.mark.slow
    def test_parse_database_large_synthetic_completes_within_time_and_memory_bounds(
        self, large_synthetic_db, large_synthetic_row_count
    ):
        tracemalloc.start()
        start = time.perf_counter()

        messages, total_records, wal_recovery = _parse(large_synthetic_db)

        elapsed = time.perf_counter() - start
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert elapsed < LARGE_DB_TIME_LIMIT_SECONDS, (
            f"Parsing {large_synthetic_row_count:,} rows took {elapsed:.2f}s "
            f"(limit {LARGE_DB_TIME_LIMIT_SECONDS}s)"
        )
        assert peak < LARGE_DB_MEMORY_CEILING_BYTES, (
            f"Peak memory {peak / (1024 * 1024):.1f} MB exceeds "
            f"{LARGE_DB_MEMORY_CEILING_BYTES / (1024 * 1024):.0f} MB ceiling"
        )
        assert total_records == large_synthetic_row_count
        assert len(messages) == large_synthetic_row_count
        assert wal_recovery["wal_present"] is False


class TestCancellationMidParse:
    def test_parse_database_cancel_fn_stops_after_first_batch(
        self, many_messages_db, many_messages_row_count
    ):
        """
        cancel_fn is supported on parse_database_standalone — no QThread required.
        After the first progress callback the cancel flag is set; parsing should
        stop before consuming all rows.
        """
        progress_calls = {"count": 0}

        def progress_fn(current, total, _msg):
            progress_calls["count"] += 1

        def cancel_fn():
            return progress_calls["count"] >= 1

        messages, total_records, _wal = _parse(
            many_messages_db,
            progress_fn=progress_fn,
            cancel_fn=cancel_fn,
        )

        assert total_records == many_messages_row_count
        assert len(messages) < many_messages_row_count
        assert len(messages) == PARSER_BATCH_SIZE
        assert progress_calls["count"] == 1
