"""
Unit tests for WAL detection logic inside parse_database_standalone.
"""

from unittest.mock import patch

import pytest

from main import compute_sha256_standalone, parse_database_standalone


def _parse(db_path):
    with patch("main.time.sleep"):
        return parse_database_standalone(str(db_path))


class TestWalPresenceDetection:
    def test_db_with_wal_reports_wal_present_and_recovered_count(
        self, db_with_wal_copy, wal_recoverable_count, wal_total_count
    ):
        messages, total_records, wal_recovery = _parse(db_with_wal_copy)

        assert wal_recovery["wal_present"] is True
        assert wal_recovery["recovered_message_count"] == wal_recoverable_count
        assert total_records == wal_total_count
        assert len(messages) == wal_total_count

        recovered = [m for m in messages if m.get("recovered")]
        assert len(recovered) == wal_recoverable_count
        assert recovered[0]["sender"] == "Charlie"
        assert recovered[0]["content"] == "WAL-only msg 3"

    def test_plain_db_without_wal_reports_wal_present_false(self, plain_db_no_wal):
        _messages, _total, wal_recovery = _parse(plain_db_no_wal)

        assert wal_recovery["wal_present"] is False
        assert wal_recovery["recovered_message_count"] == 0


class TestWalHashField:
    def test_wal_hash_populated_when_wal_present(self, db_with_wal_copy, fixtures_dir):
        wal_path = fixtures_dir / "db_with_wal.db-wal"
        expected_hash = compute_sha256_standalone(str(wal_path))

        _messages, _total, wal_recovery = _parse(db_with_wal_copy)

        assert wal_recovery["wal_present"] is True
        assert wal_recovery["wal_hash"] == expected_hash
        assert wal_recovery["wal_hash"] is not None

    def test_wal_hash_is_none_when_wal_absent(self, plain_db_no_wal):
        _messages, _total, wal_recovery = _parse(plain_db_no_wal)

        assert wal_recovery["wal_present"] is False
        assert wal_recovery["wal_hash"] is None
