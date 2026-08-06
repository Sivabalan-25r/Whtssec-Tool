"""
Unit tests for parse_database_standalone (imported from main.py).
"""

from unittest.mock import patch

import pytest

from main import parse_database_standalone


def _parse(db_path):
    """Parse with time.sleep patched out for faster tests."""
    with patch("main.time.sleep"):
        return parse_database_standalone(str(db_path))


def _message_key(msg):
    return (msg["sender"], msg["timestamp"], msg["content"])


class TestParseDatabaseMessageCount:
    def test_parse_database_message_count_matches_fixture(
        self, simple_messages_db, simple_messages_expected
    ):
        messages, total_records, _wal = _parse(simple_messages_db)
        assert total_records == len(simple_messages_expected)
        assert len(messages) == len(simple_messages_expected)


class TestParseDatabaseKnownMessages:
    def test_parse_database_known_sender_timestamp_content(
        self, simple_messages_db, simple_messages_expected
    ):
        messages, _, _ = _parse(simple_messages_db)

        for expected in simple_messages_expected:
            matches = [
                m for m in messages
                if m["sender"] == expected["sender"]
                and m["timestamp"] == expected["timestamp"]
                and m["content"] == expected["content"]
            ]
            assert len(matches) == 1, (
                f"Expected exactly one match for {expected['sender']} @ "
                f"{expected['timestamp']}: {expected['content']!r}"
            )
            assert matches[0]["chat"] == expected["chat"]


class TestParseDatabaseMediaLabel:
    def test_parse_database_labels_null_content_as_media(self, simple_messages_db):
        messages, _, _ = _parse(simple_messages_db)

        charlie_msgs = [m for m in messages if m["sender"] == "Charlie"]
        assert len(charlie_msgs) == 1
        assert charlie_msgs[0]["content"] == "[Media]"


class TestParseDatabaseBatching:
    def test_parse_database_batch_size_greater_than_row_count(
        self, simple_messages_db, simple_messages_expected
    ):
        """Parser batch_size=500 exceeds 5-row fixture — all rows in one batch."""
        first_run = _parse(simple_messages_db)
        second_run = _parse(simple_messages_db)

        assert first_run[0] == second_run[0]
        assert len(first_run[0]) == len(simple_messages_expected)

    def test_parse_database_batch_size_less_than_row_count(
        self, many_messages_db, many_messages_row_count
    ):
        """600-row fixture forces multiple fetchmany(500) calls."""
        messages, total_records, _ = _parse(many_messages_db)

        assert total_records == many_messages_row_count
        assert len(messages) == many_messages_row_count

        contents = [m["content"] for m in messages]
        assert len(set(contents)) == many_messages_row_count
        assert contents[0] == "Message 0000"
        assert contents[-1] == f"Message {many_messages_row_count - 1:04d}"

    def test_parse_database_batching_produces_identical_results_on_repeat(
        self, many_messages_db, many_messages_row_count
    ):
        run_a = _parse(many_messages_db)
        run_b = _parse(many_messages_db)

        keys_a = sorted(_message_key(m) for m in run_a[0])
        keys_b = sorted(_message_key(m) for m in run_b[0])
        assert keys_a == keys_b
        assert len(keys_a) == many_messages_row_count


class TestParseDatabaseCorruption:
    def test_parse_database_corrupted_file_raises_runtime_error(self, corrupted_db):
        with pytest.raises(RuntimeError, match="corrupted or incomplete"):
            _parse(corrupted_db)
