"""
Shared pytest fixtures for the WhtsSec forensic tool test suite.
"""

import shutil
from pathlib import Path

import pytest

from tests.fixtures.create_fixtures import (
    KNOWN_CONTENT_SHA256,
    LARGE_SYNTHETIC_ROW_COUNT,
    MANY_MESSAGES_ROW_COUNT,
    SIMPLE_MESSAGES_EXPECTED,
    WAL_RECOVERABLE_COUNT,
    WAL_TOTAL_COUNT,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir():
    """Absolute path to tests/fixtures/."""
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def simple_messages_expected():
    """Hand-crafted expected rows for simple_messages.db."""
    return list(SIMPLE_MESSAGES_EXPECTED)


@pytest.fixture(scope="session")
def many_messages_row_count():
    return MANY_MESSAGES_ROW_COUNT


@pytest.fixture(scope="session")
def wal_recoverable_count():
    return WAL_RECOVERABLE_COUNT


@pytest.fixture(scope="session")
def wal_total_count():
    return WAL_TOTAL_COUNT


@pytest.fixture(scope="session")
def known_content_sha256():
    return KNOWN_CONTENT_SHA256


@pytest.fixture
def simple_messages_db(tmp_path, fixtures_dir):
    """Copy of simple_messages.db in a temp directory (read-only source preserved)."""
    src = fixtures_dir / "simple_messages.db"
    dst = tmp_path / "simple_messages.db"
    shutil.copy2(src, dst)
    return dst


@pytest.fixture
def many_messages_db(tmp_path, fixtures_dir):
    """Copy of many_messages.db in a temp directory."""
    src = fixtures_dir / "many_messages.db"
    dst = tmp_path / "many_messages.db"
    shutil.copy2(src, dst)
    return dst


@pytest.fixture
def db_with_wal_copy(tmp_path, fixtures_dir):
    """Copy of db_with_wal.db and its -wal sidecar into a temp directory."""
    base_name = "db_with_wal.db"
    src_db = fixtures_dir / base_name
    src_wal = fixtures_dir / f"{base_name}-wal"

    dst_db = tmp_path / base_name
    dst_wal = tmp_path / f"{base_name}-wal"

    shutil.copy2(src_db, dst_db)
    if src_wal.exists():
        shutil.copy2(src_wal, dst_wal)

    return dst_db


@pytest.fixture
def plain_db_no_wal(tmp_path, fixtures_dir):
    """Copy of simple_messages.db with any WAL sidecar explicitly removed."""
    src = fixtures_dir / "simple_messages.db"
    dst = tmp_path / "plain_no_wal.db"
    shutil.copy2(src, dst)
    wal = tmp_path / "plain_no_wal.db-wal"
    if wal.exists():
        wal.unlink()
    return dst


@pytest.fixture
def corrupted_db(tmp_path, fixtures_dir):
    """Copy of corrupted.db in a temp directory."""
    src = fixtures_dir / "corrupted.db"
    dst = tmp_path / "corrupted.db"
    shutil.copy2(src, dst)
    return dst


@pytest.fixture
def known_content_file(tmp_path, fixtures_dir):
    """Copy of known_content.txt in a temp directory."""
    src = fixtures_dir / "known_content.txt"
    dst = tmp_path / "known_content.txt"
    shutil.copy2(src, dst)
    return dst


@pytest.fixture(scope="session")
def large_synthetic_row_count():
    return LARGE_SYNTHETIC_ROW_COUNT


@pytest.fixture
def empty_db(tmp_path, fixtures_dir):
    """Copy of empty.db (0-byte invalid file) in a temp directory."""
    src = fixtures_dir / "empty.db"
    dst = tmp_path / "empty.db"
    shutil.copy2(src, dst)
    return dst


@pytest.fixture
def valid_empty_db(tmp_path, fixtures_dir):
    """Copy of valid_empty.db in a temp directory."""
    src = fixtures_dir / "valid_empty.db"
    dst = tmp_path / "valid_empty.db"
    shutil.copy2(src, dst)
    return dst


@pytest.fixture
def large_synthetic_db(tmp_path, fixtures_dir):
    """Copy of large_synthetic.db in a temp directory."""
    src = fixtures_dir / "large_synthetic.db"
    dst = tmp_path / "large_synthetic.db"
    shutil.copy2(src, dst)
    return dst


@pytest.fixture
def db_missing_wal_reference(tmp_path, fixtures_dir):
    """Copy of db_missing_wal_reference.db with no -wal sidecar."""
    src = fixtures_dir / "db_missing_wal_reference.db"
    dst = tmp_path / "db_missing_wal_reference.db"
    shutil.copy2(src, dst)
    wal = tmp_path / "db_missing_wal_reference.db-wal"
    if wal.exists():
        wal.unlink()
    return dst


@pytest.fixture
def empty_file(tmp_path, fixtures_dir):
    """Copy of empty_file.txt in a temp directory."""
    src = fixtures_dir / "empty_file.txt"
    dst = tmp_path / "empty_file.txt"
    shutil.copy2(src, dst)
    return dst
