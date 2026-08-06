#!/usr/bin/env python3
"""
create_fixtures.py — Generates small, deterministic SQLite fixture databases
for the pytest test suite.

Run once (or re-run whenever the schema expectations change):
    python tests/fixtures/create_fixtures.py

Produced files
--------------
simple_messages.db          Five rows in a flat "messages" table (sender/timestamp/chat/content).
real_schema.db              WhatsApp-like "message"/"chat"/"jid" tables with joins.
many_messages.db            Six hundred rows for fetchmany batching tests (batch_size=500 in parser).
db_with_wal.db              Base database (2 rows checkpointed).
db_with_wal.db-wal          WAL file containing 1 additional row not in the checkpointed base.
corrupted.db                Truncated SQLite file for corruption-handling tests.
empty.db                    Zero-byte file (not a valid SQLite header).
valid_empty.db              Valid message/chat/jid schema with zero message rows.
large_synthetic.db          Fifty-thousand synthetic rows for performance / no-freeze tests.
db_missing_wal_reference.db WAL journal mode in header, but no -wal sidecar present.
known_content.txt           Small file with known bytes for SHA-256 hash testing.
empty_file.txt              Zero-byte file for empty-input hash testing.
"""

import hashlib
import os
import shutil
import sqlite3

FIXTURES_DIR = os.path.dirname(os.path.abspath(__file__))

# Canonical expected values for simple_messages.db (used by tests and docs)
SIMPLE_MESSAGES_EXPECTED = [
    {"sender": "Alice",   "timestamp": "2024-01-15 09:00:00", "chat": "Group Chat",  "content": "Hello everyone!"},
    {"sender": "Bob",     "timestamp": "2024-01-15 09:01:00", "chat": "Group Chat",  "content": "Hey Alice!"},
    {"sender": "Me",      "timestamp": "2024-01-15 09:02:00", "chat": "Group Chat",  "content": "Good morning"},
    {"sender": "Charlie", "timestamp": "2024-01-15 09:03:00", "chat": "Direct Chat", "content": "[Media]"},
    {"sender": "Alice",   "timestamp": "2024-01-15 09:04:00", "chat": "Group Chat",  "content": "See you later"},
]

MANY_MESSAGES_ROW_COUNT = 600

LARGE_SYNTHETIC_ROW_COUNT = 50_000
LARGE_SYNTHETIC_INSERT_BATCH = 1_000

# WAL fixture: 2 checkpointed rows + 1 recoverable row only in WAL
WAL_CHECKPOINTED_COUNT = 2
WAL_RECOVERABLE_COUNT = 1
WAL_TOTAL_COUNT = WAL_CHECKPOINTED_COUNT + WAL_RECOVERABLE_COUNT

KNOWN_CONTENT_BYTES = b"WhatsApp Forensic Tool - deterministic test payload for SHA-256\n"
KNOWN_CONTENT_SHA256 = hashlib.sha256(KNOWN_CONTENT_BYTES).hexdigest()

EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _fresh(name):
    """Return absolute path inside fixtures dir; remove existing file if any."""
    path = os.path.join(FIXTURES_DIR, name)
    for suffix in ("", "-wal", "-shm"):
        candidate = path + suffix if suffix else path
        if os.path.exists(candidate):
            os.remove(candidate)
    return path


def _log(msg):
    print(f"  [ok] {msg}")


def create_simple_messages():
    path = _fresh("simple_messages.db")
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE messages (
            sender    TEXT,
            timestamp TEXT,
            chat      TEXT,
            content   TEXT
        )
    """)
    rows = [
        ("Alice",   "2024-01-15 09:00:00", "Group Chat",  "Hello everyone!"),
        ("Bob",     "2024-01-15 09:01:00", "Group Chat",  "Hey Alice!"),
        ("Me",      "2024-01-15 09:02:00", "Group Chat",  "Good morning"),
        ("Charlie", "2024-01-15 09:03:00", "Direct Chat", None),
        ("Alice",   "2024-01-15 09:04:00", "Group Chat",  "See you later"),
    ]
    c.executemany("INSERT INTO messages VALUES (?,?,?,?)", rows)
    conn.commit()
    conn.close()
    _log(f"{os.path.basename(path)}  (5 rows, flat schema)")
    return path


def create_real_schema():
    path = _fresh("real_schema.db")
    conn = sqlite3.connect(path)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE jid (
            _id        INTEGER PRIMARY KEY,
            raw_string TEXT
        )
    """)
    c.executemany("INSERT INTO jid VALUES (?,?)", [
        (1, "alice@s.whatsapp.net"),
        (2, "bob@s.whatsapp.net"),
        (3, "charlie@s.whatsapp.net"),
    ])

    c.execute("""
        CREATE TABLE chat (
            _id     INTEGER PRIMARY KEY,
            subject TEXT
        )
    """)
    c.executemany("INSERT INTO chat VALUES (?,?)", [
        (1, "Family Group"),
        (2, "Work Team"),
    ])

    c.execute("""
        CREATE TABLE message (
            _id               INTEGER PRIMARY KEY,
            from_me           INTEGER,
            timestamp         INTEGER,
            data              TEXT,
            chat_row_id       INTEGER,
            sender_jid_row_id INTEGER
        )
    """)
    base_ts = 1705312800000
    c.executemany("INSERT INTO message VALUES (?,?,?,?,?,?)", [
        (1, 0, base_ts,          "Hello from Alice", 1, 1),
        (2, 1, base_ts + 60000,  "Reply from me",    1, 0),
        (3, 0, base_ts + 120000, "Bob here",         2, 2),
        (4, 0, base_ts + 180000, None,               1, 3),
        (5, 0, base_ts + 240000, "See you",          2, 1),
    ])

    conn.commit()
    conn.close()
    _log(f"{os.path.basename(path)}  (5 rows, WhatsApp schema with jid + chat joins)")
    return path


def create_many_messages():
    """600 rows so parser batch_size=500 requires multiple fetchmany calls."""
    path = _fresh("many_messages.db")
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE messages (
            sender    TEXT,
            timestamp TEXT,
            chat      TEXT,
            content   TEXT
        )
    """)
    rows = [
        (
            f"User{i % 10}",
            f"2024-03-01 {i // 3600:02d}:{(i // 60) % 60:02d}:{i % 60:02d}",
            "Batch Chat",
            f"Message {i:04d}",
        )
        for i in range(MANY_MESSAGES_ROW_COUNT)
    ]
    c.executemany("INSERT INTO messages VALUES (?,?,?,?)", rows)
    conn.commit()
    conn.close()
    _log(f"{os.path.basename(path)}  ({MANY_MESSAGES_ROW_COUNT} rows for batching tests)")
    return path


def create_db_with_wal():
    """
    Create db_with_wal.db with 2 checkpointed rows, then a -wal sidecar
    containing 1 additional row not yet merged into the main db file.

    Strategy: copy the db file immediately after checkpointing 2 rows,
    then insert the 3rd row so it lives only in the WAL.  The checkpointed
    db copy is saved as the fixture; the WAL is copied before close.
    """
    fixture_db = _fresh("db_with_wal.db")
    fixture_wal = fixture_db + "-wal"
    work_db = os.path.join(FIXTURES_DIR, "_wal_work.db")
    for extra in (work_db, work_db + "-wal", work_db + "-shm"):
        if os.path.exists(extra):
            os.remove(extra)

    conn = sqlite3.connect(work_db)
    c = conn.cursor()

    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA wal_autocheckpoint=0")
    c.execute("""
        CREATE TABLE messages (
            sender    TEXT,
            timestamp TEXT,
            chat      TEXT,
            content   TEXT
        )
    """)

    base_rows = [
        ("Alice", "2024-06-01 10:00:00", "Test Chat", "Checkpointed msg 1"),
        ("Bob",   "2024-06-01 10:01:00", "Test Chat", "Checkpointed msg 2"),
    ]
    c.executemany("INSERT INTO messages VALUES (?,?,?,?)", base_rows)
    conn.commit()

    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.commit()

    # Snapshot the checkpointed base BEFORE the WAL-only insert
    shutil.copy2(work_db, fixture_db)

    c.execute(
        "INSERT INTO messages VALUES (?,?,?,?)",
        ("Charlie", "2024-06-01 10:02:00", "Test Chat", "WAL-only msg 3"),
    )
    conn.commit()

    wal_source = work_db + "-wal"
    if os.path.exists(wal_source) and os.path.getsize(wal_source) > 0:
        shutil.copy2(wal_source, fixture_wal)

    conn.close()

    for extra in (work_db, work_db + "-wal", work_db + "-shm"):
        if os.path.exists(extra):
            os.remove(extra)

    if os.path.exists(fixture_wal) and os.path.getsize(fixture_wal) > 0:
        _log(
            f"{os.path.basename(fixture_db)} + WAL  "
            f"({WAL_CHECKPOINTED_COUNT} checkpointed + {WAL_RECOVERABLE_COUNT} WAL-only)"
        )
    else:
        raise RuntimeError(
            "Failed to create WAL fixture — no WAL file produced. "
            "Try re-running on a SQLite build with WAL journal support."
        )

    return fixture_db


def create_corrupted():
    """Truncate a valid SQLite file to produce an unreadable database."""
    source = os.path.join(FIXTURES_DIR, "simple_messages.db")
    if not os.path.exists(source):
        create_simple_messages()
    dest = _fresh("corrupted.db")
    with open(source, "rb") as src:
        data = src.read(100)
    with open(dest, "wb") as dst:
        dst.write(data)
    _log(f"{os.path.basename(dest)}  (truncated to 100 bytes)")
    return dest


def create_empty_db():
    """Zero-byte file — not a valid SQLite database."""
    path = _fresh("empty.db")
    open(path, "wb").close()
    _log(f"{os.path.basename(path)}  (0 bytes, invalid)")
    return path


def create_valid_empty():
    """
    Structurally valid WhatsApp-like schema (message/chat/jid) with zero rows
    in the message table — simulates a brand-new install.
    """
    path = _fresh("valid_empty.db")
    conn = sqlite3.connect(path)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE jid (
            _id        INTEGER PRIMARY KEY,
            raw_string TEXT
        )
    """)
    c.execute("""
        CREATE TABLE chat (
            _id     INTEGER PRIMARY KEY,
            subject TEXT
        )
    """)
    c.execute("""
        CREATE TABLE message (
            _id               INTEGER PRIMARY KEY,
            from_me           INTEGER,
            timestamp         INTEGER,
            data              TEXT,
            chat_row_id       INTEGER,
            sender_jid_row_id INTEGER
        )
    """)

    conn.commit()
    conn.close()
    _log(f"{os.path.basename(path)}  (valid schema, 0 message rows)")
    return path


def create_large_synthetic():
    """Large flat-schema database for performance / memory ceiling tests."""
    path = _fresh("large_synthetic.db")
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE messages (
            sender    TEXT,
            timestamp TEXT,
            chat      TEXT,
            content   TEXT
        )
    """)

    for start in range(0, LARGE_SYNTHETIC_ROW_COUNT, LARGE_SYNTHETIC_INSERT_BATCH):
        end = min(start + LARGE_SYNTHETIC_INSERT_BATCH, LARGE_SYNTHETIC_ROW_COUNT)
        rows = [
            (
                f"User{i % 100}",
                f"2023-01-01 {(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}",
                f"Chat {i % 50}",
                f"Synthetic message {i:06d}",
            )
            for i in range(start, end)
        ]
        c.executemany("INSERT INTO messages VALUES (?,?,?,?)", rows)
        conn.commit()

    conn.close()
    _log(f"{os.path.basename(path)}  ({LARGE_SYNTHETIC_ROW_COUNT:,} synthetic rows)")
    return path


def create_db_missing_wal_reference():
    """
    Database created in WAL journal mode with all data checkpointed, then the
    -wal sidecar removed — simulates an incomplete evidence pull.
    """
    path = _fresh("db_missing_wal_reference.db")
    conn = sqlite3.connect(path)
    c = conn.cursor()

    c.execute("PRAGMA journal_mode=WAL")
    c.execute("""
        CREATE TABLE messages (
            sender    TEXT,
            timestamp TEXT,
            chat      TEXT,
            content   TEXT
        )
    """)
    c.executemany("INSERT INTO messages VALUES (?,?,?,?)", [
        ("Alice", "2024-07-01 08:00:00", "Evidence Chat", "Checkpointed only"),
    ])
    conn.commit()
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.commit()

    mode = c.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()

    for suffix in ("-wal", "-shm"):
        sidecar = path + suffix
        if os.path.exists(sidecar):
            os.remove(sidecar)

    _log(
        f"{os.path.basename(path)}  "
        f"(journal_mode={mode}, no -wal sidecar)"
    )
    return path


def create_known_content_file():
    path = os.path.join(FIXTURES_DIR, "known_content.txt")
    if os.path.exists(path):
        os.remove(path)
    with open(path, "wb") as f:
        f.write(KNOWN_CONTENT_BYTES)
    _log(f"known_content.txt  (SHA-256: {KNOWN_CONTENT_SHA256})")
    return path


def create_empty_file():
    path = os.path.join(FIXTURES_DIR, "empty_file.txt")
    if os.path.exists(path):
        os.remove(path)
    open(path, "wb").close()
    _log(f"empty_file.txt  (0 bytes, SHA-256: {EMPTY_FILE_SHA256[:16]}...)")
    return path


def main():
    print("Creating test fixtures...\n")
    create_simple_messages()
    create_real_schema()
    create_many_messages()
    create_db_with_wal()
    create_corrupted()
    create_empty_db()
    create_valid_empty()
    create_large_synthetic()
    create_db_missing_wal_reference()
    create_known_content_file()
    create_empty_file()
    print(f"\nAll fixtures written to: {FIXTURES_DIR}")


if __name__ == "__main__":
    main()
