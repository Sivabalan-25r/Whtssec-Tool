import sys
import os
import time
import hashlib
import sqlite3
import subprocess
import tarfile
import shutil
import mimetypes
import csv
import json
import math
# pyrefly: ignore [missing-import]
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QStackedWidget, QLabel, QTableWidget, QTableWidgetItem,
    QLineEdit, QTextEdit, QProgressBar, QTabWidget, QGridLayout, QFormLayout,
    QRadioButton, QButtonGroup, QCheckBox, QHeaderView, QFileDialog, QScrollArea, QFrame
)
# pyrefly: ignore [missing-import]
from PySide6.QtCore import Qt, QThread, Signal, Slot
# pyrefly: ignore [missing-import]
from PySide6.QtGui import QFont, QColor, QPixmap

# ==============================================================================
# 1. DEVICE COMMUNICATION LAYER (THREADED WATCHER)
# ==============================================================================
class DeviceWatcher(QThread):
    """
    Polls 'adb devices' in a background loop to detect connection
    and authorization status without blocking the PySide6 UI thread.
    """
    status_changed = Signal(str, str)  # Emits (status_type, device_id)

    def __init__(self, adb_path="adb"):
        super().__init__()
        self.adb_path = adb_path
        self._is_running = True

    def run(self):
        while self._is_running:
            status, device_id = self.check_adb_status()
            self.status_changed.emit(status, device_id)
            
            # If an authorized device is connected, stop polling loop
            if status == "authorized":
                break
            time.sleep(2)

    def check_adb_status(self):
        try:
            result = subprocess.run(
                [self.adb_path, "devices"],
                capture_output=True,
                text=True,
                timeout=15
            )
            lines = []
            device_started_section = False
            for line in result.stdout.splitlines():
                line_stripped = line.strip()
                if not line_stripped:
                    continue
                if "List of devices attached" in line_stripped:
                    device_started_section = True
                    continue
                if device_started_section:
                    lines.append(line_stripped)
            
            if not lines:
                return "no_device", ""
            
            parts = lines[0].split()
            device_id = parts[0]
            state = parts[1] if len(parts) > 1 else ""

            if state == "unauthorized":
                return "unauthorized", device_id
            elif state == "device":
                return "authorized", device_id
            return "unknown", device_id
        except Exception:
            return "no_device", ""

    def stop(self):
        self._is_running = False
        self.wait()


# ==============================================================================
# 2.0. STANDALONE FORENSIC FUNCTIONS (importable without Qt)
# ==============================================================================

def compute_sha256_standalone(filepath):
    """Compute SHA-256 hash of a file. Pure function, no Qt dependency."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def parse_database_standalone(db_path, log_fn=None, progress_fn=None, cancel_fn=None):
    """
    Parse a WhatsApp msgstore.db file and return (messages, total_records, wal_recovery).

    This is the same logic used by ExtractionWorker.parse_database(), extracted so it
    can be called independently from the test harness or any non-Qt context.

    Parameters:
        db_path:      Path to the msgstore.db file
        log_fn:       Optional callable(str) for log messages (defaults to no-op)
        progress_fn:  Optional callable(current, total, msg) for progress updates
        cancel_fn:    Optional callable() -> bool, returns True to abort early
    Returns:
        (messages, total_records, wal_recovery) where wal_recovery is a dict
    """
    if log_fn is None:
        log_fn = lambda msg: None
    if progress_fn is None:
        progress_fn = lambda cur, tot, msg: None
    if cancel_fn is None:
        cancel_fn = lambda: False

    messages = []
    total_records = 0
    checkpointed_tuples = set()
    checkpointed_loaded = False
    wal_recovery = {"wal_present": False, "wal_hash": None, "recovered_message_count": 0}

    if not os.path.exists(db_path) or os.path.getsize(db_path) == 0:
        raise RuntimeError("Extracted database file is empty or unreadable")

    # Check for encrypted .crypt14 / .crypt15 files
    try:
        with open(db_path, "rb") as f:
            header = f.read(16)
        is_sqlite = header.startswith(b"SQLite format 3\x00")
        if not is_sqlite:
            filename_lower = os.path.basename(db_path).lower()
            if "crypt" in filename_lower or header.startswith(b"Crypt") or header.startswith(b"\x00\x00\x00\x00"):
                log_fn("[WARNING] Database is encrypted (crypt14/15) — decryption key not provided. Skipping analysis of this file. To analyze encrypted backups, a decryption key extracted from a rooted device is required.")
                return messages, total_records, wal_recovery
    except Exception:
        pass

    def parse_db_file(file_path):
        t_set = set()
        try:
            conn_temp = sqlite3.connect(f"file:{file_path}?mode=ro", uri=True)
            cursor_temp = conn_temp.cursor()

            cursor_temp.execute("SELECT name FROM sqlite_master WHERE type='table'")
            temp_tables = [row[0] for row in cursor_temp.fetchall()]

            if "messages" in temp_tables:
                cursor_temp.execute("SELECT sender, timestamp, content FROM messages")
                while True:
                    rows = cursor_temp.fetchmany(500)
                    if not rows:
                        break
                    for r in rows:
                        sender = r[0]
                        timestamp_str = str(r[1])
                        content_str = r[2] if r[2] else "[Media]"
                        t_set.add((sender, timestamp_str, content_str))
            elif "message" in temp_tables:
                cursor_temp.execute("PRAGMA table_info(message)")
                msg_cols = [r[1] for r in cursor_temp.fetchall()]

                text_col = "data" if "data" in msg_cols else ("text_data" if "text_data" in msg_cols else None)
                if not text_col:
                    text_col = msg_cols[0]

                time_col = "timestamp" if "timestamp" in msg_cols else ("received_timestamp" if "received_timestamp" in msg_cols else msg_cols[0])

                select_parts = [
                    "m.from_me AS from_me",
                    f"m.{time_col} AS msg_time",
                    f"m.{text_col} AS msg_content"
                ]
                joins = []

                if "chat" in temp_tables:
                    cursor_temp.execute("PRAGMA table_info(chat)")
                    chat_cols = [r[1] for r in cursor_temp.fetchall()]
                    chat_subject = "subject" if "subject" in chat_cols else ("key_remote_jid" if "key_remote_jid" in chat_cols else chat_cols[0])

                    if "chat_row_id" in msg_cols and "_id" in chat_cols:
                        joins.append("LEFT JOIN chat c ON m.chat_row_id = c._id")
                        select_parts.append(f"c.{chat_subject} AS chat_name")
                    elif "key_remote_jid" in msg_cols and "jid" in chat_cols:
                        joins.append("LEFT JOIN chat c ON m.key_remote_jid = c.jid")
                        select_parts.append(f"c.{chat_subject} AS chat_name")
                    else:
                        select_parts.append("NULL AS chat_name")
                else:
                    select_parts.append("NULL AS chat_name")

                if "jid" in temp_tables:
                    cursor_temp.execute("PRAGMA table_info(jid)")
                    jid_cols = [r[1] for r in cursor_temp.fetchall()]

                    if "sender_jid_row_id" in msg_cols and "_id" in jid_cols:
                        joins.append("LEFT JOIN jid j_sender ON m.sender_jid_row_id = j_sender._id")
                        select_parts.append("j_sender.raw_string AS sender_jid")
                    else:
                        select_parts.append("NULL AS sender_jid")
                else:
                    select_parts.append("NULL AS sender_jid")

                query = f"SELECT {', '.join(select_parts)} FROM message m " + " ".join(joins)
                cursor_temp.execute(query)

                while True:
                    rows = cursor_temp.fetchmany(500)
                    if not rows:
                        break
                    for r in rows:
                        from_me = r[0]
                        raw_time = r[1]
                        content = r[2]
                        chat_name = r[3]
                        sender_jid = r[4]

                        try:
                            t_sec = float(raw_time) / 1000.0
                            timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t_sec))
                        except Exception:
                            timestamp_str = str(raw_time)

                        if from_me == 1:
                            sender = "Me"
                        else:
                            sender = sender_jid if sender_jid else (chat_name if chat_name else "Unknown Contact")

                        content_str = content if content else "[Media]"
                        t_set.add((sender, timestamp_str, content_str))
            conn_temp.close()
        except Exception:
            pass
        return t_set

    # Detect WAL file and log its presence with size and hash
    wal_path = db_path + "-wal"
    if os.path.exists(wal_path):
        wal_size = os.path.getsize(wal_path)
        wal_hash = compute_sha256_standalone(wal_path)
        log_fn(f"[INFO] WAL file detected ({wal_size} bytes) — connecting will include uncommitted/recoverable data")
        wal_recovery = {
            "wal_present": True,
            "wal_hash": wal_hash,
            "recovered_message_count": 0
        }

        # Create a temporary copy of the DB without the WAL file to isolate checkpointed data
        db_temp_path = db_path + ".checkpointed"
        try:
            shutil.copy2(db_path, db_temp_path)
            checkpointed_tuples = parse_db_file(db_temp_path)
            checkpointed_loaded = True
        except Exception as e:
            log_fn(f"[NOTICE] Failed to parse checkpointed base database snapshot: {str(e)}")
        finally:
            if os.path.exists(db_temp_path):
                try:
                    os.remove(db_temp_path)
                except Exception:
                    pass
    else:
        log_fn("[INFO] No WAL file found — database appears fully checkpointed")

    try:
        # Connect in read-only mode using uri=True
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()

        # Query available tables to detect schema type (real vs mock)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        if "messages" not in tables and "message" not in tables:
            raise RuntimeError("The extracted database appears corrupted or incomplete — table 'message' not found")

        # Determine table type and build query dynamically
        if "messages" in tables:
            # Custom/Mock schema
            cursor.execute("SELECT COUNT(*) FROM messages")
            total_records = cursor.fetchone()[0]

            cursor.execute("SELECT sender, timestamp, chat, content FROM messages")

            batch_size = 500
            while not cancel_fn():
                rows = cursor.fetchmany(batch_size)
                if not rows:
                    break

                for row in rows:
                    sender = row[0]
                    timestamp_str = str(row[1])
                    chat = row[2]
                    content_str = row[3] if row[3] else "[Media]"

                    # Identify if recovered via WAL
                    recovered = False
                    if wal_recovery["wal_present"] and checkpointed_loaded:
                        if (sender, timestamp_str, content_str) not in checkpointed_tuples:
                            recovered = True
                            wal_recovery["recovered_message_count"] += 1

                    messages.append({
                        "sender": sender,
                        "timestamp": timestamp_str,
                        "chat": chat,
                        "content": content_str,
                        "recovered": recovered
                    })

                progress_fn(len(messages), total_records, f"Parsed {len(messages)}/{total_records} records")
                time.sleep(0.01)

        elif "message" in tables:
            # Real WhatsApp database schema
            cursor.execute("PRAGMA table_info(message)")
            msg_cols = [r[1] for r in cursor.fetchall()]

            # Check for standard fields
            text_col = "data" if "data" in msg_cols else ("text_data" if "text_data" in msg_cols else None)
            if not text_col:
                text_col = msg_cols[0]

            time_col = "timestamp" if "timestamp" in msg_cols else ("received_timestamp" if "received_timestamp" in msg_cols else msg_cols[0])

            # Query count
            cursor.execute("SELECT COUNT(*) FROM message")
            total_records = cursor.fetchone()[0]

            # Reconstruct query dynamically based on database version
            select_parts = [
                "m.from_me AS from_me",
                f"m.{time_col} AS msg_time",
                f"m.{text_col} AS msg_content"
            ]
            joins = []

            if "chat" in tables:
                cursor.execute("PRAGMA table_info(chat)")
                chat_cols = [r[1] for r in cursor.fetchall()]
                chat_subject = "subject" if "subject" in chat_cols else ("key_remote_jid" if "key_remote_jid" in chat_cols else chat_cols[0])

                if "chat_row_id" in msg_cols and "_id" in chat_cols:
                    joins.append("LEFT JOIN chat c ON m.chat_row_id = c._id")
                    select_parts.append(f"c.{chat_subject} AS chat_name")
                elif "key_remote_jid" in msg_cols and "jid" in chat_cols:
                    joins.append("LEFT JOIN chat c ON m.key_remote_jid = c.jid")
                    select_parts.append(f"c.{chat_subject} AS chat_name")
                else:
                    select_parts.append("NULL AS chat_name")
            else:
                select_parts.append("NULL AS chat_name")

            if "jid" in tables:
                cursor.execute("PRAGMA table_info(jid)")
                jid_cols = [r[1] for r in cursor.fetchall()]

                if "sender_jid_row_id" in msg_cols and "_id" in jid_cols:
                    joins.append("LEFT JOIN jid j_sender ON m.sender_jid_row_id = j_sender._id")
                    select_parts.append("j_sender.raw_string AS sender_jid")
                else:
                    select_parts.append("NULL AS sender_jid")
            else:
                select_parts.append("NULL AS sender_jid")

            # Build full query string
            query = f"SELECT {', '.join(select_parts)} FROM message m " + " ".join(joins)
            cursor.execute(query)

            batch_size = 500
            while not cancel_fn():
                rows = cursor.fetchmany(batch_size)
                if not rows:
                    break

                for row in rows:
                    from_me = row[0]
                    raw_time = row[1]
                    content = row[2]
                    chat_name = row[3]
                    sender_jid = row[4]

                    # Format timestamp (WhatsApp timestamp is in milliseconds unix epoch)
                    try:
                        t_sec = float(raw_time) / 1000.0
                        timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t_sec))
                    except Exception:
                        timestamp_str = str(raw_time)

                    # Determine sender name / JID
                    if from_me == 1:
                        sender = "Me"
                    else:
                        sender = sender_jid if sender_jid else (chat_name if chat_name else "Unknown Contact")

                    # Determine chat target
                    chat = chat_name if chat_name else (sender_jid if sender_jid else "Direct Chat")

                    # Clean null / media messages
                    content_str = content if content else "[Media]"

                    # Identify if recovered via WAL
                    recovered = False
                    if wal_recovery["wal_present"] and checkpointed_loaded:
                        if (sender, timestamp_str, content_str) not in checkpointed_tuples:
                            recovered = True
                            wal_recovery["recovered_message_count"] += 1

                    messages.append({
                        "sender": sender,
                        "timestamp": timestamp_str,
                        "chat": chat,
                        "content": content_str,
                        "recovered": recovered
                    })

                progress_fn(len(messages), total_records, f"Parsed {len(messages)}/{total_records} records")
                time.sleep(0.01)

        conn.close()

    except sqlite3.OperationalError as op_err:
        err_text = str(op_err)
        if "no such table" in err_text.lower() or "table" in err_text.lower():
            tbl = err_text.split(":")[-1].strip() if ":" in err_text else "message"
            raise RuntimeError(f"The extracted database appears corrupted or incomplete — table '{tbl}' not found")
        raise RuntimeError(f"The extracted database appears corrupted or incomplete — {err_text}")
    except sqlite3.DatabaseError as db_err:
        raise RuntimeError(f"The extracted database appears corrupted or incomplete — invalid SQLite database header or structure ({str(db_err)})")
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"Database parsing failed: {str(e)}")

    return messages, total_records, wal_recovery


# ==============================================================================
# 2. EXTRACTION & INGESTION LAYER (BACKGROUND WORKER)
# ==============================================================================
class ExtractionWorker(QThread):
    """
    Handles ADB data acquisition, forensic SHA-256 file hashing,
    SQLite database ingestion, and log updates off the UI thread.
    """
    progress = Signal(int, int, str)  # (current_count, total_count, status_message)
    log = Signal(str)                  # (log_message)
    finished = Signal(dict)            # (parsed_case_data_dictionary)
    error = Signal(str)                 # (error_message)

    def __init__(self, case_info, adb_path="adb", abe_path="./tools/abe.jar"):
        super().__init__()
        self.case_info = case_info
        self.adb_path = adb_path
        self.abe_path = abe_path
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        try:
            self.log.emit("[INFO] Starting forensic extraction pipeline...")
            out_dir = self.case_info.get("output_dir", "./cases/default")
            os.makedirs(out_dir, exist_ok=True)
            
            self.log.emit(f"[INFO] Target output directory verified: {out_dir}")
            time.sleep(0.5)
            
            if self._is_cancelled:
                return

            # Step 0: Query device metadata FIRST (before extraction)
            device_id = self.case_info.get("device_id", "")
            manual_db_path = self.case_info.get("manual_db_path", "")
            
            if device_id and device_id != "MANUAL_IMPORT":
                self.log.emit("[INFO] Querying connected device specifications...")
                device_info = self.get_device_info(device_id, out_dir)
                self.log.emit("─" * 50)
                self.log.emit("[DEVICE] Connected Device Details:")
                for key, val in device_info.items():
                    if key not in ("Extraction Method", "Acquisition Time", "Output Directory", "Backup File Size"):
                        self.log.emit(f"  • {key}: {val}")
                self.log.emit("─" * 50)
            else:
                device_info = self.get_device_info(device_id, out_dir)

            if self._is_cancelled:
                return

            db_path = os.path.join(out_dir, "msgstore.db")
            wal_path = os.path.join(out_dir, "msgstore.db-wal")
            
            # Step 1: Database Acquisition
            self.extraction_method = "Unknown"

            if manual_db_path and os.path.exists(manual_db_path):
                # Manual import: copy user-selected file directly
                self.log.emit(f"[INFO] Loading manually provided database: {os.path.basename(manual_db_path)}")
                shutil.copy2(manual_db_path, db_path)
                # Check for a WAL file alongside the manual DB
                manual_wal = manual_db_path + "-wal"
                if os.path.exists(manual_wal):
                    shutil.copy2(manual_wal, wal_path)
                    self.log.emit("[INFO] WAL file found alongside database — included in analysis.")
                else:
                    with open(wal_path, "w") as f:
                        f.write("")
                self.extraction_method = f"Manual Import ({os.path.basename(manual_db_path)})"
                self.log.emit("[SUCCESS] Manual database import complete.")
            else:
                self.log.emit("[INFO] Attempting physical/backup acquisition via ADB...")
                self.extract_database(db_path, wal_path)
            
            # Step 2: Forensic Hashing Phase (SHA-256)
            self.log.emit("[INFO] Calculating cryptographic SHA-256 hashes for evidence verification...")
            hashes = []
            files_to_hash = [db_path, wal_path]
            
            for index, fpath in enumerate(files_to_hash):
                if self._is_cancelled:
                    return
                if os.path.exists(fpath):
                    sha256_hash = self.compute_sha256(fpath)
                    filename = os.path.basename(fpath)
                    hashes.append({"file": filename, "hash": sha256_hash, "status": "VERIFIED"})
                    self.log.emit(f"[HASH] {filename}: {sha256_hash}")
                
            # Step 3: Ingestion & Batch Database Parsing Phase
            self.log.emit("[INFO] Ingesting message store and detecting WAL log integrity...")
            messages, total_records = self.parse_database(db_path)
            
            if self._is_cancelled:
                self.log.emit("[WARNING] Extraction process cancelled by investigator.")
                return

            self.log.emit("[SUCCESS] Database parsing and timeline synchronization complete.")
            
            # Step 3.5: Media Scanning Phase
            media_dir = os.path.join(out_dir, "WhatsApp", "Media")
            self.log.emit("[INFO] Initiating media storage scanning...")
            media_data = self.scan_media(media_dir, db_path)
            
            if self._is_cancelled:
                self.log.emit("[WARNING] Extraction process cancelled by investigator.")
                return

            # Update device info with extraction method
            device_info["Extraction Method"] = getattr(self, "extraction_method", "Unknown")

            # Step 4.5: Construct real chronological timeline
            self.log.emit("[INFO] Constructing chronological forensic timeline...")
            wal_recovery_data = getattr(self, "wal_recovery", {"wal_present": False, "wal_hash": None, "recovered_message_count": 0})
            acquisition_time = device_info.get("Acquisition Time", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
            timeline_data = self.build_timeline(messages, media_data, wal_recovery_data, acquisition_time)

            if self._is_cancelled:
                self.log.emit("[WARNING] Extraction process cancelled by investigator.")
                return

            # Step 5: Construct Result Data Payload
            results = {
                "case_info": self.case_info,
                "device_info": device_info,
                "hashes": hashes,
                "messages": messages,
                "media": media_data,
                "wal_recovery": wal_recovery_data,
                "timeline": timeline_data
            }
            
            self.finished.emit(results)

        except Exception as e:
            err_msg = str(e)
            if "Could not extract WhatsApp data" in err_msg:
                self.log.emit("[NOTICE] No WhatsApp backup data is available on this mobile device, or backup permission was denied by the user/system.")
                self.log.emit("[TIP] You can use 'Load DB/Backup Manually' on the Evidence Ingestion page to import a database file directly.")
            self.error.emit(err_msg)

    def compute_sha256(self, filepath):
        return compute_sha256_standalone(filepath)

    def get_device_info(self, device_id, out_dir):
        """
        Queries real device properties via ADB and returns a metadata dict.
        Falls back to 'Unknown' for any property that fails to retrieve.
        """
        props = {
            "Model": "ro.product.model",
            "Manufacturer": "ro.product.manufacturer",
            "Brand": "ro.product.brand",
            "Android Version": "ro.build.version.release",
            "API Level": "ro.build.version.sdk",
            "Serial Number": "ro.serialno",
            "Network Operator": "gsm.operator.alpha",
            "SIM Operator": "gsm.sim.operator.alpha",
            "Build Fingerprint": "ro.build.fingerprint",
            "Device Name": "ro.product.device",
        }

        info = {}
        for label, prop_key in props.items():
            try:
                cmd = [self.adb_path]
                if device_id:
                    cmd += ["-s", device_id]
                cmd += ["shell", "getprop", prop_key]

                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                value = res.stdout.strip()

                if res.returncode != 0 or not value:
                    raise ValueError("Empty or failed response")

                info[label] = value
            except Exception:
                info[label] = "Unknown"
                self.log.emit(f"[WARNING] Could not retrieve {label} from device")

        # Use device_id as Serial Number fallback if getprop returned Unknown
        if info.get("Serial Number") == "Unknown" and device_id:
            info["Serial Number"] = device_id

        # Extraction method from extract_database
        info["Extraction Method"] = getattr(self, "extraction_method", "Unknown")

        # Acquisition timestamp
        info["Acquisition Time"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        # Output directory
        info["Output Directory"] = out_dir

        # Backup file size
        backup_ab = os.path.join(out_dir, "whatsapp_backup.ab")
        if os.path.exists(backup_ab):
            size_bytes = os.path.getsize(backup_ab)
            if size_bytes >= 1024 * 1024:
                info["Backup File Size"] = f"{size_bytes / (1024 * 1024):.2f} MB"
            elif size_bytes >= 1024:
                info["Backup File Size"] = f"{size_bytes / 1024:.2f} KB"
            else:
                info["Backup File Size"] = f"{size_bytes} bytes"
        else:
            info["Backup File Size"] = "N/A (backup file cleaned up or not created)"

        return info

    def scan_media(self, media_dir, db_path):
        """
        Recursively walks media_dir to collect media metadata, generate thumbnails for images,
        and links them back to database messages using message_media mappings.
        """
        media_list = []
        if not os.path.exists(media_dir):
            self.log.emit("[INFO] No media folder found — skipping media scan")
            return media_list

        # 1. Query message_media mapping from database if available
        media_mapping = {}
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='message_media'")
            if cursor.fetchone():
                cursor.execute("PRAGMA table_info(message_media)")
                cols = [r[1] for r in cursor.fetchall()]
                
                file_path_col = "file_path" if "file_path" in cols else ("local_path" if "local_path" in cols else ("file_name" if "file_name" in cols else None))
                msg_id_col = "message_row_id" if "message_row_id" in cols else ("message_id" if "message_id" in cols else None)
                
                if file_path_col and msg_id_col:
                    cursor.execute(f"SELECT {file_path_col}, {msg_id_col} FROM message_media")
                    rows = cursor.fetchall()
                    for path_val, msg_id in rows:
                        if path_val and msg_id:
                            fn = os.path.basename(str(path_val))
                            media_mapping[fn] = msg_id
            conn.close()
        except Exception as e:
            self.log.emit(f"[NOTICE] Failed to retrieve message_media mapping from database: {str(e)}")

        # 2. Collect all files in media_dir
        all_files = []
        for root, dirs, files in os.walk(media_dir):
            for file in files:
                all_files.append(os.path.join(root, file))

        total_files = len(all_files)
        self.log.emit(f"[INFO] Found {total_files} media files to process.")

        # Extensions categorizations
        img_exts = {'.jpg', '.jpeg', '.png', '.webp', '.gif'}
        vid_exts = {'.mp4', '.3gp', '.mkv', '.avi', '.mov'}
        audio_exts = {'.opus', '.m4a', '.mp3', '.wav', '.amr', '.ogg'}

        # 3. Batch processing of files
        batch_size = 50
        image_count = 0

        for i in range(0, total_files, batch_size):
            if self._is_cancelled:
                break
            
            batch = all_files[i:i+batch_size]
            for filepath in batch:
                if self._is_cancelled:
                    break

                try:
                    filename = os.path.basename(filepath)
                    file_size = os.path.getsize(filepath)
                    
                    # File type based on extension
                    _, ext = os.path.splitext(filename.lower())
                    if ext in img_exts:
                        file_type = "image"
                    elif ext in vid_exts:
                        file_type = "video"
                    elif ext in audio_exts:
                        file_type = "voice_note"
                    else:
                        file_type = "document"

                    # Calculate SHA-256 hash using existing compute_sha256
                    file_hash = self.compute_sha256(filepath)

                    # Initialize EXIF/metadata dictionary
                    exif_dict = {}
                    thumbnail_path = None

                    # Always capture basic filesystem parameters (size and timestamps)
                    mtime = os.path.getmtime(filepath)
                    exif_dict["modified_time"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))

                    if file_type == "image":
                        image_count += 1
                        # EXIF extraction
                        try:
                            from PIL import Image
                            from PIL.ExifTags import TAGS, GPSTAGS
                            
                            with Image.open(filepath) as img:
                                raw_exif = img._getexif()
                                if raw_exif:
                                    gps_info = {}
                                    for tag_id, val in raw_exif.items():
                                        tag = TAGS.get(tag_id, tag_id)
                                        if tag in ["DateTime", "DateTimeOriginal", "DateTimeDigitized"]:
                                            exif_dict["datetime"] = str(val)
                                        elif tag in ["Model", "Make"]:
                                            exif_dict[tag.lower()] = str(val)
                                        elif tag == "GPSInfo":
                                            for g_id, g_val in val.items():
                                                g_tag = GPSTAGS.get(g_id, g_id)
                                                gps_info[g_tag] = g_val
                                    
                                    # Process GPSInfo if complete
                                    gps_latitude = gps_info.get("GPSLatitude")
                                    gps_latitude_ref = gps_info.get("GPSLatitudeRef")
                                    gps_longitude = gps_info.get("GPSLongitude")
                                    gps_longitude_ref = gps_info.get("GPSLongitudeRef")
                                    
                                    if gps_latitude and gps_longitude and gps_latitude_ref and gps_longitude_ref:
                                        def to_decimal(dms):
                                            try:
                                                d = float(dms[0])
                                                m = float(dms[1])
                                                s = float(dms[2])
                                                return d + (m / 60.0) + (s / 3600.0)
                                            except Exception:
                                                return str(dms)
                                        
                                        lat = to_decimal(gps_latitude)
                                        lon = to_decimal(gps_longitude)
                                        if gps_latitude_ref == 'S':
                                            lat = -lat
                                        if gps_longitude_ref == 'W':
                                            lon = -lon
                                        exif_dict["gps"] = {"latitude": lat, "longitude": lon}
                        except Exception:
                            # Expected if no EXIF
                            pass

                        # Pre-generate thumbnail for only first ~50 images (under 50MB)
                        if image_count <= 50 and file_size <= 50 * 1024 * 1024:
                            try:
                                from PIL import Image
                                out_dir = os.path.dirname(os.path.dirname(media_dir))
                                thumb_dir = os.path.join(out_dir, "thumbnails")
                                os.makedirs(thumb_dir, exist_ok=True)
                                
                                thumb_name = f"thumb_{file_hash}.png"
                                thumb_full_path = os.path.join(thumb_dir, thumb_name)
                                
                                if not os.path.exists(thumb_full_path):
                                    with Image.open(filepath) as img:
                                        img.thumbnail((150, 150))
                                        img.save(thumb_full_path, "PNG")
                                thumbnail_path = thumb_full_path
                            except Exception:
                                pass

                    # EXIF/metadata for non-images
                    if file_type != "image":
                        mime_type, _ = mimetypes.guess_type(filepath)
                        ctime = os.path.getctime(filepath)
                        
                        exif_dict["file_size"] = file_size
                        exif_dict["mime_type"] = mime_type or "application/octet-stream"
                        exif_dict["creation_time"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ctime))

                    # Link media to messages
                    linked_message = media_mapping.get(filename, None)

                    media_list.append({
                        "filename": filename,
                        "filepath": filepath,
                        "file_type": file_type,
                        "hash": file_hash,
                        "size_bytes": file_size,
                        "thumbnail_path": thumbnail_path,
                        "exif": exif_dict,
                        "linked_message": linked_message
                    })

                except Exception as e:
                    self.log.emit(f"[WARNING] Failed to process media file {filename}: {str(e)}")

            # Emit progress signal
            processed_count = min(i + batch_size, total_files)
            self.progress.emit(processed_count, total_files, f"Scanned {processed_count}/{total_files} media files")
            time.sleep(0.01)

        return media_list

    def build_timeline(self, messages, media_items, wal_recovery, acquisition_time):
        """
        Merges messages, media items, and WAL recovery events into a single
        chronologically sorted timeline.
        """
        timeline_entries = []

        def normalize_time_str(t_str):
            if not t_str:
                return None
            t_str = str(t_str).strip()
            # If it uses YYYY:MM:DD HH:MM:SS (EXIF format), replace the first two colons with hyphens
            if len(t_str) >= 19 and t_str[4] == ':' and t_str[7] == ':':
                t_str = t_str[:4] + '-' + t_str[5:7] + '-' + t_str[8:]
            try:
                # Validate the date format structure (YYYY-MM-DD HH:MM:SS)
                time.strptime(t_str[:19], '%Y-%m-%d %H:%M:%S')
                return t_str[:19]
            except Exception:
                return None

        # 1. Add Message entries
        for msg in messages:
            msg_time = msg.get("timestamp")
            norm_time = normalize_time_str(msg_time)
            detail = f"{msg.get('sender')}: {msg.get('content', '')}"
            # Truncate content to ~50 characters
            if len(detail) > 50:
                detail = detail[:47] + "..."

            if norm_time:
                msg_type = "MESSAGE (RECOVERED)" if msg.get("recovered") else "MESSAGE"
                timeline_entries.append({
                    "time": norm_time,
                    "type": msg_type,
                    "detail": detail
                })
            else:
                self.log.emit(f"[WARNING] Skipped timeline entry with unparseable timestamp: {detail}")

        # 2. Add Media entries
        for item in media_items:
            filename = item.get("filename", "Unknown File")
            exif = item.get("exif") or {}
            
            # EXIF Capture Time entry
            exif_time = exif.get("datetime")
            if exif_time:
                norm_exif_time = normalize_time_str(exif_time)
                if norm_exif_time:
                    timeline_entries.append({
                        "time": norm_exif_time,
                        "type": "MEDIA_CAPTURED",
                        "detail": f"{filename} captured"
                    })
                else:
                    self.log.emit(f"[WARNING] Skipped timeline entry with unparseable timestamp: {filename} captured ({exif_time})")
            
            # Filesystem Modified Time entry
            mod_time = exif.get("modified_time")
            if mod_time:
                norm_mod_time = normalize_time_str(mod_time)
                if norm_mod_time:
                    timeline_entries.append({
                        "time": norm_mod_time,
                        "type": "MEDIA_RECEIVED",
                        "detail": f"{filename} received on device"
                    })
                else:
                    self.log.emit(f"[WARNING] Skipped timeline entry with unparseable timestamp: {filename} received ({mod_time})")

        # 3. Add WAL recovery summary entry
        if wal_recovery and wal_recovery.get("wal_present"):
            # Strip UTC suffix for normalization if present
            norm_acq_time = normalize_time_str(acquisition_time)
            if norm_acq_time:
                recovered_count = wal_recovery.get("recovered_message_count", 0)
                timeline_entries.append({
                    "time": norm_acq_time,
                    "type": "SYSTEM",
                    "detail": f"WAL file merged — {recovered_count} recoverable message(s) included"
                })
            else:
                self.log.emit(f"[WARNING] Skipped timeline entry with unparseable timestamp: WAL file merged summary ({acquisition_time})")

        # 4. Sort chronologically by the normalized 'time' string
        try:
            timeline_entries.sort(key=lambda x: x["time"])
        except Exception as sort_err:
            self.log.emit(f"[WARNING] Timeline sorting failed: {str(sort_err)}")

        return timeline_entries

    def check_root_access(self, adb_path, device_id):
        """
        Checks whether su/root access is available on the connected Android device.
        Catches all exceptions and returns False on failure/denial.
        """
        try:
            cmd = [adb_path]
            if device_id:
                cmd += ["-s", device_id]
            cmd += ["shell", "su", "-c", "id"]

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if "device not found" in res.stderr.lower() or "device offline" in res.stderr.lower():
                raise RuntimeError("Device disconnected during extraction — please reconnect and retry")
            if res.returncode == 0 and "uid=0" in res.stdout:
                return True

            # Fallback check for alternate su syntax (e.g. su 0 id)
            cmd_alt = [adb_path]
            if device_id:
                cmd_alt += ["-s", device_id]
            cmd_alt += ["shell", "su", "0", "id"]

            res_alt = subprocess.run(cmd_alt, capture_output=True, text=True, timeout=5)
            if res_alt.returncode == 0 and "uid=0" in res_alt.stdout:
                return True
        except FileNotFoundError:
            raise RuntimeError(f"ADB executable not found at '{adb_path}' — check the path in Settings")
        except RuntimeError:
            raise
        except Exception:
            pass

        return False

    def pull_via_root(self, adb_path, device_id, db_path, wal_path):
        """
        Pulls WhatsApp database directly from /data/data/com.whatsapp/databases/ using root su.
        Uses a two-step copy to /sdcard/ before pulling to host to bypass Android sandboxing.
        """
        self.log.emit("[INFO] Root access confirmed — attempting direct pull from /data/data/com.whatsapp/databases/...")

        temp_db = "/sdcard/msgstore_temp.db"
        temp_wal = "/sdcard/msgstore_wal_temp.db"

        try:
            base_adb = [adb_path]
            if device_id:
                base_adb += ["-s", device_id]

            # 1. Copy msgstore.db to /sdcard/ via root su
            cp_db_cmd = base_adb + ["shell", "su", "-c", f"cp /data/data/com.whatsapp/databases/msgstore.db {temp_db}"]
            res_cp_db = subprocess.run(cp_db_cmd, capture_output=True, text=True, timeout=30)
            if "device not found" in res_cp_db.stderr.lower() or "device offline" in res_cp_db.stderr.lower():
                raise RuntimeError("Device disconnected during extraction — please reconnect and retry")
            if res_cp_db.returncode != 0:
                self.log.emit(f"[ERROR] Direct pull failed: Could not copy msgstore.db via root (exit code {res_cp_db.returncode})")
                return False

            # 2. Check if WAL exists and copy if present
            check_wal_cmd = base_adb + ["shell", "su", "-c", "test -f /data/data/com.whatsapp/databases/msgstore.db-wal && echo EXISTS"]
            res_check_wal = subprocess.run(check_wal_cmd, capture_output=True, text=True, timeout=5)
            
            wal_exists = "EXISTS" in res_check_wal.stdout
            if wal_exists:
                cp_wal_cmd = base_adb + ["shell", "su", "-c", f"cp /data/data/com.whatsapp/databases/msgstore.db-wal {temp_wal}"]
                subprocess.run(cp_wal_cmd, capture_output=True, text=True, timeout=30)

            # 3. Pull temporary files from SDCard to host
            pull_db_cmd = base_adb + ["pull", temp_db, db_path]
            res_pull_db = subprocess.run(pull_db_cmd, capture_output=True, text=True, timeout=30)

            if wal_exists:
                pull_wal_cmd = base_adb + ["pull", temp_wal, wal_path]
                subprocess.run(pull_wal_cmd, capture_output=True, text=True, timeout=30)
            else:
                if not os.path.exists(wal_path):
                    with open(wal_path, "w") as f:
                        f.write("")

            # 4. Clean up temporary files on device
            rm_cmd = base_adb + ["shell", "su", "-c", f"rm -f {temp_db} {temp_wal}"]
            subprocess.run(rm_cmd, capture_output=True, text=True, timeout=10)

            # 5. Validation
            if os.path.exists(db_path) and os.path.getsize(db_path) > 1024:
                self.log.emit("[SUCCESS] Direct pull via root completed")
                return True
            else:
                self.log.emit("[ERROR] Direct pull failed: Pulled database file missing or too small (<= 1KB)")
                return False

        except Exception as e:
            self.log.emit(f"[ERROR] Direct pull failed: {str(e)}")
            return False

    def extract_database(self, db_path, wal_path):
        """
        Multi-tier extraction pipeline:
        Tier 1: ADB backup + ABE unpack
        Tier 2: Root direct pull (/data/data/com.whatsapp/databases/)
        Tier 3: Non-root SDCard pull (/sdcard/WhatsApp/Databases/)
        """
        out_dir = os.path.dirname(db_path)
        backup_ab = os.path.join(out_dir, "whatsapp_backup.ab")
        backup_tar = os.path.join(out_dir, "whatsapp_backup.tar")
        extract_dir = os.path.join(out_dir, "whatsapp_extracted")
        device_id = self.case_info.get("device_id", "")

        success = False

        # ----------------------------------------------------------------------
        # Tier 1: ADB Backup Extraction
        # ----------------------------------------------------------------------
        self.log.emit("[INFO] Initiating ADB backup (Tier 1)... Please authorize backup on target device if prompted.")
        try:
            cmd = [self.adb_path]
            if device_id:
                cmd += ["-s", device_id]
            cmd += ["backup", "-f", backup_ab, "com.whatsapp", "-noapk"]

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if self._is_cancelled:
                return

            if "device not found" in res.stderr.lower() or "device offline" in res.stderr.lower():
                raise RuntimeError("Device disconnected during extraction — please reconnect and retry")

            if res.returncode == 0 and os.path.exists(backup_ab) and os.path.getsize(backup_ab) > 0:
                self.log.emit("[INFO] ADB backup completed. Unpacking archive using Android Backup Extractor...")
                
                if self._is_cancelled:
                    return

                try:
                    unpack_cmd = ["java", "-jar", self.abe_path, "unpack", backup_ab, backup_tar]
                    unpack_res = subprocess.run(unpack_cmd, capture_output=True, text=True, timeout=60)
                except FileNotFoundError:
                    raise RuntimeError(f"Android Backup Extractor (abe.jar) or Java not found at '{self.abe_path}' — check the path in Settings")
                
                if self._is_cancelled:
                    return

                if unpack_res.returncode == 0 and os.path.exists(backup_tar) and os.path.getsize(backup_tar) > 0:
                    self.log.emit("[INFO] Unpacked backup to TAR. Extracting database files...")
                    os.makedirs(extract_dir, exist_ok=True)
                    with tarfile.open(backup_tar, "r:") as tar:
                        tar.extractall(path=extract_dir)

                    found_db = None
                    found_wal = None
                    for root, dirs, files in os.walk(extract_dir):
                        for file in files:
                            if file == "msgstore.db":
                                found_db = os.path.join(root, file)
                            elif file == "msgstore.db-wal":
                                found_wal = os.path.join(root, file)

                    if found_db and os.path.exists(found_db) and os.path.getsize(found_db) > 1024:
                        shutil.copy2(found_db, db_path)
                        if found_wal and os.path.exists(found_wal):
                            shutil.copy2(found_wal, wal_path)
                        else:
                            with open(wal_path, "w") as f:
                                f.write("")
                        self.log.emit("[SUCCESS] Extracted via ADB backup (Tier 1)")
                        self.extraction_method = "ADB Backup (com.whatsapp)"
                        success = True
                    else:
                        self.log.emit("[NOTICE] ADB backup extracted database is missing or invalid (<= 1KB).")
        except FileNotFoundError:
            raise RuntimeError(f"ADB executable not found at '{self.adb_path}' — check the path in Settings")
        except RuntimeError:
            raise
        except Exception as e:
            self.log.emit(f"[NOTICE] ADB backup attempt encountered an error: {str(e)}")

        if self._is_cancelled:
            return

        # ----------------------------------------------------------------------
        # Tier 2: Root Direct Pull Fallback
        # ----------------------------------------------------------------------
        if not success:
            self.log.emit("[INFO] Tier 1 ADB backup failed or returned invalid data. Checking root access (Tier 2)...")
            if self.check_root_access(self.adb_path, device_id):
                if self._is_cancelled:
                    return
                root_ok = self.pull_via_root(self.adb_path, device_id, db_path, wal_path)
                if root_ok and os.path.exists(db_path) and os.path.getsize(db_path) > 1024:
                    self.extraction_method = "Root Direct Pull (/data/data/com.whatsapp/)"
                    success = True
            else:
                self.log.emit("[NOTICE] Root access not available on target device.")

        if self._is_cancelled:
            return

        # ----------------------------------------------------------------------
        # Tier 3: Non-Root SDCard Pull Fallback
        # ----------------------------------------------------------------------
        if not success:
            self.log.emit("[INFO] Attempting non-root SDCard pull fallback (Tier 3)...")
            try:
                base_adb = [self.adb_path]
                if device_id:
                    base_adb += ["-s", device_id]

                # Try pulling primary SDCard database path
                pull_db_cmd = base_adb + ["pull", "/sdcard/WhatsApp/Databases/msgstore.db", db_path]
                res_db = subprocess.run(pull_db_cmd, capture_output=True, text=True, timeout=15)
                
                if "device not found" in res_db.stderr.lower() or "device offline" in res_db.stderr.lower():
                    raise RuntimeError("Device disconnected during extraction — please reconnect and retry")

                # Alternate location for Android 11+ scoping
                if not (res_db.returncode == 0 and os.path.exists(db_path) and os.path.getsize(db_path) > 1024):
                    pull_db_alt = base_adb + ["pull", "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db", db_path]
                    res_alt = subprocess.run(pull_db_alt, capture_output=True, text=True, timeout=15)
                    if "device not found" in res_alt.stderr.lower() or "device offline" in res_alt.stderr.lower():
                        raise RuntimeError("Device disconnected during extraction — please reconnect and retry")

                if self._is_cancelled:
                    return

                if os.path.exists(db_path) and os.path.getsize(db_path) > 1024:
                    pull_wal_cmd = base_adb + ["pull", "/sdcard/WhatsApp/Databases/msgstore.db-wal", wal_path]
                    subprocess.run(pull_wal_cmd, capture_output=True, text=True, timeout=15)
                    
                    if not os.path.exists(wal_path):
                        with open(wal_path, "w") as f:
                            f.write("")
                    
                    self.log.emit("[SUCCESS] Extracted via non-root SDCard pull (Tier 3)")
                    self.extraction_method = "Non-Root SDCard Pull (/sdcard/WhatsApp/Databases/)"
                    success = True
                else:
                    self.log.emit("[NOTICE] Non-root SDCard pull produced no valid database file.")
            except FileNotFoundError:
                raise RuntimeError(f"ADB executable not found at '{self.adb_path}' — check the path in Settings")
            except RuntimeError:
                raise
            except Exception as e:
                self.log.emit(f"[NOTICE] Direct pull attempt encountered an error: {str(e)}")

        # ----------------------------------------------------------------------
        # Cleanup temporary extraction artifacts
        # ----------------------------------------------------------------------
        try:
            if os.path.exists(backup_ab):
                os.remove(backup_ab)
            if os.path.exists(backup_tar):
                os.remove(backup_tar)
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
        except Exception:
            pass

        if self._is_cancelled:
            return

        if not success:
            raise RuntimeError("Could not extract WhatsApp data: backup denied and no root/file access available")

    def parse_database(self, db_path):
        """
        Thin wrapper around parse_database_standalone that bridges Qt signals
        (self.log, self.progress, self._is_cancelled) into the standalone function's
        callback interface. Keeps all existing public behavior/signals unchanged.
        """
        messages, total_records, wal_recovery = parse_database_standalone(
            db_path,
            log_fn=lambda msg: self.log.emit(msg),
            progress_fn=lambda cur, tot, msg: self.progress.emit(cur, tot, msg),
            cancel_fn=lambda: self._is_cancelled
        )
        self.wal_recovery = wal_recovery
        return messages, total_records


# ==============================================================================
# 2.4. CONFIGURATION & SETTINGS MANAGER
# ==============================================================================
class SettingsManager:
    @staticmethod
    def get_settings_path():
        config_dir = os.path.join(os.path.expanduser("~"), ".whtssec_forensic")
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, "settings.json")

    @classmethod
    def load_settings(cls):
        filepath = cls.get_settings_path()
        local_adb = os.path.abspath("./platform-tools/adb.exe") if os.path.exists("./platform-tools/adb.exe") else "adb"
        default_settings = {
            "adb_path": local_adb,
            "abe_path": "./tools/abe.jar",
            "default_output_dir": os.path.expanduser("~/cases"),
            "theme": "dark"
        }
        if not os.path.exists(filepath):
            return default_settings

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                saved = json.load(f)
                if saved.get("adb_path") == "adb" and os.path.exists("./platform-tools/adb.exe"):
                    saved["adb_path"] = os.path.abspath("./platform-tools/adb.exe")
                default_settings.update(saved)
                return default_settings
        except Exception:
            return default_settings

    @classmethod
    def save_settings(cls, settings_dict):
        filepath = cls.get_settings_path()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(settings_dict, f, indent=4)


# ==============================================================================
# 2.4.5. AUDIT LOGGING SYSTEM
# ==============================================================================
class AuditLogger:
    _in_memory_logs = []

    @staticmethod
    def get_log_filepath(output_dir=None):
        if output_dir and os.path.exists(output_dir):
            return os.path.join(output_dir, "case_audit_log.json")
        global_dir = os.path.join(os.path.expanduser("~"), ".whtssec_forensic")
        os.makedirs(global_dir, exist_ok=True)
        return os.path.join(global_dir, "global_audit_log.json")

    @classmethod
    def log_action(cls, action, details="", output_dir=None, user=None):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": str(action),
            "details": str(details),
            "user": str(user) if user else "Unassigned"
        }
        cls._in_memory_logs.append(entry)

        filepath = cls.get_log_filepath(output_dir)
        logs = []
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except Exception:
                logs = []

        logs.append(entry)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4)
        except Exception:
            pass

    @classmethod
    def get_logs(cls, output_dir=None):
        filepath = cls.get_log_filepath(output_dir)
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return cls._in_memory_logs



# ==============================================================================
# 2.5. REPORT EXPORT FUNCTION (PDF / CSV / HTML)
# ==============================================================================
def export_report(data, report_format, output_dir, sections):
    """
    Generates a forensic report file from extraction results.
    Returns the path to the generated report file(s).
    """
    case_info = data.get("case_info", {})
    case_name = case_info.get("case_name", "CASE_UNNAMED")
    timestamp_str = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    os.makedirs(output_dir, exist_ok=True)

    if report_format == "pdf":
        return _export_pdf(data, output_dir, case_name, timestamp_str, sections)
    elif report_format == "csv":
        return _export_csv(data, output_dir, case_name, timestamp_str, sections)
    elif report_format == "html":
        return _export_html(data, output_dir, case_name, timestamp_str, sections)
    else:
        raise ValueError(f"Unsupported report format: {report_format}")


def _export_pdf(data, output_dir, case_name, ts, sections):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    filepath = os.path.join(output_dir, f"{case_name}_report_{ts}.pdf")
    doc = SimpleDocTemplate(filepath, pagesize=A4,
                            leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=22, spaceAfter=6)
    heading_style = ParagraphStyle("SectionHead", parent=styles["Heading2"], fontSize=14, spaceBefore=16, spaceAfter=8, textColor=colors.HexColor("#6c71c4"))
    cell_style = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=8, leading=10)
    elements = []

    # Title page
    case_info = data.get("case_info", {})
    elements.append(Paragraph("WHTSSEC Forensic Report", title_style))
    elements.append(Spacer(1, 8))
    title_info = [
        ["Case Name:", case_info.get("case_name", "N/A")],
        ["Investigator:", case_info.get("investigator", "N/A")],
        ["Generated:", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())],
    ]
    t = Table(title_info, colWidths=[100, 350])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 20))

    def make_table(header, rows, col_widths=None):
        table_data = [header] + rows
        tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#313244")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#45475a")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#1e1e2e"), colors.HexColor("#181825")]),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#cdd6f4")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return tbl

    # Device Info section
    if "device_info" in sections:
        dev = data.get("device_info", {})
        elements.append(Paragraph("Device Information", heading_style))
        rows = [[k, str(v)] for k, v in dev.items()]
        elements.append(make_table(["Property", "Value"], rows, col_widths=[150, 350]))
        elements.append(Spacer(1, 12))

    # Messages section
    if "messages" in sections:
        msgs = data.get("messages", [])
        elements.append(Paragraph(f"Messages ({len(msgs)} total)", heading_style))
        display_msgs = msgs[:500]
        rows = []
        for m in display_msgs:
            content = str(m.get("content", ""))[:60]
            rows.append([
                Paragraph(str(m.get("sender", "")), cell_style),
                Paragraph(str(m.get("timestamp", "")), cell_style),
                Paragraph(str(m.get("chat", "")), cell_style),
                Paragraph(content, cell_style),
            ])
        elements.append(make_table(["Sender", "Timestamp", "Chat", "Content"], rows, col_widths=[80, 110, 100, 210]))
        if len(msgs) > 500:
            elements.append(Paragraph(f"<i>... truncated. {len(msgs) - 500} additional messages not shown.</i>", styles["Italic"]))
        elements.append(Spacer(1, 12))

    # Media section
    if "media" in sections:
        media = data.get("media", [])
        elements.append(Paragraph(f"Media Inventory ({len(media)} files)", heading_style))
        rows = []
        for m in media[:500]:
            size_kb = m.get("size_bytes", 0) / 1024
            rows.append([
                Paragraph(str(m.get("filename", "")), cell_style),
                str(m.get("file_type", "")),
                f"{size_kb:.1f} KB",
                str(m.get("hash", ""))[:16] + "...",
            ])
        elements.append(make_table(["Filename", "Type", "Size", "SHA-256 (prefix)"], rows, col_widths=[160, 70, 70, 200]))
        elements.append(Spacer(1, 12))

    # Hashes section
    if "hashes" in sections:
        hashes = data.get("hashes", [])
        elements.append(Paragraph("Hashes / Integrity Verification", heading_style))
        rows = [[h.get("file", ""), h.get("hash", ""), h.get("status", "")] for h in hashes]
        elements.append(make_table(["File", "SHA-256 Hash", "Status"], rows, col_widths=[120, 300, 80]))
        elements.append(Spacer(1, 12))

    # Timeline section
    if "timeline" in sections:
        tl = data.get("timeline", [])
        elements.append(Paragraph(f"Forensic Timeline ({len(tl)} events)", heading_style))
        rows = [[e.get("time", ""), e.get("type", ""), Paragraph(str(e.get("detail", "")), cell_style)] for e in tl[:500]]
        elements.append(make_table(["Timestamp", "Type", "Detail"], rows, col_widths=[120, 110, 270]))
        elements.append(Spacer(1, 12))

    doc.build(elements)
    return filepath


def _export_csv(data, output_dir, case_name, ts, sections):
    created_files = []
    prefix = f"{case_name}_{ts}"

    if "device_info" in sections:
        fp = os.path.join(output_dir, f"{prefix}_device_info.csv")
        with open(fp, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Property", "Value"])
            for k, v in data.get("device_info", {}).items():
                writer.writerow([k, v])
        created_files.append(fp)

    if "messages" in sections:
        fp = os.path.join(output_dir, f"{prefix}_messages.csv")
        with open(fp, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Sender", "Timestamp", "Chat", "Content", "Recovered"])
            for m in data.get("messages", []):
                writer.writerow([m.get("sender", ""), m.get("timestamp", ""), m.get("chat", ""), m.get("content", ""), m.get("recovered", False)])
        created_files.append(fp)

    if "media" in sections:
        fp = os.path.join(output_dir, f"{prefix}_media.csv")
        with open(fp, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Filename", "Type", "Size (bytes)", "SHA-256", "Linked Message", "Thumbnail"])
            for m in data.get("media", []):
                writer.writerow([m.get("filename", ""), m.get("file_type", ""), m.get("size_bytes", 0), m.get("hash", ""), m.get("linked_message", ""), m.get("thumbnail_path", "")])
        created_files.append(fp)

    if "hashes" in sections:
        fp = os.path.join(output_dir, f"{prefix}_hashes.csv")
        with open(fp, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["File", "SHA-256 Hash", "Status"])
            for h in data.get("hashes", []):
                writer.writerow([h.get("file", ""), h.get("hash", ""), h.get("status", "")])
        created_files.append(fp)

    if "timeline" in sections:
        fp = os.path.join(output_dir, f"{prefix}_timeline.csv")
        with open(fp, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Type", "Detail"])
            for e in data.get("timeline", []):
                writer.writerow([e.get("time", ""), e.get("type", ""), e.get("detail", "")])
        created_files.append(fp)

    return ", ".join(created_files)


def _export_html(data, output_dir, case_name, ts, sections):
    filepath = os.path.join(output_dir, f"{case_name}_report_{ts}.html")
    case_info = data.get("case_info", {})

    css = """
    body { font-family: 'Segoe UI', Roboto, sans-serif; background: #1e1e2e; color: #cdd6f4; margin: 0; padding: 30px; }
    h1 { color: #89b4fa; border-bottom: 2px solid #313244; padding-bottom: 10px; }
    h2 { color: #cba6f7; margin-top: 30px; }
    table { width: 100%; border-collapse: collapse; margin: 12px 0 24px 0; font-size: 13px; }
    th { background: #313244; color: #cdd6f4; text-align: left; padding: 10px 12px; border: 1px solid #45475a; }
    td { padding: 8px 12px; border: 1px solid #313244; vertical-align: top; }
    tr:nth-child(even) { background: #181825; }
    tr:nth-child(odd) { background: #1e1e2e; }
    .meta-table td:first-child { font-weight: bold; color: #a6adc8; width: 200px; }
    .meta-table td:last-child { color: #a6e3a1; }
    .truncation-note { color: #f9e2af; font-style: italic; margin-top: -16px; margin-bottom: 20px; }
    """

    html_parts = [f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>WHTSSEC Report — {case_name}</title><style>{css}</style></head>
<body>
<h1>WHTSSEC Forensic Report</h1>
<table class="meta-table">
<tr><td>Case Name</td><td>{case_info.get('case_name', 'N/A')}</td></tr>
<tr><td>Investigator</td><td>{case_info.get('investigator', 'N/A')}</td></tr>
<tr><td>Generated</td><td>{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</td></tr>
</table>"""]

    def html_escape(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def make_html_table(headers, rows):
        parts = ["<table><thead><tr>"]
        for h in headers:
            parts.append(f"<th>{html_escape(h)}</th>")
        parts.append("</tr></thead><tbody>")
        for row in rows:
            parts.append("<tr>")
            for cell in row:
                parts.append(f"<td>{html_escape(cell)}</td>")
            parts.append("</tr>")
        parts.append("</tbody></table>")
        return "".join(parts)

    if "device_info" in sections:
        html_parts.append("<h2>Device Information</h2>")
        rows = [[k, str(v)] for k, v in data.get("device_info", {}).items()]
        html_parts.append(make_html_table(["Property", "Value"], rows))

    if "messages" in sections:
        msgs = data.get("messages", [])
        html_parts.append(f"<h2>Messages ({len(msgs)} total)</h2>")
        display_msgs = msgs[:500]
        rows = [[m.get("sender", ""), m.get("timestamp", ""), m.get("chat", ""), str(m.get("content", ""))[:80]] for m in display_msgs]
        html_parts.append(make_html_table(["Sender", "Timestamp", "Chat", "Content"], rows))
        if len(msgs) > 500:
            html_parts.append(f'<p class="truncation-note">... truncated. {len(msgs) - 500} additional messages not shown.</p>')

    if "media" in sections:
        media = data.get("media", [])
        html_parts.append(f"<h2>Media Inventory ({len(media)} files)</h2>")
        rows = [[m.get("filename", ""), m.get("file_type", ""), f"{m.get('size_bytes', 0) / 1024:.1f} KB", str(m.get("hash", ""))[:24] + "..."] for m in media[:500]]
        html_parts.append(make_html_table(["Filename", "Type", "Size", "SHA-256 (prefix)"], rows))

    if "hashes" in sections:
        hashes = data.get("hashes", [])
        html_parts.append("<h2>Hashes / Integrity Verification</h2>")
        rows = [[h.get("file", ""), h.get("hash", ""), h.get("status", "")] for h in hashes]
        html_parts.append(make_html_table(["File", "SHA-256 Hash", "Status"], rows))

    if "timeline" in sections:
        tl = data.get("timeline", [])
        html_parts.append(f"<h2>Forensic Timeline ({len(tl)} events)</h2>")
        rows = [[e.get("time", ""), e.get("type", ""), e.get("detail", "")] for e in tl[:500]]
        html_parts.append(make_html_table(["Timestamp", "Type", "Detail"], rows))

    html_parts.append("</body></html>")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))

    return filepath


# ==============================================================================
# 3. PRESENTATION LAYER (MAIN PYSIDE6 APPLICATION)
# ==============================================================================
class WhtssecForensicTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Whtssec Forensic Tool")
        self.resize(1200, 800)
        self.setStyleSheet(self.get_dark_stylesheet())
        
        # State Tracking Variables
        self.app_settings = SettingsManager.load_settings()
        self.current_case = {}
        self.current_case_results = None
        self.device_watcher = None
        self.extraction_worker = None

        # Main Layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar Construction
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(15, 25, 15, 25)
        sidebar_layout.setSpacing(10)
        sidebar.setFixedWidth(240)
        
        title_label = QLabel("WHTSSEC")
        title_label.setObjectName("appTitle")
        title_label.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(title_label)

        sidebar_layout.addSpacing(30)
        
        # Navigation Buttons
        self.nav_buttons = []
        nav_items = [
            ("⌂", "Home / Dashboard", 0),
            ("◈", "New Case", 1),
            ("⬡", "Evidence Ingestion", 2),
            ("◎", "Extraction Progress", 3),
            ("▦", "Report", 4),
            ("⇪", "Export", 5),
        ]

        self.stacked_widget = QStackedWidget()

        for symbol, label, index in nav_items:
            btn = self._make_nav_button(symbol, label, index)
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sidebar_layout.addStretch()

        bottom_nav_items = [
            ("✦", "Settings", 6),
            ("◉", "About / Case Log", 7),
        ]
        for symbol, label, index in bottom_nav_items:
            btn = self._make_nav_button(symbol, label, index)
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)
            
        main_layout.addWidget(sidebar)
        
        # Setup Pages
        self.setup_pages()
        main_layout.addWidget(self.stacked_widget)
        
        # Start at Home Dashboard
        self.switch_page(0)

    def _make_nav_button(self, symbol, label, index):
        """Creates a nav button with a purple-pill symbol badge and plain text label."""
        btn = QPushButton()
        btn.setCheckable(True)
        btn.setCursor(Qt.PointingHandCursor)
        btn.clicked.connect(lambda checked, idx=index: self.switch_page(idx))
        btn.setFixedHeight(44)

        row = QHBoxLayout(btn)
        row.setContentsMargins(10, 0, 10, 0)
        row.setSpacing(10)

        badge = QLabel(symbol)
        badge.setFixedSize(28, 28)
        badge.setAlignment(Qt.AlignCenter)
        badge.setObjectName("navBadge")
        badge.setStyleSheet(
            "background-color: #6c3483; color: #000000; border-radius: 6px;"
            "font-size: 14px; font-weight: bold;"
        )

        text = QLabel(label)
        text.setObjectName("navLabel")
        text.setStyleSheet("color: #c4b5d4; font-size: 13px; font-family: 'Segoe UI', sans-serif;")

        row.addWidget(badge)
        row.addWidget(text)
        row.addStretch()

        btn._badge = badge
        btn._label = text
        return btn

    def switch_page(self, index):
        self.stacked_widget.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(False)
            if hasattr(btn, "_badge"):
                btn._badge.setStyleSheet(
                    "background-color: #6c3483; color: #000000; border-radius: 6px;"
                    "font-size: 14px; font-weight: bold;"
                )
                btn._label.setStyleSheet("color: #c4b5d4; font-size: 13px; font-family: 'Segoe UI', sans-serif;")
                btn.setStyleSheet("background-color: transparent; border: none; border-radius: 6px;")
        if index < len(self.nav_buttons):
            btn = self.nav_buttons[index]
            btn.setChecked(True)
            if hasattr(btn, "_badge"):
                btn._badge.setStyleSheet(
                    "background-color: #000000; color: #cba6f7; border-radius: 6px;"
                    "font-size: 14px; font-weight: bold;"
                )
                btn._label.setStyleSheet("color: #e9d5ff; font-size: 13px; font-weight: bold; font-family: 'Segoe UI', sans-serif;")
                btn.setStyleSheet("background-color: #130525; border: none; border-radius: 6px;")
        if index == 7:
            self.refresh_audit_log()

    def get_dark_stylesheet(self):
        return """
            QMainWindow { background-color: #050008; }
            QWidget { background-color: #050008; color: #e0d7f5; font-family: "Consolas", "Courier New", monospace; font-size: 13px; }
            QLabel { font-family: "Segoe UI", "Roboto", sans-serif; background-color: transparent; }
            h1 { font-size: 24px; font-weight: bold; color: #c084fc; }
            #sidebar { background-color: #030006; border-right: 1px solid #2d1050; }
            #appTitle { font-size: 22px; font-weight: bold; color: #c084fc; font-family: "Segoe UI", sans-serif; letter-spacing: 2px; }
            QPushButton { background-color: transparent; color: #c4b5d4; border: none; padding: 12px 15px; text-align: left; border-radius: 6px; font-size: 14px; font-family: "Segoe UI", sans-serif; }
            QPushButton:hover { background-color: #130525; color: #e9d5ff; }
            QPushButton:checked { background-color: #130525; color: #e9d5ff; font-weight: bold; }
            .PrimaryButton { background-color: #7c3aed; color: #ffffff; border-radius: 6px; padding: 10px 20px; font-weight: bold; text-align: center; }
            .PrimaryButton:hover { background-color: #6d28d9; }
            .Card { background-color: #0a000f; border-radius: 10px; border: 1px solid #2d1050; padding: 20px; }
            QLineEdit, QTextEdit { background-color: #030006; border: 1px solid #3b1f5e; border-radius: 6px; padding: 10px; color: #86efac; }
            QLineEdit:focus, QTextEdit:focus { border: 1px solid #a855f7; }
            QTableWidget { background-color: #030006; border: 1px solid #2d1050; border-radius: 6px; gridline-color: #1a0030; alternate-background-color: #0a000f; }
            QHeaderView::section { background-color: #0d0018; color: #c084fc; padding: 8px; border: none; border-right: 1px solid #2d1050; border-bottom: 1px solid #2d1050; font-weight: bold; }
            QProgressBar { border: 1px solid #3b1f5e; border-radius: 6px; text-align: center; background-color: #030006; color: #e9d5ff; font-weight: bold; }
            QProgressBar::chunk { background-color: #7c3aed; border-radius: 4px; }
            QTabWidget::pane { border: 1px solid #2d1050; border-radius: 6px; background-color: #0a000f; top: -1px; }
            QTabBar::tab { background-color: #030006; color: #c4b5d4; border: 1px solid #2d1050; padding: 10px 20px; border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 2px; }
            QTabBar::tab:selected { background-color: #0d0018; color: #e9d5ff; border-bottom-color: #0d0018; font-weight: bold; }
            QTabBar::tab:hover:!selected { background-color: #130525; }
            QScrollBar:vertical { background-color: #030006; width: 8px; border-radius: 4px; }
            QScrollBar::handle:vertical { background-color: #4c1d95; border-radius: 4px; min-height: 20px; }
            QScrollBar::handle:vertical:hover { background-color: #7c3aed; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
            .StatusText { color: #a855f7; font-size: 18px; font-family: "Segoe UI", sans-serif; }
        """

    def create_page_container(self, title):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        
        header = QLabel(f"<h1>{title}</h1>")
        header.setStyleSheet("font-family: 'Segoe UI', sans-serif;")
        layout.addWidget(header)
        return page, layout

    def setup_pages(self):
        # ----------------------------------------------------------------------
        # PAGE 0: DASHBOARD
        # ----------------------------------------------------------------------
        home_page, home_layout = self.create_page_container("Dashboard")
        home_header = QHBoxLayout()
        home_header.addStretch()
        new_case_btn = QPushButton("📁 New Case")
        new_case_btn.setProperty("class", "PrimaryButton")
        new_case_btn.setCursor(Qt.PointingHandCursor)
        new_case_btn.clicked.connect(lambda: self.switch_page(1))
        home_header.addWidget(new_case_btn)
        home_layout.insertLayout(0, home_header)
        
        self.cases_table = QTableWidget(5, 4)
        self.cases_table.setAlternatingRowColors(True)
        self.cases_table.setHorizontalHeaderLabels(["Case Name", "Date", "Investigator", "Status"])
        self.cases_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.cases_table.verticalHeader().setVisible(False)
        self.cases_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.cases_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        for i in range(5):
            self.cases_table.setItem(i, 0, QTableWidgetItem(f"CASE_2026_{i+1:03d}"))
            self.cases_table.setItem(i, 1, QTableWidgetItem("2026-08-06"))
            self.cases_table.setItem(i, 2, QTableWidgetItem("Inv. Smith"))
            status_item = QTableWidgetItem("COMPLETED" if i % 2 == 0 else "IN PROGRESS")
            status_item.setForeground(Qt.green if i % 2 == 0 else Qt.yellow)
            self.cases_table.setItem(i, 3, status_item)
            
        home_layout.addWidget(self.cases_table)
        self.stacked_widget.addWidget(home_page)

        # ----------------------------------------------------------------------
        # PAGE 1: NEW CASE SETUP
        # ----------------------------------------------------------------------
        nc_page, nc_layout = self.create_page_container("New Case Setup")
        nc_form = QWidget()
        nc_form.setProperty("class", "Card")
        form_layout = QFormLayout(nc_form)
        form_layout.setLabelAlignment(Qt.AlignRight)
        form_layout.setSpacing(15)
        
        self.input_case_name = QLineEdit()
        self.input_case_name.setPlaceholderText("e.g. CASE_2026_006")
        form_layout.addRow("Case Name:", self.input_case_name)
        
        self.input_investigator = QLineEdit()
        self.input_investigator.setPlaceholderText("e.g. John Doe")
        form_layout.addRow("Investigator Name:", self.input_investigator)
        
        self.input_notes = QTextEdit()
        self.input_notes.setPlaceholderText("Enter preliminary notes about this device extraction...")
        self.input_notes.setMaximumHeight(120)
        form_layout.addRow("Notes:", self.input_notes)
        
        out_dir_layout = QHBoxLayout()
        default_out_path = os.path.abspath(os.path.join(self.app_settings.get("default_output_dir", "./cases"), "CASE_2026_006"))
        self.input_out_dir = QLineEdit(default_out_path)
        out_dir_btn = QPushButton("Browse...")
        out_dir_btn.setStyleSheet("background-color: #130525; padding: 10px; border-radius: 6px;")
        out_dir_btn.clicked.connect(self.browse_output_directory)
        out_dir_layout.addWidget(self.input_out_dir)
        out_dir_layout.addWidget(out_dir_btn)
        form_layout.addRow("Output Folder:", out_dir_layout)
        
        nc_layout.addWidget(nc_form)
        nc_layout.addStretch()
        
        start_case_btn = QPushButton("Start Case ->")
        start_case_btn.setProperty("class", "PrimaryButton")
        start_case_btn.clicked.connect(self.initiate_case_setup)
        nc_layout.addWidget(start_case_btn, alignment=Qt.AlignRight)
        self.stacked_widget.addWidget(nc_page)

        # ----------------------------------------------------------------------
        # PAGE 2: EVIDENCE INGESTION (DEVICE WATCHER INTEGRATION)
        # ----------------------------------------------------------------------
        ing_page, ing_layout = self.create_page_container("Evidence Ingestion")
        
        self.stepper_label = QLabel("Step 1 of 4: Waiting for device connection...")
        self.stepper_label.setAlignment(Qt.AlignCenter)
        self.stepper_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 16px; color: #c4b5d4;")
        ing_layout.addWidget(self.stepper_label)
        
        ing_layout.addStretch()
        
        status_card = QWidget()
        status_card.setProperty("class", "Card")
        status_card.setMinimumSize(400, 250)
        status_layout = QVBoxLayout(status_card)
        status_layout.setAlignment(Qt.AlignCenter)
        
        self.ing_status_icon = QLabel("📱")
        self.ing_status_icon.setStyleSheet("font-size: 72px;")
        self.ing_status_icon.setAlignment(Qt.AlignCenter)
        
        self.ing_status_text = QLabel("Waiting for device...")
        self.ing_status_text.setProperty("class", "StatusText")
        self.ing_status_text.setAlignment(Qt.AlignCenter)
        
        status_layout.addWidget(self.ing_status_icon)
        status_layout.addWidget(self.ing_status_text)
        
        ing_center_layout = QHBoxLayout()
        ing_center_layout.addStretch()
        ing_center_layout.addWidget(status_card)
        ing_center_layout.addStretch()
        
        ing_layout.addLayout(ing_center_layout)
        ing_layout.addStretch()
        
        ing_actions = QHBoxLayout()
        ing_actions.addStretch()
        
        cancel_ing_btn = QPushButton("Cancel")
        cancel_ing_btn.setStyleSheet("background-color: #3b0020; color: #f9a8d4; border-radius: 6px; padding: 10px 20px; font-weight: bold;")
        cancel_ing_btn.clicked.connect(self.stop_device_watcher)
        
        manual_load_btn = QPushButton("📂 Load DB/Backup Manually")
        manual_load_btn.setStyleSheet("background-color: #3b0f6e; color: #e9d5ff; border-radius: 6px; padding: 10px 20px; font-weight: bold;")
        manual_load_btn.clicked.connect(self.load_manual_db)
        
        ing_actions.addWidget(cancel_ing_btn)
        ing_actions.addWidget(manual_load_btn)
        ing_layout.addLayout(ing_actions)
        self.stacked_widget.addWidget(ing_page)

        # ----------------------------------------------------------------------
        # PAGE 3: EXTRACTION PROGRESS (WORKER THREAD INTEGRATION)
        # ----------------------------------------------------------------------
        prog_page, prog_layout = self.create_page_container("Extraction Progress")
        
        prog_card = QWidget()
        prog_card.setProperty("class", "Card")
        pc_layout = QVBoxLayout(prog_card)
        pc_layout.setSpacing(15)
        
        self.prog_status_head = QLabel("Extracting WhatsApp Database...")
        self.prog_status_head.setStyleSheet("font-family: 'Segoe UI'; font-size: 16px; font-weight: bold;")
        pc_layout.addWidget(self.prog_status_head)
        
        self.prog_bar = QProgressBar()
        self.prog_bar.setValue(0)
        self.prog_bar.setFixedHeight(25)
        pc_layout.addWidget(self.prog_bar)
        
        self.prog_count_label = QLabel("0 / 0 records (0%)")
        self.prog_count_label.setAlignment(Qt.AlignRight)
        pc_layout.addWidget(self.prog_count_label)
        
        self.prog_log_view = QTextEdit()
        self.prog_log_view.setReadOnly(True)
        self.prog_log_view.setStyleSheet(
            "background-color: #030006; border: 1px solid #3b1f5e; border-radius: 6px;"
            "padding: 10px; color: #4ade80; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px;"
        )
        pc_layout.addWidget(self.prog_log_view)
        
        prog_layout.addWidget(prog_card)
        
        prog_btns = QHBoxLayout()
        prog_btns.addStretch()
        
        cancel_ext_btn = QPushButton("Cancel Extraction")
        cancel_ext_btn.setStyleSheet("background-color: transparent; border: 1px solid #f9a8d4; color: #f9a8d4; border-radius: 6px; padding: 10px 20px;")
        cancel_ext_btn.clicked.connect(self.cancel_extraction)
        
        prog_btns.addWidget(cancel_ext_btn)
        prog_layout.addLayout(prog_btns)
        self.stacked_widget.addWidget(prog_page)

        # ----------------------------------------------------------------------
        # PAGE 4: REPORT & RESULTS VIEW
        # ----------------------------------------------------------------------
        rep_page, rep_layout = self.create_page_container("Forensic Report")
        self.report_tabs = QTabWidget()
        
        # Tab 1: Messages
        msg_tab = QWidget()
        msg_layout = QVBoxLayout(msg_tab)
        msg_layout.setContentsMargins(15, 15, 15, 15)

        # Pagination Bar
        msg_page_layout = QHBoxLayout()
        self.msg_prev_btn = QPushButton("◀ Previous")
        self.msg_prev_btn.setStyleSheet("background-color: #130525; color: #e9d5ff; border-radius: 6px; padding: 6px 12px;")
        self.msg_prev_btn.clicked.connect(lambda: self.change_message_page(-1))

        self.msg_page_label = QLabel("Page 1 of 1")
        self.msg_page_label.setStyleSheet("color: #c084fc; font-weight: bold; font-size: 13px;")

        self.msg_next_btn = QPushButton("Next ▶")
        self.msg_next_btn.setStyleSheet("background-color: #130525; color: #e9d5ff; border-radius: 6px; padding: 6px 12px;")
        self.msg_next_btn.clicked.connect(lambda: self.change_message_page(1))

        msg_page_layout.addWidget(self.msg_prev_btn)
        msg_page_layout.addWidget(self.msg_page_label)
        msg_page_layout.addWidget(self.msg_next_btn)
        msg_page_layout.addStretch()

        msg_layout.addLayout(msg_page_layout)

        self.report_msg_table = QTableWidget(0, 4)
        self.report_msg_table.setAlternatingRowColors(True)
        self.report_msg_table.setHorizontalHeaderLabels(["Sender", "Timestamp", "Chat/Group", "Content"])
        self.report_msg_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.report_msg_table.verticalHeader().setVisible(False)
        self.report_msg_table.setSelectionBehavior(QTableWidget.SelectRows)
        msg_layout.addWidget(self.report_msg_table)
        self.report_tabs.addTab(msg_tab, "💬 Messages")
        
        # Tab 2: Media Gallery
        media_tab = QWidget()
        media_layout = QVBoxLayout(media_tab)
        media_layout.setContentsMargins(15, 15, 15, 15)
        
        media_scroll = QScrollArea()
        media_scroll.setWidgetResizable(True)
        media_scroll.setStyleSheet("QScrollArea { border: none; background-color: transparent; }")
        
        self.media_content = QWidget()
        self.media_grid_layout = QVBoxLayout(self.media_content)

        self.media_grid = QGridLayout()
        self.media_grid.setSpacing(15)
        self.media_grid_layout.addLayout(self.media_grid)

        self.load_more_media_btn = QPushButton("Load More Media")
        self.load_more_media_btn.setStyleSheet("background-color: #130525; color: #c084fc; border-radius: 6px; padding: 10px 20px; font-weight: bold;")
        self.load_more_media_btn.clicked.connect(self.load_next_media_batch)
        self.media_grid_layout.addWidget(self.load_more_media_btn, alignment=Qt.AlignCenter)

        media_scroll.setWidget(self.media_content)
        media_layout.addWidget(media_scroll)
        self.report_tabs.addTab(media_tab, "🖼️ Media")
        
        # Tab 3: Device Metadata
        info_tab = QWidget()
        info_layout = QVBoxLayout(info_tab)
        info_layout.setContentsMargins(15, 15, 15, 15)
        info_card = QWidget()
        info_card.setProperty("class", "Card")
        self.report_info_form = QFormLayout(info_card)
        self.report_info_form.setSpacing(20)
        self.report_info_form.setLabelAlignment(Qt.AlignRight)
        info_layout.addWidget(info_card)
        info_layout.addStretch()
        self.report_tabs.addTab(info_tab, "📱 Device Info")
        
        # Tab 4: Hashes & Forensic Integrity
        hash_tab = QWidget()
        hash_layout = QVBoxLayout(hash_tab)
        hash_layout.setContentsMargins(15, 15, 15, 15)
        self.report_hash_table = QTableWidget(0, 3)
        self.report_hash_table.setAlternatingRowColors(True)
        self.report_hash_table.setHorizontalHeaderLabels(["File Name", "Hash (SHA-256)", "Status"])
        self.report_hash_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.report_hash_table.verticalHeader().setVisible(False)
        self.report_hash_table.setEditTriggers(QTableWidget.NoEditTriggers)
        hash_layout.addWidget(self.report_hash_table)
        self.report_tabs.addTab(hash_tab, "🔒 Hashes/Integrity")
        
        # Tab 5: Forensic Timeline
        time_tab = QWidget()
        time_layout = QVBoxLayout(time_tab)
        time_layout.setContentsMargins(15, 15, 15, 15)
        self.report_time_table = QTableWidget(0, 3)
        self.report_time_table.setAlternatingRowColors(True)
        self.report_time_table.setHorizontalHeaderLabels(["Timestamp", "Event Type", "Event Detail"])
        self.report_time_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.report_time_table.verticalHeader().setVisible(False)
        time_layout.addWidget(self.report_time_table)
        self.report_tabs.addTab(time_tab, "⏱️ Timeline")
        
        rep_layout.addWidget(self.report_tabs)
        self.stacked_widget.addWidget(rep_page)

        # Setup Export Page (Page 5)
        self.setup_export_page()

        # Setup Settings Page (Page 6)
        self.setup_settings_page()

        # Setup About & Audit Log Page (Page 7)
        self.setup_audit_log_page()

    # ==========================================================================
    # 4. EXPORT PAGE SETUP & REPORT GENERATION
    # ==========================================================================
    def setup_export_page(self):
        exp_page, exp_layout = self.create_page_container("Export Report")

        # Format selection card
        fmt_card = QWidget()
        fmt_card.setProperty("class", "Card")
        fmt_card_layout = QVBoxLayout(fmt_card)
        fmt_card_layout.setSpacing(12)

        fmt_label = QLabel("Report Format")
        fmt_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 15px; font-weight: bold; color: #c084fc;")
        fmt_card_layout.addWidget(fmt_label)

        self.export_format_group = QButtonGroup(self)
        fmt_row = QHBoxLayout()
        self.radio_pdf = QRadioButton("PDF")
        self.radio_csv = QRadioButton("CSV")
        self.radio_html = QRadioButton("HTML")
        self.radio_pdf.setChecked(True)
        self.export_format_group.addButton(self.radio_pdf, 0)
        self.export_format_group.addButton(self.radio_csv, 1)
        self.export_format_group.addButton(self.radio_html, 2)
        for rb in [self.radio_pdf, self.radio_csv, self.radio_html]:
            rb.setStyleSheet("QRadioButton { spacing: 8px; font-size: 14px; } QRadioButton::indicator { width: 16px; height: 16px; }")
            fmt_row.addWidget(rb)
        fmt_row.addStretch()
        fmt_card_layout.addLayout(fmt_row)
        exp_layout.addWidget(fmt_card)

        # Section checklist card
        sec_card = QWidget()
        sec_card.setProperty("class", "Card")
        sec_card_layout = QVBoxLayout(sec_card)
        sec_card_layout.setSpacing(12)

        sec_label = QLabel("Sections to Include")
        sec_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 15px; font-weight: bold; color: #c084fc;")
        sec_card_layout.addWidget(sec_label)

        self.export_section_checks = {}
        section_names = [
            ("device_info", "Device Info"),
            ("messages", "Messages"),
            ("media", "Media Inventory"),
            ("hashes", "Hashes / Integrity"),
            ("timeline", "Timeline")
        ]
        for key, label in section_names:
            cb = QCheckBox(label)
            cb.setChecked(True)
            cb.setStyleSheet("QCheckBox { spacing: 8px; font-size: 14px; } QCheckBox::indicator { width: 16px; height: 16px; }")
            sec_card_layout.addWidget(cb)
            self.export_section_checks[key] = cb

        exp_layout.addWidget(sec_card)

        # Generate button
        gen_btn = QPushButton("📄 Generate Report")
        gen_btn.setProperty("class", "PrimaryButton")
        gen_btn.setCursor(Qt.PointingHandCursor)
        gen_btn.setFixedHeight(45)
        gen_btn.clicked.connect(self.on_generate_report_clicked)
        exp_layout.addWidget(gen_btn, alignment=Qt.AlignLeft)

        # Status label
        self.export_status_label = QLabel("")
        self.export_status_label.setWordWrap(True)
        self.export_status_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 13px; color: #a6adc8; padding: 5px 0;")
        exp_layout.addWidget(self.export_status_label)

        exp_layout.addStretch()
        self.stacked_widget.addWidget(exp_page)

    def on_generate_report_clicked(self):
        if not self.current_case_results:
            self.export_status_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 13px; color: #f9a8d4; padding: 5px 0;")
            self.export_status_label.setText("⚠️ No extraction data available. Run an extraction first.")
            return

        # Determine format
        fmt_id = self.export_format_group.checkedId()
        fmt_map = {0: "pdf", 1: "csv", 2: "html"}
        report_format = fmt_map.get(fmt_id, "pdf")

        # Determine selected sections
        sections = [key for key, cb in self.export_section_checks.items() if cb.isChecked()]
        if not sections:
            self.export_status_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 13px; color: #f9a8d4; padding: 5px 0;")
            self.export_status_label.setText("⚠️ Select at least one section to include in the report.")
            return

        out_dir = self.current_case.get("output_dir", "./cases/default")
        os.makedirs(out_dir, exist_ok=True)

        self.export_status_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 13px; color: #a855f7; padding: 5px 0;")
        self.export_status_label.setText("◎  Generating report...")

        try:
            result_path = export_report(self.current_case_results, report_format, out_dir, sections)
            self.export_status_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 13px; color: #86efac; padding: 5px 0;")
            self.export_status_label.setText(f"✅ Report saved to: {result_path}")

            user = self.current_case.get("investigator")
            AuditLogger.log_action("REPORT_EXPORTED", f"Format: {report_format.upper()}, Path: {result_path}", output_dir=out_dir, user=user)
        except Exception as e:
            self.export_status_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 13px; color: #f9a8d4; padding: 5px 0;")
            self.export_status_label.setText(f"❌ Report generation failed: {str(e)}")

    def setup_settings_page(self):
        settings_page, settings_layout = self.create_page_container("Application Settings")

        card = QWidget()
        card.setProperty("class", "Card")
        form_layout = QFormLayout(card)
        form_layout.setLabelAlignment(Qt.AlignRight)
        form_layout.setSpacing(15)

        # 1. ADB Executable Path
        adb_layout = QHBoxLayout()
        self.input_adb_path = QLineEdit(self.app_settings.get("adb_path", "adb"))
        adb_browse_btn = QPushButton("Browse...")
        adb_browse_btn.setStyleSheet("background-color: #130525; padding: 10px; border-radius: 6px;")
        adb_browse_btn.clicked.connect(self.browse_adb_path)
        adb_layout.addWidget(self.input_adb_path)
        adb_layout.addWidget(adb_browse_btn)
        form_layout.addRow("ADB Binary Path:", adb_layout)

        # 2. ABE Jar Path
        abe_layout = QHBoxLayout()
        self.input_abe_path = QLineEdit(self.app_settings.get("abe_path", "./tools/abe.jar"))
        abe_browse_btn = QPushButton("Browse...")
        abe_browse_btn.setStyleSheet("background-color: #130525; padding: 10px; border-radius: 6px;")
        abe_browse_btn.clicked.connect(self.browse_abe_path)
        abe_layout.addWidget(self.input_abe_path)
        abe_layout.addWidget(abe_browse_btn)
        form_layout.addRow("ABE Jar Path:", abe_layout)

        # 3. Default Output Directory
        out_dir_layout = QHBoxLayout()
        self.input_default_out_dir = QLineEdit(self.app_settings.get("default_output_dir", "~/cases"))
        out_dir_browse_btn = QPushButton("Browse...")
        out_dir_browse_btn.setStyleSheet("background-color: #130525; padding: 10px; border-radius: 6px;")
        out_dir_browse_btn.clicked.connect(self.browse_default_output_dir)
        out_dir_layout.addWidget(self.input_default_out_dir)
        out_dir_layout.addWidget(out_dir_browse_btn)
        form_layout.addRow("Default Output Folder:", out_dir_layout)

        # 4. Theme Toggle Radio Buttons
        theme_layout = QHBoxLayout()
        self.theme_button_group = QButtonGroup(self)
        self.radio_theme_dark = QRadioButton("Dark Theme")
        self.radio_theme_light = QRadioButton("Light Theme")
        
        current_theme = self.app_settings.get("theme", "dark")
        if current_theme == "light":
            self.radio_theme_light.setChecked(True)
        else:
            self.radio_theme_dark.setChecked(True)

        self.theme_button_group.addButton(self.radio_theme_dark, 0)
        self.theme_button_group.addButton(self.radio_theme_light, 1)

        theme_layout.addWidget(self.radio_theme_dark)
        theme_layout.addWidget(self.radio_theme_light)
        theme_layout.addStretch()
        form_layout.addRow("Interface Theme:", theme_layout)

        settings_layout.addWidget(card)

        # Save Button
        save_btn = QPushButton("💾 Save Settings")
        save_btn.setProperty("class", "PrimaryButton")
        save_btn.setCursor(Qt.PointingHandCursor)
        save_btn.clicked.connect(self.save_app_settings)
        settings_layout.addWidget(save_btn, alignment=Qt.AlignRight)

        # Status Label
        self.settings_status_label = QLabel("")
        self.settings_status_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 13px; font-weight: bold;")
        settings_layout.addWidget(self.settings_status_label)

        settings_layout.addStretch()
        self.stacked_widget.addWidget(settings_page)

    def browse_adb_path(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select ADB Executable", "", "Executables (*.exe *);;All Files (*)")
        if file_path:
            self.input_adb_path.setText(file_path)

    def browse_abe_path(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Android Backup Extractor (abe.jar)", "", "Java Archives (*.jar);;All Files (*)")
        if file_path:
            self.input_abe_path.setText(file_path)

    def browse_default_output_dir(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Default Case Output Folder", os.path.expanduser("~"))
        if directory:
            self.input_default_out_dir.setText(directory)

    def save_app_settings(self):
        selected_theme = "light" if self.radio_theme_light.isChecked() else "dark"
        new_settings = {
            "adb_path": self.input_adb_path.text().strip(),
            "abe_path": self.input_abe_path.text().strip(),
            "default_output_dir": self.input_default_out_dir.text().strip(),
            "theme": selected_theme
        }
        
        try:
            SettingsManager.save_settings(new_settings)
            self.app_settings = new_settings
            self.settings_status_label.setStyleSheet("color: #86efac; font-weight: bold;")
            self.settings_status_label.setText("✅ Settings saved successfully.")

            out_dir = self.current_case.get("output_dir") if hasattr(self, "current_case") else None
            user = self.current_case.get("investigator") if hasattr(self, "current_case") else None
            AuditLogger.log_action("SETTINGS_UPDATED", f"ADB: {new_settings.get('adb_path')}", output_dir=out_dir, user=user)
        except Exception as e:
            self.settings_status_label.setStyleSheet("color: #f9a8d4; font-weight: bold;")
            self.settings_status_label.setText(f"❌ Failed to save settings: {str(e)}")

    def setup_audit_log_page(self):
        about_page, about_layout = self.create_page_container("About & Audit Log")

        # Top section: App About info card
        about_card = QWidget()
        about_card.setProperty("class", "Card")
        ac_layout = QVBoxLayout(about_card)
        ac_layout.setSpacing(8)

        app_title = QLabel("WHTSSEC Forensic Extractor v1.0.0")
        app_title.setStyleSheet("font-family: 'Segoe UI'; font-size: 18px; font-weight: bold; color: #c084fc;")
        
        app_desc = QLabel("Automated WhatsApp Evidence Extraction & Forensic Analysis Tool")
        app_desc.setStyleSheet("font-family: 'Segoe UI'; font-size: 13px; color: #e0d7f5;")

        app_tagline = QLabel("Built for lawful digital forensics analysis")
        app_tagline.setStyleSheet("font-family: 'Segoe UI'; font-size: 12px; font-style: italic; color: #a6adc8;")

        ac_layout.addWidget(app_title)
        ac_layout.addWidget(app_desc)
        ac_layout.addWidget(app_tagline)

        about_layout.addWidget(about_card)

        # Bottom section: Case Audit Log table card
        log_card = QWidget()
        log_card.setProperty("class", "Card")
        lc_layout = QVBoxLayout(log_card)
        lc_layout.setSpacing(12)

        log_head_layout = QHBoxLayout()
        log_title = QLabel("Case Audit Log")
        log_title.setStyleSheet("font-family: 'Segoe UI'; font-size: 16px; font-weight: bold; color: #c084fc;")
        log_head_layout.addWidget(log_title)
        log_head_layout.addStretch()

        refresh_btn = QPushButton("🔄 Refresh Log")
        refresh_btn.setStyleSheet("background-color: #130525; color: #e9d5ff; border-radius: 6px; padding: 8px 15px;")
        refresh_btn.clicked.connect(self.refresh_audit_log)

        export_log_btn = QPushButton("📥 Export Log (CSV)")
        export_log_btn.setStyleSheet("background-color: #130525; color: #e9d5ff; border-radius: 6px; padding: 8px 15px;")
        export_log_btn.clicked.connect(self.export_audit_log_csv)

        log_head_layout.addWidget(refresh_btn)
        log_head_layout.addWidget(export_log_btn)
        lc_layout.addLayout(log_head_layout)

        self.audit_log_table = QTableWidget(0, 4)
        self.audit_log_table.setAlternatingRowColors(True)
        self.audit_log_table.setHorizontalHeaderLabels(["Timestamp", "Action", "Details", "User"])
        self.audit_log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.audit_log_table.verticalHeader().setVisible(False)
        self.audit_log_table.setEditTriggers(QTableWidget.NoEditTriggers)

        lc_layout.addWidget(self.audit_log_table)
        about_layout.addWidget(log_card)

        self.stacked_widget.addWidget(about_page)

    def refresh_audit_log(self):
        out_dir = self.current_case.get("output_dir") if hasattr(self, "current_case") else None
        logs = AuditLogger.get_logs(out_dir)

        self.audit_log_table.setRowCount(len(logs))
        for idx, entry in enumerate(logs):
            self.audit_log_table.setItem(idx, 0, QTableWidgetItem(entry.get("timestamp", "")))
            self.audit_log_table.setItem(idx, 1, QTableWidgetItem(entry.get("action", "")))
            self.audit_log_table.setItem(idx, 2, QTableWidgetItem(entry.get("details", "")))
            self.audit_log_table.setItem(idx, 3, QTableWidgetItem(entry.get("user", "")))

    def export_audit_log_csv(self):
        out_dir = self.current_case.get("output_dir", "./cases/default")
        os.makedirs(out_dir, exist_ok=True)
        
        filepath, _ = QFileDialog.getSaveFileName(self, "Export Audit Log", os.path.join(out_dir, "case_audit_log.csv"), "CSV Files (*.csv)")
        if not filepath:
            return

        logs = AuditLogger.get_logs(out_dir)
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Action", "Details", "User"])
                for entry in logs:
                    writer.writerow([entry.get("timestamp", ""), entry.get("action", ""), entry.get("details", ""), entry.get("user", "")])
        except Exception:
            pass

    # ==========================================================================
    # 5. CONTROLLER & WORKER EVENT SLOTS
    # ==========================================================================
    def browse_output_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Output Folder", os.path.expanduser("~"))
        if directory:
            self.input_out_dir.setText(directory)

    def initiate_case_setup(self):
        case_name = self.input_case_name.text().strip() or "CASE_UNNAMED"
        investigator = self.input_investigator.text().strip() or "Unassigned"
        out_dir = self.input_out_dir.text().strip()
        notes = self.input_notes.toPlainText().strip()

        self.current_case = {
            "case_name": case_name,
            "investigator": investigator,
            "output_dir": out_dir,
            "notes": notes
        }

        AuditLogger.log_action("CASE_CREATED", f"Case Name: {case_name}", output_dir=out_dir, user=investigator)

        # Navigate to Evidence Ingestion and start DeviceWatcher thread
        self.switch_page(2)
        self.start_device_watcher()

    def start_device_watcher(self):
        self.stop_device_watcher()
        self.stepper_label.setText("Step 1 of 4: Waiting for device connection...")
        self.ing_status_icon.setText("📱")
        self.ing_status_text.setText("Waiting for device connection...")
        
        adb_path = self.app_settings.get("adb_path", "adb")
        self.device_watcher = DeviceWatcher(adb_path=adb_path)
        self.device_watcher.status_changed.connect(self.on_device_status_changed)
        self.device_watcher.start()

    def stop_device_watcher(self):
        if self.device_watcher and self.device_watcher.isRunning():
            self.device_watcher.stop()
            self.device_watcher = None

    @Slot(str, str)
    def on_device_status_changed(self, status, device_id):
        if status == "no_device":
            self.ing_status_icon.setText("📱")
            self.ing_status_text.setText("Waiting for device connection...")
        elif status == "unauthorized":
            self.ing_status_icon.setText("⚠️")
            self.ing_status_text.setText("Device detected — Tap 'Allow USB Debugging' on phone")
        elif status == "authorized":
            self.ing_status_icon.setText("✅")
            self.ing_status_text.setText(f"Device Authorized: {device_id} — Starting scan...")
            self.current_case["device_id"] = device_id
            
            out_dir = self.current_case.get("output_dir")
            user = self.current_case.get("investigator")
            AuditLogger.log_action("DEVICE_CONNECTED", f"Device ID: {device_id}", output_dir=out_dir, user=user)

            # Stop watcher and automatically launch ExtractionWorker
            self.stop_device_watcher()
            QThread.msleep(800)
            self.start_extraction_worker()

    def load_manual_db(self):
        """Open a file dialog for the user to select a WhatsApp DB or backup file for manual analysis."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select WhatsApp Database or Backup File",
            os.path.expanduser("~"),
            "Database Files (*.db *.sqlite *.sqlite3);;All Files (*.*)"
        )
        if file_path:
            self.stop_device_watcher()
            self.current_case["manual_db_path"] = file_path
            self.current_case["device_id"] = "MANUAL_IMPORT"
            
            out_dir = self.current_case.get("output_dir")
            user = self.current_case.get("investigator")
            AuditLogger.log_action("MANUAL_DB_IMPORT", f"File: {file_path}", output_dir=out_dir, user=user)
            
            self.ing_status_icon.setText("📂")
            self.ing_status_text.setText(f"Manual file loaded: {os.path.basename(file_path)}")
            QThread.msleep(500)
            self.start_extraction_worker()

    def start_extraction_worker(self):
        self.switch_page(3)
        self.prog_bar.setValue(0)
        self.prog_log_view.clear()
        self.prog_status_head.setText(f"Extracting Data for {self.current_case.get('case_name')}")

        out_dir = self.current_case.get("output_dir")
        user = self.current_case.get("investigator")
        AuditLogger.log_action("EXTRACTION_STARTED", f"Target Dir: {out_dir}", output_dir=out_dir, user=user)

        adb_path = self.app_settings.get("adb_path", "adb")
        abe_path = self.app_settings.get("abe_path", "./tools/abe.jar")
        self.extraction_worker = ExtractionWorker(self.current_case, adb_path=adb_path, abe_path=abe_path)
        self.extraction_worker.progress.connect(self.on_extraction_progress)
        self.extraction_worker.log.connect(self.on_extraction_log)
        self.extraction_worker.finished.connect(self.on_extraction_finished)
        self.extraction_worker.error.connect(self.on_extraction_error)
        self.extraction_worker.start()

    def cancel_extraction(self):
        if self.extraction_worker and self.extraction_worker.isRunning():
            self.extraction_worker.cancel()
            self.prog_log_view.append("[USER ACTION] Cancelling extraction requested...")
            out_dir = self.current_case.get("output_dir")
            user = self.current_case.get("investigator")
            AuditLogger.log_action("EXTRACTION_CANCELLED", "Extraction cancelled by investigator", output_dir=out_dir, user=user)

    @Slot(int, int, str)
    def on_extraction_progress(self, current, total, detail):
        percentage = int((current / total) * 100) if total > 0 else 0
        self.prog_bar.setValue(percentage)
        self.prog_count_label.setText(f"{current:,} / {total:,} records ({percentage}%)")

    @Slot(str)
    def on_extraction_log(self, message):
        self.prog_log_view.append(message)

    @Slot(str)
    def on_extraction_error(self, err_msg):
        self.prog_log_view.append(f"[ERROR] {err_msg}")
        self.prog_status_head.setText("Extraction Failed")

    @Slot(dict)
    def on_extraction_finished(self, parsed_data):
        self.current_case_results = parsed_data
        self.populate_report_page(parsed_data)

        msgs_count = len(parsed_data.get("messages", []))
        media_count = len(parsed_data.get("media", []))
        out_dir = self.current_case.get("output_dir")
        user = self.current_case.get("investigator")
        AuditLogger.log_action("EXTRACTION_COMPLETED", f"Messages: {msgs_count}, Media: {media_count}", output_dir=out_dir, user=user)

        self.switch_page(4)  # Seamlessly switch to Report view upon completion

    def load_thumbnail_on_demand(self, media_item):
        """
        Generates a thumbnail for a media item on demand if not already present.
        Returns the thumbnail file path.
        """
        if media_item.get("thumbnail_path") and os.path.exists(media_item["thumbnail_path"]):
            return media_item["thumbnail_path"]

        if media_item.get("file_type") != "image":
            return None

        filepath = media_item.get("filepath")
        if not filepath or not os.path.exists(filepath):
            return None

        file_size = media_item.get("size_bytes", 0)
        if file_size > 50 * 1024 * 1024:
            return None

        try:
            from PIL import Image
            file_hash = media_item.get("hash", "nohash")
            out_dir = self.current_case.get("output_dir", "./cases/default")
            thumb_dir = os.path.join(out_dir, "thumbnails")
            os.makedirs(thumb_dir, exist_ok=True)

            thumb_name = f"thumb_{file_hash}.png"
            thumb_full_path = os.path.join(thumb_dir, thumb_name)

            if not os.path.exists(thumb_full_path):
                with Image.open(filepath) as img:
                    img.thumbnail((150, 150))
                    img.save(thumb_full_path, "PNG")

            media_item["thumbnail_path"] = thumb_full_path
            return thumb_full_path
        except Exception:
            return None

    def render_message_page(self, page_number):
        if not hasattr(self, "all_messages") or not self.all_messages:
            self.report_msg_table.setRowCount(0)
            self.msg_page_label.setText("Page 0 of 0")
            self.msg_prev_btn.setEnabled(False)
            self.msg_next_btn.setEnabled(False)
            return

        page_size = 200
        total_items = len(self.all_messages)
        total_pages = math.ceil(total_items / page_size) if total_items > 0 else 1

        self.current_msg_page = max(1, min(page_number, total_pages))

        start_idx = (self.current_msg_page - 1) * page_size
        end_idx = min(start_idx + page_size, total_items)
        page_messages = self.all_messages[start_idx:end_idx]

        self.report_msg_table.setRowCount(len(page_messages))
        for idx, msg in enumerate(page_messages):
            self.report_msg_table.setItem(idx, 0, QTableWidgetItem(str(msg.get("sender", ""))))
            self.report_msg_table.setItem(idx, 1, QTableWidgetItem(str(msg.get("timestamp", ""))))
            self.report_msg_table.setItem(idx, 2, QTableWidgetItem(str(msg.get("chat", ""))))
            self.report_msg_table.setItem(idx, 3, QTableWidgetItem(str(msg.get("content", ""))))

        self.msg_page_label.setText(f"Page {self.current_msg_page} of {total_pages} ({total_items:,} total)")
        self.msg_prev_btn.setEnabled(self.current_msg_page > 1)
        self.msg_next_btn.setEnabled(self.current_msg_page < total_pages)

    def change_message_page(self, delta):
        if hasattr(self, "current_msg_page"):
            self.render_message_page(self.current_msg_page + delta)

    def render_media_batch(self, reset=False):
        if reset:
            self.rendered_media_count = 0
            while self.media_grid.count():
                item = self.media_grid.takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()

        if not hasattr(self, "all_media") or not self.all_media:
            self.load_more_media_btn.setVisible(False)
            return

        batch_size = 50
        start_idx = self.rendered_media_count
        end_idx = min(start_idx + batch_size, len(self.all_media))

        for idx in range(start_idx, end_idx):
            item = self.all_media[idx]
            thumb_widget = QWidget()
            thumb_widget.setStyleSheet("background-color: #130525; border-radius: 8px;")
            thumb_widget.setFixedSize(140, 150)
            t_lay = QVBoxLayout(thumb_widget)
            t_lay.setContentsMargins(5, 5, 5, 5)

            file_type = item.get("file_type", "document")
            thumb_path = self.load_thumbnail_on_demand(item)

            if thumb_path and os.path.exists(thumb_path):
                img_label = QLabel()
                pixmap = QPixmap(thumb_path)
                img_label.setPixmap(pixmap.scaled(110, 110, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                img_label.setAlignment(Qt.AlignCenter)
                t_lay.addWidget(img_label)
            else:
                ic = QLabel("🖼️" if file_type == "image" else ("🎥" if file_type == "video" else ("🎵" if file_type == "voice_note" else "📄")))
                ic.setFont(QFont("Arial", 28))
                ic.setAlignment(Qt.AlignCenter)
                t_lay.addWidget(ic)

            lb = QLabel(item.get("filename", "unnamed")[:18])
            lb.setAlignment(Qt.AlignCenter)
            lb.setStyleSheet("color: #a6adc8; font-size: 11px;")
            t_lay.addWidget(lb)

            self.media_grid.addWidget(thumb_widget, idx // 4, idx % 4)

        self.rendered_media_count = end_idx
        remaining = len(self.all_media) - self.rendered_media_count
        if remaining > 0:
            self.load_more_media_btn.setText(f"Load More Media ({remaining} remaining)")
            self.load_more_media_btn.setVisible(True)
        else:
            self.load_more_media_btn.setVisible(False)

    def load_next_media_batch(self):
        self.render_media_batch(reset=False)

    def populate_report_page(self, data):
        # 1. Populate Messages Tab with Pagination (200 rows per page)
        self.all_messages = data.get("messages", [])
        self.render_message_page(1)

        # 2. Populate Media Tab with Lazy Loading & Pagination (50 cards per batch)
        self.all_media = data.get("media", [])
        self.render_media_batch(reset=True)

        # 2. Populate Device Info Tab
        while self.report_info_form.rowCount() > 0:
            self.report_info_form.removeRow(0)
            
        dev_info = data.get("device_info", {})
        for key, val in dev_info.items():
            val_label = QLabel(str(val))
            val_label.setStyleSheet("color: #c084fc; font-weight: bold;")
            self.report_info_form.addRow(f"{key}:", val_label)

        # 3. Populate Hashes Tab
        hashes = data.get("hashes", [])
        self.report_hash_table.setRowCount(len(hashes))
        for idx, h in enumerate(hashes):
            self.report_hash_table.setItem(idx, 0, QTableWidgetItem(h.get("file", "")))
            self.report_hash_table.setItem(idx, 1, QTableWidgetItem(h.get("hash", "")))
            status_item = QTableWidgetItem(h.get("status", "VERIFIED"))
            status_item.setForeground(QColor("#a6e3a1"))
            self.report_hash_table.setItem(idx, 2, status_item)

        # 4. Populate Timeline Tab
        timeline = data.get("timeline", [])
        self.report_time_table.setRowCount(len(timeline))
        for idx, event in enumerate(timeline):
            self.report_time_table.setItem(idx, 0, QTableWidgetItem(event.get("time", "")))
            self.report_time_table.setItem(idx, 1, QTableWidgetItem(event.get("type", "")))
            self.report_time_table.setItem(idx, 2, QTableWidgetItem(event.get("detail", "")))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WhtssecForensicTool()
    window.show()
    sys.exit(app.exec())
