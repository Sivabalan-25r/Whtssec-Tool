#!/usr/bin/env python3
"""
test_ground_truth.py — Ground-Truth Validation Harness & Diff Engine
                       for WhtsSec Forensic Tool

Independently verifies the app's parsing output against a manually-confirmed
ground truth JSON file. Imports standalone parsing/hashing functions directly
from main.py.

New Capabilities:
- compare_results(parsed_data, ground_truth): Structured comparison engine separating
  computation from output rendering.
- Diagnostic Hints: Evaluates count mismatches to detect WAL merge issues, media-only
  content skipping, or duplicate querying bugs.
- Fuzzy Timestamp Matching: Detects small timestamp conversion drifts (<= 60s) and
  finds up to 3 closest candidate messages when exact matches fail.
- --save-report Flag: Writes structured JSON results to disk (default comparison_report.json).

Usage:
    python test_ground_truth.py ground_truth.json [--save-report [output_file.json]]

Exit code:
    0  — all checks passed
    1  — one or more checks failed
    2  — usage / configuration error
"""

import sys
import os
import json
from datetime import datetime

# ---------------------------------------------------------------------------
# Ensure stdout/stderr handle UTF-8 symbols cleanly on Windows consoles
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

try:
    from main import compute_sha256_standalone, parse_database_standalone
except ImportError as exc:
    print(f"❌  IMPORT ERROR: Could not import from main.py — {exc}")
    print("    Make sure main.py is in the same directory and PySide6 is installed.")
    sys.exit(2)


PASS = "✅"
FAIL = "❌"
WARN = "⚠️"


# ===========================================================================
# Helper Utilities
# ===========================================================================

def load_ground_truth(path):
    """Load and minimally validate the ground-truth JSON file."""
    if not os.path.isfile(path):
        print(f"{FAIL}  Ground truth file not found: {path}")
        sys.exit(2)

    with open(path, "r", encoding="utf-8") as f:
        try:
            gt = json.load(f)
        except json.JSONDecodeError as exc:
            print(f"{FAIL}  Invalid JSON in ground truth file: {exc}")
            sys.exit(2)

    if "db_path" not in gt:
        print(f"{FAIL}  Ground truth JSON is missing the required 'db_path' key.")
        sys.exit(2)

    return gt


def parse_timestamp_to_seconds(ts_str):
    """Parse timestamp string into float unix seconds for mathematical delta comparison."""
    if not ts_str:
        return None
    ts_str = str(ts_str).strip()
    
    # Try standard YYYY-MM-DD HH:MM:SS formats
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f', '%Y/%m/%d %H:%M:%S'):
        try:
            return datetime.strptime(ts_str[:19], '%Y-%m-%d %H:%M:%S').timestamp()
        except ValueError:
            pass

    # Try raw numeric epoch
    try:
        val = float(ts_str)
        if val > 1e11:  # milliseconds
            val /= 1000.0
        return val
    except ValueError:
        return None


# ===========================================================================
# STRUCTURED COMPARISON ENGINE
# ===========================================================================

def compare_results(parsed_data, ground_truth):
    """
    Computes a detailed, structured diff comparing parsed output against ground truth.
    
    Parameters:
        parsed_data:  dict with keys: 'messages', 'total_records', 'wal_recovery', 'file_hash'
        ground_truth: dict loaded from ground_truth.json
        
    Returns:
        Structured result dict containing exact match statuses, fuzzy drift details,
        diagnostic hypotheses, pass counts, and failures.
    """
    messages = parsed_data.get("messages", [])
    actual_total = parsed_data.get("total_records", len(messages))
    wal_recovery = parsed_data.get("wal_recovery", {})
    actual_wal_present = wal_recovery.get("wal_present", False)
    actual_recovered_count = wal_recovery.get("recovered_message_count", 0)
    actual_file_hash = parsed_data.get("file_hash", "")

    result = {
        "overall_pass": True,
        "pass_count": 0,
        "total_checks": 0,
        "failed_fields": [],
        "failures_summary": [],
        "details": {}
    }

    # -----------------------------------------------------------------------
    # 1. Total Message Count Check & Diagnostics
    # -----------------------------------------------------------------------
    if "expected_total_messages" in ground_truth:
        result["total_checks"] += 1
        expected_total = ground_truth["expected_total_messages"]
        diff = actual_total - expected_total
        match = (actual_total == expected_total)
        
        diagnostic_hint = None
        if not match:
            result["overall_pass"] = False
            result["failed_fields"].append("total_message_count")
            
            if actual_total < expected_total:
                missing_count = expected_total - actual_total
                expected_wal_rec = ground_truth.get("expected_recovered_message_count")
                
                if expected_wal_rec is not None and missing_count == expected_wal_rec:
                    diagnostic_hint = (
                        f"Missing {missing_count} message(s) matches expected WAL recovery count ({expected_wal_rec}). "
                        f"Uncommitted WAL log data may not have been parsed or merged properly."
                    )
                elif missing_count == actual_recovered_count and actual_recovered_count > 0:
                    diagnostic_hint = (
                        f"Missing {missing_count} message(s) matches detected WAL recovery count ({actual_recovered_count}). "
                        f"Check if WAL log checkpoint isolation omitted uncommitted rows."
                    )
                else:
                    media_null_count = sum(1 for m in messages if m.get("content") == "[Media]" or not m.get("content"))
                    if missing_count <= media_null_count and media_null_count > 0:
                        diagnostic_hint = (
                            f"Missing {missing_count} message(s) may be NULL/media-only records that were filtered or omitted "
                            f"during database SELECT column mapping."
                        )
                    else:
                        diagnostic_hint = (
                            f"Missing {missing_count} message(s). Check for missing chat tables or incomplete "
                            f"cursor.fetchmany pagination."
                        )
            else:
                extra_count = actual_total - expected_total
                diagnostic_hint = (
                    f"Unusual: Parsed count exceeds expected count by {extra_count}. Possible duplicate row parsing bug "
                    f"(e.g., duplicate JOIN matches across schema variations)."
                )
            
            result["failures_summary"].append({
                "field": "total_message_count",
                "message": f"Expected {expected_total}, got {actual_total} (diff: {diff:+d}).",
                "hypothesis": diagnostic_hint
            })
        else:
            result["pass_count"] += 1

        result["details"]["total_message_count"] = {
            "expected": expected_total,
            "actual": actual_total,
            "match": match,
            "diff": diff,
            "diagnostic_hint": diagnostic_hint
        }

    # -----------------------------------------------------------------------
    # 2. Known Messages Check & Fuzzy Drift Engine
    # -----------------------------------------------------------------------
    known_msgs = ground_truth.get("known_messages", [])
    known_results = []
    
    for idx, known in enumerate(known_msgs):
        result["total_checks"] += 1
        sender = known.get("sender")
        timestamp = known.get("timestamp")
        content_substr = known.get("content_contains", "")
        target_ts_sec = parse_timestamp_to_seconds(timestamp)

        # Step A: Check for exact match
        exact_candidates = [
            m for m in messages
            if m.get("sender") == sender and m.get("timestamp") == timestamp and content_substr in m.get("content", "")
        ]

        if exact_candidates:
            result["pass_count"] += 1
            known_results.append({
                "index": idx + 1,
                "expected": known,
                "found": True,
                "match_type": "exact",
                "match_details": "exact match on sender + timestamp + content",
                "timestamp_delta_seconds": 0.0,
                "matched_message": exact_candidates[0]
            })
            continue

        # Step B: Check for fuzzy timestamp drift (content + sender match, timestamp drift <= 60s)
        drift_match = None
        min_delta = None

        for m in messages:
            if m.get("sender") == sender and content_substr in m.get("content", ""):
                m_ts_sec = parse_timestamp_to_seconds(m.get("timestamp"))
                if target_ts_sec is not None and m_ts_sec is not None:
                    delta = abs(m_ts_sec - target_ts_sec)
                    if delta <= 60.0:
                        if min_delta is None or delta < min_delta:
                            min_delta = delta
                            drift_match = (m, m_ts_sec - target_ts_sec)

        if drift_match:
            matched_msg, delta_sec = drift_match
            result["pass_count"] += 1
            known_results.append({
                "index": idx + 1,
                "expected": known,
                "found": True,
                "match_type": "partial_timestamp_drift",
                "match_details": f"partial match: content matched, timestamp drift of {delta_sec:+.1f} seconds",
                "timestamp_delta_seconds": round(delta_sec, 2),
                "matched_message": matched_msg
            })
            continue

        # Step C: No match found — locate up to 3 closest candidates for diagnostics
        result["overall_pass"] = False
        result["failed_fields"].append(f"known_messages[{idx}]")

        candidates = []
        for m in messages:
            m_sender = m.get("sender")
            m_content = m.get("content", "")
            if m_sender == sender or content_substr in m_content:
                m_ts_sec = parse_timestamp_to_seconds(m.get("timestamp"))
                dist = abs(m_ts_sec - target_ts_sec) if (target_ts_sec and m_ts_sec) else 99999999
                candidates.append((dist, m))

        candidates.sort(key=lambda x: x[0])
        top_candidates = []
        for dist, cand_msg in candidates[:3]:
            cand_ts_sec = parse_timestamp_to_seconds(cand_msg.get("timestamp"))
            d_sec = (cand_ts_sec - target_ts_sec) if (target_ts_sec and cand_ts_sec) else None
            top_candidates.append({
                "sender": cand_msg.get("sender"),
                "timestamp": cand_msg.get("timestamp"),
                "content": cand_msg.get("content"),
                "timestamp_delta_seconds": round(d_sec, 2) if d_sec is not None else None
            })

        hypothesis = (
            f"Expected message from '{sender}' at '{timestamp}' containing '{content_substr}' not found. "
        )
        if top_candidates:
            c0 = top_candidates[0]
            hypothesis += f"Nearest candidate timestamp is off by {c0['timestamp_delta_seconds']:+.1f}s — check timestamp formatting or SQLite timezone offset."
        else:
            hypothesis += "No messages found from this sender or containing this text substring."

        result["failures_summary"].append({
            "field": f"known_messages[{idx}]",
            "message": f"Known message #{idx + 1} (sender='{sender}', timestamp='{timestamp}') not found.",
            "hypothesis": hypothesis
        })

        known_results.append({
            "index": idx + 1,
            "expected": known,
            "found": False,
            "match_type": "none",
            "match_details": "no matching message found within 60s window",
            "closest_candidates": top_candidates
        })

    if known_msgs:
        result["details"]["known_messages"] = known_results

    # -----------------------------------------------------------------------
    # 3. WAL Presence Check
    # -----------------------------------------------------------------------
    if "expected_wal_present" in ground_truth:
        result["total_checks"] += 1
        expected_wal = ground_truth["expected_wal_present"]
        match = (actual_wal_present == expected_wal)
        
        if not match:
            result["overall_pass"] = False
            result["failed_fields"].append("wal_present")
            result["failures_summary"].append({
                "field": "wal_present",
                "message": f"Expected WAL present={expected_wal}, got {actual_wal_present}.",
                "hypothesis": "WAL log file (.db-wal) missing or not detected alongside database file."
            })
        else:
            result["pass_count"] += 1

        result["details"]["wal_present"] = {
            "expected": expected_wal,
            "actual": actual_wal_present,
            "match": match
        }

    # -----------------------------------------------------------------------
    # 4. Recovered Message Count Check
    # -----------------------------------------------------------------------
    if "expected_recovered_message_count" in ground_truth:
        result["total_checks"] += 1
        expected_rec = ground_truth["expected_recovered_message_count"]
        match = (actual_recovered_count == expected_rec)
        
        if not match:
            result["overall_pass"] = False
            result["failed_fields"].append("recovered_message_count")
            result["failures_summary"].append({
                "field": "recovered_message_count",
                "message": f"Expected recovered count={expected_rec}, got {actual_recovered_count}.",
                "hypothesis": "WAL recovery differential parsing mismatch — check checkpointed snapshot comparison logic."
            })
        else:
            result["pass_count"] += 1

        result["details"]["recovered_message_count"] = {
            "expected": expected_rec,
            "actual": actual_recovered_count,
            "match": match
        }

    # -----------------------------------------------------------------------
    # 5. File Hash Check
    # -----------------------------------------------------------------------
    if "known_file_hash" in ground_truth:
        result["total_checks"] += 1
        expected_hash = ground_truth["known_file_hash"].strip()
        if not expected_hash.startswith("sha256:"):
            expected_hash = f"sha256:{expected_hash}"
            
        actual_prefixed = f"sha256:{actual_file_hash}"
        match = (actual_prefixed == expected_hash)
        
        if not match:
            result["overall_pass"] = False
            result["failed_fields"].append("file_hash")
            result["failures_summary"].append({
                "field": "file_hash",
                "message": f"File hash mismatch.",
                "hypothesis": "Database file modified on disk or different snapshot provided in ground truth."
            })
        else:
            result["pass_count"] += 1

        result["details"]["file_hash"] = {
            "expected": expected_hash,
            "actual": actual_prefixed,
            "match": match
        }

    return result


# ===========================================================================
# REPORT PRINTER
# ===========================================================================

def print_report(res, db_path, gt_path, logs=None):
    """Prints a clean human-readable CLI report with inline diagnostics and summary."""
    print("=" * 60)
    print("WhtsSec Forensic Tool — Ground-Truth Validation Report")
    print("=" * 60)
    print(f"  Database:     {db_path}")
    print(f"  Ground Truth: {os.path.abspath(gt_path)}")
    print()

    if logs:
        print("Parser log output:")
        for log_line in logs:
            print(f"  {log_line}")
        print()

    print("Running checks...")

    # 1. Total message count
    tmc = res["details"].get("total_message_count")
    if tmc:
        if tmc["match"]:
            print(f"  {PASS}  Total message count: {tmc['actual']} == {tmc['expected']}")
        else:
            print(f"  {FAIL}  Total message count: got {tmc['actual']}, expected {tmc['expected']} (diff: {tmc['diff']:+d})")
            if tmc.get("diagnostic_hint"):
                print(f"      💡 Diagnostic: {tmc['diagnostic_hint']}")

    # 2. Known messages
    km_list = res["details"].get("known_messages", [])
    for km in km_list:
        idx = km["index"]
        expected = km["expected"]
        sender = expected.get("sender")
        timestamp = expected.get("timestamp")
        content_substr = expected.get("content_contains", "")

        if km["match_type"] == "exact":
            print(f"  {PASS}  Known message #{idx}: sender='{sender}', timestamp='{timestamp}', content contains '{content_substr}' (exact match)")
        elif km["match_type"] == "partial_timestamp_drift":
            matched = km["matched_message"]
            delta = km["timestamp_delta_seconds"]
            print(f"  {WARN}  Known message #{idx}: sender='{sender}' — partial match (timestamp drift of {delta:+.1f}s: actual '{matched.get('timestamp')}')")
        else:
            print(f"  {FAIL}  Known message #{idx}: sender='{sender}' at timestamp='{timestamp}' — NOT FOUND")
            candidates = km.get("closest_candidates", [])
            if candidates:
                print(f"      💡 Diagnostic: No exact match for sender='{sender}' containing '{content_substr}'.")
                print(f"      Closest candidates:")
                for c_idx, cand in enumerate(candidates, 1):
                    delta_str = f"{cand['timestamp_delta_seconds']:+.1f}s" if cand['timestamp_delta_seconds'] is not None else "N/A"
                    print(f"        {c_idx}. sender='{cand['sender']}', timestamp='{cand['timestamp']}', content='{cand['content']}' (delta: {delta_str})")

    # 3. WAL present
    wp = res["details"].get("wal_present")
    if wp:
        if wp["match"]:
            print(f"  {PASS}  WAL present: {wp['actual']} == {wp['expected']}")
        else:
            print(f"  {FAIL}  WAL present: got {wp['actual']}, expected {wp['expected']}")

    # 4. Recovered message count
    rmc = res["details"].get("recovered_message_count")
    if rmc:
        if rmc["match"]:
            print(f"  {PASS}  Recovered message count: {rmc['actual']} == {rmc['expected']}")
        else:
            print(f"  {FAIL}  Recovered message count: got {rmc['actual']}, expected {rmc['expected']}")

    # 5. File hash
    fh = res["details"].get("file_hash")
    if fh:
        if fh["match"]:
            print(f"  {PASS}  File hash: {fh['actual']}")
        else:
            print(f"  {FAIL}  File hash mismatch:")
            print(f"         Got:      {fh['actual']}")
            print(f"         Expected: {fh['expected']}")

    # -----------------------------------------------------------------------
    # --- SUMMARY ---
    # -----------------------------------------------------------------------
    pass_count = res["pass_count"]
    total_checks = res["total_checks"]
    pct = (pass_count / total_checks * 100.0) if total_checks > 0 else 0.0

    print()
    print("=" * 60)
    print("--- SUMMARY ---")
    print("=" * 60)
    print(f"Pass Rate: {pass_count}/{total_checks} checks passed ({pct:.1f}%)")

    if res["failures_summary"]:
        print("\nFailed / Warning Fields:")
        for fail in res["failures_summary"]:
            print(f"  • {fail['field']}: {fail['message']}")
            if fail.get('hypothesis'):
                print(f"    Hypothesis: {fail['hypothesis']}")

    print("=" * 60)


# ===========================================================================
# MAIN DRIVER
# ===========================================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_ground_truth.py <ground_truth.json> [--save-report [output_file.json]]")
        sys.exit(2)

    gt_path = sys.argv[1]
    
    # Parse CLI flags
    save_report = False
    report_filename = "comparison_report.json"
    
    if "--save-report" in sys.argv:
        save_report = True
        idx = sys.argv.index("--save-report")
        if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith("-"):
            report_filename = sys.argv[idx + 1]

    gt = load_ground_truth(gt_path)

    db_path = gt["db_path"]
    if not os.path.isabs(db_path):
        gt_dir = os.path.dirname(os.path.abspath(gt_path))
        db_path = os.path.join(gt_dir, db_path)

    if not os.path.isfile(db_path):
        print(f"{FAIL}  Database file not found: {db_path}")
        sys.exit(2)

    logs = []

    # Run parsing (same logic as the app)
    try:
        messages, total_records, wal_recovery = parse_database_standalone(
            db_path,
            log_fn=lambda msg: logs.append(msg),
        )
    except RuntimeError as exc:
        print(f"{FAIL}  parse_database_standalone raised an error:")
        print(f"    {exc}")
        print()
        print(f"RESULT: 0/? checks passed — parsing failed before checks could run")
        sys.exit(1)

    file_hash = compute_sha256_standalone(db_path)

    parsed_data = {
        "messages": messages,
        "total_records": total_records,
        "wal_recovery": wal_recovery,
        "file_hash": file_hash
    }

    # Run comparison engine
    res = compare_results(parsed_data, gt)

    # Print human readable report
    print_report(res, db_path, gt_path, logs=logs)

    # Optionally write report to JSON file
    if save_report:
        report_dir = os.path.dirname(os.path.abspath(report_filename))
        if report_dir:
            os.makedirs(report_dir, exist_ok=True)
        with open(report_filename, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=4)
        print(f"\n[INFO] Detailed structured report saved to: {os.path.abspath(report_filename)}")

    sys.exit(0 if res["overall_pass"] else 1)


if __name__ == "__main__":
    main()
