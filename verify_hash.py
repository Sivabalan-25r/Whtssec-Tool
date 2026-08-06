#!/usr/bin/env python3
"""
verify_hash.py — Standalone SHA-256 Cryptographic Integrity Verification Tool
                 for WhtsSec Forensic Tool

Independently verifies file evidence integrity against expected SHA-256 hashes.
Cross-checks the app's hash function (from main.py) against an independent 8KB-buffer
hash algorithm to guarantee implementation consistency and evidence authenticity.

Modes:
1. Direct File Verification:
   python verify_hash.py <file_path> <expected_hash>

2. Report Lookup Verification:
   python verify_hash.py <file_path> --from-report <hashes_report.json>

3. Batch Directory Verification:
   python verify_hash.py --batch <hashes_report.json> <evidence_folder>

Exit Code:
    0 — All hashes matched and verified cleanly
    1 — One or more hash mismatches detected
    2 — Usage or configuration error
"""

import sys
import os
import json
import hashlib

# Ensure stdout/stderr handle UTF-8 symbols cleanly on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Import the app's hash implementation from main.py
try:
    from main import compute_sha256_standalone
except ImportError as exc:
    print(f"❌  IMPORT ERROR: Could not import compute_sha256_standalone from main.py — {exc}")
    print("    Make sure main.py is in the same directory and dependencies are installed.")
    sys.exit(2)


PASS = "✅"
FAIL = "❌"


# ===========================================================================
# Independent Cross-Check Hashing Algorithm
# ===========================================================================

def compute_sha256_independent(filepath):
    """
    Independent SHA-256 algorithm reading 8192-byte (8KB) chunks.
    Serves as an independent cross-check against main.py's 65536-byte (64KB) implementation.
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ===========================================================================
# Report Parser Utility
# ===========================================================================

def extract_hashes_from_report(report_path):
    """
    Extracts a filename (basename) -> sha256_hash mapping from a WhtsSec report JSON file.
    Supports list format, dict format with 'hashes'/'media' keys, or simple KV dicts.
    """
    if not os.path.isfile(report_path):
        print(f"{FAIL}  Report file not found: {report_path}")
        sys.exit(2)

    with open(report_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            print(f"{FAIL}  Invalid JSON in report file: {exc}")
            sys.exit(2)

    mapping = {}

    def clean_hash(h_val):
        h = str(h_val).strip().lower()
        if h.startswith("sha256:"):
            h = h[7:]
        return h

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                fname = item.get("file") or item.get("filename") or item.get("filepath") or item.get("file_path")
                hval = item.get("hash") or item.get("sha256")
                if fname and hval:
                    mapping[os.path.basename(fname)] = clean_hash(hval)

    elif isinstance(data, dict):
        if "hashes" in data and isinstance(data["hashes"], list):
            for item in data["hashes"]:
                fname = item.get("file") or item.get("filename")
                hval = item.get("hash")
                if fname and hval:
                    mapping[os.path.basename(fname)] = clean_hash(hval)

        if "media" in data and isinstance(data["media"], list):
            for item in data["media"]:
                fname = item.get("filename") or item.get("filepath")
                hval = item.get("hash")
                if fname and hval:
                    mapping[os.path.basename(fname)] = clean_hash(hval)

        for k, v in data.items():
            if isinstance(v, str):
                cv = clean_hash(v)
                if len(cv) == 64:
                    mapping[os.path.basename(k)] = cv

    return mapping


# ===========================================================================
# Single-File Verification Mode
# ===========================================================================

def verify_single_file(filepath, expected_hash):
    """
    Computes both app-method and independent-method hashes for a file,
    verifies internal consistency, and compares against the expected hash.
    """
    if not os.path.isfile(filepath):
        print(f"{FAIL}  Target file not found: {filepath}")
        return False

    app_hash = compute_sha256_standalone(filepath)
    indep_hash = compute_sha256_independent(filepath)

    norm_expected = expected_hash.strip().lower()
    if norm_expected.startswith("sha256:"):
        norm_expected = norm_expected[7:]

    internal_match = (app_hash.lower() == indep_hash.lower())
    app_match = (app_hash.lower() == norm_expected)
    indep_match = (indep_hash.lower() == norm_expected)
    all_match = internal_match and app_match and indep_match

    print("=" * 65)
    print("WhtsSec Forensic Tool — SHA-256 Integrity Verification")
    print("=" * 65)
    print(f"Target File:       {os.path.abspath(filepath)}")
    print(f"Expected Hash:     sha256:{norm_expected}")
    print()
    print(f"App Method Hash:   sha256:{app_hash} (64KB buffer)")
    print(f"Independent Hash:  sha256:{indep_hash} (8KB buffer)")
    print()

    if internal_match:
        print(f"  {PASS}  Internal Cross-Check: App algorithm matches Independent algorithm")
    else:
        print(f"  {FAIL}  Internal Cross-Check: MISMATCH between App algorithm and Independent algorithm!")

    if all_match:
        print(f"  {PASS}  Verification Result:  MATCH (Evidence integrity verified)")
    else:
        print(f"  {FAIL}  Verification Result:  MISMATCH (Evidence integrity check failed!)")

    print("=" * 65)
    return all_match


# ===========================================================================
# Batch Verification Mode
# ===========================================================================

def verify_batch(report_path, evidence_folder):
    """
    Verifies every file listed in a report JSON against evidence files inside evidence_folder.
    Renders a formatted table and returns True if all files match.
    """
    if not os.path.isdir(evidence_folder):
        print(f"{FAIL}  Evidence folder not found: {evidence_folder}")
        return False

    mapping = extract_hashes_from_report(report_path)
    if not mapping:
        print(f"{FAIL}  No file hashes found in report: {report_path}")
        return False

    # Collect available files in evidence_folder (indexed by basename)
    file_pool = {}
    for root, dirs, files in os.walk(evidence_folder):
        for f in files:
            file_pool[f] = os.path.join(root, f)

    print("=" * 95)
    print("WhtsSec Forensic Tool — Batch SHA-256 Evidence Verification")
    print("=" * 95)
    print(f"Evidence Folder: {os.path.abspath(evidence_folder)}")
    print(f"Hash Report:     {os.path.abspath(report_path)}")
    print("-" * 95)
    print(f"{'Filename':<25} {'Expected (short)':<20} {'App Hash (short)':<20} {'Indep Hash':<12} {'Status'}")
    print("-" * 95)

    all_passed = True
    verified_count = 0
    total_count = len(mapping)

    for filename, expected_h in mapping.items():
        exp_short = expected_h[:8] + "..." + expected_h[-8:]
        
        if filename not in file_pool:
            print(f"{filename:<25} {exp_short:<20} {'FILE NOT FOUND':<20} {'N/A':<12} {FAIL} MISSING")
            all_passed = False
            continue

        filepath = file_pool[filename]
        app_h = compute_sha256_standalone(filepath).lower()
        indep_h = compute_sha256_independent(filepath).lower()
        
        app_short = app_h[:8] + "..." + app_h[-8:]

        internal_match = (app_h == indep_h)
        hash_match = (app_h == expected_h) and (indep_h == expected_h)

        if internal_match and hash_match:
            print(f"{filename:<25} {exp_short:<20} {app_short:<20} {'64K==8K OK':<12} {PASS} MATCH")
            verified_count += 1
        else:
            status_str = f"{FAIL} MISMATCH" if not hash_match else f"{FAIL} INT_ERR"
            print(f"{filename:<25} {exp_short:<20} {app_short:<20} {'DIFF':<12} {status_str}")
            all_passed = False

    print("-" * 95)
    if all_passed:
        print(f"  {PASS}  Batch Verification Result: {verified_count}/{total_count} files verified successfully — ALL CLEAR")
    else:
        print(f"  {FAIL}  Batch Verification Result: {verified_count}/{total_count} files verified ({total_count - verified_count} failed or missing)")
    print("=" * 95)

    return all_passed


# ===========================================================================
# MAIN CLI DRIVER
# ===========================================================================

def main():
    args = sys.argv[1:]

    if not args:
        print("Usage:")
        print("  1. Direct Mode:  python verify_hash.py <file_path> <expected_hash>")
        print("  2. Report Mode:  python verify_hash.py <file_path> --from-report <hashes_report.json>")
        print("  3. Batch Mode:   python verify_hash.py --batch <hashes_report.json> <evidence_folder>")
        sys.exit(2)

    # Batch Mode
    if args[0] == "--batch":
        if len(args) < 3:
            print("Usage: python verify_hash.py --batch <hashes_report.json> <evidence_folder>")
            sys.exit(2)
        report_path = args[1]
        folder_path = args[2]
        success = verify_batch(report_path, folder_path)
        sys.exit(0 if success else 1)

    # Report Lookup Mode
    if len(args) >= 3 and args[1] == "--from-report":
        target_file = args[0]
        report_path = args[2]
        mapping = extract_hashes_from_report(report_path)
        base_name = os.path.basename(target_file)
        
        if base_name not in mapping:
            print(f"{FAIL}  Filename '{base_name}' not found in report '{report_path}'.")
            print(f"      Available files in report: {list(mapping.keys())}")
            sys.exit(2)

        expected_hash = mapping[base_name]
        success = verify_single_file(target_file, expected_hash)
        sys.exit(0 if success else 1)

    # Direct Mode
    if len(args) == 2:
        target_file = args[0]
        expected_hash = args[1]
        success = verify_single_file(target_file, expected_hash)
        sys.exit(0 if success else 1)

    print("Usage: python verify_hash.py <file_path> <expected_hash>")
    sys.exit(2)


if __name__ == "__main__":
    main()
