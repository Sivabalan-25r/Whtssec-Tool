#!/usr/bin/env python3
"""
e2e_checklist.py — End-to-End Manual Testing Interactive Checklist and Logger
for the WhtsSec Forensic Tool.

This tool guides the investigator through a physical, physical-device-linked manual
test of the WhtsSec application, logging verification results and saving a timestamped
audit report to document compliance and repeatable test execution.
"""

import os
import sys
import json
from datetime import datetime

# Enforce UTF-8 output on Windows consoles to prevent encoding crashes
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CHECKLIST_DATA = [
    {
        "step_id": "home_page_load",
        "page": "Home / Dashboard",
        "expected_behavior": "Home page loads correctly. The 'New Case' button is visible and clickable.",
        "verification_method": "Confirm the application window displays the home dashboard with historical case tables and a green/yellow status, and that clicking 'New Case' transitions the UI.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "case_setup_form",
        "page": "New Case",
        "expected_behavior": "Case setup form accepts investigator inputs and navigates to the Evidence Ingestion page on submit.",
        "verification_method": "Fill in the Case Name, Investigator Name, and Output Directory in the form. Submit the form and verify the page shifts to 'Evidence Ingestion'.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "ingestion_waiting_device",
        "page": "Evidence Ingestion",
        "expected_behavior": "Evidence Ingestion shows 'Waiting for device' before a device is connected.",
        "verification_method": "Observe the device status indicator at the center of the page. It must display 'Waiting for device' or similar before plugging in the physical phone.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "unauthorized_device_prompt",
        "page": "Evidence Ingestion",
        "expected_behavior": "On connecting an unauthorized device, the status updates to a 'Waiting for authorization' prompt.",
        "verification_method": "Connect the physical Android phone via USB (with USB debugging enabled but unauthorized). Confirm the status in the UI transitions to 'waiting for authorization'.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "authorized_auto_transition",
        "page": "Evidence Ingestion / Extraction Progress",
        "expected_behavior": "On tapping Allow on the physical phone, status updates to 'authorized' and auto-transitions to Extraction Progress.",
        "verification_method": "Tap 'Allow USB Debugging' on the phone. Confirm the status changes to 'authorized' and that the screen automatically transitions to 'Extraction Progress' within a second.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "extraction_progress_updates",
        "page": "Extraction Progress",
        "expected_behavior": "Progress bar and log panel update live during extraction (not frozen/static).",
        "verification_method": "Ensure the progress bar moves as records are fetched and the log panel updates with active pipeline stages. Verify the window is responsive to drag/move operations during this process.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "completion_auto_navigation",
        "page": "Report",
        "expected_behavior": "On completion, the application auto-navigates to the Report page.",
        "verification_method": "Once extraction and ingestion complete, confirm the view changes automatically from 'Extraction Progress' to the 'Forensic Report' tabbed panel.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "report_messages_tab",
        "page": "Report - Messages Tab",
        "expected_behavior": "Messages tab: row count matches what was independently counted in DB Browser for SQLite; spot-check 3 specific messages against known content.",
        "verification_method": "Compare the message count on the dashboard against the count from opening the sqlite DB in DB Browser. Verify 3 messages match the contents defined in ground_truth.json (e.g. sender, content snippet).",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "report_device_info_tab",
        "page": "Report - Device Info Tab",
        "expected_behavior": "Device Info tab: model/Android version match the actual physical device being tested.",
        "verification_method": "Cross-check the model number and Android OS version displayed in the tab against the device settings in 'About Phone' on the physical handset.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "report_hashes_tab",
        "page": "Report - Hashes Tab",
        "expected_behavior": "Hashes tab: hash values match independent verify_hash.py output for the same files.",
        "verification_method": "Run 'python verify_hash.py --from-report <report_path>' or manually hash the database/log files and verify the hash strings match the values displayed in the Hashes tab.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "report_media_tab",
        "page": "Report - Media Tab",
        "expected_behavior": "Media tab: thumbnail count and a few spot-checked files match what's actually in the device's WhatsApp/Media/ folder.",
        "verification_method": "Count the extracted media items in output directory. Verify a few image/video thumbnails match actual media stored under the phone's WhatsApp media folder.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "report_timeline_tab",
        "page": "Report - Timeline Tab",
        "expected_behavior": "Timeline tab: entries are in chronological order, WAL-recovered messages (if any) appear flagged.",
        "verification_method": "Verify that timestamps increment sequentially. If WAL recovery occurred, look for the 'Recovered' column/flag indicating WAL-sourced records.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "export_reports_formats",
        "page": "Export Page",
        "expected_behavior": "Generate a report in each of the three formats (PDF/CSV/HTML), confirm each opens correctly and contains the expected sections.",
        "verification_method": "Click export for PDF, CSV, and HTML formats. Open each exported file in its default viewer (browser/excel/PDF viewer). Check for sections: Summary, Messages, and Integrity Hashes.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "settings_persistence",
        "page": "Settings Page",
        "expected_behavior": "Change a path (e.g. default output path or ADB path), save, restart app, confirm the value persisted.",
        "verification_method": "Go to settings, modify a path, and click 'Save Settings'. Exit the app, launch it again, and check if the field displays the updated value.",
        "result": None,
        "notes": ""
    },
    {
        "step_id": "case_audit_log",
        "page": "About / Case Log Page",
        "expected_behavior": "Confirms this run's actions appear in the audit trail with correct timestamps.",
        "verification_method": "Go to 'About / Case Log'. Review the table list to verify logs exist for 'Case Initialization', 'ADB Connection', 'Extraction Start', and 'Extraction Finished' with accurate timestamps.",
        "result": None,
        "notes": ""
    }
]

def show_banner():
    print("=" * 80)
    print("                WHTSSEC FORENSIC TOOL — MANUAL E2E TEST CHECKLIST                ")
    print("=" * 80)
    print("  This runner guides you through manual testing using a physical Android device.")
    print("  For each step, perform the action in the app UI, verify the behavior, and")
    print("  input the result (Pass/Fail/Skip). Results will be saved to a JSON file.")
    print("=" * 80 + "\n")

def get_input(prompt, choices):
    while True:
        val = input(prompt).strip().lower()
        if val in choices:
            return val
        print(f"Invalid input. Please choose from: {', '.join(choices)}")

def main():
    show_banner()
    
    checklist = [dict(item) for item in CHECKLIST_DATA]
    total_steps = len(checklist)
    
    for idx, item in enumerate(checklist, 1):
        print("-" * 80)
        print(f"STEP {idx}/{total_steps}: {item['step_id'].upper()}")
        print(f"Page:         {item['page']}")
        print(f"Expected:     {item['expected_behavior']}")
        print(f"Verify:       {item['verification_method']}")
        print("-" * 80)
        
        choice = get_input("Result -> [P]ass, [F]ail, [S]kip, [Q]uit test run: ", ["p", "f", "s", "q"])
        
        if choice == "q":
            print("\n[!] Test run aborted by investigator. Saving partial progress...")
            break
        elif choice == "p":
            item["result"] = "pass"
            notes = input("Optional notes/observations: ").strip()
            item["notes"] = notes
            print("✅ Marked as PASSED.")
        elif choice == "f":
            item["result"] = "fail"
            notes = input("Required notes detailing failure: ").strip()
            while not notes:
                print("Failure notes cannot be empty.")
                notes = input("Required notes detailing failure: ").strip()
            item["notes"] = notes
            print("❌ Marked as FAILED.")
        elif choice == "s":
            item["result"] = "skip"
            reason = input("Required reason for skipping: ").strip()
            while not reason:
                print("Skip reason cannot be empty.")
                reason = input("Required reason for skipping: ").strip()
            item["notes"] = f"Skipped: {reason}"
            print("⚠️ Marked as SKIPPED.")
        print()

    # Generate timestamped filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    filename = f"e2e_run_{timestamp}.json"
    
    # Save output to JSON
    run_summary = {
        "timestamp": datetime.now().isoformat(),
        "total_steps": total_steps,
        "results": checklist
    }
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(run_summary, f, indent=4)
        
    # Calculate stats
    passed = sum(1 for item in checklist if item["result"] == "pass")
    failed = sum(1 for item in checklist if item["result"] == "fail")
    skipped = sum(1 for item in checklist if item["result"] == "skip")
    incomplete = sum(1 for item in checklist if item["result"] is None)
    
    print("=" * 80)
    print("                               TEST RUN SUMMARY                                ")
    print("=" * 80)
    print(f"Saved results to: {os.path.abspath(filename)}")
    print(f"Total Steps:      {total_steps}")
    print(f"Passed:           {passed}")
    print(f"Failed:           {failed}")
    print(f"Skipped:          {skipped}")
    if incomplete > 0:
        print(f"Incomplete/Aborted: {incomplete}")
    print("-" * 80)
    
    if failed > 0:
        print("\nFailed Steps:")
        for item in checklist:
            if item["result"] == "fail":
                print(f"  - [{item['page']}] {item['step_id']}: {item['notes']}")
                
    if skipped > 0:
        print("\nSkipped Steps:")
        for item in checklist:
            if item["result"] == "skip":
                print(f"  - [{item['page']}] {item['step_id']}: {item['notes']}")
                
    print("\n" + "=" * 80)

if __name__ == "__main__":
    main()
