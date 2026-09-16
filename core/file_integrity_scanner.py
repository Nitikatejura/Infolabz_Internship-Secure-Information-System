"""
File Integrity Monitoring (FIM) Engine (core/file_integrity_scanner.py)
Features:
- Recursive directory hashing using SHA-256 with memory-efficient 64KB chunking.
- Persistent baseline storage in SQLite database (integrity_baselines table).
- Real-time directory state diff auditing (Modified, Added, Deleted, Unchanged).
"""

import hashlib
import os
import time
from pathlib import Path
from typing import Dict, List, Tuple
from core.database import log_event, save_baseline, get_baselines, save_scan_result

def compute_sha256_chunked(filepath: str, chunk_size: int = 65536) -> str:
    """Computes SHA-256 hash using chunked binary reading to avoid memory loading overhead."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError):
        return ""

def scan_directory_hashes(target_dir: str) -> Dict[str, str]:
    """Recursively scans a target directory and computes SHA-256 hashes for all files."""
    hashes = {}
    abs_dir = os.path.abspath(target_dir)
    
    for root, _, files in os.walk(abs_dir):
        for file in files:
            full_path = os.path.join(root, file)
            h_val = compute_sha256_chunked(full_path)
            if h_val:
                hashes[full_path] = h_val

    return hashes

def create_and_persist_baseline(target_dir: str) -> int:
    """Generates baseline hashes for target directory and persists them to sis_audit.db."""
    start_time = time.time()
    hashes = scan_directory_hashes(target_dir)
    
    for path, h_val in hashes.items():
        save_baseline(path, h_val, status="BASELINE")
        
    elapsed_ms = (time.time() - start_time) * 1000
    log_id = log_event("file_integrity_scanner", "create_baseline", target_dir, "SUCCESS", "INFO", elapsed_ms)
    save_scan_result(log_id, "fim_baseline_created", {"folder": target_dir, "total_files": len(hashes)})
    return len(hashes)

def audit_directory_integrity(target_dir: str) -> Dict[str, List[str]]:
    """Compares current directory state against saved database baselines."""
    start_time = time.time()
    current_hashes = scan_directory_hashes(target_dir)
    stored_baselines = get_baselines()

    # Filter stored baselines relevant to target_dir
    abs_target = os.path.abspath(target_dir)
    relevant_baselines = {
        k: v for k, v in stored_baselines.items() 
        if k.startswith(abs_target)
    }

    initial_paths = set(relevant_baselines.keys())
    current_paths = set(current_hashes.keys())

    modified = [
        p for p in (initial_paths & current_paths) 
        if relevant_baselines[p] != current_hashes[p]
    ]
    added = list(current_paths - initial_paths)
    deleted = list(initial_paths - current_paths)
    unchanged = [
        p for p in (initial_paths & current_paths) 
        if relevant_baselines[p] == current_hashes[p]
    ]

    # Update database status for modified / deleted / added
    for p in modified:
        save_baseline(p, current_hashes[p], status="MODIFIED")
    for p in added:
        save_baseline(p, current_hashes[p], status="ADDED")
    for p in deleted:
        save_baseline(p, relevant_baselines[p], status="DELETED")

    elapsed_ms = (time.time() - start_time) * 1000
    severity = "WARNING" if (modified or deleted) else "INFO"
    log_id = log_event("file_integrity_scanner", "audit_integrity", target_dir, "SUCCESS", severity, elapsed_ms)
    
    diff_report = {
        "modified": modified,
        "added": added,
        "deleted": deleted,
        "unchanged": unchanged
    }
    save_scan_result(log_id, "fim_audit_report", {
        "folder": target_dir,
        "modified_count": len(modified),
        "added_count": len(added),
        "deleted_count": len(deleted),
        "unchanged_count": len(unchanged)
    })

    return diff_report

def run_interactive():
    """Interactive CLI interface for File Integrity Monitor."""
    print("\n" + "=" * 50)
    print(" FILE INTEGRITY MONITORING (FIM) ENGINE")
    print("=" * 50)
    
    folder = input("Enter Folder Path to Audit: ").strip()
    if not os.path.exists(folder) or not os.path.isdir(folder):
        print("[-] Error: Folder path does not exist.")
        return

    print("\n[1] Create / Reset Baseline Hashes")
    print("[2] Audit Directory Integrity Against Stored Baseline")
    choice = input("\nSelect Option (1-2): ").strip()

    if choice == "1":
        print(f"[*] Generating SHA-256 baselines for: {folder}")
        count = create_and_persist_baseline(folder)
        print(f"[+] Baseline successfully stored in database for {count} files.")
    elif choice == "2":
        print(f"[*] Auditing directory state for: {folder}")
        diff = audit_directory_integrity(folder)
        print("\n" + "-" * 50)
        print(" INTEGRITY AUDIT RESULTS")
        print("-" * 50)
        print(f"[!] Modified Files ({len(diff['modified'])}):")
        for f in diff['modified']:
            print(f"    -> {f}")
        print(f"[+] Added Files    ({len(diff['added'])}):")
        for f in diff['added']:
            print(f"    -> {f}")
        print(f"[-] Deleted Files  ({len(diff['deleted'])}):")
        for f in diff['deleted']:
            print(f"    -> {f}")
        print(f"[=] Unchanged Files ({len(diff['unchanged'])}): Safe")
    else:
        print("[-] Invalid selection.")

if __name__ == "__main__":
    run_interactive()
