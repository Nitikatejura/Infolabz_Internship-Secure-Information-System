"""
Browser Forensic Acquisition & Artifact Parser Engine (core/browser_forensic_toolkit.py)
Features:
- Automated Google Chrome & Microsoft Edge Browser History DB discovery.
- Safe Shadow Copying via tempfile and shutil.copy2 to bypass SQLite database locks.
- Chrome WebKit Microsecond Epoch Timestamp Conversion (Base: Jan 1, 1601 UTC).
- Domain Visit Aggregation & Top Domain Frequency Analysis.
- Google Search Query Intent Extraction (q= parameter parsing).
- Export Capabilities to JSON and CSV in reports/ directory.
"""

import csv
import json
import os
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs

from core.database import log_event, save_scan_result

def get_possible_chrome_history_paths() -> List[str]:
    """Generates standard candidate file paths for Chrome and Edge history databases on Windows."""
    user_home = os.path.expanduser("~")
    candidates = [
        os.path.join(user_home, r"AppData\Local\Google\Chrome\User Data\Default\History"),
        os.path.join(user_home, r"AppData\Local\Google\Chrome\User Data\Profile 1\History"),
        os.path.join(user_home, r"AppData\Local\Google\Chrome\User Data\Profile 22\History"),
        os.path.join(user_home, r"AppData\Local\Microsoft\Edge\User Data\Default\History")
    ]
    return [p for p in candidates if os.path.exists(p)]

def convert_chrome_timestamp(microsec_timestamp: int) -> str:
    """Converts WebKit microsecond epoch timestamp (starting 1601-01-01 UTC) to formatted string."""
    try:
        base_time = datetime(1601, 1, 1)
        converted_time = base_time + timedelta(microseconds=microsec_timestamp)
        return converted_time.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Unknown Date"

def parse_browser_history(db_path: str, limit: int = 100) -> Dict[str, Any]:
    """
    Safely copies the SQLite history DB to a temp location and parses browser activity metrics.
    """
    start_time = time.time()

    if not os.path.exists(db_path):
        raise FileNotFoundError(f"History database file not found at: {db_path}")

    # Create temporary copy to avoid database locks
    temp_dir = tempfile.mkdtemp()
    temp_db_path = os.path.join(temp_dir, "History_ShadowCopy.db")

    try:
        shutil.copy2(db_path, temp_db_path)
        
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time 
            FROM urls 
            ORDER BY last_visit_time DESC 
            LIMIT ?;
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()

    finally:
        # Cleanup temp file and directory
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)
        if os.path.exists(temp_dir):
            os.rmdir(temp_dir)

    history_records = []
    domain_stats = {}
    total_visits = 0
    search_queries = []
    seen_queries = set()

    for url, title, visit_count, last_visit_time in rows:
        if not url:
            continue

        formatted_time = convert_chrome_timestamp(last_visit_time)
        history_records.append({
            "url": url,
            "title": title or "Untitled",
            "visit_count": visit_count,
            "last_visit_time": formatted_time
        })

        # Domain Aggregation
        domain = urlparse(url).netloc.replace("www.", "").lower()
        if domain:
            total_visits += visit_count
            domain_stats[domain] = domain_stats.get(domain, 0) + visit_count

        # Google Search Query Parsing
        if "google.com/search" in url:
            parsed = parse_qs(urlparse(url).query)
            q_list = parsed.get("q")
            if q_list and q_list[0] not in seen_queries:
                seen_queries.add(q_list[0])
                search_queries.append(q_list[0])

    sorted_domains = sorted(domain_stats.items(), key=lambda x: x[1], reverse=True)
    top_10_domains = [{"domain": d, "visits": v} for d, v in sorted_domains[:10]]

    report = {
        "db_source": db_path,
        "total_records_parsed": len(rows),
        "total_website_visits": total_visits,
        "unique_domains_count": len(domain_stats),
        "top_domains": top_10_domains,
        "recent_search_queries": search_queries[:15],
        "recent_history_samples": history_records[:20]
    }

    elapsed_ms = (time.time() - start_time) * 1000
    log_id = log_event("browser_forensic_toolkit", "browser_history_audit", db_path, "SUCCESS", "INFO", elapsed_ms)
    save_scan_result(log_id, "browser_forensic_report", report)

    return report

def export_browser_report(report_data: Dict[str, Any], output_format: str = "json") -> str:
    """Exports browser forensic report to reports/ directory in JSON or CSV format."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_format.lower() == "csv":
        out_path = os.path.join(reports_dir, f"browser_history_{timestamp_str}.csv")
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Detail", "Count / Time"])
            for d in report_data["top_domains"]:
                writer.writerow(["Top Domain", d["domain"], d["visits"]])
            for q in report_data["recent_search_queries"]:
                writer.writerow(["Search Query", q, "-"])
            for r in report_data["recent_history_samples"]:
                writer.writerow(["History Record", r["url"], r["last_visit_time"]])
    else:
        out_path = os.path.join(reports_dir, f"browser_history_{timestamp_str}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)

    return out_path

def run_interactive():
    """Interactive CLI interface for Browser Forensic Engine."""
    print("\n" + "=" * 50)
    print(" BROWSER EVIDENCE ACQUISITION & FORENSIC ENGINE")
    print("=" * 50)
    
    candidates = get_possible_chrome_history_paths()
    if candidates:
        print("\nDiscovered Browser History Databases:")
        for idx, path in enumerate(candidates, 1):
            print(f"  [{idx}] {path}")
        print(f"  [{len(candidates) + 1}] Enter custom file path")
        
        choice = input(f"\nSelect option (1-{len(candidates) + 1}): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(candidates):
            target_db = candidates[int(choice) - 1]
        else:
            target_db = input("Enter SQLite History File Path: ").strip()
    else:
        target_db = input("Enter Chrome/Edge History SQLite File Path: ").strip()

    if not target_db or not os.path.exists(target_db):
        print("[-] Error: History database path does not exist.")
        return

    print(f"\n[*] Extracting shadow copy and parsing browser artifacts...")
    try:
        report = parse_browser_history(target_db)
        print("\n" + "-" * 50)
        print(" BROWSER FORENSIC SUMMARY")
        print("-" * 50)
        print(f" History Source Database : {report['db_source']}")
        print(f" Total Records Extracted  : {report['total_records_parsed']}")
        print(f" Total Visited Web Pages  : {report['total_website_visits']}")
        print(f" Unique Domains Tracked   : {report['unique_domains_count']}")

        print("\n TOP 10 MOST VISITED DOMAINS:")
        for idx, item in enumerate(report["top_domains"], 1):
            print(f"   {idx:2d}. {item['domain']:35s} ({item['visits']} visits)")

        if report["recent_search_queries"]:
            print("\n RECENT GOOGLE SEARCH QUERIES:")
            for idx, q in enumerate(report["recent_search_queries"][:8], 1):
                print(f"   {idx:2d}. {q}")

        exp = input("\nExport findings to file? [j=JSON / c=CSV / n=No]: ").strip().lower()
        if exp == "j":
            out_f = export_browser_report(report, "json")
            print(f"[+] Report exported to: {out_f}")
        elif exp == "c":
            out_f = export_browser_report(report, "csv")
            print(f"[+] Report exported to: {out_f}")

    except Exception as e:
        print(f"[-] Forensic Extraction Error: {e}")

if __name__ == "__main__":
    run_interactive()
