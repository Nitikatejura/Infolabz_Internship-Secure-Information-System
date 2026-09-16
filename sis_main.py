"""
Secure Information System (SIS) - Master CLI Suite Launcher (sis_main.py)
Unified Terminal Interface & Security Operations Dashboard
"""

import sys
import os
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import init_db, fetch_audit_logs

# Attempt to import rich for advanced terminal formatting, with fallback to standard ANSI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

def display_banner():
    """Renders stylized application header banner."""
    if RICH_AVAILABLE:
        banner_text = """
 [bold cyan]╔═════════════════════════════════════════════════════════════════════════════╗[/bold cyan]
 [bold cyan]║[/bold cyan]  [bold yellow]SECURE INFORMATION SYSTEM (SIS)[/bold yellow]                                       [bold cyan]║[/bold cyan]
 [bold cyan]║[/bold cyan]  [white]Modular Cyber Defense & Digital Forensics Suite v2.0[/white]                      [bold cyan]║[/bold cyan]
 [bold cyan]╚═════════════════════════════════════════════════════════════════════════════╝[/bold cyan]
        """
        rprint(banner_text)
    else:
        print("=" * 78)
        print(" SECURE INFORMATION SYSTEM (SIS)")
        print(" Modular Cyber Defense & Digital Forensics Suite v2.0")
        print("=" * 78)

def render_menu():
    """Displays the master module selection menu."""
    if RICH_AVAILABLE:
        table = Table(title="[bold green]Available Security & Forensic Modules[/bold green]", show_header=True, header_style="bold magenta")
        table.add_column("Option", style="bold yellow", width=8, justify="center")
        table.add_column("Engine Category", style="cyan", width=26)
        table.add_column("Description", style="white")

        table.add_row("1", "Access Control & Auth", "Password strength, Hash ID, HIBP Leak Checker (k-Anonymity)")
        table.add_row("2", "Cryptographic Digest", "MD5, SHA-256, SHA-512, BLAKE2b hashing & File hashing")
        table.add_row("3", "File Integrity (FIM)", "SHA-256 Chunked Hashing, SQLite Baselines, State Diff Audit")
        table.add_row("4", "Network Scanner", "Asynchronous Concurrent TCP Port Scanner & Banner Grabber")
        table.add_row("5", "Web Threat Recon", "Security Headers Audit, Latency, SSL Cert, Cookie Flags & WHOIS")
        table.add_row("6", "Digital Forensics", "Magic Byte Signature Verification, EXIF, PDF & ZIP Analyzer")
        table.add_row("7", "Browser Forensics", "Chrome/Edge History Extraction, Epoch Timestamps, Query Audit")
        table.add_row("8", "Audit Log Viewer", "View SQLite event audit records from database/sis_audit.db")
        table.add_row("0", "Exit Suite", "Terminate Security Operations Dashboard")

        console.print(table)
    else:
        print("\n--- Available Security & Forensic Modules ---")
        print("  [1] Access Control & Password Security Engine")
        print("  [2] Cryptographic Digest & Hashing Engine")
        print("  [3] File Integrity Monitoring (FIM) Engine")
        print("  [4] High-Performance Async Network Scanner")
        print("  [5] Threat Reconnaissance & Web Header Audit")
        print("  [6] Digital Evidence Artifact Analyzer")
        print("  [7] Browser Evidence Acquisition Engine")
        print("  [8] Interactive Audit Log Viewer (SQLite DB)")
        print("  [0] Exit Suite")

def view_audit_logs():
    """Queries and renders recent system event audit logs from database/sis_audit.db."""
    logs = fetch_audit_logs(limit=25)
    
    if RICH_AVAILABLE:
        table = Table(title="[bold blue]Recent System Audit Logs (database/sis_audit.db)[/bold blue]", show_header=True, header_style="bold yellow")
        table.add_column("ID", style="cyan", width=5)
        table.add_column("Timestamp", style="white", width=20)
        table.add_column("Module", style="green", width=22)
        table.add_column("Action", style="magenta", width=22)
        table.add_column("Status", style="bold white", width=10)
        table.add_column("Execution Time", style="yellow", width=15)

        for log in logs:
            status_color = "green" if log["status"] == "SUCCESS" else "bold red"
            table.add_row(
                str(log["event_id"]),
                str(log["timestamp"])[:19],
                str(log["module_name"]),
                str(log["action"]),
                f"[{status_color}]{log['status']}[/{status_color}]",
                f"{log['execution_time_ms']:.2f} ms"
            )
        console.print(table)
    else:
        print("\n" + "=" * 80)
        print(f"{'ID':<5} {'TIMESTAMP':<20} {'MODULE':<22} {'ACTION':<20} {'STATUS':<10}")
        print("=" * 80)
        for log in logs:
            print(f"{log['event_id']:<5} {str(log['timestamp'])[:19]:<20} {log['module_name']:<22} {log['action']:<20} {log['status']:<10}")

def main():
    """Main CLI execution controller."""
    init_db()
    
    while True:
        display_banner()
        render_menu()
        
        choice = input("\n[SIS Dashboard] Select Option (0-8): ").strip()
        
        if choice == "1":
            from core.password_checker import run_interactive
            run_interactive()
        elif choice == "2":
            from core.create_hash import run_interactive
            run_interactive()
        elif choice == "3":
            from core.file_integrity_scanner import run_interactive
            run_interactive()
        elif choice == "4":
            from core.networkscanner import run_interactive
            run_interactive()
        elif choice == "5":
            from core.info_scanner import run_interactive
            run_interactive()
        elif choice == "6":
            from core.dft_kit import run_interactive
            run_interactive()
        elif choice == "7":
            from core.browser_forensic_toolkit import run_interactive
            run_interactive()
        elif choice == "8":
            view_audit_logs()
        elif choice == "0":
            if RICH_AVAILABLE:
                rprint("\n[bold yellow][+] Exiting Secure Information System Suite. Operations Terminated.[/bold yellow]\n")
            else:
                print("\n[+] Exiting Secure Information System Suite. Operations Terminated.\n")
            break
        else:
            print("[-] Invalid Selection. Please choose a valid option (0-8).")
        
        input("\nPress Enter to return to main dashboard...")

if __name__ == "__main__":
    main()
