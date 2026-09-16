"""
High-Performance Network & Port Scanner (core/networkscanner.py)
Features:
- Asynchronous non-blocking socket probing using asyncio.
- TCP Banner Grabbing for service version fingerprinting.
- Internal Security Risk Matrix mapping.
- Persistent audit logging and scan result storage in SQLite.
"""

import asyncio
import socket
import time
from typing import Dict, List, Tuple, Optional
from core.database import log_event, save_scan_result

DEFAULT_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "Remote Desktop (RDP)",
    8080: "HTTP-Proxy / Alt Web",
    27017: "MongoDB"
}

RISK_MATRIX = {
    21: "HIGH - FTP transmits credentials in plain-text.",
    22: "MEDIUM - SSH secure if pubkey auth enforced.",
    25: "MEDIUM - SMTP Mail Relay service exposed.",
    53: "LOW - DNS Name Resolution Service.",
    80: "LOW - Unencrypted HTTP Web Server.",
    110: "MEDIUM - Legacy POP3 Mail Service.",
    143: "MEDIUM - IMAP Mail Service.",
    443: "LOW - Encrypted HTTPS Web Server.",
    3306: "HIGH - Database engine should not be publicly accessible.",
    3389: "HIGH - RDP exposed; susceptible to brute-force & BlueKeep.",
    8080: "MEDIUM - Alternative web application endpoint.",
    27017: "HIGH - MongoDB exposed without default auth."
}

async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float = 1.0) -> str:
    """Attempts to read service banner string upon successful TCP connection."""
    try:
        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
        await writer.drain()
        banner_bytes = await asyncio.wait_for(reader.read(256), timeout=timeout)
        banner_str = banner_bytes.decode("ascii", errors="ignore").strip().splitlines()[0]
        return banner_str[:60]
    except Exception:
        return "No Banner Returned"

async def scan_single_port(ip: str, port: int, service_name: str, timeout: float = 1.5) -> Tuple[int, str, bool, str]:
    """Asynchronously probes a single TCP port and grabs banner if open."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        banner = await grab_banner(reader, writer)
        writer.close()
        await writer.wait_closed()
        return port, service_name, True, banner
    except (asyncio.TimeoutError, OSError):
        return port, service_name, False, ""

async def scan_target_ports(target_host: str, ports_to_scan: Optional[Dict[int, str]] = None) -> Tuple[str, str, List[Dict]]:
    """Scans all specified target ports concurrently using asyncio.gather."""
    ports_map = ports_to_scan if ports_to_scan else DEFAULT_PORTS
    start_time = time.time()

    try:
        ip_address = socket.gethostbyname(target_host)
    except socket.gaierror:
        raise ValueError(f"Unable to resolve host: {target_host}")

    tasks = [scan_single_port(ip_address, p, s) for p, s in ports_map.items()]
    results = await asyncio.gather(*tasks)

    open_ports_list = []
    for port, service, is_open, banner in results:
        if is_open:
            risk = RISK_MATRIX.get(port, "INFORMATIONAL")
            open_ports_list.append({
                "port": port,
                "service": service,
                "banner": banner,
                "risk": risk
            })

    elapsed_ms = (time.time() - start_time) * 1000
    severity = "HIGH" if any(p['risk'].startswith("HIGH") for p in open_ports_list) else "INFO"
    
    log_id = log_event("networkscanner", "port_scan", f"{target_host} ({ip_address})", "SUCCESS", severity, elapsed_ms)
    save_scan_result(log_id, "network_port_scan", {
        "target": target_host,
        "ip": ip_address,
        "total_ports_scanned": len(ports_map),
        "open_ports_count": len(open_ports_list),
        "open_ports": open_ports_list,
        "scan_duration_ms": round(elapsed_ms, 2)
    })

    return target_host, ip_address, open_ports_list

def run_port_scan(target_host: str) -> Tuple[str, str, List[Dict]]:
    """Synchronous wrapper to execute the async scanner."""
    return asyncio.run(scan_target_ports(target_host))

def run_interactive():
    """Interactive CLI runner for Network Scanner."""
    print("\n" + "=" * 50)
    print(" HIGH-PERFORMANCE ASYNCHRONOUS PORT SCANNER")
    print("=" * 50)
    target = input("\nEnter Target Domain or IP (e.g. scanme.nmap.org): ").strip()
    if not target:
        print("[-] Target host cannot be empty.")
        return

    print(f"\n[*] Probing {target} concurrently across common ports...")
    try:
        host, ip, open_ports = run_port_scan(target)
        print(f"\n[+] Target Resolved: {host} -> {ip}")
        print("-" * 65)
        print(f"{'PORT':<8} {'SERVICE':<15} {'BANNER / RESPONSE':<30}")
        print("-" * 65)
        
        if not open_ports:
            print("No open common ports detected.")
        else:
            for item in open_ports:
                banner_disp = item['banner'] if item['banner'] else "Open"
                print(f"{item['port']:<8} {item['service']:<15} {banner_disp:<30}")

        print("-" * 65)
        print("\nRISK ASSESSMENT SUMMARY:")
        for item in open_ports:
            print(f"  • Port {item['port']} ({item['service']}): {item['risk']}")

    except Exception as e:
        print(f"[-] Scan Error: {e}")

if __name__ == "__main__":
    run_interactive()
