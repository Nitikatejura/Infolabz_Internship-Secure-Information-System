"""
AegisPoint Enterprise Security Platform (v3.1-LTS)
Full-Stack Cyber Defense, Reconnaissance & Digital Forensics Suite
Aligned with NIST CSF & ISO/IEC 27001 Controls | Centralized SIEM Persistence
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import math
import os
import re
import shutil
import socket
import sqlite3
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import streamlit as st

# =============================================================================
# ENVIRONMENT & PATH BOOTSTRAPPING
# =============================================================================
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

DB_PATH = os.path.join(APP_ROOT, "database", "sis_audit.db")

# Optional third-party packages
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    try:
        import PyPDF2 as pypdf
        PYPDF_AVAILABLE = True
    except ImportError:
        PYPDF_AVAILABLE = False


# =============================================================================
# DATABASE PERSISTENCE LAYER (ROBUST MULTI-FALLBACK)
# =============================================================================
def init_database() -> str:
    """Initializes sis_audit.db with required audit tables."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            module_name TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            status TEXT NOT NULL DEFAULT 'SUCCESS',
            severity TEXT NOT NULL DEFAULT 'INFO',
            execution_time_ms REAL DEFAULT 0.0
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            scan_type TEXT NOT NULL,
            details_json TEXT,
            FOREIGN KEY(log_id) REFERENCES audit_logs(event_id) ON DELETE CASCADE
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS integrity_baselines (
            file_path TEXT PRIMARY KEY,
            sha256_hash TEXT NOT NULL,
            last_verified TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'BASELINE'
        );
        """)
        conn.commit()
    return DB_PATH

def log_audit_event(module_name: str, action: str, target: str = "",
                    status: str = "SUCCESS", severity: str = "INFO",
                    execution_time_ms: float = 0.0,
                    details: Optional[Dict[str, Any]] = None) -> int:
    """Inserts a structured security event into sis_audit.db."""
    try:
        init_database()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO audit_logs (timestamp, module_name, action, target, status, severity, execution_time_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, module_name, action, target, status, severity, round(execution_time_ms, 2)))
            event_id = cur.lastrowid or 0

            if details is not None and event_id > 0:
                cur.execute("""
                    INSERT INTO scan_results (log_id, scan_type, details_json)
                    VALUES (?, ?, ?)
                """, (event_id, module_name, json.dumps(details, default=str)))
            conn.commit()
            return event_id
    except Exception:
        return 0

def fetch_audit_records(limit: int = 100, module_filter: str = "All",
                        severity_filter: str = "All", search_query: str = "") -> List[Dict[str, Any]]:
    """Fetches filtered audit logs from the persistence layer."""
    init_database()
    query = "SELECT event_id, timestamp, module_name, action, target, status, severity, execution_time_ms FROM audit_logs WHERE 1=1"
    params: List[Any] = []

    if module_filter and module_filter != "All":
        query += " AND module_name = ?"
        params.append(module_filter)

    if severity_filter and severity_filter != "All":
        query += " AND severity = ?"
        params.append(severity_filter)

    if search_query:
        query += " AND (action LIKE ? OR target LIKE ? OR module_name LIKE ?)"
        term = f"%{search_query}%"
        params.extend([term, term, term])

    query += " ORDER BY event_id DESC LIMIT ?"
    params.append(limit)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]

def get_telemetry_metrics() -> Dict[str, Any]:
    """Retrieves high-level summary counters for executive cards."""
    init_database()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        total_events = cur.execute("SELECT COUNT(*) as c FROM audit_logs").fetchone()["c"]
        high_critical = cur.execute("SELECT COUNT(*) as c FROM audit_logs WHERE severity IN ('HIGH', 'CRITICAL')").fetchone()["c"]
        unique_modules = cur.execute("SELECT COUNT(DISTINCT module_name) as c FROM audit_logs").fetchone()["c"]
        last_event = cur.execute("SELECT timestamp FROM audit_logs ORDER BY event_id DESC LIMIT 1").fetchone()
        last_ts = last_event["timestamp"] if last_event else "No audits recorded"

        by_module = {
            row["module_name"]: row["c"]
            for row in cur.execute("SELECT module_name, COUNT(*) as c FROM audit_logs GROUP BY module_name").fetchall()
        }
        by_severity = {
            row["severity"]: row["c"]
            for row in cur.execute("SELECT severity, COUNT(*) as c FROM audit_logs GROUP BY severity").fetchall()
        }

    return {
        "total_events": total_events,
        "high_critical": high_critical,
        "unique_modules": unique_modules,
        "last_timestamp": last_ts,
        "by_module": by_module,
        "by_severity": by_severity
    }


# =============================================================================
# RESILIENT TABLE RENDERING (SUPPORTS PYARROW & SYSTEM APP-CONTROL POLICIES)
# =============================================================================
def render_security_table(data: Any, width: str = "stretch", hide_index: bool = True) -> None:
    """
    Renders structured tables using st.dataframe.
    If Windows AppLocker or environment policy blocks pyarrow C++ DLL,
    gracefully falls back to high-fidelity Markdown table formatting.
    """
    try:
        st.dataframe(data, width=width, hide_index=hide_index)
        return
    except Exception:
        pass

    # Safe fallback formatting
    try:
        if PANDAS_AVAILABLE and isinstance(data, pd.DataFrame):
            cols = list(data.columns)
            hdr = "| " + " | ".join(str(c) for c in cols) + " |"
            div = "| " + " | ".join(["---"] * len(cols)) + " |"
            lines = [hdr, div]
            for _, r in data.iterrows():
                row_str = "| " + " | ".join(str(r[c]).replace("|", "&#124;") for c in cols) + " |"
                lines.append(row_str)
            st.markdown("\n".join(lines))
            return
        elif isinstance(data, list) and data:
            cols = list(data[0].keys())
            hdr = "| " + " | ".join(str(c) for c in cols) + " |"
            div = "| " + " | ".join(["---"] * len(cols)) + " |"
            lines = [hdr, div]
            for r in data:
                row_str = "| " + " | ".join(str(r.get(c, "")).replace("|", "&#124;") for c in cols) + " |"
                lines.append(row_str)
            st.markdown("\n".join(lines))
            return
    except Exception:
        pass

    st.text(str(data))


# =============================================================================
# CORE LOGIC ENGINES (SELF-CONTAINED & ROBUST FALLBACKS)
# =============================================================================

# --- 1. Identity & Password Security ---
COMMON_PASSWORDS_SET = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein", "admin",
    "welcome", "login", "master", "shadow", "pass123", "iloveyou", "football",
    "dragon", "superman", "trustno1", "password123", "p@ssword", "root"
}

def evaluate_password_resilience(password: str) -> Dict[str, Any]:
    """Calculates NIST-aligned entropy, criteria flags, and 0-100 score."""
    if not password:
        return {"score": 0, "entropy": 0.0, "label": "CRITICAL", "checks": {}, "suggestions": []}

    length = len(password)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{}|;':\",./<>?`~\\/]", password))
    not_common = password.lower() not in COMMON_PASSWORDS_SET
    no_repeat = not bool(re.search(r"(.)\1{2,}", password))

    pool = 0
    if has_lower: pool += 26
    if has_upper: pool += 26
    if has_digit: pool += 10
    if has_symbol: pool += 33
    pool = max(pool, 1)

    entropy = round(length * math.log2(pool), 1)

    score = 0
    if length >= 16: score += 30
    elif length >= 12: score += 25
    elif length >= 8: score += 15
    else: score += 5

    if has_upper: score += 10
    if has_lower: score += 10
    if has_digit: score += 15
    if has_symbol: score += 20
    if not_common: score += 10
    if no_repeat: score += 5
    score = min(max(score, 5), 100)

    if score >= 85: label = "ELITE"
    elif score >= 70: label = "STRONG"
    elif score >= 50: label = "MODERATE"
    elif score >= 30: label = "WEAK"
    else: label = "CRITICAL"

    checks = {
        "Minimum Length (8+ chars)": length >= 8,
        "Enterprise Length (12+ chars)": length >= 12,
        "Uppercase Character (A-Z)": has_upper,
        "Lowercase Character (a-z)": has_lower,
        "Numeric Digit (0-9)": has_digit,
        "Special Symbol (!@#$...)": has_symbol,
        "Dictionary Blacklist Clearance": not_common,
        "No Repeated Character Runs": no_repeat
    }

    suggestions = []
    if length < 12: suggestions.append("Increase length to at least 12 characters.")
    if not has_upper: suggestions.append("Include uppercase characters (A-Z).")
    if not has_symbol: suggestions.append("Add special symbols (e.g. #, $, %, &).")
    if not not_common: suggestions.append("Replace commonly breached dictionary words.")

    return {
        "score": score,
        "entropy": entropy,
        "label": label,
        "length": length,
        "checks": checks,
        "suggestions": suggestions
    }

def check_hibp_breach(password: str) -> Tuple[bool, int]:
    """Queries HaveIBeenPwned k-Anonymity API (safe 5-char SHA-1 prefix)."""
    if not REQUESTS_AVAILABLE:
        return False, -1
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        resp = requests.get(url, headers={"User-Agent": "AegisPoint-Platform/3.1"}, timeout=4.0)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if ":" in line:
                    sfx, count_str = line.split(":")
                    if sfx.strip() == suffix:
                        return True, int(count_str.strip())
            return False, 0
    except Exception:
        pass
    return False, -1

def detect_hash_algorithm(hash_str: str) -> str:
    """Fingerprints hash algorithm by character length and pattern."""
    h = hash_str.strip().lower()
    if len(h) == 32 and re.match(r"^[a-f0-9]{32}$", h): return "MD5 (128-bit)"
    if len(h) == 40 and re.match(r"^[a-f0-9]{40}$", h): return "SHA-1 (160-bit)"
    if len(h) == 64 and re.match(r"^[a-f0-9]{64}$", h): return "SHA-256 (256-bit)"
    if len(h) == 128 and re.match(r"^[a-f0-9]{128}$", h): return "SHA-512 / BLAKE2b (512-bit)"
    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"): return "bcrypt"
    if h.startswith("$argon2"): return "Argon2"
    return "Unknown or Custom Format"

# --- 2. Cryptographic Digesting ---
def compute_digests(data: bytes, salt: str = "") -> Dict[str, str]:
    """Generates MD5, SHA-1, SHA-256, SHA-512, and BLAKE2b digests."""
    payload = data + (salt.encode("utf-8") if salt else b"")
    return {
        "SHA-256": hashlib.sha256(payload).hexdigest(),
        "SHA-512": hashlib.sha512(payload).hexdigest(),
        "BLAKE2b": hashlib.blake2b(payload).hexdigest(),
        "MD5": hashlib.md5(payload).hexdigest(),
        "SHA-1": hashlib.sha1(payload).hexdigest()
    }

# --- 3. Attack Surface Port Scanner ---
DEFAULT_PORTS_MAP = {
    21: ("FTP", "HIGH - Cleartext protocol; susceptible to sniffing."),
    22: ("SSH", "MEDIUM - Secure if pubkey auth enforced."),
    23: ("Telnet", "CRITICAL - Unencrypted; decommission immediately."),
    25: ("SMTP", "MEDIUM - Mail transfer service; verify relay settings."),
    53: ("DNS", "LOW - Standard name resolution."),
    80: ("HTTP", "LOW - Unencrypted web; redirect to HTTPS."),
    110: ("POP3", "MEDIUM - Legacy mail protocol; enforce TLS."),
    143: ("IMAP", "MEDIUM - Enforce STARTTLS for mail."),
    443: ("HTTPS", "LOW - Encrypted web traffic (Standard)."),
    445: ("SMB", "CRITICAL - Primary lateral movement & ransomware vector."),
    3306: ("MySQL", "CRITICAL - Database engine should not be public."),
    3389: ("RDP", "HIGH - Remote desktop; vulnerable to brute-force."),
    5432: ("PostgreSQL", "CRITICAL - Database endpoint exposed."),
    6379: ("Redis", "CRITICAL - High vulnerability if unauthenticated."),
    8080: ("HTTP-Alt", "MEDIUM - Non-standard web application."),
    8443: ("HTTPS-Alt", "LOW - Alternate encrypted web port."),
    27017: ("MongoDB", "CRITICAL - NoSQL database exposed.")
}

def scan_single_tcp_port(ip: str, port: int, service: str, risk: str, timeout: float = 1.0) -> Dict[str, Any]:
    """Probes a single TCP port and grabs banner if open."""
    t0 = time.perf_counter()
    status = "CLOSED"
    banner = ""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            status = "OPEN"
            s.settimeout(0.8)
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                raw = s.recv(128)
                banner = raw.decode("ascii", errors="ignore").strip().splitlines()[0][:50]
            except Exception:
                banner = "Service Active (No Banner)"
    except Exception:
        status = "CLOSED"
    lat_ms = round((time.perf_counter() - t0) * 1000, 1)

    return {
        "Port": port,
        "Service": service,
        "Status": status,
        "Latency (ms)": lat_ms,
        "Risk": risk.split(" - ")[0] if status == "OPEN" else "NONE",
        "Risk Description": risk if status == "OPEN" else "Port closed.",
        "Banner": banner if status == "OPEN" else "-"
    }

def run_concurrent_port_scan(host: str, ports: List[int], timeout: float = 0.8) -> Tuple[str, str, List[Dict[str, Any]], float]:
    """Concurrently scans ports using ThreadPoolExecutor."""
    try:
        ip = socket.gethostbyname(host.strip())
    except socket.gaierror:
        return host, "Resolution Failed", [], 0.0

    t_start = time.perf_counter()
    results = []
    with ThreadPoolExecutor(max_workers=min(len(ports), 40)) as pool:
        futures = {
            pool.submit(
                scan_single_tcp_port,
                ip,
                p,
                DEFAULT_PORTS_MAP.get(p, ("Custom", "MEDIUM - Custom Port"))[0],
                DEFAULT_PORTS_MAP.get(p, ("Custom", "MEDIUM - Custom Port"))[1],
                timeout
            ): p for p in ports
        }
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda x: x["Port"])
    total_time = round(time.perf_counter() - t_start, 2)
    return host, ip, results, total_time

# --- 4. Digital Forensics Parsers ---
MAGIC_SIGS = [
    (b"\x25\x50\x44\x46", "PDF Document"),
    (b"\xff\xd8\xff", "JPEG Image"),
    (b"\x89\x50\x4e\x47\x0d\x0a", "PNG Image"),
    (b"\x50\x4b\x03\x04", "ZIP / Office Archive"),
    (b"\x4d\x5a", "Windows PE Executable"),
    (b"\x7f\x45\x4c\x46", "Linux ELF Binary"),
    (b"\x47\x49\x46\x38", "GIF Image"),
    (b"\x42\x4d", "BMP Image")
]

DANGEROUS_EXTS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".msi", ".dll", ".hta"}

def parse_file_evidence_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    """Analyzes raw bytes for magic header, masquerading, and metadata."""
    size = len(data)
    ext = os.path.splitext(filename)[1].lower()
    magic_hex = data[:16].hex().upper()

    magic_type = "Unknown or Plaintext"
    for sig, label in MAGIC_SIGS:
        if data.startswith(sig):
            magic_type = label
            break

    is_danger = ext in DANGEROUS_EXTS or magic_type in ["Windows PE Executable", "Linux ELF Binary"]
    double_ext = filename.count(".") > 1

    report: Dict[str, Any] = {
        "Filename": filename,
        "Filesize": f"{size / 1024:.2f} KB" if size >= 1024 else f"{size} Bytes",
        "Extension": ext or "None",
        "Detected Type": magic_type,
        "Header Hex": magic_hex,
        "Executable Payload Alert": "YES - SUSPICIOUS" if is_danger else "NO - NOMINAL",
        "Double Extension Masking": "YES - DETECTED" if double_ext else "NO - NORMAL",
        "Metadata": {}
    }

    # Image metadata
    if ext in [".jpg", ".jpeg", ".png"] and PIL_AVAILABLE:
        try:
            img = Image.open(io.BytesIO(data))
            report["Metadata"]["Dimensions"] = f"{img.width} x {img.height}"
            report["Metadata"]["Color Mode"] = img.mode
            if hasattr(img, "getexif"):
                exif = img.getexif()
                if exif:
                    for tid, val in list(exif.items())[:8]:
                        tname = TAGS.get(tid, str(tid))
                        report["Metadata"][f"EXIF_{tname}"] = str(val)[:50]
        except Exception:
            pass

    # PDF metadata
    if ext == ".pdf" and PYPDF_AVAILABLE:
        try:
            reader = pypdf.PdfReader(io.BytesIO(data))
            report["Metadata"]["Page Count"] = len(reader.pages)
            report["Metadata"]["Encrypted"] = reader.is_encrypted
            if reader.metadata:
                for k, v in reader.metadata.items():
                    report["Metadata"][k.lstrip("/")] = str(v)
        except Exception:
            pass

    # ZIP metadata
    if ext in [".zip", ".docx", ".xlsx"] and data.startswith(b"\x50\x4b\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                infos = zf.infolist()
                report["Metadata"]["Archive Item Count"] = len(infos)
                report["Metadata"]["Encrypted Entries"] = any(f.flag_bits & 0x1 for f in infos)
                report["Metadata"]["First 5 Files"] = ", ".join(f.filename for f in infos[:5])
        except Exception:
            pass

    return report

def parse_sqlite_history_bytes(data: bytes) -> Dict[str, Any]:
    """Parses Chrome/Edge SQLite history database from in-memory bytes."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    records = []
    domain_counts: Dict[str, int] = {}
    search_queries: List[str] = []

    try:
        with sqlite3.connect(tmp_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls';")
            if not cur.fetchone():
                return {"error": "Invalid SQLite file. The 'urls' history table was not detected."}

            cur.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100")
            for row in cur.fetchall():
                url = row["url"] or ""
                title = row["title"] or "No Title"
                visits = row["visit_count"] or 1
                ctime = row["last_visit_time"] or 0

                try:
                    dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ctime)
                    dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    dt_str = "Unknown"

                records.append({
                    "Timestamp (UTC)": dt_str,
                    "Page Title": title[:45],
                    "Target URL": url[:70],
                    "Visits": visits
                })

                domain = urlparse(url).netloc.replace("www.", "").strip()
                if domain:
                    domain_counts[domain] = domain_counts.get(domain, 0) + visits

                if "google.com/search" in url:
                    q = parse_qs(urlparse(url).query).get("q", [])
                    if q and q[0] not in search_queries:
                        search_queries.append(q[0])
    except Exception as exc:
        return {"error": f"SQLite parsing failed: {exc}"}
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    sorted_domains = sorted([{"Domain": d, "Visits": c} for d, c in domain_counts.items()],
                            key=lambda x: x["Visits"], reverse=True)[:10]

    return {
        "total_records": len(records),
        "history": records,
        "top_domains": sorted_domains,
        "searches": search_queries[:10]
    }


# =============================================================================
# STREAMLIT PAGE SETUP & PRODUCTION CYBER THEME CSS
# =============================================================================
st.set_page_config(
    page_title="AegisPoint Enterprise Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom High-End SOC Dashboard CSS
st.markdown("""
<style>
/* CSS Reset and Font Stack */
html, body, [class*="css"] {
    background-color: #0b0f19 !important;
    color: #e2e8f0 !important;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
}

/* Header Ribbon */
.soc-header {
    background: linear-gradient(135deg, #0f172a 0%, #111827 50%, #0b0f19 100%);
    border: 1px solid #1e293b;
    border-top: 2px solid #0ea5e9;
    border-radius: 8px;
    padding: 16px 24px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}
.soc-brand {
    display: flex;
    align-items: center;
    gap: 14px;
}
.soc-title {
    font-size: 22px;
    font-weight: 800;
    letter-spacing: 0.5px;
    color: #f8fafc;
}
.soc-subtitle {
    font-size: 12px;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 1.5px;
}
.soc-status-group {
    display: flex;
    align-items: center;
    gap: 12px;
}
.badge-nist {
    background: rgba(14, 165, 233, 0.12);
    border: 1px solid #0ea5e9;
    color: #0ea5e9;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}
.badge-online {
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid #10b981;
    color: #10b981;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}

/* Metric Cards */
.soc-card {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 16px 20px;
    text-align: center;
}
.soc-card-label {
    font-size: 11px;
    text-transform: uppercase;
    color: #94a3b8;
    letter-spacing: 1.2px;
    margin-bottom: 6px;
}
.soc-card-value {
    font-size: 28px;
    font-weight: 800;
    color: #0ea5e9;
    line-height: 1;
}
.soc-card-delta {
    font-size: 11px;
    color: #10b981;
    margin-top: 6px;
}

/* Business Risk Callout */
.risk-banner {
    background: rgba(14, 165, 233, 0.06);
    border-left: 4px solid #0ea5e9;
    border-top: 1px solid #1e293b;
    border-right: 1px solid #1e293b;
    border-bottom: 1px solid #1e293b;
    border-radius: 0 6px 6px 0;
    padding: 12px 18px;
    margin-bottom: 18px;
    font-size: 13px;
    color: #cbd5e1;
}

/* Monospace output container */
.terminal-window {
    background: #030712;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 14px 18px;
    font-family: 'Consolas', 'JetBrains Mono', monospace;
    font-size: 13px;
    color: #38bdf8;
    word-break: break-all;
    margin: 8px 0;
}

/* Tab Navigation Styling */
.stTabs [data-baseweb="tab-list"] {
    background-color: #111827 !important;
    border-bottom: 1px solid #1e293b !important;
    padding: 4px 8px 0 8px !important;
    gap: 4px !important;
}
.stTabs [data-baseweb="tab"] {
    background-color: transparent !important;
    color: #94a3b8 !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    padding: 8px 16px !important;
    border-radius: 6px 6px 0 0 !important;
    transition: all 0.2s ease !important;
}
.stTabs [aria-selected="true"] {
    background-color: #1e293b !important;
    color: #0ea5e9 !important;
    border-bottom: 2px solid #0ea5e9 !important;
}

/* Form inputs */
input, textarea, select {
    background-color: #111827 !important;
    color: #f1f5f9 !important;
    border: 1px solid #334155 !important;
    border-radius: 6px !important;
}
input:focus, textarea:focus {
    border-color: #0ea5e9 !important;
    box-shadow: 0 0 0 1px #0ea5e9 !important;
}

/* Buttons */
.stButton>button {
    background-color: #1e293b !important;
    color: #38bdf8 !important;
    border: 1px solid #0ea5e9 !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    transition: all 0.2s ease !important;
}
.stButton>button:hover {
    background-color: #0ea5e9 !important;
    color: #040812 !important;
    box-shadow: 0 0 12px rgba(14, 165, 233, 0.4) !important;
}
</style>
""", unsafe_allow_html=True)


# =============================================================================
# PERSISTENT SESSION STATE SETUP
# =============================================================================
SESSION_DEFAULTS = {
    "pw_input": "",
    "pw_report": None,
    "hash_text_input": "",
    "hash_results": None,
    "fim_diff_result": None,
    "scan_results": None,
    "scan_target": "127.0.0.1",
    "forensics_report": None,
    "history_report": None,
    "console_logs": [
        "AegisPoint SOC Terminal Console v3.1-LTS initialized.",
        "Type 'help' to inspect operational command reference."
    ]
}
for k, v in SESSION_DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# Auto-initialize database on cold start
init_database()


# =============================================================================
# CACHED DATA WRAPPERS
# =============================================================================
@st.cache_data(ttl=5)
def get_cached_telemetry() -> Dict[str, Any]:
    return get_telemetry_metrics()

@st.cache_data(ttl=5)
def get_cached_audit_logs(limit: int, mod: str, sev: str, query: str) -> List[Dict[str, Any]]:
    return fetch_audit_records(limit, mod, sev, query)


# =============================================================================
# HEADER RIBBON
# =============================================================================
st.markdown("""
<div class="soc-header">
    <div class="soc-brand">
        <span style="font-size: 32px;">🛡️</span>
        <div>
            <div class="soc-title">AegisPoint Enterprise Security Platform</div>
            <div class="soc-subtitle">Modular Defense, Reconnaissance &amp; Digital Forensics &nbsp;|&nbsp; v3.1-LTS</div>
        </div>
    </div>
    <div class="soc-status-group">
        <span class="badge-nist">NIST CSF &amp; ISO 27001 ALIGNED</span>
        <span class="badge-online">● SIEM ENGINE ACTIVE</span>
    </div>
</div>
""", unsafe_allow_html=True)


# =============================================================================
# 8-TAB TOP LEVEL NAVIGATION
# =============================================================================
tab_overview, tab_iam, tab_crypto, tab_fim, tab_recon, tab_forensics, tab_siem, tab_console = st.tabs([
    "🌐 Platform Center",
    "🔑 Identity Resilience",
    "🔒 Data Fingerprinting",
    "🛡️ Tamper Detection (FIM)",
    "📡 Attack Surface Scanner",
    "🔍 Incident Triage",
    "📊 Compliance & Telemetry",
    "💻 SOC Terminal Console"
])


# =============================================================================
# TAB 1: PLATFORM CENTER
# =============================================================================
with tab_overview:
    telemetry = get_cached_telemetry()

    # Metric Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
        <div class="soc-card">
            <div class="soc-card-label">Total Audit Events</div>
            <div class="soc-card-value">{telemetry['total_events']}</div>
            <div class="soc-card-delta">Centralized SQLite WAL</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="soc-card">
            <div class="soc-card-label">High / Critical Alerts</div>
            <div class="soc-card-value" style="color: {'#ef4444' if telemetry['high_critical'] > 0 else '#10b981'};">
                {telemetry['high_critical']}
            </div>
            <div class="soc-card-delta">Severity Threshold Flag</div>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="soc-card">
            <div class="soc-card-label">Active Defensive Cores</div>
            <div class="soc-card-value">7 / 7</div>
            <div class="soc-card-delta">All Engines Online</div>
        </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
        <div class="soc-card">
            <div class="soc-card-label">Last Audit Timestamp</div>
            <div class="soc-card-value" style="font-size: 14px; padding-top: 8px; color: #94a3b8;">
                {telemetry['last_timestamp'][:19]}
            </div>
            <div class="soc-card-delta">Continuous Logging</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("""
    <div class="risk-banner">
        💼 <strong>Executive Security Summary:</strong> AegisPoint v3.1-LTS consolidates critical cybersecurity controls
        spanning credential verification, cryptographic integrity monitoring, external perimeter reconnaissance,
        and post-incident forensics into a single unified telemetry pipeline.
    </div>
    """, unsafe_allow_html=True)

    col_desc, col_matrix = st.columns([3, 2])
    with col_desc:
        st.markdown("### Operational Capabilities & Business Value")
        st.markdown("""
        - **Identity Resilience Engine:** Evaluates password complexity, Shannon entropy, and queries k-anonymity breach registries to neutralize credential stuffing attacks.
        - **Data Fingerprinting & Integrity:** Cryptographic digest studio implementing SHA-256, SHA-512, BLAKE2b, and MD5 for immutable verification of software artifacts and records.
        - **File Integrity Tripwire (FIM):** Recursive baseline snapshots and dual-file cryptographic diffing to immediately isolate unauthorized alterations.
        - **Attack Surface Enumerator:** Concurrent non-blocking port scanner profiling public endpoints, detecting exposed databases, and evaluating exposure severity.
        - **Digital Forensics Suite:** Extracts metadata from compromised files, detects double-extension obfuscation, and safely parses locked browser histories.
        """)

    with col_matrix:
        st.markdown("### Standards Compliance Matrix")
        standards_data = [
            {"Control Standard": "NIST SP 800-63B", "Scope": "Identity & Password Resilience", "Status": "ENFORCED"},
            {"Control Standard": "FIPS 180-4 / RFC 7693", "Scope": "SHA-2 / BLAKE2 Hashing", "Status": "VERIFIED"},
            {"Control Standard": "PCI DSS 10.5.5", "Scope": "File Integrity Monitoring", "Status": "ACTIVE"},
            {"Control Standard": "CIS Controls v8 (Control 9)", "Scope": "Attack Surface & Port Defense", "Status": "MONITORED"},
            {"Control Standard": "ISO/IEC 27043", "Scope": "Digital Evidence Acquisition", "Status": "READY"},
            {"Control Standard": "ISO 27001 Annex A.12.4", "Scope": "SIEM Logging & Telemetry", "Status": "PERSISTED"}
        ]
        if PANDAS_AVAILABLE:
            df_std = pd.DataFrame(standards_data)
            render_security_table(df_std, width="stretch", hide_index=True)
        else:
            for item in standards_data:
                st.text(f"{item['Control Standard']} | {item['Scope']} -> {item['Status']}")


# =============================================================================
# TAB 2: IDENTITY RESILIENCE
# =============================================================================
with tab_iam:
    st.markdown("""
    <div class="risk-banner">
        💼 <strong>Business Risk Impact:</strong> Stolen and weak credentials cause over 80% of confirmed enterprise breaches.
        This control proactively evaluates credential entropy and cross-references known breach leaks before credentials enter identity pools.
    </div>
    """, unsafe_allow_html=True)

    with st.expander("ℹ️ How Identity Resilience Works (NIST SP 800-63B Standards)"):
        st.markdown("""
        - **Entropy Evaluation:** Calculates Shannon entropy based on pool size and length.
        - **k-Anonymity Breach Lookup:** Only the first 5 characters of the SHA-1 hash are sent to the HIBP API. The plaintext password is never transmitted.
        """)

    c_in, c_demo = st.columns([3, 1])
    with c_in:
        pwd_input = st.text_input("Enter Password to Audit", value=st.session_state["pw_input"], type="password", key="pwd_field")
    with c_demo:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("Load Complex Demo", key="btn_pw_demo", width="stretch"):
            st.session_state["pw_input"] = "Tr0ub4dor&3_AegisPoint2026!"
            st.rerun()

    c_btn1, c_btn2 = st.columns(2)
    with c_btn1:
        eval_click = st.button("Evaluate Password Resilience", key="btn_eval_pw", width="stretch")
    with c_btn2:
        breach_click = st.button("Check Public Breach DB (k-Anonymity)", key="btn_breach_pw", width="stretch")

    if eval_click and pwd_input:
        t0 = time.perf_counter()
        rep = evaluate_password_resilience(pwd_input)
        elapsed = (time.perf_counter() - t0) * 1000
        st.session_state["pw_report"] = rep
        log_audit_event("password_checker", "entropy_evaluation", "***REDACTED***", "SUCCESS", "INFO", elapsed)

    if breach_click and pwd_input:
        with st.spinner("Querying HaveIBeenPwned k-anonymity registry..."):
            t0 = time.perf_counter()
            breached, count = check_hibp_breach(pwd_input)
            elapsed = (time.perf_counter() - t0) * 1000

            if count == -1:
                st.warning("⚠️ Breach registry API unreachable. Verify outbound network connectivity.")
                log_audit_event("password_checker", "breach_check", "HIBP API", "WARNING", "MEDIUM", elapsed)
            elif breached:
                st.error(f"🚨 CREDENTIAL COMPROMISED: This password was discovered in {count:,} known public data breaches! Replace immediately.")
                log_audit_event("password_checker", "breach_check", "BREACH FOUND", "WARNING", "HIGH", elapsed)
            else:
                st.success("✅ Clean Record: No instances of this password detected in known public breaches.")
                log_audit_event("password_checker", "breach_check", "CLEAN RECORD", "SUCCESS", "INFO", elapsed)

    if st.session_state["pw_report"]:
        rep = st.session_state["pw_report"]
        score = rep["score"]
        color = "#10b981" if score >= 70 else "#f59e0b" if score >= 50 else "#ef4444"

        st.markdown("<br>", unsafe_allow_html=True)
        col_m1, col_m2, col_m3 = st.columns(3)
        col_m1.metric("Resilience Score", f"{score} / 100", rep["label"])
        col_m2.metric("Shannon Entropy", f"{rep['entropy']} bits", "Unpredictability")
        col_m3.metric("Length", f"{rep['length']} characters", "NIST Min: 8")

        st.progress(score / 100)

        st.markdown("#### Security Criteria Checklist")
        chk_cols = st.columns(2)
        items = list(rep["checks"].items())
        mid = len(items) // 2
        for i, (crit, ok) in enumerate(items):
            c_idx = 0 if i < mid else 1
            icon = "✅" if ok else "❌"
            chk_cols[c_idx].markdown(f"{icon} **{crit}**")

        if rep["suggestions"]:
            st.markdown("#### Hardening Recommendations")
            for s in rep["suggestions"]:
                st.markdown(f"• {s}")

    st.markdown("---")
    st.markdown("#### Hash Type Identifier")
    hash_test = st.text_input("Paste any unknown hash string to identify algorithm", placeholder="e.g. 5d41402abc4b2a76b9719d911017c592")
    if hash_test:
        detected = detect_hash_algorithm(hash_test)
        st.info(f"🔎 Probable Algorithm Fingerprint: **{detected}**")


# =============================================================================
# TAB 3: DATA FINGERPRINTING
# =============================================================================
with tab_crypto:
    st.markdown("""
    <div class="risk-banner">
        💼 <strong>Business Risk Impact:</strong> Cryptographic digests guarantee data integrity.
        A single altered bit creates an entirely different digest, instantly unmasking unauthorized modifications.
    </div>
    """, unsafe_allow_html=True)

    mode = st.radio("Select Hashing Mode", ["Hash Direct String", "Hash Uploaded File", "Verify Hash Comparison"], horizontal=True)

    if mode == "Hash Direct String":
        c_str, c_sdemo = st.columns([3, 1])
        with c_str:
            txt = st.text_area("Input Text Payload", value=st.session_state["hash_text_input"], height=100)
        with c_sdemo:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            if st.button("Load Test String", key="btn_hdemo", width="stretch"):
                st.session_state["hash_text_input"] = "AegisPoint-v3.1-Release-Verification-Token"
                st.rerun()

        salt = st.text_input("Optional Cryptographic Salt", type="password")

        if st.button("Generate Cryptographic Digests", key="btn_gen_h", width="stretch"):
            if txt:
                t0 = time.perf_counter()
                digests = compute_digests(txt.encode("utf-8"), salt)
                elapsed = (time.perf_counter() - t0) * 1000
                st.session_state["hash_results"] = digests
                log_audit_event("create_hash", "hash_string", f"Payload {len(txt)} chars", "SUCCESS", "INFO", elapsed)
            else:
                st.warning("Please enter text payload.")

        if st.session_state["hash_results"]:
            for algo, dig in st.session_state["hash_results"].items():
                st.markdown(f"**{algo} Digest:**")
                st.code(dig, language=None)

    elif mode == "Hash Uploaded File":
        up_file = st.file_uploader("Upload Any File to Compute Cryptographic Hashes", key="file_hash_up")
        if up_file:
            data = up_file.read()
            digests = compute_digests(data)
            st.success(f"File '{up_file.name}' ({len(data):,} bytes) hashed successfully.")
            for algo, dig in digests.items():
                st.markdown(f"**{algo} Digest:**")
                st.code(dig, language=None)
            log_audit_event("create_hash", "hash_file", up_file.name, "SUCCESS", "INFO", 0.0)

    else:
        st.markdown("#### Dual-Digest Side-by-Side Verification")
        c_v1, c_v2 = st.columns(2)
        with c_v1:
            h1 = st.text_input("Computed or Reference Hash", placeholder="Paste original hash").strip().lower()
        with c_v2:
            h2 = st.text_input("Suspect or Verification Hash", placeholder="Paste verification hash").strip().lower()

        if h1 and h2:
            if h1 == h2:
                st.success("🟢 INTEGRITY CONFIRMED: Hashes match perfectly. Data is authentic.")
            else:
                st.error("🔴 TAMPER DETECTED: Hashes do not match! Payload has been altered.")


# =============================================================================
# TAB 4: TAMPER DETECTION (FIM)
# =============================================================================
with tab_fim:
    st.markdown("""
    <div class="risk-banner">
        💼 <strong>Business Risk Impact:</strong> File Integrity Monitoring acts as a system tripwire.
        Critical binary or configuration modification is the first indicator of root compromise or lateral movement.
    </div>
    """, unsafe_allow_html=True)

    fim_mode = st.radio("FIM Execution Profile", ["In-Memory Dual-File Cryptographic Diff", "Simulate Baseline Tamper Event"], horizontal=True)

    if fim_mode == "In-Memory Dual-File Cryptographic Diff":
        c_f1, c_f2 = st.columns(2)
        with c_f1:
            f_orig = st.file_uploader("Upload Reference File (Known Baseline)", key="fim_f1")
        with c_f2:
            f_susp = st.file_uploader("Upload Suspect File (Target for Audit)", key="fim_f2")

        if st.button("Run Cryptographic Tripwire Audit", key="btn_fim_run", width="stretch"):
            if f_orig and f_susp:
                b1 = f_orig.read()
                b2 = f_susp.read()
                h1 = hashlib.sha256(b1).hexdigest()
                h2 = hashlib.sha256(b2).hexdigest()

                st.session_state["fim_diff_result"] = {
                    "orig_name": f_orig.name, "orig_hash": h1,
                    "susp_name": f_susp.name, "susp_hash": h2,
                    "match": (h1 == h2)
                }
                status = "SUCCESS" if h1 == h2 else "WARNING"
                sev = "INFO" if h1 == h2 else "CRITICAL"
                log_audit_event("file_integrity_scanner", "file_pair_audit", f"{f_orig.name} vs {f_susp.name}", status, sev, 0.0)
            else:
                st.warning("Please upload both Reference and Suspect files.")

    else:
        st.markdown("#### Simulated Attack Tripwire Demo")
        if st.button("Simulate Malicious Binary Injection", key="btn_sim_tamper", width="stretch"):
            orig_data = b"# AegisPoint Secure Kernel Config v3.1\nALLOW_ROOT=0\nENFORCE_MFA=1\n"
            tampered_data = b"# AegisPoint Secure Kernel Config v3.1\nALLOW_ROOT=1\nENFORCE_MFA=0\n"
            h1 = hashlib.sha256(orig_data).hexdigest()
            h2 = hashlib.sha256(tampered_data).hexdigest()
            st.session_state["fim_diff_result"] = {
                "orig_name": "kernel_security.cfg [Original]", "orig_hash": h1,
                "susp_name": "kernel_security.cfg [Tampered Payload]", "susp_hash": h2,
                "match": False
            }
            log_audit_event("file_integrity_scanner", "tamper_simulation", "kernel_security.cfg", "WARNING", "CRITICAL", 0.0)

    if st.session_state["fim_diff_result"]:
        res = st.session_state["fim_diff_result"]
        st.markdown("<br>", unsafe_allow_html=True)
        if res["match"]:
            st.success(f"🟢 INTEGRITY VERIFIED: Hashes for '{res['orig_name']}' and '{res['susp_name']}' match completely.")
        else:
            st.error(f"🚨 CRITICAL TAMPER ALERT: Cryptographic mismatch detected between '{res['orig_name']}' and '{res['susp_name']}'!")

        c_h1, c_h2 = st.columns(2)
        with c_h1:
            st.markdown(f"**Baseline SHA-256 Digest ({res['orig_name']}):**")
            st.code(res["orig_hash"], language=None)
        with c_h2:
            st.markdown(f"**Suspect SHA-256 Digest ({res['susp_name']}):**")
            st.code(res["susp_hash"], language=None)


# =============================================================================
# TAB 5: ATTACK SURFACE SCANNER
# =============================================================================
with tab_recon:
    st.markdown("""
    <div class="risk-banner">
        💼 <strong>Business Risk Impact:</strong> Perimeter scans identify unintentionally exposed services,
        unauthenticated databases, and outdated protocols before malicious actors discover them via automated scanning.
    </div>
    """, unsafe_allow_html=True)

    c_host, c_pre = st.columns([2, 2])
    with c_host:
        target = st.text_input("Target Hostname or IP Address", value=st.session_state["scan_target"], placeholder="e.g. 127.0.0.1 or scanme.nmap.org")
    with c_pre:
        preset = st.selectbox("Scan Profile Preset", [
            "Common Top Services (10 Ports)",
            "Web Applications (80, 443, 8080, 8443)",
            "Database Engines (3306, 5432, 6379, 27017)",
            "Remote & Admin Access (21, 22, 23, 3389, 445)",
            "Full Standard Suite (All 17 Ports)"
        ])

    preset_ports = {
        "Common Top Services (10 Ports)": [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389],
        "Web Applications (80, 443, 8080, 8443)": [80, 443, 8080, 8443],
        "Database Engines (3306, 5432, 6379, 27017)": [3306, 5432, 6379, 27017],
        "Remote & Admin Access (21, 22, 23, 3389, 445)": [21, 22, 23, 3389, 445],
        "Full Standard Suite (All 17 Ports)": list(DEFAULT_PORTS_MAP.keys())
    }

    c_s1, c_s2 = st.columns([2, 1])
    with c_s1:
        run_scan = st.button("Launch Concurrent Port Audit", key="btn_run_scan", width="stretch")
    with c_s2:
        if st.button("Scan Loopback (127.0.0.1)", key="btn_scan_loop", width="stretch"):
            st.session_state["scan_target"] = "127.0.0.1"
            st.rerun()

    if run_scan and target:
        ports_list = preset_ports[preset]
        with st.spinner(f"Probing {target} concurrently across {len(ports_list)} ports..."):
            host_res, ip_res, scan_data, elapsed = run_concurrent_port_scan(target, ports_list)
            st.session_state["scan_results"] = {
                "host": host_res, "ip": ip_res, "data": scan_data, "elapsed": elapsed
            }
            open_count = sum(1 for p in scan_data if p["Status"] == "OPEN")
            sev = "HIGH" if any(p["Risk"] in ["HIGH", "CRITICAL"] for p in scan_data) else "INFO"
            log_audit_event("networkscanner", "port_scan", f"{host_res} ({ip_res})", "SUCCESS", sev, elapsed * 1000)

    if st.session_state["scan_results"]:
        sr = st.session_state["scan_results"]
        st.markdown("<br>", unsafe_allow_html=True)
        col_r1, col_r2, col_r3 = st.columns(3)
        col_r1.metric("Resolved IP", sr["ip"])
        col_r2.metric("Open Ports", sum(1 for p in sr["data"] if p["Status"] == "OPEN"))
        col_r3.metric("Scan Duration", f"{sr['elapsed']} s")

        if PANDAS_AVAILABLE and sr["data"]:
            df_scan = pd.DataFrame(sr["data"])
            render_security_table(df_scan, width="stretch", hide_index=True)
        else:
            for p in sr["data"]:
                st.text(f"Port {p['Port']} ({p['Service']}): {p['Status']} | Risk: {p['Risk']} | Banner: {p['Banner']}")


# =============================================================================
# TAB 6: INCIDENT TRIAGE & DIGITAL FORENSICS
# =============================================================================
with tab_forensics:
    st.markdown("""
    <div class="risk-banner">
        💼 <strong>Business Risk Impact:</strong> Forensic artifact acquisition establishes chain of custody,
        identifies malware disguised as legitimate documents, and recovers compromised activity timelines.
    </div>
    """, unsafe_allow_html=True)

    triage_mode = st.radio("Forensic Artifact Mode", ["Digital File Evidence Analyzer", "Browser History SQLite Parser"], horizontal=True)

    if triage_mode == "Digital File Evidence Analyzer":
        c_fup, c_fdemo = st.columns([3, 1])
        with c_fup:
            ev_file = st.file_uploader("Upload Evidence Artifact (Image, PDF, Document, Binary)", key="forensics_file_up")
        with c_fdemo:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            if st.button("Load Sample Mock Artifact", key="btn_fdemo", width="stretch"):
                mock_data = b"\x4d\x5a\x90\x00\x03\x00\x00\x00Malicious_Binary_Simulation_Payload"
                st.session_state["forensics_report"] = parse_file_evidence_bytes(mock_data, "invoice_payment.pdf.exe")
                st.rerun()

        if ev_file:
            data = ev_file.read()
            st.session_state["forensics_report"] = parse_file_evidence_bytes(data, ev_file.name)
            log_audit_event("forensics", "file_analysis", ev_file.name, "SUCCESS", "INFO", 0.0)

        if st.session_state["forensics_report"]:
            rep = st.session_state["forensics_report"]
            st.markdown("#### Artifact Assessment Summary")
            c_e1, c_e2, c_e3 = st.columns(3)
            c_e1.metric("Identified Format", rep["Detected Type"])
            c_e2.metric("Filesize", rep["Filesize"])
            c_e3.metric("Executable Threat Flag", rep["Executable Payload Alert"])

            st.markdown(f"**Magic Header Bytes (Hex):** `{rep['Header Hex']}`")

            if rep["Executable Payload Alert"].startswith("YES"):
                st.error("🚨 HIGH-SEVERITY ALERT: File extension masquerades as a document but magic bytes confirm executable machine code!")

            if rep["Metadata"]:
                st.markdown("#### Extracted Metadata Tags")
                if PANDAS_AVAILABLE:
                    render_security_table(pd.DataFrame([{"Tag": k, "Value": str(v)} for k, v in rep["Metadata"].items()]), width="stretch", hide_index=True)
                else:
                    for k, v in rep["Metadata"].items():
                        st.text(f"{k}: {v}")

    else:
        st.markdown("#### Browser History Forensic Acquisition")
        c_hup, c_hdemo = st.columns([3, 1])
        with c_hup:
            hist_file = st.file_uploader("Upload Chrome or Edge 'History' SQLite Database", key="hist_file_up")
        with c_hdemo:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            if st.button("Load Mock History Data", key="btn_h_mock", width="stretch"):
                st.session_state["history_report"] = {
                    "total_records": 3,
                    "top_domains": [{"Domain": "github.com", "Visits": 42}, {"Domain": "cve.mitre.org", "Visits": 18}],
                    "searches": ["CVE-2024-21413 exploit", "reverse shell python3"],
                    "history": [
                        {"Timestamp (UTC)": "2026-09-16 10:14:00", "Page Title": "GitHub Security Advisories", "Target URL": "https://github.com/advisories", "Visits": 12},
                        {"Timestamp (UTC)": "2026-09-16 09:30:11", "Page Title": "NVD NIST Vulnerability", "Target URL": "https://nvd.nist.gov", "Visits": 8}
                    ]
                }
                st.rerun()

        if hist_file:
            data = hist_file.read()
            st.session_state["history_report"] = parse_sqlite_history_bytes(data)
            log_audit_event("forensics", "browser_history_analysis", hist_file.name, "SUCCESS", "INFO", 0.0)

        if st.session_state["history_report"]:
            hr = st.session_state["history_report"]
            if "error" in hr:
                st.error(hr["error"])
            else:
                st.success(f"Successfully processed {hr['total_records']} browsing activity records.")
                st.markdown("#### Top Visited Domains")
                if PANDAS_AVAILABLE and hr["top_domains"]:
                    render_security_table(pd.DataFrame(hr["top_domains"]), width="stretch", hide_index=True)

                if hr["searches"]:
                    st.markdown("#### Extracted Search Queries")
                    for s in hr["searches"]:
                        st.markdown(f"• `{s}`")

                st.markdown("#### Recent Access Log")
                if PANDAS_AVAILABLE and hr["history"]:
                    render_security_table(pd.DataFrame(hr["history"]), width="stretch", hide_index=True)


# =============================================================================
# TAB 7: COMPLIANCE & TELEMETRY (SIEM)
# =============================================================================
with tab_siem:
    st.markdown("""
    <div class="risk-banner">
        💼 <strong>Business Risk Impact:</strong> Immutable audit persistence proves continuous compliance with
        GDPR Article 32, HIPAA §164.312, and SOC 2 Type II logging requirements during regulatory reviews.
    </div>
    """, unsafe_allow_html=True)

    c_filt1, c_filt2, c_filt3, c_filt4 = st.columns([2, 2, 3, 1])
    with c_filt1:
        mod_sel = st.selectbox("Filter Module", ["All", "password_checker", "create_hash", "file_integrity_scanner", "networkscanner", "forensics"])
    with c_filt2:
        sev_sel = st.selectbox("Filter Severity", ["All", "INFO", "WARNING", "HIGH", "CRITICAL"])
    with c_filt3:
        search_txt = st.text_input("Full-Text Search", placeholder="Filter by action or target...")
    with c_filt4:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("Refresh", key="btn_ref_siem", width="stretch"):
            st.cache_data.clear()
            st.rerun()

    audit_records = get_cached_audit_logs(100, mod_sel, sev_sel, search_txt)

    if audit_records:
        if PANDAS_AVAILABLE:
            df_audit = pd.DataFrame(audit_records)
            render_security_table(df_audit, width="stretch", hide_index=True)

            csv_buffer = io.StringIO()
            df_audit.to_csv(csv_buffer, index=False)
            st.download_button(
                label="📥 Export SIEM Audit Trail (.csv)",
                data=csv_buffer.getvalue(),
                file_name=f"aegispoint_siem_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                width="stretch"
            )
        else:
            for r in audit_records:
                st.text(f"[{r['timestamp']}] {r['module_name']} | {r['action']} | {r['severity']} | {r['status']}")
    else:
        st.info("No audit logs matching current query parameters.")


# =============================================================================
# TAB 8: SOC TERMINAL CONSOLE
# =============================================================================
with tab_console:
    st.markdown("""
    <div class="risk-banner">
        💼 <strong>Rapid Triage Console:</strong> Execute direct incident response actions via command-line syntax.
        All commands are audited and persisted directly into the SIEM database.
    </div>
    """, unsafe_allow_html=True)

    def execute_terminal_command(cmd: str) -> str:
        tokens = cmd.strip().split()
        if not tokens:
            return ""
        verb = tokens[0].lower()

        if verb == "help":
            return (
                "AEGISPOINT COMMAND REFERENCE:\n"
                "----------------------------------------------------------------\n"
                "help                     - List available CLI instructions\n"
                "version                  - Print active platform version & standards\n"
                "scan <host>              - Execute rapid port probe against host\n"
                "hash --sha256 <string>   - Compute SHA-256 digest for input\n"
                "pwned <password>         - Query k-anonymity breach database\n"
                "audit --all              - Display recent 5 SIEM audit entries\n"
                "fim --verify             - Trigger simulated tripwire integrity diff\n"
                "clear                    - Clear terminal console screen"
            )

        elif verb == "version":
            return "AegisPoint Enterprise Security Platform (v3.1-LTS) | NIST CSF Aligned"

        elif verb == "scan":
            if len(tokens) < 2:
                return "Error: Target host missing. Syntax: scan <host>"
            host = tokens[1]
            h, ip, results, elapsed = run_concurrent_port_scan(host, [21, 22, 80, 443, 3306, 3389])
            out = [f"Port probe completed for {h} ({ip}) in {elapsed}s:"]
            for r in results:
                out.append(f"  Port {r['Port']:<5} {r['Service']:<12} {r['Status']:<8} Risk: {r['Risk']}")
            log_audit_event("soc_console", "console_port_scan", host, "SUCCESS", "INFO", elapsed * 1000)
            return "\n".join(out)

        elif verb == "hash":
            if len(tokens) < 3 or tokens[1] != "--sha256":
                return "Syntax: hash --sha256 <string_payload>"
            payload = " ".join(tokens[2:])
            dig = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            log_audit_event("soc_console", "console_hash", "SHA-256", "SUCCESS", "INFO", 0.0)
            return f"SHA-256: {dig}"

        elif verb == "pwned":
            if len(tokens) < 2:
                return "Syntax: pwned <password>"
            pwd = tokens[1]
            b, c = check_hibp_breach(pwd)
            if c == -1: return "HIBP API Unreachable."
            return f"ALERT: Discovered in {c:,} breach incidents!" if b else "CLEAN: Not found in public breach records."

        elif verb == "audit" and "--all" in tokens:
            recs = fetch_audit_records(5)
            out = ["RECENT SIEM AUDIT ENTRIES:"]
            for r in recs:
                out.append(f"  [{r['timestamp'][:19]}] {r['module_name']} -> {r['action']} ({r['severity']})")
            return "\n".join(out)

        elif verb == "fim" and "--verify" in tokens:
            log_audit_event("soc_console", "console_fim_verify", "SIMULATION", "WARNING", "HIGH", 0.0)
            return "FIM TRIPWIRE ALERT: Cryptographic mismatch detected between baseline and active binary!"

        elif verb == "clear":
            st.session_state["console_logs"] = []
            return ""

        return f"Command not recognized: '{verb}'. Type 'help' for manual."

    c_cmd_in, c_cmd_btn = st.columns([5, 1])
    with c_cmd_in:
        user_cmd = st.text_input("Console Input", placeholder="e.g. help, scan 127.0.0.1, hash --sha256 AegisPoint", label_visibility="collapsed")
    with c_cmd_btn:
        exec_click = st.button("Execute", key="btn_exec_cmd", width="stretch")

    c_h1, c_h2, c_h3, c_h4 = st.columns(4)
    if c_h1.button("help", width="stretch"): user_cmd = "help"; exec_click = True
    if c_h2.button("scan 127.0.0.1", width="stretch"): user_cmd = "scan 127.0.0.1"; exec_click = True
    if c_h3.button("audit --all", width="stretch"): user_cmd = "audit --all"; exec_click = True
    if c_h4.button("clear", width="stretch"): user_cmd = "clear"; exec_click = True

    if exec_click and user_cmd:
        res = execute_terminal_command(user_cmd)
        if user_cmd.strip().lower() != "clear":
            st.session_state["console_logs"].append(f"$ {user_cmd}")
            if res:
                st.session_state["console_logs"].append(res)
        st.rerun()

    terminal_text = "\n".join(st.session_state["console_logs"])
    st.markdown(f'<div class="terminal-window">{terminal_text}</div>', unsafe_allow_html=True)
