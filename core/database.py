"""
Secure Information System (SIS) - Persistence Layer
Manages SQLite database initialization, audit event logging, scan result storage, and baseline tracking.
"""

import os
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

# Base directory paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "sis_audit.db")

def get_connection() -> sqlite3.Connection:
    """Returns a connection to the SQLite database, ensuring directory exists."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """Initializes the database schema if tables do not exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Audit Logs Table
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

        # 2. Scan Results Detail Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER NOT NULL,
            scan_type TEXT NOT NULL,
            details_json TEXT NOT NULL,
            FOREIGN KEY(log_id) REFERENCES audit_logs(event_id) ON DELETE CASCADE
        );
        """)

        # 3. File Integrity Baselines Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS integrity_baselines (
            file_path TEXT PRIMARY KEY,
            sha256_hash TEXT NOT NULL,
            last_verified TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'UNCHANGED'
        );
        """)
        
        conn.commit()

def log_event(module_name: str, action: str, target: str = "", 
              status: str = "SUCCESS", severity: str = "INFO", 
              execution_time_ms: float = 0.0) -> int:
    """Logs a system event into the audit_logs table and returns the event_id."""
    init_db()
    timestamp = datetime.now().isoformat()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, module_name, action, target, status, severity, execution_time_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, module_name, action, target, status, severity, execution_time_ms))
        conn.commit()
        return cursor.lastrowid

def save_scan_result(log_id: int, scan_type: str, details: Dict[str, Any]) -> int:
    """Stores structured JSON scan payload linked to an audit log ID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_results (log_id, scan_type, details_json)
            VALUES (?, ?, ?)
        """, (log_id, scan_type, json.dumps(details)))
        conn.commit()
        return cursor.lastrowid

def save_baseline(file_path: str, sha256_hash: str, status: str = "UNCHANGED") -> None:
    """Saves or updates a file integrity hash baseline."""
    timestamp = datetime.now().isoformat()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO integrity_baselines (file_path, sha256_hash, last_verified, status)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
                sha256_hash=excluded.sha256_hash,
                last_verified=excluded.last_verified,
                status=excluded.status
        """, (file_path, sha256_hash, timestamp, status))
        conn.commit()

def get_baselines() -> Dict[str, str]:
    """Retrieves all stored file path -> sha256 baseline records."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT file_path, sha256_hash FROM integrity_baselines")
        rows = cursor.fetchall()
        return {row["file_path"]: row["sha256_hash"] for row in rows}

def fetch_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetches recent audit log events."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT event_id, timestamp, module_name, action, target, status, severity, execution_time_ms
            FROM audit_logs ORDER BY event_id DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

# Auto-initialize on import
init_db()
