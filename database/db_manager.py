"""
AegisPoint — Centralized Audit Persistence Layer
Module: database/db_manager.py

Auto-creates and manages sis_audit.db with three normalized tables:
    - audit_logs        : Every tool execution event
    - scan_results      : JSON-serialized scan outputs
    - integrity_baselines: FIM baseline snapshots
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Database lives at project root
_DB_PATH = Path(__file__).resolve().parent.parent / "sis_audit.db"

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS audit_logs (
    event_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    module_name      TEXT    NOT NULL,
    action           TEXT    NOT NULL,
    target           TEXT,
    status           TEXT    NOT NULL DEFAULT 'SUCCESS',
    severity         TEXT    NOT NULL DEFAULT 'INFO',
    execution_time_ms REAL
);

CREATE TABLE IF NOT EXISTS scan_results (
    result_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id      INTEGER REFERENCES audit_logs(event_id) ON DELETE CASCADE,
    scan_type   TEXT NOT NULL,
    details_json TEXT
);

CREATE TABLE IF NOT EXISTS integrity_baselines (
    file_path     TEXT PRIMARY KEY,
    sha256_hash   TEXT NOT NULL,
    last_verified TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'BASELINE'
);
"""


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def init_db(db_path: str | Path | None = None) -> str:
    """
    Initialize the SQLite database, creating tables if they don't exist.

    Args:
        db_path: Optional override path. Defaults to project-root sis_audit.db.

    Returns:
        Absolute path string of the database file.
    """
    path = Path(db_path) if db_path else _DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(path) as conn:
        conn.executescript(_DDL)
    return str(path)


def get_db_path() -> Path:
    """Return the resolved Path to sis_audit.db."""
    return _DB_PATH


# ---------------------------------------------------------------------------
# Write operations
# ---------------------------------------------------------------------------

def log_event(
    module_name: str,
    action: str,
    target: str = "",
    status: str = "SUCCESS",
    severity: str = "INFO",
    execution_time_ms: float | None = None,
    details: dict[str, Any] | None = None,
    scan_type: str | None = None,
) -> int:
    """
    Insert one audit event and optionally store associated scan details.

    Args:
        module_name:       Name of the calling module (e.g. 'NetworkScanner').
        action:            Short action description (e.g. 'Port Scan').
        target:            Target string (IP, URL, file path, etc.).
        status:            'SUCCESS' | 'FAILURE' | 'WARNING' | 'ERROR'.
        severity:          'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'.
        execution_time_ms: Optional elapsed time in milliseconds.
        details:           Optional dict to serialise into scan_results.
        scan_type:         Required if details provided — labels the result row.

    Returns:
        The new event_id integer.
    """
    init_db()
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO audit_logs
                (module_name, action, target, status, severity, execution_time_ms)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (module_name, action, target, status, severity, execution_time_ms),
        )
        event_id = cur.lastrowid

        if details is not None and event_id:
            conn.execute(
                "INSERT INTO scan_results (log_id, scan_type, details_json) VALUES (?, ?, ?)",
                (event_id, scan_type or module_name, json.dumps(details, default=str)),
            )
    return event_id or 0


def upsert_baseline(file_path: str, sha256_hash: str, status: str = "BASELINE") -> None:
    """
    Insert or update an integrity baseline record.

    Args:
        file_path:   Absolute or relative file path (primary key).
        sha256_hash: SHA-256 hex digest of the file.
        status:      'BASELINE' | 'VERIFIED' | 'TAMPERED'.
    """
    init_db()
    ts = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO integrity_baselines (file_path, sha256_hash, last_verified, status)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
                sha256_hash   = excluded.sha256_hash,
                last_verified = excluded.last_verified,
                status        = excluded.status
            """,
            (file_path, sha256_hash, ts, status),
        )


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------

def fetch_logs(
    limit: int = 200,
    module_filter: str | None = None,
    search: str | None = None,
) -> list[dict[str, Any]]:
    """
    Retrieve audit log rows with optional filtering.

    Args:
        limit:         Maximum rows to return (newest first).
        module_filter: If set, filter to this module_name.
        search:        Substring search across action and target columns.

    Returns:
        List of dicts matching column names.
    """
    init_db()
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params: list[Any] = []

    if module_filter:
        query += " AND module_name = ?"
        params.append(module_filter)
    if search:
        query += " AND (action LIKE ? OR target LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])

    query += " ORDER BY event_id DESC LIMIT ?"
    params.append(limit)

    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def fetch_stats() -> dict[str, Any]:
    """
    Return aggregate statistics for the SOC dashboard metric cards.

    Returns:
        dict with total_events, last_event_ts, by_module, by_severity, by_status.
    """
    init_db()
    with _connect() as conn:
        conn.row_factory = sqlite3.Row

        total = conn.execute("SELECT COUNT(*) as c FROM audit_logs").fetchone()["c"]
        last  = conn.execute(
            "SELECT timestamp FROM audit_logs ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        last_ts = last["timestamp"] if last else "Never"

        by_module = {
            row["module_name"]: row["c"]
            for row in conn.execute(
                "SELECT module_name, COUNT(*) as c FROM audit_logs GROUP BY module_name"
            ).fetchall()
        }
        by_severity = {
            row["severity"]: row["c"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) as c FROM audit_logs GROUP BY severity"
            ).fetchall()
        }
        by_status = {
            row["status"]: row["c"]
            for row in conn.execute(
                "SELECT status, COUNT(*) as c FROM audit_logs GROUP BY status"
            ).fetchall()
        }

    return {
        "total_events": total,
        "last_event_ts": last_ts,
        "by_module":    by_module,
        "by_severity":  by_severity,
        "by_status":    by_status,
    }


def fetch_baselines() -> list[dict[str, Any]]:
    """Return all integrity baseline records."""
    init_db()
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM integrity_baselines ORDER BY last_verified DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_distinct_modules() -> list[str]:
    """Return sorted list of distinct module names logged so far."""
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT module_name FROM audit_logs ORDER BY module_name"
        ).fetchall()
    return [r[0] for r in rows]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _connect(path: Path | None = None) -> sqlite3.Connection:
    """Open a WAL-mode SQLite connection with sane defaults."""
    return sqlite3.connect(str(path or _DB_PATH), check_same_thread=False)


class Timer:
    """Context manager that measures elapsed milliseconds."""

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_: Any) -> None:
        self.elapsed_ms = round((time.perf_counter() - self._start) * 1000, 1)
