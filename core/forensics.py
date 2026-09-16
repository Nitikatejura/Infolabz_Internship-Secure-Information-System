"""
AegisPoint — Digital Forensics & Evidence Acquisition Engine
Module: core/forensics.py

Provides:
    - analyze_file():           Metadata, magic-byte, EXIF, PDF, ZIP analysis.
    - analyze_browser_history(): Chrome/Edge SQLite history forensics.

Both functions accept in-memory bytes to work in cloud environments
(Streamlit file_uploader) without requiring local filesystem access.
"""

from __future__ import annotations

import io
import os
import shutil
import sqlite3
import struct
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Magic byte signatures (file type fingerprinting)
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x25\x50\x44\x46",           "PDF Document"),
    (b"\xff\xd8\xff",               "JPEG Image"),
    (b"\x89\x50\x4e\x47\x0d\x0a",  "PNG Image"),
    (b"\x47\x49\x46\x38",           "GIF Image"),
    (b"\x42\x4d",                   "BMP Image"),
    (b"\x50\x4b\x03\x04",           "ZIP Archive / Office Document"),
    (b"\x4d\x5a",                   "Windows PE Executable"),
    (b"\x7f\x45\x4c\x46",           "ELF Executable (Linux)"),
    (b"\xd0\xcf\x11\xe0",           "OLE2 Compound (Legacy Office)"),
    (b"\x52\x61\x72\x21",           "RAR Archive"),
    (b"\x1f\x8b",                   "GZIP Archive"),
    (b"\x37\x7a\xbc\xaf\x27\x1c",  "7-Zip Archive"),
    (b"\x25\x21\x50\x53",           "PostScript"),
    (b"\x49\x44\x33",               "MP3 Audio"),
    (b"\x00\x00\x00\x20\x66\x74",   "MP4 Video (ftyp)"),
    (b"\x52\x49\x46\x46",           "WAV/AVI (RIFF)"),
]

DANGEROUS_EXTENSIONS: set[str] = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr",
    ".pif", ".com", ".reg", ".hta", ".msi", ".dll",
}


# ---------------------------------------------------------------------------
# File Analysis
# ---------------------------------------------------------------------------

def analyze_file(file_bytes: bytes, filename: str) -> dict[str, Any]:
    """
    Perform digital forensic analysis on an uploaded file.

    Args:
        file_bytes: Raw bytes of the file (from st.file_uploader or open()).
        filename:   Original filename including extension.

    Returns:
        Structured forensic report dict. Never raises.
    """
    result: dict[str, Any] = {
        "filename":         filename,
        "size_bytes":       len(file_bytes),
        "size_human":       _human_size(len(file_bytes)),
        "extension":        os.path.splitext(filename)[1].lower(),
        "magic_type":       "Unknown",
        "magic_hex":        "",
        "is_dangerous":     False,
        "has_double_ext":   False,
        "image_metadata":   None,
        "pdf_metadata":     None,
        "zip_contents":     None,
        "exif_data":        None,
        "errors":           [],
    }

    # ── Magic bytes ───────────────────────────────────────────────────────
    header = file_bytes[:16]
    result["magic_hex"] = header.hex().upper()
    for sig, label in MAGIC_SIGNATURES:
        if file_bytes[:len(sig)] == sig:
            result["magic_type"] = label
            break

    # ── Extension checks ──────────────────────────────────────────────────
    ext = result["extension"]
    result["is_dangerous"]   = ext in DANGEROUS_EXTENSIONS
    result["has_double_ext"] = filename.count(".") > 1

    # ── Image / EXIF analysis ─────────────────────────────────────────────
    if ext in (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".webp"):
        result.update(_analyze_image(file_bytes, ext))

    # ── PDF analysis ──────────────────────────────────────────────────────
    elif ext == ".pdf":
        result.update(_analyze_pdf(file_bytes))

    # ── ZIP analysis ──────────────────────────────────────────────────────
    elif ext in (".zip", ".docx", ".xlsx", ".pptx"):
        result.update(_analyze_zip(file_bytes))

    return result


def _human_size(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b / 1024 ** 2:.2f} MB"
    return f"{b / 1024 ** 3:.3f} GB"


def _analyze_image(file_bytes: bytes, ext: str) -> dict[str, Any]:
    """Extract image dimensions and EXIF metadata."""
    try:
        from PIL import Image  # type: ignore[import]
        from PIL.ExifTags import TAGS  # type: ignore[import]

        img = Image.open(io.BytesIO(file_bytes))
        exif_raw = img.getexif() if hasattr(img, "getexif") else {}

        useful_tags = {
            "Make", "Model", "DateTime", "DateTimeOriginal", "Software",
            "GPSInfo", "Flash", "ExposureTime", "FocalLength", "LensModel",
            "ISOSpeedRatings", "WhiteBalance", "Orientation",
        }
        exif_data: dict[str, str] = {}
        for tag_id, value in exif_raw.items():
            tag = TAGS.get(tag_id, str(tag_id))
            if tag in useful_tags:
                exif_data[tag] = str(value)

        return {
            "image_metadata": {
                "width":  img.width,
                "height": img.height,
                "format": img.format or ext.upper().lstrip("."),
                "mode":   img.mode,
            },
            "exif_data": exif_data or None,
        }
    except ImportError:
        return {"errors": ["Pillow not installed — image EXIF analysis unavailable."]}
    except Exception as exc:
        return {"errors": [f"Image analysis error: {exc}"]}


def _analyze_pdf(file_bytes: bytes) -> dict[str, Any]:
    """Extract PDF metadata and page count."""
    try:
        import pypdf  # type: ignore[import]

        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        meta   = reader.metadata or {}
        return {
            "pdf_metadata": {
                "pages":     len(reader.pages),
                "encrypted": reader.is_encrypted,
                **{k.lstrip("/"): str(v) for k, v in meta.items()},
            }
        }
    except ImportError:
        try:
            # Fallback to pypdf2 if installed
            import PyPDF2  # type: ignore[import]
            reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
            meta   = reader.metadata or {}
            return {
                "pdf_metadata": {
                    "pages":     len(reader.pages),
                    "encrypted": reader.is_encrypted,
                    **{k.lstrip("/"): str(v) for k, v in meta.items()},
                }
            }
        except Exception as exc:
            return {"errors": [f"PDF library not available: {exc}"]}
    except Exception as exc:
        return {"errors": [f"PDF analysis error: {exc}"]}


def _analyze_zip(file_bytes: bytes) -> dict[str, Any]:
    """List ZIP/Office archive contents and detect encryption."""
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
            entries = []
            encrypted = False
            for info in zf.infolist():
                is_enc = bool(info.flag_bits & 0x1)
                if is_enc:
                    encrypted = True
                entries.append({
                    "name":       info.filename,
                    "size_bytes": info.file_size,
                    "compressed": info.compress_size,
                    "encrypted":  is_enc,
                })
            return {
                "zip_contents": {
                    "total_files": len(entries),
                    "encrypted":   encrypted,
                    "entries":     entries[:50],  # cap for large archives
                }
            }
    except zipfile.BadZipFile:
        return {"errors": ["File is not a valid ZIP archive."]}
    except Exception as exc:
        return {"errors": [f"ZIP analysis error: {exc}"]}


# ---------------------------------------------------------------------------
# Browser History Forensics
# ---------------------------------------------------------------------------

def analyze_browser_history(
    db_bytes: bytes,
    limit: int = 100,
) -> dict[str, Any]:
    """
    Forensically parse a Chrome/Edge browser History SQLite database.

    Accepts in-memory bytes (e.g., from st.file_uploader) to handle
    locked databases without requiring filesystem access.

    Args:
        db_bytes: Raw bytes of the browser History SQLite file.
        limit:    Maximum number of history records to return.

    Returns:
        Structured forensic report with history, domain stats, and searches.
    """
    result: dict[str, Any] = {
        "total_records":    0,
        "unique_domains":   0,
        "total_visits":     0,
        "history":          [],
        "top_domains":      [],
        "google_searches":  [],
        "error":            None,
    }

    tmp_path: str | None = None
    conn: sqlite3.Connection | None = None

    try:
        # Write bytes to a temp file — SQLite needs a real file path
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp.write(db_bytes)
            tmp_path = tmp.name

        conn = sqlite3.connect(tmp_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Verify it's a Chrome-compatible schema
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='urls';"
        )
        if not cur.fetchone():
            result["error"] = "Not a valid Chrome/Edge History database (missing 'urls' table)."
            return result

        cur.execute(
            "SELECT url, title, visit_count, last_visit_time FROM urls "
            "ORDER BY last_visit_time DESC LIMIT ?;",
            (limit,),
        )
        rows = cur.fetchall()
        result["total_records"] = len(rows)

        domain_stats: dict[str, int] = {}
        seen_searches: set[str] = set()
        history_records: list[dict[str, Any]] = []

        for row in rows:
            url, title, visits, ctime = (
                row["url"], row["title"], row["visit_count"], row["last_visit_time"]
            )

            # Convert Chrome's microseconds-since-1601 timestamp
            try:
                visit_time = (
                    datetime(1601, 1, 1, tzinfo=timezone.utc)
                    + timedelta(microseconds=int(ctime))
                ).strftime("%d-%m-%Y %H:%M:%S UTC")
            except Exception:
                visit_time = "Unknown"

            history_records.append({
                "url":        url,
                "title":      title or "No Title",
                "visits":     visits,
                "last_visit": visit_time,
            })

            # Domain stats
            domain = urlparse(url).netloc.replace("www.", "").strip()
            if domain:
                domain_stats[domain] = domain_stats.get(domain, 0) + (visits or 1)

            # Google search extraction
            if "google.com/search" in url:
                q_list = parse_qs(urlparse(url).query).get("q", [])
                if q_list and q_list[0] not in seen_searches:
                    seen_searches.add(q_list[0])
                    result["google_searches"].append(q_list[0])

        result["history"]        = history_records
        result["top_domains"]    = sorted(
            [{"domain": d, "visits": v} for d, v in domain_stats.items()],
            key=lambda x: x["visits"],
            reverse=True,
        )[:15]
        result["unique_domains"] = len(domain_stats)
        result["total_visits"]   = sum(r["visits"] or 0 for r in rows)

    except sqlite3.DatabaseError as exc:
        result["error"] = f"SQLite error: {exc}"
    except Exception as exc:
        result["error"] = f"Unexpected error: {exc}"
    finally:
        if conn:
            conn.close()
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    return result


# ---------------------------------------------------------------------------
# Demo / Sample Data
# ---------------------------------------------------------------------------

SAMPLE_FORENSIC_REPORT: dict[str, Any] = {
    "filename":       "evidence_photo.jpg",
    "size_bytes":     3_145_728,
    "size_human":     "3.00 MB",
    "extension":      ".jpg",
    "magic_type":     "JPEG Image",
    "magic_hex":      "FFD8FFE00010JFIF",
    "is_dangerous":   False,
    "has_double_ext": False,
    "image_metadata": {"width": 4032, "height": 3024, "format": "JPEG", "mode": "RGB"},
    "exif_data": {
        "Make":              "Apple",
        "Model":             "iPhone 14 Pro",
        "DateTime":          "2024:03:15 09:42:11",
        "Software":          "17.3.1",
        "GPSInfo":           "GPS coordinates embedded",
        "ISOSpeedRatings":   "100",
        "FocalLength":       "6.86mm",
    },
    "errors": [],
}

SAMPLE_HISTORY_REPORT: dict[str, Any] = {
    "total_records": 3,
    "unique_domains": 3,
    "total_visits": 47,
    "history": [
        {"url": "https://github.com/search?q=python+security", "title": "Search Results · GitHub", "visits": 12, "last_visit": "17-09-2024 08:30:00 UTC"},
        {"url": "https://stackoverflow.com/questions/tagged/cybersecurity", "title": "Cybersecurity Questions - Stack Overflow", "visits": 8, "last_visit": "17-09-2024 07:15:22 UTC"},
        {"url": "https://google.com/search?q=CVE-2024-21413", "title": "CVE-2024-21413 - Google Search", "visits": 27, "last_visit": "17-09-2024 06:05:11 UTC"},
    ],
    "top_domains": [
        {"domain": "google.com", "visits": 27},
        {"domain": "github.com", "visits": 12},
        {"domain": "stackoverflow.com", "visits": 8},
    ],
    "google_searches": ["CVE-2024-21413", "python network scanner asyncio"],
    "error": None,
}
