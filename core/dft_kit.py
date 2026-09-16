"""
Digital Evidence Artifact Analyzer (core/dft_kit.py)
Features:
- Magic Byte Signature Verification (Detects File Extension Spoofing)
- MACB Forensic Timeline Extraction (Created, Modified, Accessed)
- Suspicious Double-Extension & Hidden Dotfile Inspection
- Image EXIF Metadata Extraction (Camera Info, GPS, Timestamps)
- PDF Metadata & Encryption Analysis
- ZIP Archive Inspection & Encrypted Flag Detection (Bitwise 0x1)
- Report Exporter to JSON / CSV format in reports/ directory
"""

import csv
import json
import os
import time
import zipfile
from datetime import datetime
from typing import Dict, Any, Optional

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import PyPDF2
    PYPDF2_AVAILABLE = True
except ImportError:
    PYPDF2_AVAILABLE = False

from core.database import log_event, save_scan_result

MAGIC_SIGNATURES = {
    "25504446": "PDF Document",
    "FFD8FF": "JPEG Image",
    "89504E47": "PNG Image",
    "504B0304": "ZIP Archive / Office Document",
    "4D5A": "Windows Executable (PE)",
    "7F454C46": "Linux ELF Executable",
    "49492A00": "TIFF Image (Little Endian)",
    "4D4D002A": "TIFF Image (Big Endian)"
}

DANGEROUS_EXTENSIONS = [".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".ps1"]

def get_human_readable_size(bytes_size: int) -> str:
    """Formats raw byte counts into human-readable strings."""
    if bytes_size < 1024:
        return f"{bytes_size} Bytes"
    elif bytes_size < 1024 * 1024:
        return f"{round(bytes_size / 1024, 2)} KB"
    else:
        return f"{round(bytes_size / (1024 * 1024), 2)} MB"

def analyze_digital_evidence(filepath: str) -> Dict[str, Any]:
    """Performs deep forensic audit on a target digital evidence file."""
    start_time = time.time()
    abs_path = os.path.abspath(filepath)

    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"Evidence file not found: {filepath}")

    filename = os.path.basename(abs_path)
    extension = os.path.splitext(filename)[1].lower()
    file_size_bytes = os.path.getsize(abs_path)

    report = {
        "file_name": filename,
        "file_path": abs_path,
        "extension": extension,
        "size": get_human_readable_size(file_size_bytes),
        "size_bytes": file_size_bytes,
        "timeline": {
            "created": datetime.fromtimestamp(os.path.getctime(abs_path)).strftime("%Y-%m-%d %H:%M:%S"),
            "modified": datetime.fromtimestamp(os.path.getmtime(abs_path)).strftime("%Y-%m-%d %H:%M:%S"),
            "accessed": datetime.fromtimestamp(os.path.getatime(abs_path)).strftime("%Y-%m-%d %H:%M:%S")
        },
        "security_flags": {
            "is_hidden": filename.startswith("."),
            "suspicious_executable_extension": extension in DANGEROUS_EXTENSIONS,
            "multiple_extensions": filename.count(".") > 1
        },
        "signature_analysis": {},
        "type_specific_metadata": {}
    }

    # 1. Magic Bytes Signature Analysis
    with open(abs_path, "rb") as f:
        header_bytes = f.read(8)

    hex_sig = header_bytes.hex().upper()
    report["signature_analysis"]["raw_hex"] = " ".join(hex_sig[i:i+2] for i in range(0, len(hex_sig), 2))
    
    detected_type = "Unknown File Type"
    for sig, label in MAGIC_SIGNATURES.items():
        if hex_sig.startswith(sig):
            detected_type = label
            break

    report["signature_analysis"]["detected_type"] = detected_type
    
    # Check for Extension Spoofing
    is_spoofed = False
    if extension in [".jpg", ".jpeg"] and not hex_sig.startswith("FFD8FF"):
        is_spoofed = True
    elif extension == ".pdf" and not hex_sig.startswith("25504446"):
        is_spoofed = True
    elif extension == ".png" and not hex_sig.startswith("89504E47"):
        is_spoofed = True
    elif extension == ".exe" and not hex_sig.startswith("4D5A"):
        is_spoofed = True

    report["security_flags"]["extension_spoofed"] = is_spoofed

    # 2. Type-Specific Parsing
    if extension in [".jpg", ".jpeg", ".png"]:
        if PIL_AVAILABLE:
            try:
                with Image.open(abs_path) as img:
                    img_meta = {
                        "dimensions": f"{img.width} x {img.height}",
                        "format": img.format,
                        "color_mode": img.mode,
                        "exif": {}
                    }
                    exif_data = img.getexif()
                    if exif_data:
                        for tag_id, val in exif_data.items():
                            tag_name = TAGS.get(tag_id, tag_id)
                            if isinstance(val, (str, int, float)):
                                img_meta["exif"][str(tag_name)] = str(val)
                    report["type_specific_metadata"] = img_meta
            except Exception as e:
                report["type_specific_metadata"]["error"] = f"Image parsing failed: {e}"
        else:
            report["type_specific_metadata"]["notice"] = "Pillow library not installed. Install via `pip install Pillow` for EXIF details."

    elif extension == ".pdf":
        if PYPDF2_AVAILABLE:
            try:
                with open(abs_path, "rb") as f:
                    reader = PyPDF2.PdfReader(f)
                    pdf_meta = {
                        "total_pages": len(reader.pages),
                        "is_encrypted": reader.is_encrypted,
                        "pdf_attributes": {}
                    }
                    if reader.metadata:
                        for k, v in reader.metadata.items():
                            pdf_meta["pdf_attributes"][str(k)] = str(v)
                    report["type_specific_metadata"] = pdf_meta
            except Exception as e:
                report["type_specific_metadata"]["error"] = f"PDF parsing failed: {e}"
        else:
            report["type_specific_metadata"]["notice"] = "PyPDF2 library not installed. Install via `pip install PyPDF2` for PDF parsing."

    elif extension == ".zip":
        try:
            with zipfile.ZipFile(abs_path, "r") as zf:
                file_list = zf.infolist()
                is_password_protected = any(item.flag_bits & 0x1 for item in file_list)
                report["type_specific_metadata"] = {
                    "contained_files_count": len(file_list),
                    "is_password_protected": is_password_protected,
                    "file_names": [item.filename for item in file_list[:15]]
                }
        except Exception as e:
            report["type_specific_metadata"]["error"] = f"ZIP parsing failed: {e}"

    elapsed_ms = (time.time() - start_time) * 1000
    severity = "HIGH" if is_spoofed or report["security_flags"]["suspicious_executable_extension"] else "INFO"
    log_id = log_event("dft_kit", "evidence_analysis", filename, "SUCCESS", severity, elapsed_ms)
    save_scan_result(log_id, "digital_evidence_report", report)

    return report

def export_report(report_data: Dict[str, Any], output_format: str = "json") -> str:
    """Exports evidence analysis report to reports/ directory in JSON or CSV format."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_name = "".join(c if c.isalnum() else "_" for c in report_data["file_name"])

    if output_format.lower() == "csv":
        out_path = os.path.join(reports_dir, f"evidence_{sanitized_name}_{timestamp_str}.csv")
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Property", "Value"])
            writer.writerow(["File Name", report_data["file_name"]])
            writer.writerow(["Size", report_data["size"]])
            writer.writerow(["Detected Magic Type", report_data["signature_analysis"].get("detected_type")])
            writer.writerow(["Extension Spoofed", report_data["security_flags"].get("extension_spoofed")])
            writer.writerow(["Created Time", report_data["timeline"]["created"]])
            writer.writerow(["Modified Time", report_data["timeline"]["modified"]])
    else:
        out_path = os.path.join(reports_dir, f"evidence_{sanitized_name}_{timestamp_str}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)

    return out_path

def run_interactive():
    """Interactive CLI interface for Digital Evidence Analyzer."""
    print("\n" + "=" * 50)
    print(" DIGITAL EVIDENCE ARTIFACT ANALYZER")
    print("=" * 50)
    path = input("\nEnter File Path to Investigate: ").strip()
    if not path or not os.path.exists(path):
        print("[-] Error: File path does not exist.")
        return

    print(f"\n[*] Executing forensic analysis on: {os.path.basename(path)} ...")
    try:
        data = analyze_digital_evidence(path)
        print("\n" + "-" * 50)
        print(" FORENSIC EVIDENCE ANALYSIS REPORT")
        print("-" * 50)
        print(f" File Name     : {data['file_name']}")
        print(f" Extension     : {data['extension']}")
        print(f" File Size     : {data['size']}")
        print(f" Magic Bytes   : {data['signature_analysis']['raw_hex']}")
        print(f" Detected Type : {data['signature_analysis']['detected_type']}")
        
        flags = data["security_flags"]
        if flags["extension_spoofed"]:
            print(" [!] ALERT: FILE EXTENSION SPOOFING DETECTED!")
        if flags["suspicious_executable_extension"]:
            print(" [!] ALERT: EXECUTABLE SCRIPT EXTENSION!")
        if flags["multiple_extensions"]:
            print(" [!] WARNING: DOUBLE EXTENSION DETECTED!")

        print("\n TIMELINE ANALYSIS:")
        print(f"  • Created  : {data['timeline']['created']}")
        print(f"  • Modified : {data['timeline']['modified']}")
        print(f"  • Accessed : {data['timeline']['accessed']}")

        exp = input("\nExport report to file? [j=JSON / c=CSV / n=No]: ").strip().lower()
        if exp == "j":
            out_f = export_report(data, "json")
            print(f"[+] Report exported to: {out_f}")
        elif exp == "c":
            out_f = export_report(data, "csv")
            print(f"[+] Report exported to: {out_f}")

    except Exception as e:
        print(f"[-] Analysis Error: {e}")

if __name__ == "__main__":
    run_interactive()
