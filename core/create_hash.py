"""
Cryptographic Digest & Hashing Utility (core/create_hash.py)
Provides multi-algorithm cryptographic hashing for strings and files with salt support.
Fixed legacy hashlib.md5() initialization bug.
"""

import hashlib
import os
import time
from typing import Dict, Optional
from core.database import log_event

SUPPORTED_ALGORITHMS = ["MD5", "SHA-1", "SHA-256", "SHA-512", "BLAKE2b"]

def generate_string_hashes(text: str, salt: Optional[str] = None) -> Dict[str, str]:
    """
    Generates digests for all supported hash algorithms.
    Fixed Bug: Passes raw byte input into hasher rather than hashing empty string.
    """
    start_time = time.time()
    payload = text + (salt if salt else "")
    data_bytes = payload.encode("utf-8")

    results = {
        "MD5": hashlib.md5(data_bytes).hexdigest(),
        "SHA-1": hashlib.sha1(data_bytes).hexdigest(),
        "SHA-256": hashlib.sha256(data_bytes).hexdigest(),
        "SHA-512": hashlib.sha512(data_bytes).hexdigest(),
        "BLAKE2b": hashlib.blake2b(data_bytes).hexdigest()
    }
    
    elapsed_ms = (time.time() - start_time) * 1000
    log_event("create_hash", "hash_string", f"Length: {len(text)} chars", "SUCCESS", "INFO", elapsed_ms)
    return results

def compute_file_hash(filepath: str, algorithm: str = "SHA-256", chunk_size: int = 65536) -> str:
    """
    Computes cryptographic hash of a file using chunked binary reading.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Target file not found: {filepath}")

    algorithm_upper = algorithm.upper()
    hasher_map = {
        "MD5": hashlib.md5,
        "SHA-1": hashlib.sha1,
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512,
        "BLAKE2B": hashlib.blake2b
    }

    if algorithm_upper not in hasher_map:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Choose from {list(hasher_map.keys())}")

    hasher = hasher_map[algorithm_upper]()
    start_time = time.time()

    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)

    digest = hasher.hexdigest()
    elapsed_ms = (time.time() - start_time) * 1000
    log_event("create_hash", "hash_file", filepath, "SUCCESS", "INFO", elapsed_ms)
    return digest

def run_interactive():
    """Runs interactive CLI for hash generation."""
    print("\n" + "=" * 50)
    print(" CRYPTOGRAPHIC DIGEST & HASHING ENGINE")
    print("=" * 50)
    mode = input("Select Mode: [1] Hash String [2] Hash File: ").strip()
    
    if mode == "1":
        pwd = input("Enter text/password to hash: ").strip()
        if not pwd:
            print("[-] Error: Input string cannot be empty.")
            return
        salt = input("Enter optional salt (press Enter to skip): ").strip() or None
        digests = generate_string_hashes(pwd, salt)
        print("\nGenerated Hashes:")
        for algo, val in digests.items():
            print(f"  {algo:8s}: {val}")
    elif mode == "2":
        path = input("Enter File Path: ").strip()
        if os.path.exists(path):
            algo = input("Choose Algorithm (MD5/SHA-1/SHA-256/SHA-512) [default: SHA-256]: ").strip() or "SHA-256"
            try:
                h = compute_file_hash(path, algo)
                print(f"\n[+] {algo} Hash: {h}")
            except Exception as e:
                print(f"[-] Error: {e}")
        else:
            print("[-] Error: File not found.")
    else:
        print("[-] Invalid selection.")

if __name__ == "__main__":
    run_interactive()
