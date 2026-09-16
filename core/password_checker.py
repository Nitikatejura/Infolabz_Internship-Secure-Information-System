"""
Access Control & Password Security Engine (core/password_checker.py)
Features:
1. Hash Algorithm Identification (MD5, SHA1, SHA256, SHA512, bcrypt, Argon2)
2. Credential Hash Verification Engine
3. Password Breach Verification via Have I Been Pwned API (k-Anonymity Model)
"""

import hashlib
import re
import time
from typing import Dict, Tuple, Optional
from core.database import log_event, save_scan_result

# Try importing requests gracefully
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Mock credential database for verification demonstration
MOCK_USER_DB = {
    "amit": hashlib.sha256("Hello@123".encode()).hexdigest(),
    "raj": hashlib.sha256("Python@123".encode()).hexdigest(),
    "darshan": hashlib.sha256("Admin@123".encode()).hexdigest()
}

def identify_hash_type(sample_hash: str) -> str:
    """Identifies probable hashing algorithm based on length and formatting patterns."""
    sample_hash = sample_hash.strip().lower()
    
    if len(sample_hash) == 32 and re.match(r"^[a-f0-9]{32}$", sample_hash):
        return "MD5"
    elif len(sample_hash) == 40 and re.match(r"^[a-f0-9]{40}$", sample_hash):
        return "SHA-1"
    elif len(sample_hash) == 64 and re.match(r"^[a-f0-9]{64}$", sample_hash):
        return "SHA-256"
    elif len(sample_hash) == 128 and re.match(r"^[a-f0-9]{128}$", sample_hash):
        return "SHA-512"
    elif sample_hash.startswith("$2a$") or sample_hash.startswith("$2b$") or sample_hash.startswith("$2y$"):
        return "bcrypt"
    elif sample_hash.startswith("$argon2"):
        return "Argon2"
    else:
        return "Unknown Hash Format"

def verify_credentials(username: str, password_attempt: str) -> Tuple[bool, str]:
    """Verifies a user password attempt against salted/hashed stored credentials."""
    start_time = time.time()
    user_lower = username.strip().lower()
    
    if user_lower not in MOCK_USER_DB:
        elapsed_ms = (time.time() - start_time) * 1000
        log_event("password_checker", "verify_credentials", username, "FAILED", "WARNING", elapsed_ms)
        return False, "User not found"

    computed_hash = hashlib.sha256(password_attempt.encode()).hexdigest()
    is_valid = (computed_hash == MOCK_USER_DB[user_lower])
    
    elapsed_ms = (time.time() - start_time) * 1000
    status = "SUCCESS" if is_valid else "FAILED"
    severity = "INFO" if is_valid else "WARNING"
    log_event("password_checker", "verify_credentials", username, status, severity, elapsed_ms)
    
    return is_valid, "Authentication Successful" if is_valid else "Authentication Failed"

def check_pwned_password(password: str, timeout: float = 5.0) -> Tuple[bool, int]:
    """
    Checks if a password has been compromised in known data breaches.
    Uses k-Anonymity model: Transmits ONLY the first 5 hex chars of SHA-1 hash to HIBP API.
    Returns: (is_pwned: bool, breach_count: int)
    """
    if not REQUESTS_AVAILABLE:
        print("[-] Notice: 'requests' module not installed. Install via `pip install requests` to query HIBP API.")
        return False, 0

    start_time = time.time()
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "SecureInformationSystem-AuditTool"}

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code != 200:
            log_event("password_checker", "check_pwned_password", "HIBP API", "ERROR", "HIGH")
            return False, 0

        for line in response.text.splitlines():
            if ":" not in line:
                continue
            hash_suffix, count_str = line.split(":")
            if hash_suffix.strip() == suffix:
                count = int(count_str.strip())
                elapsed_ms = (time.time() - start_time) * 1000
                log_id = log_event("password_checker", "check_pwned_password", "Breach Found", "WARNING", "HIGH", elapsed_ms)
                save_scan_result(log_id, "pwned_password_breach", {"breached": True, "count": count, "sha1_prefix": prefix})
                return True, count

        elapsed_ms = (time.time() - start_time) * 1000
        log_id = log_event("password_checker", "check_pwned_password", "Safe Password", "SUCCESS", "INFO", elapsed_ms)
        save_scan_result(log_id, "pwned_password_breach", {"breached": False, "count": 0, "sha1_prefix": prefix})
        return False, 0

    except Exception as e:
        log_event("password_checker", "check_pwned_password", str(e), "ERROR", "MEDIUM")
        return False, 0

def run_interactive():
    """Interactive CLI execution loop."""
    print("\n" + "=" * 50)
    print(" ACCESS CONTROL & PASSWORD SECURITY ENGINE")
    print("=" * 50)
    
    print("\n[1] Identify Hash Type")
    print("[2] Test Mock User Authentication")
    print("[3] Check Password Leak Status (k-Anonymity HIBP API)")
    
    choice = input("\nSelect Option (1-3): ").strip()
    
    if choice == "1":
        h_str = input("Enter hash string: ").strip()
        algo = identify_hash_type(h_str)
        print(f"\n[+] Identified Hash Type: {algo}")
    elif choice == "2":
        u = input("Username: ").strip()
        p = input("Password: ").strip()
        ok, msg = verify_credentials(u, p)
        print(f"\n[{'+' if ok else '-'}] Result: {msg}")
    elif choice == "3":
        p = input("Enter Password to Audit: ").strip()
        if not p:
            print("[-] Error: Empty password string.")
            return
        is_breached, count = check_pwned_password(p)
        if is_breached:
            print(f"\n[!] WARNING: Password found in {count:,} known data breaches!")
        else:
            print("\n[+] SAFE: Password not found in public breach callsets (or requests package missing).")
    else:
        print("[-] Invalid Choice.")

if __name__ == "__main__":
    run_interactive()
