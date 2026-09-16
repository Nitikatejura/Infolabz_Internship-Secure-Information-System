"""
Threat Reconnaissance & Web Security Header Audit Engine (core/info_scanner.py)
Features:
- Web Application Reachability & Latency Benchmarking
- HTTP Security Headers Audit & Security Score Calculation (0-6)
- SSL/TLS Certificate Verification & Expiration Inspection
- Session Cookie Security Flag Audit (Secure, HttpOnly, SameSite)
- Domain WHOIS & DNS Information Extraction
- Redirection Chain & Endpoint File Discovery (robots.txt, sitemap.xml)
"""

import socket
import ssl
import time
from typing import Dict, Any, List
from urllib.parse import urlparse
from core.database import log_event, save_scan_result

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def scan_web_security_posture(target_url: str, timeout: float = 8.0) -> Dict[str, Any]:
    """Performs comprehensive passive security assessment of a target web application."""
    start_time = time.time()
    
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path.split("/")[0]

    report = {
        "url": target_url,
        "domain": domain,
        "reachable": False,
        "status_code": None,
        "response_time_sec": None,
        "https_enabled": target_url.startswith("https://"),
        "server_banner": None,
        "ip_address": None,
        "security_headers": {},
        "header_score": 0,
        "robots_txt_found": False,
        "sitemap_xml_found": False,
        "redirect_history": [],
        "whois_info": {},
        "cookie_security": [],
        "ssl_info": {}
    }

    if not REQUESTS_AVAILABLE:
        report["error"] = "The 'requests' library is not installed. Run `pip install requests` to enable web reconnaissance."
        return report

    # 1. HTTP GET Request & Latency
    try:
        req_start = time.time()
        resp = requests.get(target_url, timeout=timeout, allow_redirects=True)
        report["response_time_sec"] = round(time.time() - req_start, 3)
        report["reachable"] = True
        report["status_code"] = resp.status_code
        report["server_banner"] = resp.headers.get("Server", "Hidden / Not Disclosed")
        
        # Redirection tracking
        if resp.history:
            report["redirect_history"] = [{"status": r.status_code, "url": r.url} for r in resp.history]

        # 2. Security Headers Scoring
        score = 0
        for h in SECURITY_HEADERS:
            is_present = h in resp.headers
            if is_present:
                score += 1
            report["security_headers"][h] = {
                "present": is_present,
                "value": resp.headers.get(h, "") if is_present else None
            }
        report["header_score"] = score

        # 3. Cookie Flags Inspection
        for cookie in resp.cookies:
            c_info = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": "HttpOnly" in getattr(cookie, "_rest", {})
            }
            report["cookie_security"].append(c_info)

    except Exception as e:
        report["error"] = f"HTTP Connection Failed: {e}"
        log_event("info_scanner", "web_scan", target_url, "ERROR", "MEDIUM")
        return report

    # 4. DNS Lookup
    try:
        report["ip_address"] = socket.gethostbyname(domain)
    except socket.gaierror:
        report["ip_address"] = "Resolution Failed"

    # 5. robots.txt & sitemap.xml
    try:
        r_resp = requests.get(target_url.rstrip("/") + "/robots.txt", timeout=3)
        report["robots_txt_found"] = (r_resp.status_code == 200)
    except Exception:
        pass

    try:
        s_resp = requests.get(target_url.rstrip("/") + "/sitemap.xml", timeout=3)
        report["sitemap_xml_found"] = (s_resp.status_code == 200)
    except Exception:
        pass

    # 6. WHOIS Domain Records
    if WHOIS_AVAILABLE:
        try:
            w = whois.whois(domain)
            report["whois_info"] = {
                "registrar": str(w.registrar),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date)
            }
        except Exception:
            report["whois_info"] = {"status": "WHOIS Lookup Unavailable"}
    else:
        report["whois_info"] = {"status": "'python-whois' package not installed"}

    # 7. SSL Certificate Inspection
    if report["https_enabled"]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    report["ssl_info"] = {
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "not_after": cert.get("notAfter"),
                        "subject": dict(x[0] for x in cert.get("subject", ()))
                    }
        except Exception as e:
            report["ssl_info"] = {"error": f"SSL Handshake Failed: {e}"}

    elapsed_ms = (time.time() - start_time) * 1000
    log_id = log_event("info_scanner", "web_recon", target_url, "SUCCESS", "INFO", elapsed_ms)
    save_scan_result(log_id, "web_reconnaissance", report)
    return report

def run_interactive():
    """Interactive CLI runner for Web Reconnaissance Engine."""
    print("\n" + "=" * 50)
    print(" THREAT RECONNAISSANCE & WEB HEADER AUDIT ENGINE")
    print("=" * 50)
    
    if not REQUESTS_AVAILABLE:
        print("[-] Error: 'requests' package missing. Please run `pip install -r requirements.txt`.")
        return

    target = input("\nEnter Target Website URL (e.g. https://www.example.com): ").strip()
    if not target:
        print("[-] Target URL cannot be empty.")
        return

    print(f"\n[*] Probing web security posture for: {target} ...")
    data = scan_web_security_posture(target)

    if not data.get("reachable"):
        print(f"[-] Error: {data.get('error', 'Target unreachable.')}")
        return

    print("\n" + "-" * 50)
    print(" SECURITY POSTURE REPORT")
    print("-" * 50)
    print(f" Target Domain   : {data['domain']} ({data['ip_address']})")
    print(f" Status Code     : {data['status_code']}")
    print(f" Response Time   : {data['response_time_sec']} seconds")
    print(f" Server Banner   : {data['server_banner']}")
    print(f" Header Score    : {data['header_score']} / 6 Headers Implemented")
    print(f" robots.txt      : {'Found' if data['robots_txt_found'] else 'Not Found'}")
    print(f" sitemap.xml     : {'Found' if data['sitemap_xml_found'] else 'Not Found'}")
    
    print("\n SECURITY HEADERS STATUS:")
    for h, details in data["security_headers"].items():
        status_icon = "[+]" if details["present"] else "[-]"
        print(f"  {status_icon} {h:30s}: {'ENABLED' if details['present'] else 'MISSING'}")

    if data.get("ssl_info") and "not_after" in data["ssl_info"]:
        print(f"\n SSL CERTIFICATE EXPIRY: {data['ssl_info']['not_after']}")

if __name__ == "__main__":
    run_interactive()
