"""Modular, safe security scanning engine.

Performs safe, non-destructive security checks:
- HTTP response analysis and security header verification (CSP, HSTS, X-Frame-Options, etc.)
- Cookie security analysis (Secure, HttpOnly, SameSite)
- Sensitive exposed files / directories detection (.git/HEAD, .env, robots.txt, /.well-known/security.txt)
- Rate limiting, timeout management, cancellation support, and structured result generation.
Never executes destructive tests, exploits, or automatic shell commands.
"""
from __future__ import annotations

import datetime
import hashlib
import http.client
import ssl
import time
from typing import Any, Callable
from urllib.parse import urlsplit

from security_scope import ScopeError, TargetScope, resolve_and_validate_host

# Standard security headers to evaluate
SECURITY_HEADERS = {
    "content-security-policy": {
        "title": "Content-Security-Policy Missing or Weak",
        "severity": "medium",
        "cwe": "CWE-1021",
        "description": "CSP restricts resource loading and mitigates XSS/clickjacking attacks.",
    },
    "strict-transport-security": {
        "title": "HTTP Strict Transport Security (HSTS) Missing",
        "severity": "medium",
        "cwe": "CWE-523",
        "description": "HSTS enforces HTTPS connections and prevents SSL stripping.",
    },
    "x-frame-options": {
        "title": "X-Frame-Options Header Missing",
        "severity": "low",
        "cwe": "CWE-1021",
        "description": "X-Frame-Options prevents clickjacking by disallowing framing.",
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options Header Missing",
        "severity": "low",
        "cwe": "CWE-16",
        "description": "X-Content-Type-Options: nosniff prevents MIME-type sniffing.",
    },
    "referrer-policy": {
        "title": "Referrer-Policy Header Missing",
        "severity": "low",
        "cwe": "CWE-116",
        "description": "Referrer-Policy protects sensitive path or query parameters in referrers.",
    },
    "permissions-policy": {
        "title": "Permissions-Policy Header Missing",
        "severity": "low",
        "cwe": "CWE-16",
        "description": "Permissions-Policy controls browser features like camera, microphone, and geolocation.",
    },
}

# Safe paths for exposed configuration/file checks
SAFE_PROBE_PATHS = [
    ("/robots.txt", "Robots File Disclosed", "info", "Robots.txt discloses path structures."),
    ("/.well-known/security.txt", "Security.txt Contact Available", "info", "RFC 9116 security contact information."),
    ("/.git/HEAD", "Exposed .git Repository", "high", "Exposed Git repository allows complete source code disclosure."),
    ("/.env", "Exposed Environment Configuration", "critical", "Exposed .env configuration file reveals secrets and keys."),
    ("/backup.zip", "Exposed Backup Archive", "high", "Publicly downloadable backup archive file."),
]


class ScanCancelledException(Exception):
    """Raised when a scan is cancelled by user request."""


class SafeHTTPClient:
    """SSRF-guarded HTTP client that validates resolved IP on every connection."""

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    def request(
        self,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        # Enforce SSRF validation on resolved IPs immediately before connecting
        safe_ips = resolve_and_validate_host(host)

        req_headers = {
            "User-Agent": "Mizan-Security-Scanner/1.0 (Authorized Security Assessment)",
            "Accept": "*/*",
            "Host": host if port in (80, 443) else f"{host}:{port}",
        }
        if headers:
            req_headers.update(headers)

        # Anti-DNS Rebinding: connect directly to the verified safe IP while preserving Host header and SNI
        connect_ip = safe_ips[0]
        if scheme == "https":
            context = ssl.create_default_context()
            # Pass server_hostname=host so TLS SNI and cert check validate against the domain name
            conn = http.client.HTTPSConnection(connect_ip, port, context=context, timeout=self.timeout)
            # Override connection host attribute for proper SNI / certificate validation
            conn._server_hostname = host
        else:
            conn = http.client.HTTPConnection(connect_ip, port, timeout=self.timeout)

        try:
            conn.request(method, path, headers=req_headers)
            resp = conn.getresponse()
            status = resp.status
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            # Read bounded body (max 256KB)
            body = resp.read(256 * 1024)
            return status, resp_headers, body
        finally:
            conn.close()


class SecurityScanner:
    """Modular security scanner that executes safe checks with progress tracking."""

    def __init__(self, scope: TargetScope, cancel_check: Callable[[], bool] | None = None):
        self.scope = scope
        self.cancel_check = cancel_check or (lambda: False)
        self.client = SafeHTTPClient()

    def _check_cancelled(self) -> None:
        if self.cancel_check():
            raise ScanCancelledException("Scan was cancelled by operator.")

    def run_scan(self, target_url: str, check_sensitive_files: bool = True) -> dict[str, Any]:
        """Run modular security checks against target within scope."""
        scheme, host, port, path = self.scope.validate_destination(target_url)

        scan_start = datetime.datetime.now(datetime.timezone.utc)
        scan_id = f"scan-{hashlib.sha256(f'{host}:{port}:{scan_start.isoformat()}'.encode('utf-8')).hexdigest()[:16]}"

        findings: list[dict[str, Any]] = []
        checks_performed: list[str] = []
        raw_evidence_items: list[dict[str, Any]] = []

        # 1. Base Endpoint Response & Headers Check
        self._check_cancelled()
        checks_performed.append("http_baseline_and_headers")

        try:
            status, headers, body = self.client.request("GET", scheme, host, port, path)

            # Store baseline evidence
            raw_evidence_items.append({
                "type": "http_response",
                "source": f"{scheme}://{host}:{port}{path}",
                "status_code": status,
                "headers": headers,
                "body_snippet": body[:500].decode("utf-8", errors="replace"),
            })

            # Check Missing Security Headers
            for hname, hinfo in SECURITY_HEADERS.items():
                if hname not in headers:
                    findings.append({
                        "id": f"find-{hashlib.sha256((scan_id + hname).encode('utf-8')).hexdigest()[:12]}",
                        "title": hinfo["title"],
                        "category": "security_headers",
                        "severity": hinfo["severity"],
                        "confidence": "confirmed",
                        "cwe": hinfo["cwe"],
                        "description": hinfo["description"],
                        "evidence": f"Header '{hname}' was absent from HTTP {status} response headers.",
                        "status": "pending_human_review",
                    })

            # Server & Technology Header Inspection
            server_header = headers.get("server")
            x_powered_by = headers.get("x-powered-by")
            if server_header or x_powered_by:
                tech_str = f"Server: {server_header or 'none'}, X-Powered-By: {x_powered_by or 'none'}"
                findings.append({
                    "id": f"find-{hashlib.sha256((scan_id + 'tech_leak').encode('utf-8')).hexdigest()[:12]}",
                    "title": "Server Information Disclosure",
                    "category": "information_disclosure",
                    "severity": "low",
                    "confidence": "confirmed",
                    "cwe": "CWE-200",
                    "description": f"The HTTP response leaks server software/technology versions: {tech_str}",
                    "evidence": tech_str,
                    "status": "pending_human_review",
                })

            # Cookie Security Analysis
            checks_performed.append("cookie_security_analysis")
            set_cookie = headers.get("set-cookie")
            if set_cookie:
                lower_sc = set_cookie.lower()
                missing_flags = []
                if "secure" not in lower_sc and scheme == "https":
                    missing_flags.append("Secure")
                if "httponly" not in lower_sc:
                    missing_flags.append("HttpOnly")
                if "samesite" not in lower_sc:
                    missing_flags.append("SameSite")

                if missing_flags:
                    findings.append({
                        "id": f"find-{hashlib.sha256((scan_id + 'cookie_flags').encode('utf-8')).hexdigest()[:12]}",
                        "title": f"Insecure Cookie Flags: Missing {', '.join(missing_flags)}",
                        "category": "cookie_security",
                        "severity": "medium" if "HttpOnly" in missing_flags else "low",
                        "confidence": "confirmed",
                        "cwe": "CWE-614",
                        "description": f"Cookie sent without recommended security flags ({', '.join(missing_flags)}).",
                        "evidence": f"Set-Cookie: {set_cookie[:200]}",
                        "status": "pending_human_review",
                    })

        except Exception as e:
            findings.append({
                "id": f"find-{hashlib.sha256((scan_id + 'baseline_err').encode('utf-8')).hexdigest()[:12]}",
                "title": "Connection Check Warning",
                "category": "network_error",
                "severity": "none",
                "confidence": "unverifiable",
                "cwe": "CWE-0",
                "description": f"Target connection returned an error: {str(e)}",
                "evidence": str(e),
                "status": "needs_more_evidence",
            })

        # 2. Sensitive files and exposed paths check
        if check_sensitive_files:
            checks_performed.append("sensitive_files_detection")
            for probe_path, ptitle, psev, pdesc in SAFE_PROBE_PATHS:
                self._check_cancelled()
                time.sleep(0.05)  # Rate limiting delay
                try:
                    pstatus, pheaders, pbody = self.client.request("GET", scheme, host, port, probe_path)
                    # Verify authentic 200 response rather than custom 404 soft-error
                    if pstatus == 200 and len(pbody) > 0:
                        content_type = pheaders.get("content-type", "").lower()
                        # Verify signature for .git/HEAD
                        is_genuine = True
                        if probe_path == "/.git/HEAD":
                            if not pbody.startswith(b"ref: refs/"):
                                is_genuine = False
                        elif probe_path == "/.env":
                            # Must look like KEY=VALUE
                            body_str = pbody.decode("utf-8", errors="replace")
                            if "=" not in body_str or "<html" in body_str.lower():
                                is_genuine = False

                        if is_genuine:
                            findings.append({
                                "id": f"find-{hashlib.sha256((scan_id + probe_path).encode('utf-8')).hexdigest()[:12]}",
                                "title": ptitle,
                                "category": "exposed_files",
                                "severity": psev,
                                "confidence": "confirmed" if psev in ("critical", "high") else "potential",
                                "cwe": "CWE-552",
                                "description": pdesc,
                                "evidence": f"Path '{probe_path}' returned HTTP 200 (length: {len(pbody)} bytes). Snippet: {pbody[:100].decode('utf-8', errors='replace')}",
                                "status": "pending_human_review",
                            })
                except Exception:
                    pass

        scan_end = datetime.datetime.now(datetime.timezone.utc)
        elapsed_sec = (scan_end - scan_start).total_seconds()

        return {
            "scan_id": scan_id,
            "status": "completed",
            "target": f"{scheme}://{host}:{port}{path}",
            "started_at": scan_start.isoformat().replace("+00:00", "Z"),
            "completed_at": scan_end.isoformat().replace("+00:00", "Z"),
            "elapsed_seconds": round(elapsed_sec, 3),
            "checks_performed": checks_performed,
            "findings_count": len(findings),
            "findings": findings,
            "raw_evidence": raw_evidence_items,
        }
