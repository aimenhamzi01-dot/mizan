"""Passive and authorized reconnaissance engine.

Collects authorized DNS data, TLS certificates, HTTP endpoint headers,
and performs technology fingerprinting. Stores findings with provenance,
timestamps, and method metadata.
"""
from __future__ import annotations

import datetime
import hashlib
import socket
import ssl
from typing import Any
from urllib.parse import urlsplit

from security_scope import ScopeError, TargetScope, resolve_and_validate_host


def get_tls_certificate_info(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Retrieve and inspect TLS certificate details safely."""
    context = ssl.create_default_context()
    # Ensure SSRF protection
    resolve_and_validate_host(hostname)

    cert_info: dict[str, Any] = {
        "status": "unknown",
        "has_tls": False,
        "issuer": {},
        "subject": {},
        "version": None,
        "not_before": None,
        "not_after": None,
        "sans": [],
        "cipher": None,
        "protocol": None,
        "sha256_fingerprint": None,
    }

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()
                der_cert = ssock.getpeercert(binary_form=True)

                cert_info["has_tls"] = True
                cert_info["status"] = "valid"
                cert_info["cipher"] = cipher[0] if cipher else None
                cert_info["protocol"] = protocol
                if der_cert:
                    cert_info["sha256_fingerprint"] = hashlib.sha256(der_cert).hexdigest()

                if cert:
                    # Parse subject and issuer
                    for field in ("subject", "issuer"):
                        parsed_field = {}
                        for rdn in cert.get(field, ()):
                            for k, v in rdn:
                                parsed_field[k] = v
                        cert_info[field] = parsed_field

                    cert_info["version"] = cert.get("version")
                    cert_info["not_before"] = cert.get("notBefore")
                    cert_info["not_after"] = cert.get("notAfter")

                    # SANs
                    sans = []
                    for typ, val in cert.get("subjectAltName", ()):
                        sans.append(f"{typ}:{val}")
                    cert_info["sans"] = sans

                    # Expiry check
                    if cert.get("notAfter"):
                        try:
                            # e.g. "May 10 12:00:00 2025 GMT"
                            expire_dt = datetime.datetime.strptime(
                                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=datetime.timezone.utc)
                            if datetime.datetime.now(datetime.timezone.utc) > expire_dt:
                                cert_info["status"] = "expired"
                        except Exception:
                            pass
    except ssl.SSLError as e:
        cert_info["status"] = f"ssl_error: {e.reason if hasattr(e, 'reason') else str(e)}"
    except Exception as e:
        cert_info["status"] = f"connection_error: {str(e)}"

    return cert_info


def inspect_dns(hostname: str) -> dict[str, Any]:
    """Inspect DNS address records with SSRF validation."""
    resolve_and_validate_host(hostname)
    dns_records: dict[str, Any] = {
        "hostname": hostname,
        "a_records": [],
        "aaaa_records": [],
    }

    try:
        # IPv4
        v4_res = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        for r in v4_res:
            ip = r[4][0]
            if ip not in dns_records["a_records"]:
                dns_records["a_records"].append(ip)
    except Exception:
        pass

    try:
        # IPv6
        v6_res = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
        for r in v6_res:
            ip = r[4][0]
            if ip not in dns_records["aaaa_records"]:
                dns_records["aaaa_records"].append(ip)
    except Exception:
        pass

    return dns_records


def run_reconnaissance(scope: TargetScope, target_input: str) -> dict[str, Any]:
    """Execute passive & authorized reconnaissance on target within scope.

    Returns structured recon results with discovered assets and technical details.
    """
    scheme, host, port, path = scope.validate_destination(target_input)

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    recon_run_id = hashlib.sha256(f"{host}:{port}:{now_iso}".encode("utf-8")).hexdigest()[:16]

    result: dict[str, Any] = {
        "recon_id": f"recon-{recon_run_id}",
        "timestamp": now_iso,
        "target": f"{scheme}://{host}:{port}{path}",
        "host": host,
        "port": port,
        "scheme": scheme,
        "method": "passive_and_authorized_inspection",
        "assets_discovered": [],
        "dns": {},
        "tls": {},
        "provenance": {
            "scope_name": scope.name,
            "collector": "mizan-recon-engine-v1",
            "timestamp": now_iso,
        },
    }

    # 1. DNS Recon
    dns_data = inspect_dns(host)
    result["dns"] = dns_data
    for ip in dns_data.get("a_records", []):
        result["assets_discovered"].append({
            "asset_type": "ipv4_address",
            "identifier": ip,
            "provenance": f"DNS A record for {host}",
            "in_scope": True,
        })
    for ip in dns_data.get("aaaa_records", []):
        result["assets_discovered"].append({
            "asset_type": "ipv6_address",
            "identifier": ip,
            "provenance": f"DNS AAAA record for {host}",
            "in_scope": True,
        })

    # 2. TLS Recon (if port 443 or https)
    if scheme == "https" or port in (443, 8443):
        tls_data = get_tls_certificate_info(host, port)
        result["tls"] = tls_data
        for san in tls_data.get("sans", []):
            if san.startswith("DNS:"):
                san_domain = san[4:]
                result["assets_discovered"].append({
                    "asset_type": "domain_san",
                    "identifier": san_domain,
                    "provenance": f"TLS Certificate SAN on {host}:{port}",
                    "in_scope": any(
                        host == san_domain or san_domain.endswith("." + d.lstrip("*."))
                        for d in scope.authorized_domains
                    ),
                })

    # Add primary target asset
    result["assets_discovered"].append({
        "asset_type": "http_endpoint",
        "identifier": f"{scheme}://{host}:{port}",
        "provenance": "Authorized assessment target",
        "in_scope": True,
    })

    return result
