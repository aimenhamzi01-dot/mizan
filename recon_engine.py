"""Passive and authorized reconnaissance engine.

Collects authorized DNS data, TLS certificates, HTTP endpoint headers,
and performs technology fingerprinting. Stores findings with provenance,
timestamps, and method metadata.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import socket
import ssl
from typing import Any
from urllib.parse import urlsplit

from security_scope import ScopeError, TargetScope, is_ip_blocked, resolve_and_validate_host


def _validate_resolved_ips(candidates: list[str]) -> list[str]:
    """Validate an already-resolved address list without doing another DNS lookup."""
    if not candidates:
        raise ScopeError("No validated address is available for network inspection.")
    validated: list[str] = []
    for candidate in candidates:
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise ScopeError(f"Invalid resolved IP address: {candidate}") from exc
        if is_ip_blocked(ip_obj):
            raise ScopeError(f"Resolved IP {candidate} is in a restricted or private range.")
        normalized = str(ip_obj)
        if normalized not in validated:
            validated.append(normalized)
    return validated


def get_tls_certificate_info(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
    resolved_ips: list[str] | None = None,
) -> dict[str, Any]:
    """Retrieve and inspect TLS certificate details safely."""
    context = ssl.create_default_context()
    # Resolve once and connect to one of the exact validated addresses. Never
    # resolve the hostname again between SSRF validation and the connection.
    safe_ips = _validate_resolved_ips(
        resolved_ips if resolved_ips is not None else resolve_and_validate_host(hostname)
    )

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
        with socket.create_connection((safe_ips[0], port), timeout=timeout) as sock:
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


def inspect_dns(hostname: str, resolved_ips: list[str] | None = None) -> dict[str, Any]:
    """Inspect DNS address records with SSRF validation."""
    # `resolve_and_validate_host` performs one complete resolution and checks
    # every result. Reuse that result instead of doing a second DNS lookup.
    safe_ips = _validate_resolved_ips(
        resolved_ips if resolved_ips is not None else resolve_and_validate_host(hostname)
    )
    dns_records: dict[str, Any] = {
        "hostname": hostname,
        "a_records": [],
        "aaaa_records": [],
    }

    for ip in safe_ips:
        parsed = ipaddress.ip_address(ip)
        key = "a_records" if parsed.version == 4 else "aaaa_records"
        if ip not in dns_records[key]:
            dns_records[key].append(ip)

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

    # 1. DNS Recon. The same validated addresses are passed to all network
    # operations in this run, eliminating a validation/connection DNS window.
    safe_ips = resolve_and_validate_host(host)
    dns_data = inspect_dns(host, resolved_ips=safe_ips)
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
        tls_data = get_tls_certificate_info(host, port, resolved_ips=safe_ips)
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
