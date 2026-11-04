"""Target management and server-side scope enforcement with strict SSRF protections.

Validates targets, IP addresses, domains, ports, and protocols.
Protects against SSRF (private IPv4/IPv6, loopback, link-local, cloud metadata, multicast,
and DNS rebinding) by validating both hostnames and resolved IP addresses.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

# Disallowed IPv4 & IPv6 networks for SSRF protection
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 private
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier grade NAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / Cloud metadata (AWS/GCP/Azure)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 private
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation
    ipaddress.ip_network("2001::/32"),          # TEREDO
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique local address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

DEFAULT_PERMITTED_PORTS = {80, 443, 8080, 8443}
DEFAULT_PERMITTED_PROTOCOLS = {"http", "https"}


class ScopeError(ValueError):
    """Raised when an operation, target, or network address violates authorized scope."""


def is_ip_blocked(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address falls into private, loopback, metadata, or reserved ranges."""
    if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
        return True
    # Explicit network checks including cloud metadata (169.254.169.254)
    for net in BLOCKED_NETWORKS:
        if ip_obj in net:
            return True
    return False


def resolve_and_validate_host(hostname: str) -> list[str]:
    """Resolve a hostname to IP addresses and ensure none are blocked (SSRF guard).

    Returns list of safe resolved IP address strings.
    Raises ScopeError if resolution fails or resolves to private/internal IPs.
    """
    hostname = hostname.strip().lower()
    if not hostname:
        raise ScopeError("Target hostname cannot be empty.")

    # Check if host is direct IP literal
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_ip_blocked(ip_obj):
            raise ScopeError(f"Target IP {hostname} is in a restricted or private range (SSRF protection).")
        return [str(ip_obj)]
    except ValueError:
        pass  # It's a domain name, proceed to DNS resolution

    # Resolve via socket
    try:
        addrinfo = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ScopeError(f"Could not resolve host '{hostname}': {e}")

    safe_ips: list[str] = []
    seen: set[str] = set()
    for res in addrinfo:
        sockaddr = res[4]
        ip_str = sockaddr[0]
        if ip_str in seen:
            continue
        seen.add(ip_str)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_ip_blocked(ip_obj):
                raise ScopeError(
                    f"Host '{hostname}' resolved to blocked/private IP '{ip_str}' (SSRF protection)."
                )
            safe_ips.append(str(ip_obj))
        except ValueError:
            raise ScopeError(f"Invalid resolved IP format: {ip_str}")

    if not safe_ips:
        raise ScopeError(f"No valid IP addresses resolved for '{hostname}'.")
    return safe_ips


def normalize_target_url(url_or_host: str) -> tuple[str, str, int, str]:
    """Parse and normalize target string.

    Returns: (scheme, host, port, path)
    """
    raw = url_or_host.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    parts = urlsplit(raw)
    scheme = (parts.scheme or "https").lower()
    if scheme not in ("http", "https"):
        raise ScopeError(f"Protocol '{scheme}' is not permitted. Only HTTP and HTTPS are supported.")

    host = parts.hostname or ""
    if not host:
        raise ScopeError("Invalid URL: missing hostname.")

    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    return scheme, host.lower(), port, path


class TargetScope:
    """Represents an authorized target scope configuration and validates actions against it."""

    def __init__(
        self,
        name: str,
        authorized_domains: list[str],
        authorized_ips: list[str] | None = None,
        permitted_ports: list[int] | None = None,
        permitted_protocols: list[str] | None = None,
        excluded_assets: list[str] | None = None,
        expires_at: str | None = None,
        authorization_notes: str = "",
        workspace_id: str = "default",
    ):
        self.name = name.strip()
        if not self.name:
            raise ScopeError("Target name is required.")
        self.authorized_domains = [d.strip().lower() for d in authorized_domains if d.strip()]
        if not self.authorized_domains and not authorized_ips:
            raise ScopeError("At least one authorized domain or IP must be specified.")

        self.authorized_ips = [ip.strip() for ip in (authorized_ips or []) if ip.strip()]
        self.permitted_ports = set(permitted_ports or DEFAULT_PERMITTED_PORTS)
        self.permitted_protocols = {p.strip().lower() for p in (permitted_protocols or DEFAULT_PERMITTED_PROTOCOLS)}
        self.excluded_assets = [e.strip().lower() for e in (excluded_assets or []) if e.strip()]
        self.expires_at = expires_at
        self.authorization_notes = authorization_notes.strip()
        self.workspace_id = workspace_id

        # Verify authorized IPs do not specify blocked ranges
        for ip in self.authorized_ips:
            try:
                ip_net = ipaddress.ip_network(ip, strict=False)
                # Check sample IPs or network
                if is_ip_blocked(ip_net.network_address):
                    raise ScopeError(f"Authorized IP {ip} is in a blocked/private range.")
            except ValueError:
                raise ScopeError(f"Invalid authorized IP address/CIDR: {ip}")

    def is_expired(self) -> bool:
        # Authorization without a usable expiry is never considered active.
        if not isinstance(self.expires_at, str) or not self.expires_at.strip():
            return True
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                return True
            return datetime.now(timezone.utc) > exp
        except (AttributeError, TypeError, ValueError):
            return True

    def validate_destination(self, url_or_host: str, allow_resolved_ips: bool = True) -> tuple[str, str, int, str]:
        """Validate an assessment destination against this authorized scope.

        1. Checks expiration.
        2. Normalizes URL.
        3. Validates scheme and port against permitted lists.
        4. Validates excluded assets.
        5. Validates domain/host authorization.
        6. Performs DNS resolution and SSRF validation.

        Returns (scheme, host, port, path).
        Raises ScopeError if unauthorized.
        """
        if self.is_expired():
            raise ScopeError(f"Assessment scope '{self.name}' has expired.")

        scheme, host, port, path = normalize_target_url(url_or_host)

        if scheme not in self.permitted_protocols:
            raise ScopeError(f"Protocol '{scheme}' is not permitted by scope.")

        if port not in self.permitted_ports:
            raise ScopeError(f"Port {port} is not in permitted ports ({sorted(self.permitted_ports)}).")

        # Check excluded assets
        full_dest = f"{host}:{port}{path}"
        for excluded in self.excluded_assets:
            if fnmatch.fnmatch(host, excluded) or fnmatch.fnmatch(full_dest, excluded) or excluded in full_dest:
                raise ScopeError(f"Destination '{host}' matches excluded asset rule '{excluded}'.")

        # Check domain/IP authorization
        domain_authorized = False
        for auth_domain in self.authorized_domains:
            if auth_domain.startswith("*."):
                suffix = auth_domain[2:]
                if host == suffix or host.endswith("." + suffix):
                    domain_authorized = True
                    break
            elif host == auth_domain:
                domain_authorized = True
                break

        # Check if direct IP is in authorized_ips
        ip_authorized = False
        try:
            host_ip = ipaddress.ip_address(host)
            for auth_ip_str in self.authorized_ips:
                auth_net = ipaddress.ip_network(auth_ip_str, strict=False)
                if host_ip in auth_net:
                    ip_authorized = True
                    break
        except ValueError:
            pass

        if not domain_authorized and not ip_authorized:
            raise ScopeError(
                f"Host '{host}' is outside the authorized scope. Authorized domains: {self.authorized_domains}"
            )

        # Enforce SSRF protection via DNS resolution
        if allow_resolved_ips:
            resolve_and_validate_host(host)

        return scheme, host, port, path

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "authorized_domains": self.authorized_domains,
            "authorized_ips": self.authorized_ips,
            "permitted_ports": sorted(list(self.permitted_ports)),
            "permitted_protocols": sorted(list(self.permitted_protocols)),
            "excluded_assets": self.excluded_assets,
            "expires_at": self.expires_at,
            "authorization_notes": self.authorization_notes,
            "workspace_id": self.workspace_id,
            "is_expired": self.is_expired(),
        }
