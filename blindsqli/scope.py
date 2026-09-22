"""Scope enforcement.

This toolkit is for a *local* training lab only. To make that hard to misuse
by accident, every request target is checked against an allowlist of local
hosts. Anything else is refused unless the operator explicitly opts in with
``allow_nonlocal=True`` (documented, deliberately awkward to trigger).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Hostnames that are always considered in-scope.
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


class ScopeError(Exception):
    """Raised when a URL points outside the permitted local training scope."""


def _is_local_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback


def is_local_host(host: str) -> bool:
    host = (host or "").strip().lower()
    if not host:
        return False
    if host in _LOCAL_NAMES:
        return True
    if _is_local_ip(host):
        return True
    # Resolve the name and require *every* resolved address to be loopback.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        addr = info[4][0]
        if not _is_local_ip(addr):
            return False
    return True


def enforce(url: str, allow_nonlocal: bool = False) -> None:
    """Raise :class:`ScopeError` unless *url* is a local target (or opted in)."""
    if allow_nonlocal:
        return
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not is_local_host(host):
        raise ScopeError(
            f"Refusing to target non-local host {host!r}. This tool is scoped to a "
            f"local training lab. If you truly have authorization for another host, "
            f"set allow_nonlocal / --i-have-authorization explicitly."
        )
