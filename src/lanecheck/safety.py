"""Origin allow-list. The probe contacts one origin, and only when it is local or explicitly owned."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

LOOPBACK_NAMES = {"localhost", "localhost.localdomain"}
ALWAYS_REFUSED_HOSTS = {
    "metadata.google.internal",
    "metadata.google.internal.",
}


class SafetyError(Exception):
    """The target is not a single origin this process is allowed to probe."""


def origin_of(target: str) -> str:
    parsed = _parse(target)
    return f"{parsed.scheme}://{parsed.netloc}"


def assert_authorized(target: str, *, i_own_this: bool) -> str:
    """Return the origin, or raise SafetyError before any network call."""
    parsed = _parse(target)
    host = (parsed.hostname or "").rstrip(".").lower()
    if host in ALWAYS_REFUSED_HOSTS or _is_forbidden_ip(host):
        raise SafetyError(
            f"Refusing {host}. Link-local, cloud metadata, and unspecified addresses are never probed."
        )
    if _is_loopback(host):
        return origin_of(target)
    if not i_own_this:
        raise SafetyError(
            "Refusing to probe a non-loopback origin without --i-own-this. "
            "lanecheck only tests a site you own or are authorized to test, "
            "and it does not scan other people's stores."
        )
    return origin_of(target)


def same_origin(url: str, origin: str) -> bool:
    try:
        parsed = urlparse(url)
        base = urlparse(origin)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    return (
        parsed.scheme == base.scheme
        and (parsed.hostname or "").lower() == (base.hostname or "").lower()
        and (parsed.port or _default_port(parsed.scheme))
        == (base.port or _default_port(base.scheme))
    )


def _parse(target: str):
    parsed = urlparse(target.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SafetyError("The target must be an absolute http or https URL.")
    if parsed.username or parsed.password:
        raise SafetyError("Refusing a URL that contains userinfo.")
    return parsed


def _is_loopback(host: str) -> bool:
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_forbidden_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_loopback:
        return False
    return (
        ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or str(ip) == "169.254.169.254"
    )


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80
