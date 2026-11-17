"""Report objects shared by every check."""

from __future__ import annotations

from typing import Any

DISCLAIMER = (
    "lanecheck probes only an origin you own or are authorized to test. "
    "It never submits payment and it never calls a checkout complete or "
    "delegate-payment endpoint. The signing key is generated on this machine "
    "for this run and is not enrolled with any agent directory, so a blocked "
    "signed request does not prove that a real enrolled agent would be blocked. "
    "A passing report is not a certification."
)

LIMITATIONS = [
    "Payment, checkout completion, cancellation, and delegated-payment endpoints are never called.",
    "The Web Bot Auth test key is ephemeral and unenrolled. The signature uses RFC 9421 with tag web-bot-auth and a loopback http Signature-Agent URL.",
    "UCP profiles are validated with the official ucp-schema CLI against the vendored 2026-08-25 schema tree. Catalog, cart, and checkout payloads are not schema-validated.",
    "ACP discovery is checked against the vendored 2026-04-17 DiscoveryResponse schema. A missing discovery document is a warning, because a store can speak only UCP.",
    "The ACP calls use the 2026-04-17 create shape (line_items, currency, capabilities). They do not send the older items shape.",
    "WebMCP is detected from HTML source. Tools are not executed, and no browser is launched.",
    "robots.txt is evaluated with RFC 9309 exact product-token matching. HTTP redirects are not followed, including same-origin redirects, so a 3xx is reported as itself.",
    "Loopback HTTP is accepted so a local fixture can be probed. The UCP specification requires HTTPS and TLS 1.3 for a production profile.",
    "No production success rate is measured. The fixtures in this repository are the only stores the test suite contacts.",
]


def make_check(
    check_id: str,
    title: str,
    status: str,
    summary: str,
    evidence: list[dict[str, Any]] | None = None,
    fix: str = "",
) -> dict[str, Any]:
    if status not in {"pass", "fail", "warn"}:
        raise ValueError(f"unknown status {status}")
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "summary": summary,
        "evidence": evidence or [],
        "fix": fix,
    }


def evidence(summary: str, **data: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"summary": summary}
    if data:
        item["data"] = data
    return item


def worst(statuses: list[str]) -> str:
    rank = {"pass": 0, "warn": 1, "fail": 2}
    if not statuses:
        return "pass"
    return max(statuses, key=lambda item: rank[item])
