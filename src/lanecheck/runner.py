"""Run every check against one authorized origin."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from lanecheck import __version__
from lanecheck.acp_check import check_acp_discovery
from lanecheck.directory import Directory
from lanecheck.flow import check_acp_flow, check_ucp_flow, _first_item_id
from lanecheck.http_client import Client, PaymentRefusal
from lanecheck.model import DISCLAIMER, LIMITATIONS
from lanecheck.products import check_products
from lanecheck.robots import check_robots
from lanecheck.safety import SafetyError, assert_authorized
from lanecheck.signatures import ROBOTS_UA, check_signatures, generate_key
from lanecheck.ucp_check import check_ucp_profile, rest_endpoint
from lanecheck.webmcp import check_webmcp


def run_probe(
    target: str,
    *,
    i_own_this: bool = False,
    acp_token: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    origin = assert_authorized(target, i_own_this=i_own_this)
    key = generate_key()
    directory = Directory(key)
    checks: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    try:
        robots_client = Client(ROBOTS_UA, origin, timeout=timeout)
        robots = check_robots(robots_client, origin)
        checks.append(robots)
        requests.extend(robots_client.calls)

        signatures = check_signatures(origin, directory.jwks_url, key, timeout)
        requests.extend(signatures.pop("requests", []))
        checks.append(signatures)

        profile_client = Client(ROBOTS_UA, origin, timeout=timeout)
        profile = check_ucp_profile(profile_client, origin)
        checks.append(profile)
        requests.extend(profile_client.calls)
        document = _profile_document(profile_client, origin)

        ucp_result, catalog = check_ucp_flow(
            origin,
            rest_endpoint(document) if isinstance(document, dict) else "",
            directory.profile_url,
            timeout,
        )
        requests.extend(ucp_result.pop("requests", []))
        checks.append(ucp_result)

        acp_client = Client(ROBOTS_UA, origin, timeout=timeout)
        acp, acp_document, acp_state = check_acp_discovery(acp_client, origin)
        checks.append(acp)
        requests.extend(acp_client.calls)

        item_id = _first_item_id(catalog) if isinstance(catalog, dict) else None
        acp_flow = check_acp_flow(origin, acp_document, acp_state, item_id, acp_token, timeout)
        requests.extend(acp_flow.pop("requests", []))
        checks.append(acp_flow)

        products = check_products(origin, timeout, catalog if isinstance(catalog, dict) else None)
        requests.extend(products.pop("requests", []))
        checks.append(products)

        webmcp = check_webmcp(origin, timeout)
        requests.extend(webmcp.pop("requests", []))
        checks.append(webmcp)
    except PaymentRefusal as exc:
        raise SafetyError(str(exc)) from exc
    finally:
        directory.close()

    counts = {"pass": 0, "fail": 0, "warn": 0}
    for check in checks:
        counts[check["status"]] += 1
    return {
        "tool": "lanecheck",
        "version": __version__,
        "target": origin,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "disclaimer": DISCLAIMER,
        "summary": counts,
        "checks": checks,
        "requests": requests,
        "limitations": LIMITATIONS,
        "payment_endpoints_called": [],
    }


def _profile_document(client: Client, origin: str) -> dict | None:
    """Reuse the profile body already fetched. A second GET is acceptable and recorded."""
    result = client.get(origin + "/.well-known/ucp", headers={"Accept": "application/json"})
    if result.status != 200:
        return None
    try:
        document = result.json()
    except Exception:
        return None
    return document if isinstance(document, dict) else None
