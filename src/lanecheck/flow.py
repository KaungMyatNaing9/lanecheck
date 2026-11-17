"""Catalog, cart, and checkout-session calls. Never completes payment."""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlparse

from lanecheck.http_client import Client, HttpResult
from lanecheck.model import evidence, make_check
from lanecheck.safety import same_origin
from lanecheck.signatures import AGENT_UA

PRE_PAYMENT = {
    "incomplete",
    "not_ready_for_payment",
    "ready_for_payment",
    "ready_for_complete",
    "requires_escalation",
    "authentication_required",
    "pending_approval",
}
TERMINAL = {"completed", "complete_in_progress", "canceled", "expired"}


def check_ucp_flow(origin: str, endpoint: str, profile_url: str, timeout: float) -> tuple[dict, dict | None]:
    if not endpoint:
        return (
            make_check(
                "ucp_flow",
                "UCP catalog, cart, and checkout session",
                "fail",
                "There is no REST shopping endpoint to call. Discovery did not yield a valid profile with transport rest.",
                [],
                "Advertise dev.ucp.shopping with transport rest and an endpoint on this origin, plus catalog, cart, and checkout capabilities.",
            ),
            None,
        )
    if not same_origin(endpoint, origin):
        return (
            make_check(
                "ucp_flow",
                "UCP catalog, cart, and checkout session",
                "fail",
                "The UCP endpoint is on a different origin. This probe will not contact it.",
                [evidence("Endpoint refused", endpoint=endpoint, origin=origin)],
                "Point the REST endpoint at the same origin you asked to probe, or run the probe against that origin with --i-own-this.",
            ),
            None,
        )
    client = Client(AGENT_UA, origin, timeout=timeout)
    steps: list[dict[str, Any]] = []
    search = client.post_json(
        _join(endpoint, "/catalog/search"),
        {"query": "wool"},
        headers=_ucp_headers(profile_url),
    )
    steps.append(_step("catalog search", search))
    catalog = _json_object(search)
    item_id = _first_item_id(catalog) if catalog else None
    if search.status != 200 or not item_id:
        check = _flow_check(
            "ucp_flow",
            "UCP catalog, cart, and checkout session",
            "fail",
            "Catalog search did not return a product id, so the probe stopped before cart and checkout.",
            steps,
            "Implement POST {endpoint}/catalog/search and return products whose variant id can be used as a checkout line item.",
        )
        check["requests"] = client.calls
        return check, catalog if search.status == 200 else None

    cart = client.post_json(
        _join(endpoint, "/carts"),
        {"line_items": [{"item": {"id": item_id}, "quantity": 1}]},
        headers=_ucp_headers(profile_url),
    )
    steps.append(_step("create cart", cart))
    cart_body = _json_object(cart)
    cart_id = cart_body.get("id") if cart_body else None
    if cart.status not in {200, 201} or not cart_id:
        check = _flow_check(
            "ucp_flow",
            "UCP catalog, cart, and checkout session",
            "fail",
            f"Catalog returned {item_id}, and creating a cart failed.",
            steps,
            "Implement POST {endpoint}/carts. Return an id. Do not require payment to create a cart.",
        )
        check["requests"] = client.calls
        return check, catalog

    cart_get = client.get(_join(endpoint, f"/carts/{cart_id}"), headers=_ucp_headers(profile_url))
    steps.append(_step("read cart", cart_get))
    checkout = client.post_json(
        _join(endpoint, "/checkout-sessions"),
        {"line_items": [{"item": {"id": item_id}, "quantity": 1}]},
        headers=_ucp_headers(profile_url),
    )
    steps.append(_step("create checkout session", checkout))
    body = _json_object(checkout)
    status = str((body or {}).get("status") or "")
    session_id = (body or {}).get("id")
    if checkout.status not in {200, 201} or not session_id:
        check = _flow_check(
            "ucp_flow",
            "UCP catalog, cart, and checkout session",
            "fail",
            "The cart exists, and creating a checkout session failed. No complete call was sent.",
            steps,
            "Implement POST {endpoint}/checkout-sessions. Return an id and a pre-payment status such as incomplete.",
        )
        check["requests"] = client.calls
        return check, catalog
    fetched = client.get(_join(endpoint, f"/checkout-sessions/{session_id}"), headers=_ucp_headers(profile_url))
    steps.append(_step("read checkout session", fetched))
    read_body = _json_object(fetched)
    verdict, summary, fix = _session_verdict(
        "UCP",
        create_status=status,
        read_status=fetched.status,
        read_id=(read_body or {}).get("id"),
        session_id=str(session_id),
    )
    check = _flow_check("ucp_flow", "UCP catalog, cart, and checkout session", verdict, summary, steps, fix)
    check["requests"] = client.calls
    return check, catalog


def check_acp_flow(
    origin: str,
    document: dict | None,
    state: str,
    item_id: str | None,
    acp_token: str | None,
    timeout: float,
) -> dict:
    if state == "absent":
        return make_check(
            "acp_flow",
            "ACP cart and checkout session",
            "warn",
            "ACP checkout was not attempted because this origin does not publish /.well-known/acp.json.",
            [],
            "Publish a valid discovery document if agents should create an ACP checkout session.",
        )
    if state != "ok" or document is None:
        return make_check(
            "acp_flow",
            "ACP cart and checkout session",
            "fail",
            "ACP discovery did not produce a usable document, so no cart or checkout session was created.",
            [],
            "Fix /.well-known/acp.json before expecting an agent to call the checkout API.",
        )
    if not item_id:
        return make_check(
            "acp_flow",
            "ACP cart and checkout session",
            "fail",
            "No product id was discovered on this origin, so the probe did not invent a SKU for ACP.",
            [],
            "Expose a product id through the UCP catalog or the discovery flow this probe can read.",
        )
    base = str(document.get("api_base_url") or "")
    services = document.get("capabilities", {}).get("services", [])
    if not base or not same_origin(base, origin):
        return make_check(
            "acp_flow",
            "ACP cart and checkout session",
            "fail",
            "api_base_url is missing or points at a different origin. This probe will not follow it.",
            [evidence("Refused API base", api_base_url=base, origin=origin)],
            "Set api_base_url to an https URL on the origin you are probing.",
        )
    client = Client(AGENT_UA, origin, timeout=timeout)
    steps: list[dict[str, Any]] = []
    # The 2026-04-17 Item schema requires id and sets additionalProperties false,
    # so quantity is not sent. The cart example in that release includes quantity;
    # that example does not validate against Item.
    line = [{"id": item_id}]
    if "carts" in services:
        cart = client.post_json(_join(base, "/carts"), {"line_items": line}, headers=_acp_headers(acp_token))
        steps.append(_step("create cart", cart))
        cart_body = _json_object(cart)
        if cart.status in {200, 201} and cart_body and cart_body.get("id"):
            read = client.get(_join(base, f"/carts/{cart_body['id']}"), headers=_acp_headers(acp_token))
            steps.append(_step("read cart", read))
        elif cart.status == 401:
            check = _flow_check(
                "acp_flow",
                "ACP cart and checkout session",
                "fail",
                "The cart endpoint returned 401. This probe does not invent a bearer token.",
                steps,
                "On a staging store, accept the probe without a bearer token or pass a test token with --acp-token. Do not point it at production credentials you cannot rotate.",
            )
            check["requests"] = client.calls
            return check
    if "checkout" not in services:
        check = _flow_check(
            "acp_flow",
            "ACP cart and checkout session",
            "warn",
            "Discovery does not advertise the checkout service, so no checkout session was created.",
            steps,
            "Add checkout to capabilities.services when POST /checkout_sessions is implemented.",
        )
        check["requests"] = client.calls
        return check
    created = client.post_json(
        _join(base, "/checkout_sessions"),
        {"line_items": line, "currency": "usd", "capabilities": {}},
        headers=_acp_headers(acp_token),
    )
    steps.append(_step("create checkout session", created))
    body = _json_object(created)
    if created.status == 401:
        check = _flow_check(
            "acp_flow",
            "ACP cart and checkout session",
            "fail",
            "Checkout returned 401. No complete call was sent.",
            steps,
            "Pass --acp-token for a staging credential, or allow this probe to create a session without payment.",
        )
        check["requests"] = client.calls
        return check
    session_id = (body or {}).get("id")
    status = str((body or {}).get("status") or "")
    if created.status not in {200, 201} or not session_id:
        check = _flow_check(
            "acp_flow",
            "ACP cart and checkout session",
            "fail",
            "POST /checkout_sessions did not return a session id. No complete call was sent.",
            steps,
            "Accept line_items, currency, and capabilities, and return 201 with id and a pre-payment status.",
        )
        check["requests"] = client.calls
        return check
    fetched = client.get(_join(base, f"/checkout_sessions/{session_id}"), headers=_acp_headers(acp_token))
    steps.append(_step("read checkout session", fetched))
    read_body = _json_object(fetched)
    verdict, summary, fix = _session_verdict(
        "ACP",
        create_status=status,
        read_status=fetched.status,
        read_id=(read_body or {}).get("id"),
        session_id=str(session_id),
    )
    check = _flow_check("acp_flow", "ACP cart and checkout session", verdict, summary, steps, fix)
    check["requests"] = client.calls
    return check


def _session_verdict(
    protocol: str,
    *,
    create_status: str,
    read_status: int,
    read_id: Any,
    session_id: str,
) -> tuple[str, str, str]:
    if create_status in TERMINAL:
        return (
            "fail",
            f"{protocol} create returned status {create_status}. The probe did not send payment, and it will not continue.",
            "Creating a session must not complete an order. Return a pre-payment status such as incomplete or ready_for_payment.",
        )
    if create_status == "in_progress":
        return (
            "warn",
            f"{protocol} session {session_id} is in_progress. That status can mean a hosted payment is already live, so the probe stopped.",
            "Return ready_for_payment or incomplete when no payment has been submitted.",
        )
    if read_status != 200 or read_id != session_id:
        return (
            "fail",
            f"{protocol} created session {session_id}, and reading it back failed (HTTP {read_status}).",
            "GET the checkout session should return the same id without payment.",
        )
    if create_status not in PRE_PAYMENT:
        return (
            "warn",
            f"{protocol} session {session_id} was readable, with unrecognized status {create_status or 'missing'}.",
            "Use a documented pre-payment status so an agent can tell that payment has not happened.",
        )
    return (
        "pass",
        f"{protocol} went from catalog or cart to checkout session {session_id} ({create_status}) and the session was readable. No complete call was sent.",
        "",
    )


def _flow_check(check_id: str, title: str, status: str, summary: str, steps: list, fix: str) -> dict:
    return make_check(check_id, title, status, summary, [evidence(step["summary"], **step["data"]) for step in steps], fix)


def _step(label: str, result: HttpResult) -> dict[str, Any]:
    body: Any
    try:
        body = result.json()
    except Exception:
        body = result.text()[:240]
    preview = body if isinstance(body, dict) else {"body": body}
    interesting = {
        key: preview.get(key)
        for key in ("id", "status", "currency", "code", "content")
        if isinstance(preview, dict) and key in preview
    }
    return {
        "summary": f"{label}: HTTP {result.status or 'error'}",
        "data": {"url": result.url, "status": result.status, "error": result.error, **interesting},
    }


def _json_object(result: HttpResult) -> dict | None:
    if result.status == 0:
        return None
    try:
        value = result.json()
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _first_item_id(document: dict) -> str | None:
    products = document.get("products")
    if not isinstance(products, list) or not products:
        return None
    product = products[0]
    if not isinstance(product, dict):
        return None
    variants = product.get("variants")
    if isinstance(variants, list) and variants and isinstance(variants[0], dict) and variants[0].get("id"):
        return str(variants[0]["id"])
    if product.get("id"):
        return str(product["id"])
    return None


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


def _ucp_headers(profile_url: str) -> dict[str, str]:
    return {
        "UCP-Agent": f'profile="{profile_url}"',
        "Idempotency-Key": str(uuid.uuid4()),
        "Request-Id": str(uuid.uuid4()),
    }


def _acp_headers(token: str | None) -> dict[str, str]:
    headers = {
        "API-Version": "2026-04-17",
        "Idempotency-Key": str(uuid.uuid4()),
        "Request-Id": str(uuid.uuid4()),
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def path_of(url: str) -> str:
    return urlparse(url).path
