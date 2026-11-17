"""Three localhost stores used by the test suite.

friendly: agents are allowed, UCP and ACP reach a checkout session, product data is complete.
blocked: known agent tokens are disallowed and rejected, and the profile is invalid.
shoddy: agents are allowed, but the protocols are absent and the product data is incomplete.

None of them implement payment. POST .../complete returns 409 and increments a counter.
"""

from __future__ import annotations

import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from lanecheck.agents import TOKENS
from lanecheck.products import gtin_check_digit
from lanecheck.signatures import verify_request

GTIN = "840123450001" + gtin_check_digit("840123450001")
ITEM_ID = "beanie-wool-001"
_AGENT_NEEDLES = tuple(token.token.lower() for token in TOKENS if token.token != "Google-Extended")


class FixtureState:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.hits: list[dict[str, str]] = []
        self.payment_attempts = 0
        self._seq = 0
        self.carts: dict[str, dict] = {}
        self.checkouts: dict[str, dict] = {}
        self.acp_carts: dict[str, dict] = {}
        self.acp_sessions: dict[str, dict] = {}

    def next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}_{self._seq}"


class FixtureServer:
    def __init__(self, mode: str, port: int = 0) -> None:
        if mode not in {"friendly", "blocked", "shoddy"}:
            raise ValueError(mode)
        self.state = FixtureState(mode)
        handler = _handler_class(self.state)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _handler_class(state: FixtureState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._handle("PUT")

        def _handle(self, method: str) -> None:
            path = self.path.split("?", 1)[0]
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length) if length else b""
            state.hits.append({"method": method, "path": path, "ua": self.headers.get("User-Agent", "")})
            if path.rstrip("/").endswith("/complete") or path.rstrip("/").endswith("/delegate_payment"):
                state.payment_attempts += 1
                _send(self, 409, {"error": "this fixture never accepts payment"})
                return
            if path == "/_probe/hits":
                _send(
                    self,
                    200,
                    {"hits": state.hits, "payment_attempts": state.payment_attempts},
                )
                return
            if path == "/robots.txt":
                _send(self, 200, _robots(state.mode), "text/plain; charset=utf-8")
                return
            if _agent_blocked(state.mode, self.headers.get("User-Agent", "")):
                _send(self, 403, "agent blocked\n", "text/plain; charset=utf-8")
                return
            signature = _signature_status(self, method, path) if state.mode == "friendly" else None
            extra = {"X-Lane-Signature": signature} if signature else None
            _dispatch(self, state, method, path, raw, extra)

    return Handler


def _dispatch(handler: BaseHTTPRequestHandler, state: FixtureState, method: str, path: str, raw: bytes, extra: dict | None) -> None:
    host = handler.headers.get("Host", "127.0.0.1")
    if path in {"", "/"}:
        _send(handler, 200, _home(state.mode), "text/html; charset=utf-8", extra)
        return
    if path == "/products/wool-ferry-beanie" and state.mode == "friendly":
        _send(handler, 200, _good_product(host), "text/html; charset=utf-8", extra)
        return
    if path == "/products/mystery-mug" and state.mode != "friendly":
        _send(handler, 200, _bad_product(), "text/html; charset=utf-8", extra)
        return
    if path in {"/cart", "/checkout", "/terms"}:
        _send(handler, 200, _plain_page(path), "text/html; charset=utf-8", extra)
        return
    if path == "/.well-known/ucp":
        if state.mode == "friendly":
            _send(
                handler,
                200,
                _ucp_profile(host),
                "application/json",
                {**(extra or {}), "Cache-Control": "public, max-age=300", "ETag": '"ucp-fixture-1"'},
            )
        elif state.mode == "blocked":
            _send(handler, 200, {"ucp": {"version": "2026-08-25", "services": "nope"}}, "application/json", extra)
        else:
            _send(handler, 404, {"error": "no ucp profile"}, "application/json", extra)
        return
    if path == "/.well-known/acp.json":
        if state.mode == "friendly":
            _send(
                handler,
                200,
                _acp_document(host),
                "application/json",
                {**(extra or {}), "Cache-Control": "public, max-age=3600"},
            )
        elif state.mode == "blocked":
            _send(
                handler,
                200,
                {"protocol": {"name": "acp", "version": "yesterday"}, "transports": ["carrier-pigeon"]},
                "application/json",
                extra,
            )
        else:
            _send(handler, 404, {"error": "no acp discovery"}, "application/json", extra)
        return
    if state.mode != "friendly":
        _send(handler, 404, {"error": "not implemented"}, "application/json", extra)
        return
    body = json.loads(raw.decode() or "{}") if raw else {}
    if path == "/ucp/v1/catalog/search" and method == "POST":
        _send(handler, 200, _catalog(host), "application/json", extra)
        return
    if path == "/ucp/v1/carts" and method == "POST":
        cart_id = state.next_id("cart")
        cart = _ucp_cart(cart_id, body)
        state.carts[cart_id] = cart
        _send(handler, 201, cart, "application/json", extra)
        return
    if path.startswith("/ucp/v1/carts/") and method == "GET":
        cart_id = path.rsplit("/", 1)[-1]
        cart = state.carts.get(cart_id)
        if cart is None:
            _send(handler, 404, {"error": "unknown cart"}, "application/json", extra)
        else:
            _send(handler, 200, cart, "application/json", extra)
        return
    if path == "/ucp/v1/checkout-sessions" and method == "POST":
        session_id = state.next_id("chk")
        session = _ucp_checkout(session_id, host, body)
        state.checkouts[session_id] = session
        _send(handler, 201, session, "application/json", extra)
        return
    if path.startswith("/ucp/v1/checkout-sessions/") and method == "GET":
        session_id = path.rsplit("/", 1)[-1]
        session = state.checkouts.get(session_id)
        if session is None:
            _send(handler, 404, {"error": "unknown checkout"}, "application/json", extra)
        else:
            _send(handler, 200, session, "application/json", extra)
        return
    if path == "/acp/carts" and method == "POST":
        cart_id = state.next_id("acp_cart")
        cart = _acp_cart(cart_id, body)
        state.acp_carts[cart_id] = cart
        _send(handler, 201, cart, "application/json", extra)
        return
    if path.startswith("/acp/carts/") and method == "GET":
        cart_id = path.rsplit("/", 1)[-1]
        cart = state.acp_carts.get(cart_id)
        if cart is None:
            _send(handler, 404, {"error": "unknown cart"}, "application/json", extra)
        else:
            _send(handler, 200, cart, "application/json", extra)
        return
    if path == "/acp/checkout_sessions" and method == "POST":
        session_id = state.next_id("cs")
        session = _acp_checkout(session_id, body)
        state.acp_sessions[session_id] = session
        _send(handler, 201, session, "application/json", extra)
        return
    if path.startswith("/acp/checkout_sessions/") and method == "GET":
        session_id = path.rsplit("/", 1)[-1]
        session = state.acp_sessions.get(session_id)
        if session is None:
            _send(handler, 404, {"error": "unknown checkout"}, "application/json", extra)
        else:
            _send(handler, 200, session, "application/json", extra)
        return
    _send(handler, 404, {"error": "not found"}, "application/json", extra)


def _send(handler: BaseHTTPRequestHandler, status: int, body: object, content_type: str = "application/json", extra: dict | None = None) -> None:
    if isinstance(body, (dict, list)):
        data = json.dumps(body).encode("utf-8")
    elif isinstance(body, bytes):
        data = body
    else:
        data = str(body).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    for key, value in (extra or {}).items():
        if value:
            handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(data)


def _agent_blocked(mode: str, user_agent: str) -> bool:
    if mode != "blocked":
        return False
    folded = user_agent.lower()
    return any(token in folded for token in _AGENT_NEEDLES)


def _signature_status(handler: BaseHTTPRequestHandler, method: str, path: str) -> str | None:
    if "Signature" not in handler.headers:
        return None
    match = re.search(r'"(https?://[^"]+)"', handler.headers.get("Signature-Agent", ""))
    if not match:
        return "invalid"
    jwks_url = match.group(1)
    host = (urlparse(jwks_url).hostname or "").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        return "invalid"
    try:
        with urlopen(Request(jwks_url), timeout=2) as response:
            jwks = json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, json.JSONDecodeError, OSError):
        return "invalid"
    absolute = f"http://{handler.headers.get('Host', '127.0.0.1')}{path}"
    headers = {key: value for key, value in handler.headers.items()}
    ok, _reason = verify_request(method, absolute, headers, jwks=jwks)
    return "valid" if ok else "invalid"


def _robots(mode: str) -> str:
    rule = "Disallow: /" if mode == "blocked" else "Allow: /"
    lines = ["# Fixture policy for lanecheck. Not a production store.", "User-agent: *", rule, ""]
    for token in TOKENS:
        lines.extend([f"User-agent: {token.token}", rule, ""])
    return "\n".join(lines)


def _ucp_profile(host: str) -> dict:
    def capability(spec: str, schema: str) -> dict:
        return {"version": "2026-08-25", "spec": spec, "schema": schema}

    return {
        "ucp": {
            "version": "2026-08-25",
            "services": {
                "dev.ucp.shopping": [
                    {
                        "version": "2026-08-25",
                        "spec": "https://ucp.dev/2026-08-25/specification/overview",
                        "transport": "rest",
                        "endpoint": f"http://{host}/ucp/v1",
                        "schema": "https://ucp.dev/2026-08-25/services/shopping/rest.openapi.json",
                    }
                ]
            },
            "capabilities": {
                "dev.ucp.shopping.catalog.search": [
                    capability(
                        "https://ucp.dev/2026-08-25/specification/shopping/catalog",
                        "https://ucp.dev/2026-08-25/schemas/shopping/catalog_search.json",
                    )
                ],
                "dev.ucp.shopping.cart": [
                    capability(
                        "https://ucp.dev/2026-08-25/specification/shopping/cart",
                        "https://ucp.dev/2026-08-25/schemas/shopping/cart.json",
                    )
                ],
                "dev.ucp.shopping.checkout": [
                    capability(
                        "https://ucp.dev/2026-08-25/specification/shopping/checkout",
                        "https://ucp.dev/2026-08-25/schemas/shopping/checkout.json",
                    )
                ],
            },
            "payment_handlers": {},
        }
    }


def _acp_document(host: str) -> dict:
    return {
        "protocol": {
            "name": "acp",
            "version": "2026-04-17",
            "supported_versions": ["2026-01-30", "2026-04-17"],
            "documentation_url": "https://agenticcommerce.dev",
        },
        "api_base_url": f"http://{host}/acp",
        "transports": ["rest"],
        "capabilities": {
            "services": ["checkout", "carts"],
            "supported_currencies": ["usd"],
            "supported_locales": ["en-US"],
        },
    }


def _catalog(host: str) -> dict:
    price = {"amount": 3200, "currency": "USD"}
    return {
        "ucp": {"version": "2026-08-25", "status": "success"},
        "products": [
            {
                "id": "prod-beanie",
                "title": "Wool ferry beanie",
                "description": {"plain": "A dense wool cap for the morning ferry."},
                "price_range": {"min": price, "max": price},
                "variants": [
                    {
                        "id": ITEM_ID,
                        "title": "Wool ferry beanie",
                        "description": {"plain": "One size, undyed grey wool."},
                        "price": price,
                        "sku": "BEANIE-WOOL-001",
                        "url": f"http://{host}/products/wool-ferry-beanie",
                        "barcodes": [{"type": "GTIN", "value": GTIN}],
                        "availability": {"available": True, "status": "in_stock"},
                    }
                ],
            }
        ],
        "policies": [
            {
                "type": "dev.ucp.shopping.policy.return",
                "description": {"plain": "Return unworn hats by mail within 30 days in the US."},
            },
            {
                "type": "com.example.policy.shipping",
                "description": {"plain": "Ships in the US for 6.00 USD."},
            },
        ],
    }


def _line_from_ucp(body: dict) -> str:
    items = body.get("line_items") or []
    if items and isinstance(items[0], dict):
        item = items[0].get("item") or {}
        if isinstance(item, dict) and item.get("id"):
            return str(item["id"])
    return ITEM_ID


def _ucp_cart(cart_id: str, body: dict) -> dict:
    item_id = _line_from_ucp(body)
    return {
        "ucp": {"version": "2026-08-25", "status": "success"},
        "id": cart_id,
        "currency": "USD",
        "line_items": [
            {
                "id": "li_1",
                "item": {"id": item_id, "title": "Wool ferry beanie", "price": 3200},
                "quantity": 1,
                "totals": [{"type": "subtotal", "amount": 3200}, {"type": "total", "amount": 3200}],
            }
        ],
        "totals": [{"type": "subtotal", "amount": 3200}, {"type": "total", "amount": 3200}],
    }


def _ucp_checkout(session_id: str, host: str, body: dict) -> dict:
    cart = _ucp_cart(session_id, body)
    return {
        "ucp": {
            "version": "2026-08-25",
            "capabilities": {"dev.ucp.shopping.checkout": [{"version": "2026-08-25"}]},
            "payment_handlers": {},
        },
        "id": session_id,
        "status": "incomplete",
        "currency": "USD",
        "line_items": cart["line_items"],
        "totals": cart["totals"],
        "links": [{"type": "terms_of_service", "url": f"http://{host}/terms"}],
        "messages": [
            {
                "type": "info",
                "code": "payment_not_attempted",
                "content": "The session is open. This fixture will not take payment.",
                "severity": "recoverable",
            }
        ],
    }


def _acp_ids(body: dict) -> str:
    items = body.get("line_items") or []
    if items and isinstance(items[0], dict) and items[0].get("id"):
        return str(items[0]["id"])
    return ITEM_ID


def _acp_cart(cart_id: str, body: dict) -> dict:
    item_id = _acp_ids(body)
    return {
        "id": cart_id,
        "currency": "usd",
        "line_items": [{"id": "li_1", "item": {"id": item_id, "name": "Wool ferry beanie"}, "quantity": 1}],
        "totals": [{"type": "subtotal", "display_text": "Subtotal", "amount": 3200}],
    }


def _acp_checkout(session_id: str, body: dict) -> dict:
    item_id = _acp_ids(body)
    return {
        "id": session_id,
        "status": "ready_for_payment",
        "currency": "usd",
        "line_items": [{"id": "li_1", "item": {"id": item_id, "name": "Wool ferry beanie"}, "quantity": 1}],
        "totals": {"currency": "usd", "subtotal": 3200, "total": 3200},
        "fulfillment_options": [],
        "messages": [{"type": "info", "content": "Payment was not submitted."}],
        "links": [],
        "capabilities": {},
    }


def _home(mode: str) -> str:
    if mode == "friendly":
        product = "/products/wool-ferry-beanie"
        title = "Harbor & Wool"
        blurb = "One undyed wool beanie, sold from a counter that agents can read."
        tools = _tools()
    else:
        product = "/products/mystery-mug"
        title = "Northline Outlet" if mode == "blocked" else "Pier Goods"
        blurb = "A mug page with missing offer data."
        tools = ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{title}</title></head>
<body>
<main>
<h1>{title}</h1>
<p>{blurb}</p>
<p><a href="{product}">View the product</a></p>
<p><a href="/cart">Cart</a> · <a href="/checkout">Checkout</a></p>
</main>
{tools}
</body>
</html>
"""


def _tools() -> str:
    return """
<script>
document.modelContext.registerTool({
  name: "search_catalog",
  description: "Search the Harbor and Wool catalog.",
  inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] }
});
document.modelContext.registerTool({
  name: "add_to_cart",
  description: "Add a variant to the cart. Does not take payment.",
  inputSchema: { type: "object", properties: { id: { type: "string" }, quantity: { type: "integer" } }, required: ["id"] }
});
document.modelContext.registerTool({
  name: "create_checkout_session",
  description: "Open a checkout session. Does not take payment.",
  inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] }
});
</script>
"""


def _good_product(host: str) -> str:
    data = {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": "Wool ferry beanie",
        "image": f"http://{host}/images/beanie.jpg",
        "description": "A dense undyed wool cap for the morning ferry.",
        "sku": "BEANIE-WOOL-001",
        "gtin13": GTIN,
        "brand": {"@type": "Brand", "name": "Harbor & Wool"},
        "offers": {
            "@type": "Offer",
            "url": f"http://{host}/products/wool-ferry-beanie",
            "priceCurrency": "USD",
            "price": "32.00",
            "availability": "https://schema.org/InStock",
            "shippingDetails": {
                "@type": "OfferShippingDetails",
                "shippingRate": {"@type": "MonetaryAmount", "value": "6.00", "currency": "USD"},
                "shippingDestination": {"@type": "DefinedRegion", "addressCountry": "US"},
            },
            "hasMerchantReturnPolicy": {
                "@type": "MerchantReturnPolicy",
                "applicableCountry": "US",
                "returnPolicyCategory": "https://schema.org/MerchantReturnFiniteReturnWindow",
                "merchantReturnDays": 30,
            },
        },
    }
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Wool ferry beanie</title>
<script type="application/ld+json">{json.dumps(data)}</script>
</head>
<body>
<main>
<h1>Wool ferry beanie</h1>
<p>Undyed grey wool. $32.00. In stock. Ships in the US for $6.00. Returns accepted for 30 days.</p>
<p>GTIN {GTIN}.</p>
</main>
{_tools()}
</body>
</html>
"""


def _bad_product() -> str:
    data = {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": "Mystery mug",
        "description": "A ceramic mug. The page does not say which glaze, or whether it can be returned.",
        "gtin13": "123",
        "offers": {"@type": "Offer", "price": "see store", "priceCurrency": "USD"},
    }
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Mystery mug</title>
<script type="application/ld+json">{json.dumps(data)}</script>
</head>
<body>
<main>
<h1>Mystery mug</h1>
<p>Price on request. No shipping or return terms are printed here.</p>
</main>
</body>
</html>
"""


def _plain_page(path: str) -> str:
    title = path.strip("/").title()
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{title}</title></head>
<body>
<main>
<h1>{title}</h1>
<p>This fixture page does not collect a card number. Checkout completion is refused.</p>
</main>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a lanecheck fixture store on localhost.")
    parser.add_argument("mode", choices=["friendly", "blocked", "shoddy"])
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = FixtureServer(args.mode, args.port)
    print(f"{args.mode} fixture at {server.url}", flush=True)
    try:
        server.thread.join()
    except KeyboardInterrupt:
        server.close()


if __name__ == "__main__":
    main()
