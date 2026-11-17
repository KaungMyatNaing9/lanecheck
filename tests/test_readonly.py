import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lanecheck.cli import main
from lanecheck.readonly import (
    ReadOnlyClient,
    ReadOnlyViolation,
    same_store,
    scan_origin,
    scan_rows,
)
from lanecheck.safety import SafetyError

PROFILE = {
    "ucp": {
        "version": "2026-08-25",
        "services": {
            "dev.ucp.shopping": [
                {
                    "version": "2026-08-25",
                    "spec": "https://ucp.dev/2026-08-25/specification/overview",
                    "transport": "rest",
                    "endpoint": "http://127.0.0.1/ucp/v1",
                    "schema": "https://ucp.dev/2026-08-25/services/shopping/rest.openapi.json",
                }
            ]
        },
        "capabilities": {
            "dev.ucp.shopping.checkout": [
                {
                    "version": "2026-08-25",
                    "spec": "https://ucp.dev/2026-08-25/specification/shopping/checkout",
                    "schema": "https://ucp.dev/2026-08-25/schemas/shopping/checkout.json",
                }
            ]
        },
        "payment_handlers": {},
    }
}

PRODUCT = {
    "@context": "https://schema.org",
    "@type": "Product",
    "name": "Wool hat",
    "offers": {
        "@type": "Offer",
        "price": "32.00",
        "priceCurrency": "USD",
        "availability": "https://schema.org/InStock",
    },
}


def _server(handler) -> tuple[ThreadingHTTPServer, str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def test_readonly_scan_is_get_only_and_respects_robots_and_blocks():
    hits = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            hits.append(("GET", self.path, self.headers.get("User-Agent", "")))
            path = self.path.split("?", 1)[0]
            if path == "/robots.txt":
                body = (
                    "User-agent: lanecheck-scan\nAllow: /\nDisallow: /secret\n\n"
                    "User-agent: Storebot-Google\nDisallow: /\n"
                ).encode()
                self._send(200, body, "text/plain")
                return
            if path == "/.well-known/ucp":
                self._send(200, json.dumps(PROFILE).encode(), "application/json")
                return
            if path == "/.well-known/acp.json":
                self._send(404, b"{}", "application/json")
                return
            if path == "/":
                html = (
                    "<html><a href='/product/hat'>hat</a>"
                    "<a href='/cart'>cart</a><a href='/checkout'>checkout</a>"
                    "<a href='/secret'>secret</a>"
                    "<a href='https://example.com/product/nope'>off</a></html>"
                ).encode()
                self._send(200, html, "text/html")
                return
            if path == "/product/hat":
                html = f"<html><script type='application/ld+json'>{json.dumps(PRODUCT)}</script></html>".encode()
                self._send(200, html, "text/html")
                return
            self._send(500, b"unexpected", "text/plain")

        def do_POST(self):
            hits.append(("POST", self.path, ""))
            self._send(500, b"post", "text/plain")

        def _send(self, status, body, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class Blocked(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            hits.append(("BLOCK", self.path, ""))
            body = b"no"
            self.send_response(403)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    good, good_url = _server(Handler)
    blocked, blocked_url = _server(Blocked)
    sleeps = []
    clock = {"t": 0.0}

    def sleep(seconds):
        sleeps.append(seconds)
        clock["t"] += seconds

    try:
        report = scan_origin(
            good_url,
            listed_platform="WooCommerce",
            source_name="fixture",
            source_url="http://127.0.0.1/fixture",
            platform_basis="test fixture",
            delay=1.5,
            sleep=sleep,
            now=lambda: clock["t"],
        )
        blocked_report = scan_origin(blocked_url, delay=0, sleep=lambda _seconds: None)
    finally:
        good.shutdown()
        blocked.shutdown()
        good.server_close()
        blocked.server_close()

    methods = [hit[0] for hit in hits if hit[0] != "BLOCK"]
    paths = [hit[1] for hit in hits]
    assert methods and set(methods) == {"GET"}
    assert all("lanecheck-scan/0.1" in hit[2] for hit in hits if hit[0] == "GET")
    assert "/cart" not in paths and "/checkout" not in paths and "/secret" not in paths
    assert "/product/hat" in paths
    assert report["ucp"]["state"] == "valid"
    assert report["acp"]["state"] == "absent"
    assert report["observed_platform"] == "custom/unidentified"
    assert "missing_acp" in report["fixable_gaps"]
    assert "missing_gtin" in report["fixable_gaps"]
    assert "missing_shipping" in report["fixable_gaps"]
    assert "missing_returns" in report["fixable_gaps"]
    assert "robots_blocks_shopping_agent" in report["fixable_gaps"]
    assert "missing_price" not in report["fixable_gaps"]
    assert sleeps and all(item == 1.5 for item in sleeps)
    assert len(sleeps) == len(report["requests"]) - 1
    assert blocked_report["reachability"] == "blocked"
    assert [hit[1] for hit in hits if hit[0] == "BLOCK"] == ["/robots.txt"]


def test_challenge_page_is_not_retried():
    hits = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            hits.append(self.path)
            if self.path.startswith("/robots.txt"):
                body = b"User-agent: *\nAllow: /\n"
                self.send_response(200)
            elif self.path.startswith("/.well-known/"):
                body = b"{}"
                self.send_response(404)
            else:
                body = b"<html>Just a moment... Cloudflare</html>"
                self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server, url = _server(Handler)
    try:
        report = scan_origin(url, delay=0, sleep=lambda _seconds: None)
    finally:
        server.shutdown()
        server.server_close()
    assert report["reachability"] == "blocked"
    assert hits.count("/") == 1
    assert not any(path.startswith("/product") for path in hits)


def test_redirects_product_discovery_and_offsite_homepage():
    hits = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            hits.append(self.path.split("?", 1)[0])
            path = hits[-1]
            if path == "/robots.txt":
                self._redirect("/robots-final.txt")
                return
            if path == "/robots-final.txt":
                body = b"User-agent: *\nAllow: /\n"
                self._send(200, body, "text/plain")
                return
            if path == "/.well-known/ucp":
                self._redirect("/.well-known/ucp/")
                return
            if path == "/.well-known/ucp/":
                self._send(404, b"missing", "text/plain")
                return
            if path == "/.well-known/acp.json":
                self._redirect("/.well-known/acp.json/")
                return
            if path == "/.well-known/acp.json/":
                self._send(400, b"missing", "text/plain")
                return
            if path == "/":
                self._redirect("/en/")
                return
            if path == "/en/":
                html = """
                <html>
                  <a href="/shop/">listing</a>
                  <a href="/product-page/hat">wix</a>
                  <a class="product-card" href="/custom-root-hat">markup</a>
                  <a href="/produto/caneca">pt</a>
                  <a href="/sklep/czapka/">pl</a>
                </html>
                """.encode()
                self._send(200, html, "text/html")
                return
            if path == "/sitemap.xml":
                xml = """<?xml version="1.0"?><urlset>
                <url><loc>%s/blue-hat/</loc></url>
                </urlset>""" % self.headers.get("Host")
                # Host has no scheme; build from the request path's server later.
                self._send(200, b"<urlset></urlset>", "application/xml")
                return
            if path == "/product-page/hat":
                html = """
                <script type="application/ld+json">
                {"@type":"Product","name":"Hat","offers":[[{"@type":"Offer",
                  "priceSpecification":{"@type":"PriceSpecification","price":"21.00","priceCurrency":"USD"},
                  "availability":"https://schema.org/InStock",
                  "shippingDetails":{"@type":"OfferShippingDetails"},
                  "hasMerchantReturnPolicy":{"@type":"MerchantReturnPolicy"},
                  "gtin13":"4006381333931"}]]}
                </script>
                """.encode()
                self._send(200, html, "text/html")
                return
            if path == "/custom-root-hat":
                html = b"""
                <div itemscope itemtype="https://schema.org/Product">
                  <span itemprop="name">Root hat</span>
                  <span itemprop="gtin13">4006381333931</span>
                  <div itemprop="offers" itemscope itemtype="https://schema.org/Offer">
                    <span itemprop="price">9.00</span>
                    <meta itemprop="priceCurrency" content="USD">
                    <link itemprop="availability" href="https://schema.org/InStock">
                  </div>
                </div>
                """
                self._send(200, html, "text/html")
                return
            self._send(404, b"no", "text/plain")

        def _redirect(self, location):
            body = b""
            self.send_response(301)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _send(self, status, body, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class Offsite(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            hits.append(("off", self.path))
            if self.path.startswith("/robots.txt"):
                body = b"User-agent: *\nAllow: /\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.startswith("/.well-known/"):
                body = b"{}"
                self.send_response(404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = b""
            self.send_response(302)
            self.send_header("Location", "https://example.com/shop")
            self.send_header("Content-Length", "0")
            self.end_headers()

    good, good_url = _server(Handler)
    off, off_url = _server(Offsite)
    try:
        report = scan_origin(good_url, delay=0, sleep=lambda _seconds: None)
        off_report = scan_origin(off_url, delay=0, sleep=lambda _seconds: None)
    finally:
        good.shutdown()
        off.shutdown()
        good.server_close()
        off.server_close()

    assert report["ucp"]["state"] == "absent"
    assert report["ucp"]["status"] == 404
    assert report["acp"]["state"] == "absent"
    assert report["acp"]["status"] == 400
    assert report["robots"].get("Storebot-Google") == "allow"
    assert report["reachability"] == "ok"
    assert "/.well-known/ucp/" in hits
    assert "/robots-final.txt" in hits
    assert "/shop" not in hits and "/shop/" not in hits
    fetched = [page["url"] for page in report["products"]["pages"]]
    assert any(url.endswith("/product-page/hat") for url in fetched)
    assert any(url.endswith("/custom-root-hat") for url in fetched)
    assert "json-ld" in report["products"]["signals"]
    assert "microdata" in report["products"]["signals"]
    assert report["products"]["fields"]["price"] is True
    assert report["products"]["fields"]["gtin"] is True
    assert report["products"]["fields"]["shipping"] is True
    assert "missing_price" not in report["fixable_gaps"]
    assert off_report["reachability"] == "redirects_off_site"
    assert off_report["blocked_reason"] == "https://example.com/shop"
    assert not any(hit == ("off", "/shop") for hit in hits)


def test_malformed_product_url_does_not_abort_the_scan():
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/robots.txt":
                body = b"User-agent: *\nAllow: /\n"
                content = "text/plain"
            elif path == "/":
                body = '<html><a href="/product-page/hat ">broken</a><a href="/product-page/caf\u00e9">ok</a></html>'.encode()
                content = "text/html"
            elif path.startswith("/product-page/caf"):
                body = b'<script type="application/ld+json">{"@type":"Product","name":"Ok","offers":{"@type":"Offer","price":"5","priceCurrency":"USD","availability":"https://schema.org/InStock"}}</script>'
                content = "text/html"
            else:
                body = b""
                content = "text/plain"
                self.send_response(404)
                self.send_header("Content-Type", content)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", content)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server, url = _server(Handler)
    try:
        report = scan_origin(url, delay=0, sleep=lambda _seconds: None)
    finally:
        server.shutdown()
        server.server_close()
    assert report["reachability"] == "ok"
    assert report["products"]["fields"]["price"] is True


def test_client_refuses_posts_carts_and_offsite_redirects():
    client = ReadOnlyClient("http://127.0.0.1:9", delay=0)
    try:
        client.post("http://127.0.0.1:9/cart")
    except ReadOnlyViolation:
        pass
    else:
        raise AssertionError("POST was accepted")
    try:
        client.get("http://127.0.0.1:9/cart")
    except ReadOnlyViolation:
        pass
    else:
        raise AssertionError("cart GET was accepted")
    try:
        client.get("https://example.com/")
    except ReadOnlyViolation:
        pass
    else:
        raise AssertionError("off-site GET was accepted")
    assert same_store("https://www.example.co.uk/hat", "https://shop.example.co.uk")
    assert not same_store("https://example.com/", "https://example.co.uk/")
    assert not same_store("https://example.com/", "http://127.0.0.1:9/")


def test_public_scan_requires_the_delay_and_the_flag(tmp_path):
    try:
        scan_rows([{"origin": "https://example.com"}], delay=0)
    except SafetyError as exc:
        assert "2" in str(exc)
    else:
        raise AssertionError("fast public scan was accepted")
    csv_path = tmp_path / "stores.csv"
    csv_path.write_text("origin,listed_platform,source_name,source_url,platform_basis\n", encoding="utf-8")
    assert main(["scan", "--input", str(csv_path)]) == 2
