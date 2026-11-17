"""Loopback JWKS and UCP platform profile for one probe run."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lanecheck.signatures import ProbeKey


class Directory:
    def __init__(self, key: ProbeKey) -> None:
        self.key = key
        profile = {
            "ucp": {
                "version": "2026-08-25",
                "services": {
                    "dev.ucp.shopping": [
                        {
                            "version": "2026-08-25",
                            "spec": "https://ucp.dev/2026-08-25/specification/overview/",
                            "transport": "rest",
                            "schema": "https://ucp.dev/2026-08-25/services/shopping/rest.openapi.json",
                            "endpoint": "http://127.0.0.1/lanecheck-probe",
                        }
                    ]
                },
                "capabilities": {
                    "dev.ucp.shopping.catalog.search": [
                        {
                            "version": "2026-08-25",
                            "spec": "https://ucp.dev/2026-08-25/specification/shopping/catalog",
                            "schema": "https://ucp.dev/2026-08-25/schemas/shopping/catalog_search.json",
                        }
                    ],
                    "dev.ucp.shopping.cart": [
                        {
                            "version": "2026-08-25",
                            "spec": "https://ucp.dev/2026-08-25/specification/shopping/cart",
                            "schema": "https://ucp.dev/2026-08-25/schemas/shopping/cart.json",
                        }
                    ],
                    "dev.ucp.shopping.checkout": [
                        {
                            "version": "2026-08-25",
                            "spec": "https://ucp.dev/2026-08-25/specification/shopping/checkout",
                            "schema": "https://ucp.dev/2026-08-25/schemas/shopping/checkout.json",
                        }
                    ],
                },
                "payment_handlers": {},
            }
        }
        jwks = json.dumps({"keys": [key.jwk()]}).encode("utf-8")
        profile_bytes = json.dumps(profile).encode("utf-8")
        key_ref = key

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                path = self.path.split("?", 1)[0]
                if path == "/jwks.json":
                    self._send(jwks, "application/jwk-set+json")
                elif path == "/.well-known/ucp":
                    self._send(profile_bytes, "application/json")
                else:
                    self._send(b'{"error":"not found"}', "application/json", 404)

            def _send(self, body: bytes, content_type: str, status: int = 200) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

        self._key = key_ref
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    @property
    def jwks_url(self) -> str:
        return self.origin + "/jwks.json"

    @property
    def profile_url(self) -> str:
        return self.origin + "/.well-known/ucp"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
