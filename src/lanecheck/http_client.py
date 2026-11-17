"""One-origin HTTP client. Redirects off the origin are not followed. Payment paths are refused."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from lanecheck.safety import same_origin

MAX_BODY = 1_000_000
PAYMENT_SEGMENTS = {"complete", "delegate_payment"}


class _RefuseRedirect(HTTPRedirectHandler):
    """Surface 3xx to the caller. A redirect can leave the origin the operator named."""

    def http_error_302(self, req, fp, code, msg, headers):  # noqa: N802
        raise HTTPError(req.full_url, code, msg, headers, fp)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


_OPENER = build_opener(ProxyHandler({}), _RefuseRedirect)


class PaymentRefusal(RuntimeError):
    """The probe tried to call an endpoint that would move money or place an order."""


class OffOrigin(RuntimeError):
    """A URL left the single origin the operator named."""


@dataclass
class HttpResult:
    method: str
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    error: str = ""

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads(self.text() or "null")

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


@dataclass
class Client:
    user_agent: str
    origin: str
    timeout: float = 8.0
    calls: list[dict[str, Any]] = field(default_factory=list)
    max_calls: int = 40

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float | None = None,
    ) -> HttpResult:
        if len(self.calls) >= self.max_calls:
            raise RuntimeError(f"Refusing to send more than {self.max_calls} requests in one run.")
        parsed = urlparse(url)
        if is_payment_path(parsed.path):
            raise PaymentRefusal(f"Refusing {method} {parsed.path}. lanecheck does not pay or complete checkout.")
        if not same_origin(url, self.origin):
            raise OffOrigin(f"Refusing {url}, which is not on {self.origin}.")
        merged = {"User-Agent": self.user_agent, "Accept": "application/json, text/html;q=0.8, */*;q=0.1"}
        if headers:
            merged.update(headers)
        req = Request(url, data=body, headers=merged, method=method.upper())
        status = 0
        error = ""
        response_headers: dict[str, str] = {}
        payload = b""
        try:
            with _OPENER.open(req, timeout=timeout or self.timeout) as response:
                status = response.status
                response_headers = {key.lower(): value for key, value in response.headers.items()}
                payload = response.read(MAX_BODY + 1)
        except HTTPError as exc:
            status = exc.code
            response_headers = {key.lower(): value for key, value in exc.headers.items()}
            payload = exc.read(MAX_BODY + 1)
        except URLError as exc:
            error = str(exc.reason)
            status = 0
        truncated = len(payload) > MAX_BODY
        if truncated:
            payload = payload[:MAX_BODY]
        result = HttpResult(method.upper(), url, status, response_headers, payload, error)
        self.calls.append(
            {
                "method": result.method,
                "url": result.url,
                "status": result.status,
                "error": result.error,
                "truncated": truncated,
            }
        )
        return result

    def get(self, url: str, **kwargs: Any) -> HttpResult:
        return self.request("GET", url, **kwargs)

    def post_json(self, url: str, payload: dict[str, Any], **kwargs: Any) -> HttpResult:
        headers = {"Content-Type": "application/json", **kwargs.pop("headers", {})}
        body = json.dumps(payload).encode("utf-8")
        return self.request("POST", url, headers=headers, body=body, **kwargs)


def is_payment_path(path: str) -> bool:
    segment = path.rstrip("/").rsplit("/", 1)[-1].lower()
    return segment in PAYMENT_SEGMENTS


def is_block(result: HttpResult) -> bool:
    if result.status in {401, 403, 429}:
        return True
    if result.status == 0:
        return True
    if result.header("cf-mitigated"):
        return True
    text = result.text()[:4000].lower()
    return "just a moment" in text and "cloudflare" in text
