"""Read-only public-page scan.

This mode is separate from the owner probe. It may only GET robots.txt,
/.well-known/ucp, /.well-known/acp.json, the homepage, and at most three
product pages linked from that homepage. It does not post, sign, log in,
or submit forms. A 403, 429, or challenge page is recorded as blocked
and is not retried.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, unquote, urljoin, urlparse, urlsplit, urlunsplit

from lanecheck.acp_check import validate_discovery
from lanecheck.agents import TOKENS
from lanecheck.http_client import HttpResult, _OPENER
from lanecheck.products import (
    assess_jsonld,
    extract_jsonld_products,
    extract_microdata_products,
)
from lanecheck.robots import allowed, normalize_path, parse_robots
from lanecheck.safety import SafetyError, _is_forbidden_ip, _is_loopback, _parse
from lanecheck.ucp_check import validate_business_profile
from http.client import InvalidURL
from urllib.error import HTTPError, URLError
from urllib.request import Request

SCAN_UA = (
    "lanecheck-scan/0.1 (read-only public-page research; +https://example.invalid/lanecheck)"
)
SCAN_TOKEN = "lanecheck-scan"
MAX_PRODUCT_PAGES = 3
MAX_SITEMAPS = 3
MAX_REDIRECTS = 4
MIN_PUBLIC_DELAY = 2.0
FIXED_PATHS = ("/robots.txt", "/.well-known/ucp", "/.well-known/acp.json", "/")
SITEMAP_SEEDS = ("/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml")
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "com.br", "co.jp", "com.mx", "co.za", "com.tr", "com.pl", "com.sg", "com.hk",
    "co.kr", "com.ar", "com.tw", "co.in", "com.co", "com.pe", "co.il", "co.id",
    "com.my", "com.ph", "co.th", "com.ng", "com.ua", "com.vn", "com.pk", "com.eg",
    "com.sa", "com.bd",
}
SKIP_PATH_MARKERS = (
    "/cart",
    "/checkout",
    "/my-account",
    "/account/login",
    "/login",
    "/wp-login",
    "/wp-admin",
    "/customer/account",
    "/wishlist",
    "/search",
)
PRODUCT_MARKERS = (
    "/product-page/",
    "/product/",
    "/products/",
    "/produto/",
    "/produit/",
    "/producto/",
    "/produkt/",
    "/item/",
)
LISTING_PATHS = {
    "/product",
    "/products",
    "/product-page",
    "/shop",
    "/sklep",
    "/store",
    "/item",
    "/p",
    "/produto",
    "/produit",
    "/producto",
    "/produkt",
}

FIXABLE_DEFINITIONS = {
    "missing_ucp": "No UCP profile at /.well-known/ucp. Publishing one is a site change.",
    "invalid_ucp": "A UCP profile was returned and ucp-schema rejected it.",
    "missing_acp": "No ACP discovery document at /.well-known/acp.json.",
    "invalid_acp": "An ACP discovery document was returned and did not match DiscoveryResponse.",
    "robots_blocks_shopping_agent": "robots.txt disallows a shopping or search token that its operator says honors robots.txt.",
    "no_product_structured_data": "Sampled product pages had no schema.org Product in JSON-LD or microdata.",
    "missing_gtin": "Sampled products had no GTIN with a valid check digit.",
    "missing_price": "Sampled products had no numeric price with a currency.",
    "missing_availability": "Sampled products had no availability value.",
    "missing_shipping": "Sampled products had no shipping structured data.",
    "missing_returns": "Sampled products had no returns structured data.",
}


class ReadOnlyViolation(RuntimeError):
    """The read-only client was asked to do something other than an allowed GET."""


class ReadOnlyClient:
    """GET-only client. The allowlist is the four fixed paths plus product paths added first."""

    def __init__(
        self,
        origin: str,
        *,
        delay: float,
        timeout: float = 12.0,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self.origin = origin.rstrip("/")
        self.delay = delay
        self.timeout = timeout
        self.sleep = sleep
        self.now = now
        self.allowed_paths = set(FIXED_PATHS)
        self.sitemap_paths = set(SITEMAP_SEEDS)
        self.product_paths: set[str] = set()
        self.calls: list[dict[str, Any]] = []
        self._last_request_at: float | None = None

    def allow_product(self, path: str) -> bool:
        path = normalize_path(path.split("?", 1)[0])
        if _forbidden_path(path) or path in {"/", ""}:
            return False
        if path in self.product_paths:
            return True
        if len(self.product_paths) >= MAX_PRODUCT_PAGES:
            return False
        self.product_paths.add(path)
        return True

    def allow_sitemap(self, path: str) -> None:
        path = normalize_path(path.split("?", 1)[0])
        if "sitemap" not in path.lower() or _forbidden_path(path):
            raise ReadOnlyViolation(f"Refusing sitemap path {path}")
        self.sitemap_paths.add(path)

    def get(self, url: str) -> HttpResult:
        self._check_initial(url)
        return self._follow(url, hops_left=MAX_REDIRECTS)

    def _check_initial(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ReadOnlyViolation("Read-only scan accepts only http and https")
        path = normalize_path(parsed.path or "/")
        if not same_store(url, self.origin):
            raise ReadOnlyViolation(f"Read-only scan cannot leave {self.origin} for {url}")
        if path not in self.allowed_paths and path not in self.sitemap_paths and path not in self.product_paths:
            raise ReadOnlyViolation(f"Read-only scan cannot GET {path}")

    def _follow(self, url: str, hops_left: int) -> HttpResult:
        result = self._once(url)
        if result.status not in REDIRECT_STATUSES or hops_left <= 0:
            return result
        location = result.header("location")
        if not location:
            return result
        nxt = urljoin(url, location)
        if not _requestable(nxt) or not same_store(nxt, self.origin):
            result.offsite = nxt
            return result
        if _forbidden_path(urlparse(nxt).path or "/"):
            return result
        return self._follow(nxt, hops_left - 1)

    def _once(self, url: str) -> HttpResult:
        if self._last_request_at is not None and self.delay > 0:
            wait = self.delay - (self.now() - self._last_request_at)
            if wait > 0:
                self.sleep(wait)
        safe_url = _ascii_url(url)
        req = Request(
            safe_url,
            headers={
                "User-Agent": SCAN_UA,
                "Accept": "text/html, application/json, application/xml, text/plain;q=0.5",
            },
            method="GET",
        )
        status = 0
        error = ""
        headers: dict[str, str] = {}
        payload = b""
        try:
            with _OPENER.open(req, timeout=self.timeout) as response:
                status = getattr(response, "status", 200)
                headers = {key.lower(): value for key, value in response.headers.items()}
                payload = response.read(1_000_000)
        except HTTPError as exc:
            status = exc.code
            headers = {key.lower(): value for key, value in exc.headers.items()}
            payload = exc.read(200_000)
        except URLError as exc:
            error = str(exc.reason)
        except (InvalidURL, UnicodeEncodeError) as exc:
            error = str(exc)
        self._last_request_at = self.now()
        result = HttpResult("GET", safe_url, status, headers, payload, error)
        result.offsite = ""
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "status": status,
                "error": error,
                "blocked": challenge(result),
            }
        )
        return result

    def post(self, *_args: Any, **_kwargs: Any) -> None:
        raise ReadOnlyViolation("Read-only scan does not send POST requests")


def challenge(result: HttpResult) -> bool:
    """True when the response is a block or a challenge. Never a reason to retry."""
    if result.status in {401, 403, 429}:
        return True
    if result.header("cf-mitigated"):
        return True
    text = result.text()[:6000].lower()
    markers = (
        "just a moment" in text and "cloudflare" in text,
        "verify you are human" in text,
        "attention required" in text,
        "cf-challenge" in text,
        "px-captcha" in text,
        "captcha" in text and ("cloudflare" in text or "datadome" in text or "perimeterx" in text),
    )
    return any(markers)


def scan_origin(
    origin: str,
    *,
    listed_platform: str = "",
    source_name: str = "",
    source_url: str = "",
    platform_basis: str = "",
    delay: float = MIN_PUBLIC_DELAY,
    timeout: float = 12.0,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    origin = _public_origin(origin)
    client = ReadOnlyClient(origin, delay=delay, timeout=timeout, sleep=sleep, now=now)
    record: dict[str, Any] = {
        "origin": origin,
        "listed_platform": listed_platform,
        "source_name": source_name,
        "source_url": source_url,
        "platform_basis": platform_basis,
        "observed_platform": "",
        "platform_signals": [],
        "reachability": "ok",
        "blocked_reason": "",
        "robots": {},
        "ucp": {"state": "not_fetched"},
        "acp": {"state": "not_fetched"},
        "products": {"state": "not_fetched", "pages": [], "fields": {}},
        "fixable_gaps": [],
        "requests": [],
    }
    robots_text = ""
    robots_groups = None
    robots_result = client.get(origin + "/robots.txt")
    if challenge(robots_result) or robots_result.status in {401, 403, 429}:
        record["reachability"] = "blocked"
        record["blocked_reason"] = f"robots.txt HTTP {robots_result.status}"
        record["requests"] = client.calls
        return record
    if robots_result.status == 0 or robots_result.status >= 500:
        record["reachability"] = "unreachable"
        record["blocked_reason"] = robots_result.error or f"robots.txt HTTP {robots_result.status}"
        record["requests"] = client.calls
        return record
    if getattr(robots_result, "offsite", ""):
        record["reachability"] = "redirects_off_site"
        record["blocked_reason"] = robots_result.offsite
        record["requests"] = client.calls
        return record
    if robots_result.status == 200 and not challenge(robots_result):
        robots_text = robots_result.text()
        robots_groups = parse_robots(robots_text)
        record["robots"] = _token_verdicts(robots_groups, "/")
    elif robots_result.status in {400, 404}:
        record["robots"] = {token.token: "no_robots_file" for token in TOKENS}
    else:
        record["robots"] = {token.token: f"robots_http_{robots_result.status}" for token in TOKENS}

    record["ucp"] = _fetch_profile(client, origin, "/.well-known/ucp", robots_groups, kind="ucp")
    if record["reachability"] == "ok" and record["ucp"].get("blocked"):
        record["reachability"] = "blocked"
        record["blocked_reason"] = "UCP profile request was challenged"
        record["requests"] = client.calls
        return record
    record["acp"] = _fetch_profile(client, origin, "/.well-known/acp.json", robots_groups, kind="acp")
    if record["reachability"] == "ok" and record["acp"].get("blocked"):
        record["reachability"] = "blocked"
        record["blocked_reason"] = "ACP discovery request was challenged"
        record["requests"] = client.calls
        return record

    if robots_groups is not None and not allowed(robots_groups, SCAN_TOKEN, "/"):
        record["reachability"] = "robots_disallowed"
        record["blocked_reason"] = "robots.txt disallows lanecheck-scan on /"
        record["products"] = {"state": "robots_disallowed", "pages": [], "fields": {}}
        record["fixable_gaps"] = _gaps(record)
        record["requests"] = client.calls
        return record

    home = client.get(origin + "/")
    if getattr(home, "offsite", ""):
        record["reachability"] = "redirects_off_site"
        record["blocked_reason"] = home.offsite
        record["requests"] = client.calls
        return record
    if challenge(home):
        record["reachability"] = "blocked"
        record["blocked_reason"] = f"homepage HTTP {home.status} challenge"
        record["requests"] = client.calls
        return record
    if home.status == 0 or home.status >= 500:
        record["reachability"] = "unreachable"
        record["blocked_reason"] = home.error or f"homepage HTTP {home.status}"
        record["requests"] = client.calls
        return record
    if home.status != 200:
        record["reachability"] = "unreachable"
        record["blocked_reason"] = home.error or f"homepage HTTP {home.status}"
        record["requests"] = client.calls
        return record
    active = f"{urlparse(home.url).scheme}://{urlparse(home.url).netloc}"
    platform, signals = detect_platform(home.text(), dict(home.headers))
    record["observed_platform"] = platform
    record["platform_signals"] = signals
    pages = _product_targets(client, home.text(), active, robots_groups)
    fetched_pages = []
    records = []
    seen_signals: set[str] = set()
    for url in pages:
        page = client.get(url)
        fetched_pages.append({"url": page.url, "status": page.status, "blocked": challenge(page)})
        if getattr(page, "offsite", ""):
            continue
        if challenge(page):
            record["reachability"] = "blocked"
            record["blocked_reason"] = f"product page HTTP {page.status}"
            break
        if page.status != 200:
            continue
        for record_item in assess_jsonld(extract_jsonld_products(page.text())):
            record_item["source"] = "json-ld"
            records.append(record_item)
            seen_signals.add("json-ld")
        for record_item in assess_jsonld(extract_microdata_products(page.text())):
            record_item["source"] = "microdata"
            records.append(record_item)
            seen_signals.add("microdata")
    record["products"] = _product_summary(records, fetched_pages, sorted(seen_signals))
    record["fixable_gaps"] = _gaps(record)
    record["requests"] = client.calls
    return record


def scan_rows(
    rows: list[dict[str, str]],
    *,
    delay: float = MIN_PUBLIC_DELAY,
    timeout: float = 12.0,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> list[dict[str, Any]]:
    if any(not _is_loopback(urlparse(row["origin"]).hostname or "") for row in rows) and delay < MIN_PUBLIC_DELAY:
        raise SafetyError(f"Public read-only scans use a delay of at least {MIN_PUBLIC_DELAY} seconds.")
    results = []
    for row in rows:
        results.append(
            scan_origin(
                row["origin"],
                listed_platform=row.get("listed_platform", ""),
                source_name=row.get("source_name", ""),
                source_url=row.get("source_url", ""),
                platform_basis=row.get("platform_basis", ""),
                delay=delay,
                timeout=timeout,
                sleep=sleep,
                now=now,
            )
        )
    return results


def detect_platform(html: str, headers: dict[str, str]) -> tuple[str, list[str]]:
    folded = html.lower()
    header_blob = " ".join(f"{key}:{value}" for key, value in headers.items()).lower()
    text = folded + "\n" + header_blob
    signals = []

    def has(*needles: str) -> bool:
        found = [needle for needle in needles if needle in text]
        signals.extend(found)
        return bool(found)

    if has("cdn.shopify.com", "myshopify.com", "shopify.theme", "cdn.shopifycdn.com"):
        return "Shopify", signals
    if has("woocommerce", "wc-ajax", "woocommerce-no-js"):
        return "WooCommerce", signals
    if has("bigcommerce.com", "cdn11.bigcommerce", "data-content-region"):
        if "bigcommerce" in text or "cdn11.bigcommerce" in text:
            return "BigCommerce", signals
    if has("mage/cookies", "x-magento", "magento", "mageworx"):
        return "Magento", signals
    if has("squarespace.com", "static1.squarespace", "squarespace-cdn"):
        return "Squarespace", signals
    if has("wixstatic.com", "wix.com", "parastorage.com", "x-wix-"):
        return "Wix", signals
    if has("wp-content/", "wordpress"):
        return "WordPress", signals
    return "custom/unidentified", signals


def _gaps(record: dict[str, Any]) -> list[str]:
    if record["reachability"] != "ok":
        return []
    gaps = []
    ucp_state = record["ucp"].get("state")
    acp_state = record["acp"].get("state")
    if ucp_state == "absent":
        gaps.append("missing_ucp")
    elif ucp_state == "invalid":
        gaps.append("invalid_ucp")
    if acp_state == "absent":
        gaps.append("missing_acp")
    elif acp_state == "invalid":
        gaps.append("invalid_acp")
    robots = record.get("robots") or {}
    for token in TOKENS:
        if token.effect == "blocks" and robots.get(token.token) == "disallow":
            gaps.append("robots_blocks_shopping_agent")
            break
    products = record.get("products") or {}
    if products.get("state") == "fetched":
        fields = products.get("fields") or {}
        if products.get("records", 0) == 0:
            gaps.append("no_product_structured_data")
        else:
            for name in ("gtin", "price", "availability", "shipping", "returns"):
                if not fields.get(name):
                    gaps.append(f"missing_{name}")
    return gaps


def _fetch_profile(client: ReadOnlyClient, origin: str, path: str, groups, *, kind: str) -> dict[str, Any]:
    if groups is not None and not allowed(groups, SCAN_TOKEN, path):
        return {"state": "robots_disallowed", "url": origin + path}
    result = client.get(origin + path)
    if challenge(result):
        return {"state": "blocked", "blocked": True, "status": result.status, "url": result.url}
    if getattr(result, "offsite", ""):
        return {"state": "redirects_off_site", "status": result.status, "url": result.url, "offsite": result.offsite}
    if result.status in {400, 404}:
        return {"state": "absent", "status": result.status, "url": result.url}
    if result.status != 200:
        return {"state": "http_error", "status": result.status, "url": result.url}
    try:
        document = result.json()
    except json.JSONDecodeError:
        return {"state": "invalid", "status": 200, "url": result.url, "error": "not json", "excerpt": result.text()[:240]}
    if kind == "ucp":
        validation = validate_business_profile(document) if isinstance(document, dict) else {"valid": False}
        state = "valid" if validation.get("valid") else "invalid"
        return {
            "state": state,
            "status": 200,
            "url": result.url,
            "validator": validation.get("validator"),
            "errors": (validation.get("errors") or [])[:5],
        }
    errors = validate_discovery(document)
    return {
        "state": "valid" if not errors else "invalid",
        "status": 200,
        "url": result.url,
        "errors": errors[:5],
    }


def _token_verdicts(groups, path: str) -> dict[str, str]:
    return {token.token: ("allow" if allowed(groups, token.token, path) else "disallow") for token in TOKENS}


def _product_targets(client: ReadOnlyClient, html: str, origin: str, groups) -> list[str]:
    chosen: list[str] = []
    candidates = []
    candidates.extend(_jsonld_product_urls(html))
    candidates.extend(_markup_product_hrefs(html))
    candidates.extend(href for href in _hrefs(html) if is_platform_product_path(urlparse(urljoin(origin + "/", href)).path or "/"))
    candidates.extend(_sitemap_product_urls(client, origin, groups))
    for match in candidates:
        if len(chosen) >= MAX_PRODUCT_PAGES:
            break
        absolute = urljoin(origin + "/", match)
        if not _requestable(absolute) or not same_store(absolute, origin):
            continue
        path = normalize_path(urlparse(absolute).path or "/")
        if _forbidden_path(path) or path in {"/", ""}:
            continue
        if groups is not None and not allowed(groups, SCAN_TOKEN, path):
            continue
        if not client.allow_product(path):
            continue
        url = f"{urlparse(absolute).scheme}://{urlparse(absolute).netloc}{path}"
        if url not in chosen:
            chosen.append(url)
    return chosen


def _sitemap_product_urls(client: ReadOnlyClient, origin: str, groups) -> list[str]:
    found: list[str] = []
    queue = list(SITEMAP_SEEDS)
    seen: set[str] = set()
    fetched = 0
    while queue and fetched < MAX_SITEMAPS and len(found) < 12:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        if groups is not None and not allowed(groups, SCAN_TOKEN, path):
            continue
        try:
            client.allow_sitemap(path)
        except ReadOnlyViolation:
            continue
        result = client.get(origin + path)
        fetched += 1
        if result.status != 200 or challenge(result) or getattr(result, "offsite", ""):
            continue
        locs = _sitemap_locs(result.text())
        if "<sitemapindex" in result.text().lower():
            for loc in locs:
                if "product" not in loc.lower() or not _requestable(loc) or not same_store(loc, origin):
                    continue
                child = normalize_path(urlparse(loc).path or "/")
                if child not in seen:
                    queue.append(child)
            continue
        product_file = "product" in path.lower()
        for loc in locs:
            if not _requestable(loc) or not same_store(loc, origin):
                continue
            loc_path = normalize_path(urlparse(loc).path or "/")
            if product_file or is_platform_product_path(loc_path):
                found.append(loc)
    return found


def _hrefs(html: str) -> list[str]:
    import re

    return re.findall(r"""href\s*=\s*["']([^"'#]+)["']""", html, re.I)


def is_platform_product_path(path: str) -> bool:
    folded = normalize_path(path).lower()
    if _forbidden_path(folded) or folded.rstrip("/") in LISTING_PATHS:
        return False
    if any(marker in folded for marker in PRODUCT_MARKERS):
        return True
    parts = [part for part in folded.split("/") if part]
    if len(parts) >= 2 and parts[0] in {"sklep", "shop", "store", "boutique"}:
        return True
    return False


def _forbidden_path(path: str) -> bool:
    folded = normalize_path(path).lower()
    if folded.rstrip("/").rsplit("/", 1)[-1] in {"complete", "delegate_payment"}:
        return True
    return any(marker in folded for marker in SKIP_PATH_MARKERS)


def _markup_product_hrefs(html: str) -> list[str]:
    hrefs = []
    for tag in re.findall(r"<a\b[^>]*>", html, re.I):
        if not re.search(r"product|schema\.org/product", tag, re.I):
            continue
        match = re.search(r"""href\s*=\s*["']([^"']+)["']""", tag, re.I)
        if match:
            hrefs.append(match.group(1))
    return hrefs


def _jsonld_product_urls(html: str) -> list[str]:
    urls: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        types = node.get("@type")
        names = types if isinstance(types, list) else [types]
        folded = [str(name).lower() for name in names if name]
        if any(name.rsplit("/", 1)[-1] in {"product", "listitem"} for name in folded):
            if isinstance(node.get("url"), str):
                urls.append(node["url"])
            walk(node.get("item"))
        if any(name.rsplit("/", 1)[-1] == "itemlist" for name in folded):
            walk(node.get("itemListElement"))
        if isinstance(node.get("@graph"), list):
            walk(node["@graph"])

    for blob in re.findall(
        r"""<script[^>]*type=["']application/ld\+json["'][^>]*>(.*?)</script>""",
        html,
        re.I | re.S,
    ):
        try:
            walk(json.loads(blob))
        except json.JSONDecodeError:
            continue
    return urls


def _sitemap_locs(xml: str) -> list[str]:
    return [item.strip() for item in re.findall(r"<loc>\s*([^<]+)\s*</loc>", xml, re.I)]


def _product_summary(
    records: list[dict[str, Any]],
    pages: list[dict[str, Any]],
    signals: list[str],
) -> dict[str, Any]:
    if not records:
        fields = {name: False for name in ("gtin", "price", "availability", "shipping", "returns")}
    else:
        fields = {
            name: any(bool(record.get(name)) for record in records)
            for name in ("gtin", "price", "availability", "shipping", "returns")
        }
    return {
        "state": "fetched",
        "pages": pages,
        "records": len(records),
        "fields": fields,
        "signals": signals,
    }


def registrable_host(host: str) -> str:
    host = host.lower().rstrip(".").removeprefix("www.")
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _ascii_url(url: str) -> str:
    parts = urlsplit(url)
    path = quote(unquote(parts.path), safe="/%:@")
    query = quote(unquote(parts.query), safe="=&%:+,")
    host = parts.hostname or ""
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        host = quote(host)
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, path, query, ""))


def _requestable(url: str) -> bool:
    if not url or any(ord(char) < 32 or char.isspace() for char in url):
        return False
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def same_store(url: str, origin: str) -> bool:
    parsed = urlparse(url)
    base = urlparse(origin)
    if not parsed.hostname or not base.hostname:
        return False
    if registrable_host(parsed.hostname) != registrable_host(base.hostname):
        return False
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return True
    left = parsed.port or (443 if parsed.scheme == "https" else 80)
    right = base.port or (443 if base.scheme == "https" else 80)
    return parsed.hostname.lower() == base.hostname.lower() and left == right


def _public_origin(origin: str) -> str:
    parsed = _parse(origin if "://" in origin else f"https://{origin}")
    host = (parsed.hostname or "").lower()
    if _is_forbidden_ip(host):
        raise SafetyError(f"Refusing {host}")
    return f"{parsed.scheme}://{parsed.netloc}"


def load_store_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_results(results: list[dict[str, Any]], directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    fields = [
        "origin",
        "listed_platform",
        "observed_platform",
        "reachability",
        "blocked_reason",
        "ucp_state",
        "acp_state",
        "gtin",
        "price",
        "availability",
        "shipping",
        "returns",
        "fixable_gaps",
        "robots",
    ]
    with (directory / "results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in results:
            products = record.get("products") or {}
            flags = products.get("fields") or {}
            writer.writerow(
                {
                    "origin": record["origin"],
                    "listed_platform": record.get("listed_platform", ""),
                    "observed_platform": record.get("observed_platform", ""),
                    "reachability": record.get("reachability", ""),
                    "blocked_reason": record.get("blocked_reason", ""),
                    "ucp_state": (record.get("ucp") or {}).get("state", ""),
                    "acp_state": (record.get("acp") or {}).get("state", ""),
                    "gtin": flags.get("gtin", ""),
                    "price": flags.get("price", ""),
                    "availability": flags.get("availability", ""),
                    "shipping": flags.get("shipping", ""),
                    "returns": flags.get("returns", ""),
                    "fixable_gaps": "|".join(record.get("fixable_gaps") or []),
                    "robots": json.dumps(record.get("robots") or {}, sort_keys=True),
                }
            )


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    def count(predicate) -> int:
        return sum(1 for record in results if predicate(record))

    gap_counts: dict[str, int] = {}
    for record in results:
        for gap in record.get("fixable_gaps") or []:
            gap_counts[gap] = gap_counts.get(gap, 0) + 1
    platforms: dict[str, int] = {}
    for record in results:
        name = record.get("observed_platform") or record.get("listed_platform") or "unknown"
        platforms[name] = platforms.get(name, 0) + 1
    return {
        "stores": len(results),
        "ok": count(lambda record: record["reachability"] == "ok"),
        "blocked": count(lambda record: record["reachability"] == "blocked"),
        "unreachable": count(lambda record: record["reachability"] == "unreachable"),
        "robots_disallowed": count(lambda record: record["reachability"] == "robots_disallowed"),
        "fixable_gap": count(lambda record: bool(record.get("fixable_gaps"))),
        "shopify_observed": count(lambda record: record.get("observed_platform") == "Shopify"),
        "gap_counts": gap_counts,
        "platforms": platforms,
    }
