"""Product data quality from schema.org JSON-LD and UCP catalog variants."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from html.parser import HTMLParser

from lanecheck.http_client import Client, is_block
from lanecheck.model import evidence, make_check
from lanecheck.signatures import AGENT_UA, BROWSER_UA

_LD = re.compile(
    r"""<script[^>]*type=["']application/ld\+json["'][^>]*>(.*?)</script>""",
    re.IGNORECASE | re.DOTALL,
)
_HREF = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
_GTIN_KEYS = ("gtin", "gtin8", "gtin12", "gtin13", "gtin14")
_AVAILABILITY = {"instock", "outofstock", "preorder", "backorder", "soldout", "discontinued", "limitedavailability"}
_UCP_AVAILABILITY = {"in_stock", "backorder", "preorder", "out_of_stock", "discontinued"}


def gtin_check_digit(body: str) -> str:
    total = 0
    for index, char in enumerate(reversed(body)):
        total += int(char) * (3 if index % 2 == 0 else 1)
    return str((10 - (total % 10)) % 10)


def gtin_valid(value: str) -> bool:
    digits = re.sub(r"\s+", "", value or "")
    if not digits.isdigit() or len(digits) not in {8, 12, 13, 14}:
        return False
    return gtin_check_digit(digits[:-1]) == digits[-1]


def assess_jsonld(products: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_assess_jsonld_product(product) for product in products]


def extract_jsonld_products(html: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for blob in _LD.findall(html):
        try:
            data = json.loads(blob)
        except json.JSONDecodeError:
            continue
        found.extend(_walk_products(data))
    return found


def assess_ucp_catalog(document: dict[str, Any]) -> list[dict[str, Any]]:
    policies = document.get("policies") if isinstance(document.get("policies"), list) else []
    policy_text = " ".join(
        str(policy.get("type", "")) for policy in policies if isinstance(policy, dict)
    ).lower()
    shipping = "shipping" in policy_text or "fulfillment" in policy_text
    returns = "return" in policy_text
    records = []
    for product in document.get("products") or []:
        if not isinstance(product, dict):
            continue
        variants = product.get("variants") if isinstance(product.get("variants"), list) else [product]
        variant = next((item for item in variants if isinstance(item, dict)), {})
        barcodes = variant.get("barcodes") if isinstance(variant.get("barcodes"), list) else []
        gtin = False
        for barcode in barcodes:
            if isinstance(barcode, dict) and str(barcode.get("type", "")).upper() in {"GTIN", "EAN", "UPC", "ISBN"}:
                if gtin_valid(str(barcode.get("value", ""))):
                    gtin = True
        price = _ucp_price(variant.get("price")) or _ucp_price((product.get("price_range") or {}).get("min") if isinstance(product.get("price_range"), dict) else None)
        availability = variant.get("availability") if isinstance(variant.get("availability"), dict) else {}
        available = isinstance(availability.get("available"), bool) or str(availability.get("status", "")).lower() in _UCP_AVAILABILITY
        records.append(
            {
                "source": "ucp-catalog",
                "name": product.get("title") or variant.get("title") or product.get("id"),
                "id": variant.get("id") or product.get("id"),
                "gtin": gtin,
                "price": price,
                "availability": available,
                "shipping": shipping,
                "returns": returns,
            }
        )
    return records


def check_products(origin: str, timeout: float, catalog: dict[str, Any] | None) -> dict:
    agent = Client(AGENT_UA, origin, timeout=timeout)
    home = agent.get(origin + "/", headers={"Accept": "text/html, */*;q=0.1"})
    pages = [("homepage", home)]
    if home.status == 200:
        for path in _product_paths(home.text(), origin)[:3]:
            pages.append((path, agent.get(origin + path, headers={"Accept": "text/html, */*;q=0.1"})))
    records: list[dict[str, Any]] = []
    blocked = []
    for label, page in pages:
        if is_block(page) or page.status != 200:
            blocked.append({"path": label, "status": page.status, "error": page.error})
            continue
        for record in assess_jsonld(extract_jsonld_products(page.text())):
            record["page"] = label
            records.append(record)
    if catalog:
        records.extend(assess_ucp_catalog(catalog))
    browser_note = None
    if blocked and not any(record["source"] == "json-ld" for record in records):
        browser = Client(BROWSER_UA, origin, timeout=timeout)
        alt = browser.get(origin + "/", headers={"Accept": "text/html, */*;q=0.1"})
        if alt.status == 200:
            alt_records = assess_jsonld(extract_jsonld_products(alt.text()))
            browser_note = evidence(
                "A non-agent fetch could read the homepage. That does not help an agent that was blocked.",
                status=alt.status,
                records=alt_records,
            )
            agent.calls.extend(browser.calls)
    items = [
        evidence("Agent fetches", blocked=blocked, records=records),
    ]
    if browser_note:
        items.append(browser_note)
    if not records:
        return _with_requests(
            make_check(
                "product_data",
                "Product identifiers, price, availability, shipping, and returns",
                "fail",
                "No product structured data was readable with the agent user-agent.",
                items,
                "Let the agent user-agent read product pages, and put GTIN, price, availability, shipping, and returns in JSON-LD or the UCP catalog.",
            ),
            agent.calls,
        )
    missing = [record for record in records if not _complete(record)]
    if not missing:
        return _with_requests(
            make_check(
                "product_data",
                "Product identifiers, price, availability, shipping, and returns",
                "pass",
                f"{len(records)} product record(s) include a valid GTIN, price, availability, shipping, and returns.",
                items,
                "",
            ),
            agent.calls,
        )
    if len(missing) < len(records):
        status = "warn"
        summary = f"{len(missing)} of {len(records)} product records are missing one or more required fields."
    else:
        status = "fail"
        summary = "Every readable product record is missing one or more of GTIN, price, availability, shipping, and returns."
    fields = sorted({field for record in missing for field, ok in _flags(record).items() if not ok})
    return _with_requests(
        make_check(
            "product_data",
            "Product identifiers, price, availability, shipping, and returns",
            status,
            summary + f" Missing: {', '.join(fields)}.",
            items,
            "Add a valid GTIN (check digit included), a numeric price with currency, availability, shipping details, and a return policy. JSON-LD Offer fields and UCP variant barcodes both count.",
        ),
        agent.calls,
    )


def _with_requests(check: dict, calls: list) -> dict:
    check["requests"] = calls
    return check


def _complete(record: dict[str, Any]) -> bool:
    return all(_flags(record).values())


def _flags(record: dict[str, Any]) -> dict[str, bool]:
    return {
        "gtin": bool(record.get("gtin")),
        "price": bool(record.get("price")),
        "availability": bool(record.get("availability")),
        "shipping": bool(record.get("shipping")),
        "returns": bool(record.get("returns")),
    }


def _assess_jsonld_product(product: dict[str, Any]) -> dict[str, Any]:
    offer = _first_offer(product.get("offers"))
    gtin = any(gtin_valid(_text(product.get(key))) for key in _GTIN_KEYS)
    price_value, currency = _offer_price(offer)
    price = _numeric(price_value) and bool(currency)
    availability = _availability_ok(offer.get("availability") or product.get("availability"))
    shipping = _has_shipping(offer) or _has_shipping(product)
    returns = _has_returns(offer) or _has_returns(product)
    return {
        "source": "json-ld",
        "name": product.get("name"),
        "gtin": gtin,
        "price": price,
        "availability": availability,
        "shipping": shipping,
        "returns": returns,
    }


def _walk_products(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        found = []
        for item in data:
            found.extend(_walk_products(item))
        return found
    if not isinstance(data, dict):
        return []
    types = data.get("@type")
    type_names = types if isinstance(types, list) else [types]
    found = []
    if any(str(name).lower() == "product" for name in type_names):
        found.append(data)
    graph = data.get("@graph")
    if isinstance(graph, list):
        found.extend(_walk_products(graph))
    return found


def _first_offer(value: Any) -> dict[str, Any]:
    """Return the first offer dict, including a nested list such as [[{Offer}]]."""
    for _ in range(8):
        if isinstance(value, list):
            value = next((item for item in value if item not in (None, "", [])), None)
            continue
        break
    return value if isinstance(value, dict) else {}


def _offer_price(offer: dict[str, Any]) -> tuple[Any, str]:
    price = offer.get("price")
    currency = offer.get("priceCurrency") or offer.get("pricecurrency") or ""
    spec = _first_offer(offer.get("priceSpecification") or offer.get("pricespecification"))
    if spec:
        if price in (None, ""):
            price = spec.get("price")
        if not currency:
            currency = spec.get("priceCurrency") or spec.get("pricecurrency") or ""
    return price, str(currency or "")


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return str(value)
    return ""


def _numeric(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        try:
            float(value)
            return True
        except ValueError:
            return False
    return False


def _availability_ok(value: Any) -> bool:
    text = _text(value).lower().rstrip("/").rsplit("/", 1)[-1]
    return text in _AVAILABILITY


def _has_shipping(node: dict[str, Any]) -> bool:
    return any(key.lower() in {"shippingdetails", "shippingrate"} or "shipping" in key.lower() for key in node)


def _has_returns(node: dict[str, Any]) -> bool:
    keys = {key.lower() for key in node}
    return "hasmerchantreturnpolicy" in keys or "merchantreturnpolicy" in keys


def _ucp_price(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    amount = value.get("amount")
    currency = value.get("currency")
    return isinstance(amount, int) and not isinstance(amount, bool) and isinstance(currency, str) and len(currency) == 3


def extract_microdata_products(html: str) -> list[dict[str, Any]]:
    """Read schema.org Product items from microdata. Separate from JSON-LD."""
    parser = _MicrodataParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return []
    products = []
    for item in parser.products:
        shaped = _microdata_as_product(item)
        if shaped:
            products.append(shaped)
    return products


class _MicrodataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[dict[str, Any]] = []
        self.products: list[dict[str, Any]] = []
        self._open: list[tuple[str, dict[str, Any] | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key.lower(): value or "" for key, value in attrs}
        names = {key.lower() for key, _ in attrs}
        item = None
        if "itemscope" in names:
            item = {"@type": attr.get("itemtype", ""), "props": {}}
            if self.stack and "itemprop" in attr:
                self.stack[-1]["props"].setdefault(attr["itemprop"], []).append(item)
            self.stack.append(item)
            if "product" in item["@type"].lower().rsplit("/", 1)[-1]:
                self.products.append(item)
        elif self.stack and "itemprop" in attr:
            value = attr.get("content") or attr.get("href")
            if value:
                self.stack[-1]["props"].setdefault(attr["itemprop"], []).append(value)
            else:
                self.stack[-1]["_pending"] = attr["itemprop"]
        self._open.append((tag, item))

    def handle_endtag(self, tag: str) -> None:
        while self._open:
            opened, item = self._open.pop()
            if item is not None and item in self.stack:
                self.stack.remove(item)
            if self.stack:
                self.stack[-1].pop("_pending", None)
            if opened == tag:
                break

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if not text or not self.stack:
            return
        pending = self.stack[-1].get("_pending")
        if pending:
            self.stack[-1]["props"].setdefault(pending, []).append(text)


def _microdata_as_product(item: dict[str, Any]) -> dict[str, Any] | None:
    props = item.get("props") or {}

    def first(source: dict[str, Any], name: str) -> Any:
        values = source.get(name) or []
        return values[0] if values else None

    offer = first(props, "offers")
    offer_dict: dict[str, Any] = {}
    if isinstance(offer, dict):
        offer_props = offer.get("props") or {}
        offer_dict = {
            "@type": "Offer",
            "price": first(offer_props, "price"),
            "priceCurrency": first(offer_props, "priceCurrency"),
            "availability": first(offer_props, "availability"),
        }
        spec = first(offer_props, "priceSpecification")
        if isinstance(spec, dict):
            spec_props = spec.get("props") or {}
            offer_dict["priceSpecification"] = {
                "price": first(spec_props, "price"),
                "priceCurrency": first(spec_props, "priceCurrency"),
            }
        if "shippingDetails" in offer_props:
            offer_dict["shippingDetails"] = {"@type": "OfferShippingDetails"}
        if "hasMerchantReturnPolicy" in offer_props:
            offer_dict["hasMerchantReturnPolicy"] = {"@type": "MerchantReturnPolicy"}
    product: dict[str, Any] = {"@type": "Product", "name": first(props, "name"), "offers": offer_dict}
    for key in _GTIN_KEYS:
        value = first(props, key)
        if isinstance(value, str):
            product[key] = value
    return product


def _product_paths(html: str, origin: str) -> list[str]:
    paths = []
    host = urlparse(origin).netloc
    for href in _HREF.findall(html):
        absolute = urljoin(origin + "/", href)
        parsed = urlparse(absolute)
        if parsed.netloc and parsed.netloc != host:
            continue
        if parsed.path.startswith("/products/") and parsed.path not in paths:
            paths.append(parsed.path)
    return paths
