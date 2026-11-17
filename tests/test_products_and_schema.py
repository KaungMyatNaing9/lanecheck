from lanecheck.acp_check import validate_discovery
from lanecheck.products import (
    assess_jsonld,
    extract_jsonld_products,
    extract_microdata_products,
    gtin_valid,
)
from lanecheck.ucp_check import binding_ok


def test_known_gtin13_check_digit():
    assert gtin_valid("4006381333931")
    assert not gtin_valid("123")
    assert not gtin_valid("4006381333932")


def test_price_specification_and_nested_offer_lists():
    html = """
    <script type="application/ld+json">
    {"@type": "Product", "name": "Hat",
     "offers": [[{"@type": "Offer", "priceSpecification": {
        "@type": "UnitPriceSpecification", "price": "18.50", "priceCurrency": "EUR"
     }, "availability": "https://schema.org/InStock"}]]}
    </script>
    """
    record = assess_jsonld(extract_jsonld_products(html))[0]
    assert record["price"] is True
    assert record["availability"] is True


def test_microdata_product_is_a_separate_signal():
    html = """
    <div itemscope itemtype="https://schema.org/Product">
      <span itemprop="name">Mug</span>
      <span itemprop="gtin13">4006381333931</span>
      <div itemprop="offers" itemscope itemtype="https://schema.org/Offer">
        <span itemprop="price">15.00</span>
        <meta itemprop="priceCurrency" content="USD">
        <link itemprop="availability" href="https://schema.org/InStock">
        <div itemprop="shippingDetails" itemscope itemtype="https://schema.org/OfferShippingDetails"></div>
        <div itemprop="hasMerchantReturnPolicy" itemscope itemtype="https://schema.org/MerchantReturnPolicy"></div>
      </div>
    </div>
    """
    assert extract_jsonld_products(html) == []
    record = assess_jsonld(extract_microdata_products(html))[0]
    assert record["gtin"] is True
    assert record["price"] is True
    assert record["availability"] is True
    assert record["shipping"] is True
    assert record["returns"] is True


def test_jsonld_flags_missing_offer_fields():
    html = """
    <script type="application/ld+json">
    {"@type": "Product", "name": "Mug", "gtin13": "123",
     "offers": {"@type": "Offer", "price": "see store", "priceCurrency": "USD"}}
    </script>
    """
    record = assess_jsonld(extract_jsonld_products(html))[0]
    assert record["gtin"] is False
    assert record["price"] is False
    assert record["availability"] is False
    assert record["shipping"] is False
    assert record["returns"] is False


def test_authority_binding_accepts_ucp_and_rejects_a_lookalike():
    assert binding_ok(
        "dev.ucp.shopping.checkout",
        "https://ucp.dev/2026-08-25/schemas/shopping/checkout.json",
    )
    assert not binding_ok("dev.ucp.shopping.checkout", "https://evil.example/checkout.json")
    assert not binding_ok("com.examplecorp.pay", "https://example.com/pay.json")
    assert binding_ok("com.example.pay", "https://pay.example.com/pay.json")


def test_acp_discovery_schema_accepts_the_minimal_document_and_rejects_a_broken_one():
    good = {
        "protocol": {
            "name": "acp",
            "version": "2026-04-17",
            "supported_versions": ["2026-01-30", "2026-04-17"],
        },
        "api_base_url": "https://merchant.example/acp",
        "transports": ["rest"],
        "capabilities": {"services": ["checkout"]},
    }
    assert validate_discovery(good) == []
    bad = {"protocol": {"name": "acp", "version": "yesterday"}, "transports": ["carrier-pigeon"]}
    errors = validate_discovery(bad)
    assert errors
    assert any("api_base_url" in error for error in errors)
