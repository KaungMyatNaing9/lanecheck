# Research notes

Checked on 2026-11-13 by fetching the primary pages below. This file records what those pages say and what lanecheck does with them. It is not a compatibility certificate.

## Name

`lanecheck` was checked against:

- `https://registry.npmjs.org/lanecheck` → HTTP 404
- `https://pypi.org/pypi/lanecheck/json` → HTTP 404

The package has not been published to either registry.

## Universal Commerce Protocol (UCP)

Canonical spec read: [UCP overview, release 2026-08-25](https://ucp.dev/2026-08-25/specification/overview/).

Verified from that page:

- A business publishes a JSON profile at `/.well-known/ucp`. A platform sends its profile URI in the `UCP-Agent` structured-field header (`profile="https://..."`).
- `ucp.version`, `ucp.services`, and `ucp.payment_handlers` are required. `services` and `payment_handlers` must be present even when empty. `ucp.capabilities` is optional.
- Names use reverse-domain form. A declared `schema` URL must be `https`, must not contain userinfo, and its reversed hostname must equal the entity name or be a label-aligned prefix of it. `spec` URLs must be `https` and are not authority-bound.
- Profiles must be served over HTTPS, must not redirect, must send `Cache-Control: public` with `max-age` of at least 60, and should send `ETag` or `Last-Modified`.
- Signing keys, when published, live in the top-level `keys` array (a JWK set). The same document can be reused as a Web Bot Auth key source when `Signature-Agent` uses `type=jwks_uri`. The default `type=directory` expects a signed directory at `/.well-known/http-message-signatures-directory`, not the static profile.
- REST shopping paths are appended to the service `endpoint`. Checked against the REST bindings:
  - Catalog: `POST /catalog/search`, `POST /catalog/lookup`, `POST /catalog/product` — [catalog REST](https://ucp.dev/2026-08-25/specification/shopping/catalog/rest/)
  - Cart: `POST /carts`, `GET /carts/{id}`, `PUT /carts/{id}`, `POST /carts/{id}/cancel` — [cart REST](https://ucp.dev/2026-08-25/specification/shopping/cart/rest/)
  - Checkout: `POST /checkout-sessions`, `GET /checkout-sessions/{id}`, `PUT /checkout-sessions/{id}`, `POST /checkout-sessions/{id}/complete`, `POST /checkout-sessions/{id}/cancel` — [checkout REST](https://ucp.dev/2026-08-25/specification/shopping/checkout/rest/)
- Create-checkout example body is `{ "line_items": [{ "item": { "id": "..." }, "quantity": 1 }] }`. Amounts are minor units. A create response in the examples uses status `incomplete`. `ready_for_complete` appears after fulfillment selection. `POST .../complete` is the call that places the order. lanecheck does not send it.
- Checkout requests that modify state require `UCP-Agent`, and the binding says `Idempotency-Key` and `Request-Id` are required headers. The probe sends all three. The fixture does not fetch the platform profile; a strict business that cannot fetch the probe's loopback profile will fail the flow, and the report shows the HTTP status.

Official validator: [`ucp-schema` 1.4.1](https://crates.io/crates/ucp-schema), Apache-2.0, repository [Universal-Commerce-Protocol/ucp-schema](https://github.com/Universal-Commerce-Protocol/ucp-schema). `ucp-schema --version` prints `ucp-schema 1.4.1`. A business profile is validated with:

```bash
ucp-schema validate profile.json \
  --schema third_party/ucp/2026-08-25/schemas/profile.json \
  --response --op read --def business_schema --json
```

That command returned `{"valid":true}` for a minimal profile with an `http://127.0.0.1` endpoint. The JSON schema's endpoint format is `uri`, not a hard `https` pattern. The probe therefore warns on non-loopback HTTP and accepts loopback HTTP, and it says so in the limitations. The schema files are the `source/schemas` tree from git tag `v2026-08-25`, commit `87dd4b1fcff9105d68173120897237fa784c74ef`. Published `$id` values on ucp.dev are rewritten under `/2026-08-25/`; the vendored files keep the tag's `$id` values. The probe does not run `ucp-schema` on catalog, cart, or checkout payloads.

Google's merchant guide also documents `/.well-known/ucp`: [Prepare your UCP profile](https://developers.google.com/merchant/ucp/guides/overview/ucp-profile) and the [2026-04-08 publish guide](https://developers.google.com/merchant/ucp/implementation/2026-04-08/publish-profile). Those Google pages describe the 2026-04-08 and 2026-01-23 integration guides. The probe validates the 2026-08-25 schema, not a Google-only subset.

Building `ucp-schema` 1.4.1 required Rust 1.85 or newer (`rust-version = "1.85"` in its `Cargo.toml`) and OpenSSL headers. The image's default `rustc` was 1.83.0. Stable 1.100.0 was installed to compile it.

## Agentic Commerce Protocol (ACP)

Repository read: [agentic-commerce-protocol](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol). The README fetched from `main` says the specification is maintained by **OpenAI and Stripe** and is in **beta**.

A web-search snippet of [Stripe's ACP page](https://docs.stripe.com/agentic-commerce/protocols/acp) described ACP as created by Stripe, OpenAI, and Meta. The HTML fetched from that URL is a client-rendered shell and did not contain that sentence, so Meta's role is **not** treated as verified here.

Checkout, as described on [OpenAI's Agentic Checkout Spec](https://developers.openai.com/commerce/specs/checkout): create `POST /checkout_sessions`, update, get, cancel, and `POST /checkout_sessions/{id}/complete` with `payment_data`. That page's create example uses an `items` array. The released `2026-04-17` JSON schema's `CheckoutSessionCreateRequest` instead requires `line_items`, `currency`, and `capabilities`. Its `Item` object requires `id` and sets `additionalProperties: false`. The cart schema's example still shows `quantity` on those items; that example does not validate against `Item`. lanecheck sends the schema shape (`id` only, plus currency and capabilities) and does not call `complete`.

Discovery:

- [changelog/2026-04-17.md](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/blob/main/changelog/2026-04-17.md) says release `2026-04-17` added `/.well-known/acp.json` and the `DiscoveryResponse` schema. Commit `9abf303f48088d170503a54502d612b8b1997897` is the release commit. The vendored file is `spec/2026-04-17/json-schema/schema.agentic_checkout.json` from that commit, and it does contain `DiscoveryResponse`.
- [rfcs/rfc.discovery.md](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/blob/main/rfcs/rfc.discovery.md) on `main` still opens with **Status: Proposal** and **Version: unreleased**, and its conformance checklist is unchecked. Both observations are true: the changelog says the document shipped, and the RFC file was not updated to say so.
- A 404 means the seller does not advertise ACP. lanecheck warns, because a UCP-only store is in scope. A present but invalid document fails.
- Cart paths in [openapi.cart.yaml for 2026-04-17](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/blob/9abf303f48088d170503a54502d612b8b1997897/spec/2026-04-17/openapi/openapi.cart.yaml): `POST /carts`, `GET` and `PUT /carts/{id}`, `POST /carts/{id}/cancel`.
- The checkout OpenAPI requires `API-Version` and, in the 2026-01-30 file, `Authorization`. The probe sends `API-Version: 2026-04-17` and sends `Authorization` only when `--acp-token` is passed. It does not invent a bearer token. A 401 fails the ACP flow with that hint.
- Product feeds are a separate ACP surface ([OpenAI feed guide](https://developers.openai.com/commerce/guides/submit-product-feeds)). The discovery RFC lists product catalog discovery as a non-goal. lanecheck does not fetch an ACP feed. Product facts come from JSON-LD and, when present, the UCP catalog.

## Web Bot Auth and HTTP message signatures

- [draft-ietf-webbotauth-httpsig-protocol-01](https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol) (29 October 2026, Web Bot Auth working group) defines signatures for automated clients, a `Signature-Agent` dictionary of HTTPS URIs, `tag` = `web-bot-auth`, `created`, `expires`, and a `keyid` that is the base64url JWK SHA-256 thumbprint. The draft says a verifier fetches the `Signature-Agent` member directly as a JWK set. It replaces the individual draft `draft-meunier-webbotauth-httpsig-protocol`.
- [draft-meunier-http-message-signatures-directory-05](https://datatracker.ietf.org/doc/html/draft-meunier-http-message-signatures-directory) is the earlier directory draft: JWKS media type `application/http-message-signatures-directory+json`, and `Signature-Agent` as a dictionary whose values can be `https`, `http`, or `data` URIs.
- The UCP overview's WBA section does not match the October 2026 IETF draft exactly. UCP says an omitted `type` means `directory`: the value is an origin, and the verifier appends `/.well-known/http-message-signatures-directory`. `type=jwks_uri` fetches the URL as a JWK set. lanecheck implements the IETF draft's direct JWKS fetch, over loopback HTTP, and documents that a Cloudflare-style directory deployment will not treat this key as enrolled.
- [Cloudflare's Web Bot Auth docs](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/) require the directory at `/.well-known/http-message-signatures-directory`, Ed25519, tag `web-bot-auth`, and a self-signature on the directory response. The probe does not self-sign a directory.
- [Cloudflare's agentic-commerce post](https://blog.cloudflare.com/secure-agentic-commerce/) says Visa's Trusted Agent Protocol and Mastercard Agent Pay use Web Bot Auth, with tags `agent-browser-auth` and `agent-payer-auth`, a nonce, and keys in a network-hosted directory. lanecheck does not send either Visa tag and does not contact Visa or Mastercard.
- [OpenBotAuth](https://github.com/OpenBotAuth/openbotauth) is origin-side verification tooling for the same IETF drafts. lanecheck does not depend on it. The friendly fixture verifies the probe's own signature with the same RFC 9421 base construction, and a unit test locks the signature-base line shape.
- Google's user-triggered fetchers page notes that Google is experimenting with Web Bot Auth under the identity `https://agent.bot.goog`. The probe does not fetch or trust that directory.

The comparison check sends three GETs of `/`: a browser-control user-agent, an unsigned agent user-agent that includes the token `Storebot-Google`, and the same agent user-agent with the test signature. The key is discarded with the process.

## robots.txt tokens

Matching implemented from [RFC 9309](https://www.rfc-editor.org/rfc/rfc9309): case-insensitive exact product-token match, duplicate groups merged, `*` only when nothing else matches, longest path match, Allow wins an equal-length tie, `*` and `$` special characters. An empty allow/disallow pattern matches nothing. Section 2.3.1.3: HTTP 400–499 on robots.txt means crawlers may access any resource (the probe warns). Section 2.3.1.4: HTTP 500–599 or a network failure means crawlers must assume complete disallow (the probe fails). The probe does not follow redirects, which is stricter than section 2.3.1.2.

Tokens encoded as verdicts, after reading the operator page:

| Token | Effect in lanecheck | Source |
| --- | --- | --- |
| `Storebot-Google` | Disallow fails the check. Google says preferences for this token affect all Google Shopping surfaces. | [Google common crawlers](https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers) |
| `Google-Agent` | Disallow warns. Google lists it under user-triggered fetchers, which generally ignore robots.txt. The page gives mobile and desktop UA strings containing `Google-Agent`. | [Google user-triggered fetchers](https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers) |
| `Google-Extended` | Disallow warns. It has no separate request UA. It is a control token for Gemini training and grounding. | [Google common crawlers](https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers) |
| `OAI-SearchBot` | Disallow fails. Opting out removes the site from ChatGPT search answers. | [OpenAI crawlers](https://developers.openai.com/api/docs/bots) |
| `GPTBot` | Disallow warns. It is the training crawler, independent of search. | [OpenAI crawlers](https://developers.openai.com/api/docs/bots) |
| `ChatGPT-User` | Disallow warns. OpenAI says robots.txt rules may not apply because a user initiated the fetch. | [OpenAI crawlers](https://developers.openai.com/api/docs/bots) |
| `OAI-AdsBot` | Disallow warns. It visits ad landing pages and is not the shopping-index crawler. | [OpenAI crawlers](https://developers.openai.com/api/docs/bots) |
| `ClaudeBot` | Disallow warns. Training crawler. Anthropic says its bots honor robots.txt. | [Anthropic crawler help](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler) |
| `Claude-SearchBot` | Disallow fails. Search index. Anthropic says it honors robots.txt. | same Anthropic article |
| `Claude-User` | Disallow fails. User-triggered retrieval that Anthropic says still honors robots.txt. | same Anthropic article |
| `PerplexityBot` | Disallow fails. Search inclusion. | [Perplexity crawlers](https://docs.perplexity.ai/docs/resources/perplexity-crawlers) |
| `Perplexity-User` | Disallow warns. Perplexity says this fetcher generally ignores robots.txt. | [Perplexity crawlers](https://docs.perplexity.ai/docs/resources/perplexity-crawlers) |

Not encoded, because a primary page was not fetched for them in this pass: Amazonbot, Amzn-SearchBot, Amzn-User, Meta-ExternalAgent, Meta-ExternalFetcher, Applebot-Extended. User-agent strings are spoofable; none of these operators treat the token as proof of identity. The probe does not check published IP ranges.

## Product data

Google's merchant structured-data guidance, used as the field list rather than as a certification:

- [Merchant listing structured data](https://developers.google.com/search/docs/appearance/structured-data/merchant-listing)
- [Supported structured data attributes](https://support.google.com/merchants/answer/6386198)
- [Return policy structured data](https://developers.google.com/search/docs/appearance/structured-data/return-policy)

lanecheck looks for `gtin`, `gtin8`, `gtin12`, `gtin13`, or `gtin14` with a valid GS1 check digit; `Offer.price` plus `priceCurrency` (or a UCP price object of minor-unit `amount` plus ISO currency); availability (`InStock` and the other schema.org item-availability names, or UCP `available` / `status`); shipping (`Offer.shippingDetails` or a UCP policy whose type contains `shipping` or `fulfillment`); and returns (`hasMerchantReturnPolicy` or a UCP policy whose type contains `return`).

UCP variant identifiers are `barcodes[]` with `type` such as `GTIN` and a `value`, not a top-level `gtin13`. Price is `{ "amount": 3200, "currency": "USD" }`. Availability is `{ "available": true, "status": "in_stock" }`. Those fields were read from tag `v2026-08-25` `source/schemas/shopping/types/variant.json`, `price.json`, and `availability.json`.

## WebMCP

- [WebMCP draft](https://webmachinelearning.github.io/webmcp/), Draft Community Group Report dated 13 November 2026. It is not a W3C Recommendation. The interface is `document.modelContext`, with `registerTool`, `getTools`, and `executeTool`.
- [Chrome's imperative API](https://developer.chrome.com/docs/ai/webmcp/imperative-api) shows `document.modelContext.registerTool({ name, description, inputSchema, execute })`.
- [Shopify WebMCP](https://shopify.dev/docs/api/web-mcp) and [checkout WebMCP](https://shopify.dev/docs/agents/carts-and-checkout/checkout-webmcp) register storefront and checkout tools, including cart and `proceed_to_checkout` / `get_checkout` / `update_checkout` / `complete_checkout`. Shopify says checkout tools return a UCP checkout object. lanecheck does not call `complete_checkout`.
- [BigCommerce WebMCP](https://docs.bigcommerce.com/developer/api-reference/mcp/webmcp.md) describes Cloudflare-provided browser tools such as `search_products` and `create_checkout_url`. That is a vendor deployment of the draft, not a second protocol.

The probe only searches HTML for `registerTool({ name: "..." })` and a `toolname` attribute. It does not launch a browser, so it cannot tell whether the tools run.

## What this repository deliberately does not do

- No requests to third-party stores in tests or demos. The three fixtures are `friendly`, `blocked`, and `shoddy` on `127.0.0.1`.
- No payment, no `complete`, no `delegate_payment`, no Visa payer tag.
- No publication to npm, PyPI, or a package registry.
