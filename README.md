# lanecheck

lanecheck probes **a store you own or are authorized to test** and reports whether an AI shopping agent can discover products and reach a checkout session. It never submits payment, and it never calls a checkout `complete` or `delegate_payment` endpoint.

A passing report is not a certification, and it is not a measurement of how often real shoppers' agents succeed.

The name `lanecheck` returned 404 from the npm registry and from PyPI on 2026-11-13. Nothing in this repository has been published.

## What it checks

| Check | Pass means |
| --- | --- |
| `robots_txt` | Shopping and search tokens that honor robots.txt are allowed on `/`, product, cart, and checkout paths. Training opt-outs and user-triggered tokens whose operators say robots.txt may not apply are warnings. |
| `signature_comparison` | A browser-like GET, an unsigned agent GET, and a signed agent GET of `/` are compared. The signature is RFC 9421, tag `web-bot-auth`, from a key generated for that run. |
| `ucp_profile` | `GET /.well-known/ucp` is valid against the business profile shape in [ucp-schema](https://github.com/Universal-Commerce-Protocol/ucp-schema) 1.4.1, using the vendored UCP `v2026-08-25` schemas, and it advertises a shopping transport with checkout. |
| `ucp_flow` | `POST /catalog/search`, `POST /carts`, `POST /checkout-sessions`, then `GET` the cart and the session. The session status is pre-payment. |
| `acp_discovery` | `GET /.well-known/acp.json` matches the Agentic Commerce Protocol `DiscoveryResponse` schema from release `2026-04-17`. A 404 is a warning. |
| `acp_flow` | `POST /carts` when advertised, then `POST /checkout_sessions` with `line_items`, `currency`, and `capabilities`, then `GET` the session. No `complete` call. |
| `product_data` | Readable product records have a valid GTIN, a numeric price with currency, availability, shipping, and returns, from schema.org JSON-LD or the UCP catalog. |
| `webmcp` | The homepage HTML contains `document.modelContext.registerTool` or a `toolname` attribute whose name looks like catalog, cart, or checkout. Tools are not executed. |

Reports are printed in the terminal and can be written as JSON and Markdown. Each check is `pass`, `fail`, or `warn`, with evidence and a fix hint.

## Install

Python 3.11 or newer, plus the official UCP validator:

```bash
# Rust 1.85 or newer. ucp-schema 1.4.1 needs a C toolchain and OpenSSL headers.
cargo install ucp-schema --version 1.4.1 --locked

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

`ucp-schema` must be on `PATH`, or at `/usr/local/cargo/bin/ucp-schema`. If it is missing, the UCP profile check fails instead of inventing a verdict.

## Run

The built-in fixtures listen only on `127.0.0.1`:

```bash
lanecheck --demo friendly
lanecheck --demo blocked --markdown blocked.md --json blocked.json
python -m fixtures.store shoddy --port 8765
lanecheck http://127.0.0.1:8765
```

`lanecheck scan --readonly` is a separate mode for public pages on sites you do not own. It only sends GET requests for `robots.txt`, `/.well-known/ucp`, `/.well-known/acp.json`, the homepage, sitemap product URLs, and at most three product pages. The read-only scan follows same-registrable-domain redirects (up to 4 hops). It uses the user-agent `lanecheck-scan/0.1`, waits at least two seconds between requests to a host, obeys robots.txt for that user-agent, and records a block or challenge without retrying. It does not post, sign, log in, or open a checkout. The owner probe above is unchanged and still refuses origins you do not mark with `--i-own-this`.

Against your own staging origin:

```bash
lanecheck https://staging.example --i-own-this --markdown report.md --json report.json
```

Loopback targets do not need `--i-own-this`. Any other host does. Link-local addresses and `metadata.google.internal` are refused even with the flag. The process exits `0` when there are no failures (warnings are allowed), `1` when a check fails, and `2` when the target is refused or the command is incomplete.

Every run prints this boundary:

> lanecheck probes only an origin you own or are authorized to test. It never submits payment and it never calls a checkout complete or delegate-payment endpoint. The signing key is generated on this machine for this run and is not enrolled with any agent directory, so a blocked signed request does not prove that a real enrolled agent would be blocked. A passing report is not a certification.

## Tests

```bash
pytest
```

The suite is 29 tests. It starts local fixtures, including the read-only scanner, and does not contact any public store.

## Limitations

- The test key is not enrolled with Cloudflare, Google, Visa, Mastercard, or any agent directory. Acceptance does not mean the site checked a trusted directory. Rejection does not mean an enrolled agent would be rejected.
- `Signature-Agent` points at a loopback JWKS URL. That matches the direct-fetch shape in `draft-ietf-webbotauth-httpsig-protocol-01`. It does not match a deployment that requires HTTPS or Cloudflare's signed key directory.
- The probe does not send Visa Trusted Agent Protocol tags (`agent-browser-auth`, `agent-payer-auth`).
- UCP catalog, cart, and checkout **payloads** are not passed through `ucp-schema`. Only the business profile is.
- ACP create uses the `2026-04-17` `line_items` shape. The older OpenAI checkout guide still shows `items`. A server that only implements `items` will fail `acp_flow`.
- A missing ACP discovery document is a warning. A store can be UCP-only.
- WebMCP is read from HTML. No browser is launched, and `executeTool` is not called.
- The owner probe does not follow redirects. RFC 9309 says crawlers should follow robots.txt redirects; this probe reports the 3xx instead, so it cannot be bounced to another host. The read-only scan follows same-registrable-domain redirects (up to 4 hops).
- Loopback HTTP is accepted. The UCP spec requires HTTPS and TLS 1.3 in production. The JSON schema used here accepts an `http` endpoint URI; the probe warns about non-loopback HTTP.
- User-agent strings are not proof of identity. The probe does not check published IP ranges.
- Sessions created on a real staging server are left open. The probe does not cancel them.
- No success rate, latency percentile, or compatibility percentage is claimed. The only stores exercised by the tests are the three fixtures in this repository.

## Layout

- `src/lanecheck/` — the probe
- `fixtures/store.py` — `friendly`, `blocked`, and `shoddy` localhost stores
- `third_party/ucp/2026-08-25/schemas/` — UCP schemas from tag `v2026-08-25`
- `third_party/acp/2026-04-17/schema.agentic_checkout.json` — ACP schema from release `2026-04-17`
- `docs/research.md` — what was read, with links

License: Apache-2.0. Third-party schema notices are in `NOTICE`.
