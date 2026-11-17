"""RFC 9421 HTTP message signatures for one locally generated Ed25519 key.

The signature parameters follow draft-ietf-webbotauth-httpsig-protocol-01:
tag "web-bot-auth", a keyid that is the RFC 7638 JWK thumbprint, created,
expires, and nonce. Signature-Agent is a single dictionary member whose
value is the URL of this run's JWKS. Visa Trusted Agent Protocol tags
(agent-browser-auth, agent-payer-auth) are not sent.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from lanecheck.http_client import Client, HttpResult, is_block
from lanecheck.model import evidence, make_check

AGENT_UA = (
    "lanecheck-probe/0.1 (authorized checkout probe; +https://example.invalid/lanecheck) "
    "Storebot-Google"
)
BROWSER_UA = "lanecheck-probe/0.1 (browser-control; not an agent token)"
ROBOTS_UA = "lanecheck-probe/0.1 (robots.txt policy check)"


@dataclass
class ProbeKey:
    private: Ed25519PrivateKey
    public_raw: bytes
    x: str
    thumbprint: str

    def jwk(self) -> dict[str, str]:
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": self.x,
            "kid": self.thumbprint,
            "use": "sig",
            "alg": "EdDSA",
        }


def generate_key() -> ProbeKey:
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    x = base64.urlsafe_b64encode(public_raw).rstrip(b"=").decode("ascii")
    return ProbeKey(private=private, public_raw=public_raw, x=x, thumbprint=jwk_thumbprint(x))


def jwk_thumbprint(x: str) -> str:
    # RFC 7638 for an OKP key: required members crv, kty, x, in lexicographic order.
    payload = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(payload).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def authority_for(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    default = 443 if parsed.scheme == "https" else 80
    if port and port != default:
        return f"{host}:{port}"
    return host


def signature_base(components: list[tuple[str, str]], params: str) -> bytes:
    lines = [f'"{name}": {value}' for name, value in components]
    lines.append(f'"@signature-params": {params}')
    return ("\n".join(lines) + "\n").encode("utf-8")


def sign_request(
    key: ProbeKey,
    method: str,
    url: str,
    *,
    directory_url: str,
    extra_headers: dict[str, str] | None = None,
    body: bytes | None = None,
    lifetime: int = 300,
) -> dict[str, str]:
    created = int(time.time())
    expires = created + lifetime
    nonce = secrets.token_hex(16)
    agent = f'sig1="{directory_url}"'
    covered: list[tuple[str, str]] = [
        ("@method", method.upper()),
        ("@authority", authority_for(url)),
        ("@path", urlparse(url).path or "/"),
        ("signature-agent", agent),
    ]
    headers = {"Signature-Agent": agent}
    if extra_headers:
        headers.update(extra_headers)
    if body is not None:
        digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        content_digest = f"sha-256=:{digest}:"
        headers["Content-Digest"] = content_digest
        covered.append(("content-digest", content_digest))
        if "Content-Type" in headers:
            covered.append(("content-type", headers["Content-Type"]))
    names = " ".join(f'"{name}"' for name, _ in covered)
    params = (
        f"({names});created={created};expires={expires};keyid=\"{key.thumbprint}\";"
        f"nonce=\"{nonce}\";tag=\"web-bot-auth\""
    )
    signature = key.private.sign(signature_base(covered, params))
    encoded = base64.b64encode(signature).decode("ascii")
    headers["Signature-Input"] = f"sig1={params}"
    headers["Signature"] = f"sig1=:{encoded}:"
    return headers


def parse_signature_input(header: str) -> tuple[str, list[str], str]:
    label, _, rest = header.strip().partition("=")
    if not label or not rest.startswith("("):
        raise ValueError("Signature-Input is not label=(components);params")
    depth = 0
    end = None
    for index, char in enumerate(rest):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end is None:
        raise ValueError("Signature-Input component list is not closed")
    names = re.findall(r'"([^"]+)"', rest[1:end])
    return label.strip(), names, rest


def verify_request(
    method: str,
    url: str,
    headers: dict[str, str],
    *,
    jwks: dict[str, Any],
) -> tuple[bool, str]:
    folded = {key.lower(): value for key, value in headers.items()}
    try:
        _label, names, params = parse_signature_input(folded.get("signature-input", ""))
        encoded = folded.get("signature", "")
        match = re.search(r":([A-Za-z0-9+/=]+):", encoded)
        if not match:
            return False, "Signature header has no byte sequence"
        raw_sig = base64.b64decode(match.group(1))
        values = []
        for name in names:
            values.append((name, _component_value(name, method, url, folded)))
        base = signature_base(values, params)
        keyid = _param(params, "keyid")
        public = _public_key(jwks, keyid)
        public.verify(raw_sig, base)
    except Exception as exc:  # verification failures are findings, not probe crashes
        return False, str(exc)
    return True, "ed25519 signature verified against the JWKS"


def _component_value(name: str, method: str, url: str, headers: dict[str, str]) -> str:
    if name == "@method":
        return method.upper()
    if name == "@authority":
        return authority_for(url)
    if name == "@path":
        return urlparse(url).path or "/"
    if name == "@query":
        query = urlparse(url).query
        return f"?{query}" if query else "?"
    value = headers.get(name.lower())
    if value is None:
        raise KeyError(f"covered component {name} is absent")
    return value


def _param(params: str, name: str) -> str:
    match = re.search(rf";{re.escape(name)}=(\"?)([^\";]+)\1", params)
    if not match:
        raise KeyError(name)
    return match.group(2)


def _public_key(jwks: dict[str, Any], keyid: str) -> Ed25519PublicKey:
    for key in jwks.get("keys", []):
        if key.get("kid") == keyid or jwk_thumbprint(key.get("x", "")) == keyid:
            if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
                continue
            raw = base64.urlsafe_b64decode(key["x"] + "=" * (-len(key["x"]) % 4))
            return Ed25519PublicKey.from_public_bytes(raw)
    raise KeyError(f"keyid {keyid} not in JWKS")


def check_signatures(origin: str, directory_url: str, key: ProbeKey, timeout: float) -> dict:
    """Compare a browser-control GET, an unsigned agent GET, and a signed agent GET of /."""
    url = origin + "/"
    browser = Client(BROWSER_UA, origin, timeout=timeout)
    unsigned = Client(AGENT_UA, origin, timeout=timeout)
    signed_client = Client(AGENT_UA, origin, timeout=timeout)
    browser_result = browser.get(url, headers={"Accept": "text/html, */*;q=0.1"})
    unsigned_result = unsigned.get(url, headers={"Accept": "text/html, */*;q=0.1"})
    signed_headers = sign_request(key, "GET", url, directory_url=directory_url)
    signed_headers["Accept"] = "text/html, */*;q=0.1"
    signed_result = signed_client.get(url, headers=signed_headers)
    calls = browser.calls + unsigned.calls + signed_client.calls

    browser_blocked = is_block(browser_result)
    unsigned_blocked = is_block(unsigned_result)
    signed_blocked = is_block(signed_result)
    items = [
        _result_evidence("browser-control", browser_result),
        _result_evidence("unsigned agent", unsigned_result),
        _result_evidence("signed agent", signed_result),
    ]
    items.append(
        evidence(
            "The signed request covers @method, @authority, @path, and signature-agent, with tag web-bot-auth.",
            signature_agent=directory_url,
            keyid=key.thumbprint,
            tag="web-bot-auth",
            note="This key is not enrolled in any operator directory.",
        )
    )
    if browser_blocked and unsigned_blocked and signed_blocked:
        status = "fail"
        summary = "The origin did not answer the browser-control request or either agent request, so this is not an agent-specific block."
        fix = "Confirm the origin is up and that the probe is allowed to reach it. Then run the check again."
    elif unsigned_blocked and signed_blocked and not browser_blocked:
        status = "fail"
        summary = "The agent user-agent is blocked, and attaching this run's Web Bot Auth signature did not change that."
        fix = (
            "If the block is intentional, leave it. If agents should reach the store, allow the agent user-agent "
            "or accept HTTP message signatures from identities you trust. This probe key is not a trusted identity "
            "until you enroll it yourself."
        )
    elif unsigned_blocked != signed_blocked:
        status = "warn"
        summary = "The unsigned and signed agent requests got different answers. The test key is unenrolled, so a difference is a finding, not proof of a trusted-agent allow-list."
        fix = "Compare the two responses in the evidence. Do not treat acceptance of this local key as verification against Cloudflare, Visa, or Google."
    else:
        status = "pass"
        observed = signed_result.header("x-lane-signature")
        if observed:
            summary = f"Neither agent request was blocked. The fixture reported the test signature as {observed}."
        else:
            summary = "Neither agent request was blocked. The two responses do not show that the site required a signature."
        fix = ""
    check = make_check(
        "signature_comparison",
        "Signed and unsigned agent request comparison",
        status,
        summary,
        items,
        fix,
    )
    check["requests"] = calls
    return check


def _result_evidence(label: str, result: HttpResult) -> dict:
    body = result.text().replace("\n", " ")[:180]
    return evidence(
        f"{label}: HTTP {result.status or 'error'}{' blocked' if is_block(result) else ''}",
        label=label,
        status=result.status,
        error=result.error,
        signature_header=result.header("x-lane-signature"),
        body_prefix=body,
    )
