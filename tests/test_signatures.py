import base64
import hashlib
import json

from lanecheck.signatures import generate_key, jwk_thumbprint, sign_request, signature_base, verify_request


def test_signature_base_matches_the_rfc9421_line_shape():
    params = (
        '("@method" "@authority" "@path" "signature-agent");created=1700000000;'
        'expires=1700000300;keyid="abc";nonce="n";tag="web-bot-auth"'
    )
    base = signature_base(
        [
            ("@method", "GET"),
            ("@authority", "example.com"),
            ("@path", "/"),
            ("signature-agent", 'sig1="https://signer.example/jwks.json"'),
        ],
        params,
    )
    assert base.decode() == (
        '"@method": GET\n'
        '"@authority": example.com\n'
        '"@path": /\n'
        '"signature-agent": sig1="https://signer.example/jwks.json"\n'
        '"@signature-params": '
        + params
        + "\n"
    )


def test_round_trip_and_tamper():
    key = generate_key()
    canonical = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": key.x}, separators=(",", ":")).encode()
    assert key.thumbprint == base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()
    assert key.thumbprint == jwk_thumbprint(key.x)
    url = "http://127.0.0.1:9/"
    headers = sign_request(key, "GET", url, directory_url="http://127.0.0.1:9/jwks.json")
    jwks = {"keys": [key.jwk()]}
    ok, _reason = verify_request("GET", url, headers, jwks=jwks)
    assert ok
    bad = dict(headers)
    bad["Signature-Agent"] = 'sig1="http://127.0.0.1:9/other.json"'
    ok, _reason = verify_request("GET", url, bad, jwks=jwks)
    assert not ok
