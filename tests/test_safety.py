import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lanecheck.http_client import Client, PaymentRefusal, is_payment_path
from lanecheck.safety import SafetyError, assert_authorized


def test_loopback_is_allowed_without_a_flag():
    assert assert_authorized("http://127.0.0.1:9/shop", i_own_this=False) == "http://127.0.0.1:9"
    assert assert_authorized("http://localhost:9/", i_own_this=False) == "http://localhost:9"


def test_public_origin_is_refused_before_any_request():
    try:
        assert_authorized("https://example.com/products", i_own_this=False)
    except SafetyError as exc:
        assert "i-own-this" in str(exc)
    else:
        raise AssertionError("public origin was accepted")


def test_metadata_address_is_refused_even_when_claimed():
    for url in ("http://169.254.169.254/", "http://metadata.google.internal/"):
        try:
            assert_authorized(url, i_own_this=True)
        except SafetyError:
            continue
        raise AssertionError(url)


def test_userinfo_is_refused():
    try:
        assert_authorized("http://user:pass@127.0.0.1/", i_own_this=True)
    except SafetyError as exc:
        assert "userinfo" in str(exc)
    else:
        raise AssertionError("userinfo accepted")


def test_private_network_needs_the_flag():
    try:
        assert_authorized("http://192.168.1.20/", i_own_this=False)
    except SafetyError:
        pass
    else:
        raise AssertionError("private origin accepted")
    assert assert_authorized("http://192.168.1.20/", i_own_this=True) == "http://192.168.1.20"


def test_redirects_are_not_followed():
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            body = b"redirect"
            self.send_response(302)
            self.send_header("Location", "https://example.com/elsewhere")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        result = Client("lanecheck-test", origin).get(origin + "/robots.txt")
    finally:
        server.shutdown()
        server.server_close()
    assert result.status == 302
    assert result.header("location") == "https://example.com/elsewhere"
    assert result.text() == "redirect"


def test_payment_paths_are_refused_before_the_network():
    assert is_payment_path("/ucp/v1/checkout-sessions/chk_1/complete")
    assert is_payment_path("/acp/checkout_sessions/cs_1/complete")
    assert is_payment_path("/delegate_payment")
    client = Client("lanecheck-test", "http://127.0.0.1:9")
    try:
        client.post_json("http://127.0.0.1:9/ucp/v1/checkout-sessions/chk_1/complete", {"payment": {}})
    except PaymentRefusal:
        pass
    else:
        raise AssertionError("complete was sent")
    assert client.calls == []
