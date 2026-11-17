import json
import os
import subprocess
import sys
from pathlib import Path

from fixtures.store import FixtureServer
from lanecheck.runner import run_probe
from lanecheck.safety import SafetyError

ROOT = Path(__file__).resolve().parents[1]

FRIENDLY = {
    "robots_txt": "pass",
    "signature_comparison": "pass",
    "ucp_profile": "pass",
    "ucp_flow": "pass",
    "acp_discovery": "pass",
    "acp_flow": "pass",
    "product_data": "pass",
    "webmcp": "pass",
}
BLOCKED = {
    "robots_txt": "fail",
    "signature_comparison": "fail",
    "ucp_profile": "fail",
    "ucp_flow": "fail",
    "acp_discovery": "fail",
    "acp_flow": "fail",
    "product_data": "fail",
    "webmcp": "warn",
}
SHODDY = {
    "robots_txt": "pass",
    "signature_comparison": "pass",
    "ucp_profile": "fail",
    "ucp_flow": "fail",
    "acp_discovery": "warn",
    "acp_flow": "warn",
    "product_data": "fail",
    "webmcp": "warn",
}


def _statuses(report):
    return {check["id"]: check["status"] for check in report["checks"]}


def _probe(mode):
    server = FixtureServer(mode)
    try:
        report = run_probe(server.url)
        hits = json.loads(_get(server.url + "/_probe/hits"))
        return report, hits
    finally:
        server.close()


def _get(url):
    from urllib.request import urlopen

    with urlopen(url, timeout=5) as response:
        return response.read().decode()


def test_friendly_store_passes_every_check_and_never_pays():
    report, hits = _probe("friendly")
    assert _statuses(report) == FRIENDLY
    assert report["payment_endpoints_called"] == []
    assert hits["payment_attempts"] == 0
    assert not any(hit["path"].rstrip("/").endswith("/complete") for hit in hits["hits"])
    assert "not a certification" in report["disclaimer"]
    signed = next(item for item in report["checks"] if item["id"] == "signature_comparison")
    assert "valid" in signed["summary"]


def test_blocked_store_fails_the_agent_path():
    report, hits = _probe("blocked")
    assert _statuses(report) == BLOCKED
    assert hits["payment_attempts"] == 0
    robots = next(item for item in report["checks"] if item["id"] == "robots_txt")
    storebot = next(item for item in robots["evidence"] if item["data"]["token"] == "Storebot-Google")
    assert storebot["data"]["blocked_paths"]
    gpt = next(item for item in robots["evidence"] if item["data"]["token"] == "GPTBot")
    assert "/" in gpt["data"]["blocked_paths"]


def test_shoddy_store_separates_missing_protocols_from_bad_product_data():
    report, hits = _probe("shoddy")
    assert _statuses(report) == SHODDY
    assert hits["payment_attempts"] == 0
    product = next(item for item in report["checks"] if item["id"] == "product_data")
    assert "gtin" in product["summary"]
    assert "price" in product["summary"]


def test_cli_demo_and_refusal(tmp_path):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT), env.get("PYTHONPATH", "")])
    completed = subprocess.run(
        [sys.executable, "-m", "lanecheck", "--demo", "friendly", "--json", str(tmp_path / "report.json")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "PASS" in completed.stdout
    saved = json.loads((tmp_path / "report.json").read_text())
    assert saved["summary"]["fail"] == 0
    refused = subprocess.run(
        [sys.executable, "-m", "lanecheck", "https://example.com/"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert refused.returncode == 2
    assert "i-own-this" in refused.stderr
    assert "example.com" not in refused.stdout


def test_run_probe_does_not_accept_a_public_origin():
    try:
        run_probe("https://example.com/")
    except SafetyError:
        return
    raise AssertionError("public origin was probed")
