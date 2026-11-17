"""Fetch /.well-known/ucp and validate it with the official ucp-schema CLI."""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from lanecheck.http_client import Client, HttpResult
from lanecheck.model import evidence, make_check

SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "third_party" / "ucp" / "2026-08-25" / "schemas"
PROFILE_SCHEMA = SCHEMA_ROOT / "profile.json"
RELEASE = "2026-08-25"


def validator_bin() -> str | None:
    found = shutil.which("ucp-schema")
    if found:
        return found
    candidate = Path("/usr/local/cargo/bin/ucp-schema")
    return str(candidate) if candidate.is_file() else None


def check_ucp_profile(client: Client, origin: str) -> dict:
    result = client.get(
        origin + "/.well-known/ucp",
        headers={"Accept": "application/json"},
    )
    if result.status in {301, 302, 303, 307, 308} or result.header("location"):
        # urlopen follows nothing here; a 3xx is the response itself.
        if 300 <= result.status < 400:
            return make_check(
                "ucp_profile",
                "UCP business profile",
                "fail",
                "/.well-known/ucp redirected. The UCP specification says profile endpoints must not use redirects.",
                [evidence(f"HTTP {result.status}", status=result.status, location=result.header("location"))],
                "Serve the profile at /.well-known/ucp with HTTP 200 and no redirect.",
            )
    if result.status == 404:
        return make_check(
            "ucp_profile",
            "UCP business profile",
            "fail",
            "No UCP profile at /.well-known/ucp.",
            [evidence("HTTP 404", status=404)],
            "Publish a business profile at /.well-known/ucp. UCP uses that well-known path for discovery.",
        )
    if result.status != 200:
        return make_check(
            "ucp_profile",
            "UCP business profile",
            "fail",
            f"/.well-known/ucp returned HTTP {result.status or 'error'}.",
            [evidence(result.error or f"HTTP {result.status}", status=result.status)],
            "The profile must be publicly readable without authentication.",
        )
    try:
        document = result.json()
    except json.JSONDecodeError as exc:
        return make_check(
            "ucp_profile",
            "UCP business profile",
            "fail",
            "The profile is not JSON.",
            [evidence(str(exc), body_prefix=result.text()[:200])],
            "Serve application/json that matches the UCP business profile schema.",
        )
    if not isinstance(document, dict):
        return make_check(
            "ucp_profile",
            "UCP business profile",
            "fail",
            "The profile JSON is not an object.",
            [evidence(f"JSON type was {type(document).__name__}")],
            "The profile document is a JSON object with a ucp member.",
        )

    validation = validate_business_profile(document)
    binding = authority_issues(document)
    hosting = hosting_issues(result, origin)
    shopping = shopping_summary(document)
    items = [
        evidence(
            "Official validator result",
            validator=validation.get("validator"),
            valid=validation.get("valid"),
            errors=validation.get("errors", [])[:8],
            detail=validation.get("detail", ""),
        ),
        evidence("Namespace binding", issues=binding),
        evidence("Hosting headers", issues=hosting, cache_control=result.header("cache-control")),
        evidence("Shopping surface", **shopping),
    ]
    if not validation.get("valid"):
        return make_check(
            "ucp_profile",
            "UCP business profile",
            "fail",
            "ucp-schema rejected the business profile.",
            items,
            "Fix the schema errors. Required business-profile members are ucp.version, ucp.services, and ucp.payment_handlers.",
        )
    if binding:
        return make_check(
            "ucp_profile",
            "UCP business profile",
            "fail",
            "A schema URL does not match the reverse-domain authority of its name.",
            items,
            "Host each schema URL on an https origin whose reversed hostname is the name or a label-aligned prefix of it.",
        )
    warnings = hosting + ([] if shopping["checkout"] and shopping["transport"] else ["no REST or MCP shopping endpoint with a checkout capability"])
    if warnings:
        return make_check(
            "ucp_profile",
            "UCP business profile",
            "warn",
            "The profile matches the business schema, with a hosting or capability warning.",
            items,
            " ".join(warnings),
        )
    return make_check(
        "ucp_profile",
        "UCP business profile",
        "pass",
        f"The profile matches the UCP {RELEASE} business schema and advertises a shopping transport with checkout.",
        items,
        "",
    )


def validate_business_profile(document: dict) -> dict:
    binary = validator_bin()
    if binary is None:
        return {
            "valid": False,
            "validator": None,
            "errors": [{"message": "ucp-schema is not installed"}],
            "detail": "Install ucp-schema 1.4.1 to validate the profile. This probe does not substitute its own schema verdict.",
        }
    if not PROFILE_SCHEMA.is_file():
        return {
            "valid": False,
            "validator": binary,
            "errors": [{"message": f"vendored schema missing at {PROFILE_SCHEMA}"}],
            "detail": "",
        }
    version = _version(binary)
    with tempfile.TemporaryDirectory(prefix="lanecheck-ucp-") as tmp:
        payload = Path(tmp) / "profile.json"
        payload.write_text(json.dumps(document), encoding="utf-8")
        command = [
            binary,
            "validate",
            str(payload),
            "--schema",
            str(PROFILE_SCHEMA),
            "--response",
            "--op",
            "read",
            "--def",
            "business_schema",
            "--json",
        ]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    stdout = completed.stdout.strip()
    parsed: dict = {}
    if stdout:
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            parsed = {"valid": False, "errors": [{"message": stdout[:500]}]}
    else:
        parsed = {
            "valid": False,
            "errors": [{"message": (completed.stderr or f"exit {completed.returncode}")[:500]}],
        }
    parsed["validator"] = version
    parsed["exit_code"] = completed.returncode
    if completed.returncode not in {0, 1}:
        parsed["detail"] = completed.stderr[-500:]
    return parsed


def authority_issues(document: dict) -> list[str]:
    ucp = document.get("ucp")
    if not isinstance(ucp, dict):
        return ["profile has no ucp object"]
    issues = []
    for registry in ("services", "capabilities", "payment_handlers"):
        entries = ucp.get(registry) or {}
        if not isinstance(entries, dict):
            continue
        for name, values in entries.items():
            if not isinstance(values, list):
                continue
            for value in values:
                if not isinstance(value, dict):
                    continue
                schema = value.get("schema")
                if schema and not binding_ok(str(name), str(schema)):
                    issues.append(f"{name} schema URL {schema} fails authority binding")
                spec = value.get("spec")
                if spec and urlparse(str(spec)).scheme != "https":
                    issues.append(f"{name} spec URL must be https")
    return issues


def binding_ok(name: str, schema_url: str) -> bool:
    prefix = authority_prefix(schema_url)
    if prefix is None:
        return False
    return name == prefix or name.startswith(prefix + ".")


def authority_prefix(schema_url: str) -> str | None:
    parsed = urlparse(schema_url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return None
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return None
    return ".".join(reversed(labels))


def hosting_issues(result: HttpResult, origin: str) -> list[str]:
    issues = []
    cache = result.header("cache-control").lower()
    if "public" not in cache or "max-age" not in cache:
        issues.append("Cache-Control should include public and max-age of at least 60.")
    else:
        age = _max_age(cache)
        if age is not None and age < 60:
            issues.append(f"Cache-Control max-age is {age}; UCP requires at least 60.")
    if any(token in cache for token in ("private", "no-store", "no-cache")):
        issues.append("Cache-Control must not include private, no-store, or no-cache.")
    if not result.header("etag") and not result.header("last-modified"):
        issues.append("Profile should send ETag or Last-Modified.")
    if urlparse(origin).scheme != "https" and not _loopback(origin):
        issues.append("UCP requires the profile to be served over HTTPS.")
    return issues


def shopping_summary(document: dict) -> dict:
    ucp = document.get("ucp") if isinstance(document.get("ucp"), dict) else {}
    services = ucp.get("services") if isinstance(ucp.get("services"), dict) else {}
    capabilities = ucp.get("capabilities") if isinstance(ucp.get("capabilities"), dict) else {}
    transports = []
    endpoint = ""
    for name, values in services.items():
        if name != "dev.ucp.shopping" or not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, dict):
                continue
            transport = str(value.get("transport") or "")
            transports.append(transport)
            if transport in {"rest", "mcp"} and value.get("endpoint") and not endpoint:
                endpoint = str(value["endpoint"])
    return {
        "transport": any(item in {"rest", "mcp"} for item in transports),
        "transports": transports,
        "endpoint": endpoint,
        "catalog": "dev.ucp.shopping.catalog.search" in capabilities,
        "cart": "dev.ucp.shopping.cart" in capabilities,
        "checkout": "dev.ucp.shopping.checkout" in capabilities,
        "version": ucp.get("version"),
    }


def rest_endpoint(document: dict) -> str:
    summary = shopping_summary(document)
    ucp = document.get("ucp") if isinstance(document.get("ucp"), dict) else {}
    services = ucp.get("services") if isinstance(ucp.get("services"), dict) else {}
    for values in services.values():
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, dict) and value.get("transport") == "rest" and value.get("endpoint"):
                return str(value["endpoint"])
    return summary.get("endpoint") or ""


def _max_age(cache: str) -> int | None:
    for part in cache.split(","):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None


def _loopback(origin: str) -> bool:
    host = (urlparse(origin).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _version(binary: str) -> str:
    completed = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=20, check=False)
    return (completed.stdout or completed.stderr or binary).strip()
