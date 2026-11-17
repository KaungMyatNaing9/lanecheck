"""ACP discovery against the released 2026-04-17 DiscoveryResponse schema.

The RFC file on the ACP main branch still says "Proposal / unreleased".
The 2026-04-17 changelog and schema.agentic_checkout.json define
/.well-known/acp.json. A missing document is a warning: UCP-only stores
are in scope, and the probe does not invent an ACP base URL.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from lanecheck.http_client import Client
from lanecheck.model import evidence, make_check

SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "third_party"
    / "acp"
    / "2026-04-17"
    / "schema.agentic_checkout.json"
)
ACP_VERSION = "2026-04-17"


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    root = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/$defs/DiscoveryResponse",
        "$defs": root["$defs"],
    }
    return Draft202012Validator(schema)


def validate_discovery(document: Any) -> list[str]:
    errors = sorted(_validator().iter_errors(document), key=lambda item: list(item.absolute_path))
    return [_format_error(error) for error in errors[:12]]


def check_acp_discovery(client: Client, origin: str) -> tuple[dict, dict | None, str]:
    result = client.get(origin + "/.well-known/acp.json", headers={"Accept": "application/json"})
    if result.status == 404:
        return (
            make_check(
                "acp_discovery",
                "ACP discovery document",
                "warn",
                "No /.well-known/acp.json. ACP-only agents cannot bootstrap an API base URL from this origin. A UCP-only store can ignore this warning.",
                [evidence("HTTP 404", status=404, schema=str(SCHEMA_PATH.name), release=ACP_VERSION)],
                "If you implement ACP, publish the 2026-04-17 discovery document at /.well-known/acp.json with no authentication.",
            ),
            None,
            "absent",
        )
    if result.status != 200:
        return (
            make_check(
                "acp_discovery",
                "ACP discovery document",
                "fail",
                f"/.well-known/acp.json returned HTTP {result.status or 'error'}. A 404 would mean ACP is absent; this response is neither.",
                [evidence(result.error or f"HTTP {result.status}", status=result.status)],
                "Serve the discovery document as HTTP 200 application/json, or remove it and return 404 if you do not implement ACP.",
            ),
            None,
            "invalid",
        )
    try:
        document = result.json()
    except json.JSONDecodeError as exc:
        return (
            make_check(
                "acp_discovery",
                "ACP discovery document",
                "fail",
                "/.well-known/acp.json is not JSON.",
                [evidence(str(exc))],
                "Publish a DiscoveryResponse object.",
            ),
            None,
            "invalid",
        )
    errors = validate_discovery(document)
    cache = result.header("cache-control")
    items = [
        evidence(
            "Validated against DiscoveryResponse in the 2026-04-17 schema.",
            errors=errors,
            cache_control=cache,
            services=(document.get("capabilities") or {}).get("services") if isinstance(document, dict) else None,
            api_base_url=document.get("api_base_url") if isinstance(document, dict) else None,
        )
    ]
    if errors:
        return (
            make_check(
                "acp_discovery",
                "ACP discovery document",
                "fail",
                "The discovery document does not match the 2026-04-17 DiscoveryResponse schema.",
                items,
                "Include protocol (name acp, version, supported_versions), api_base_url, transports, and capabilities.services.",
            ),
            document if isinstance(document, dict) else None,
            "invalid",
        )
    warnings = []
    if "public" not in cache.lower() or "max-age" not in cache.lower():
        warnings.append("The discovery RFC and changelog say Cache-Control should be public with max-age of at least 3600.")
    services = document.get("capabilities", {}).get("services", [])
    if "checkout" not in services:
        warnings.append("capabilities.services does not include checkout.")
    if warnings:
        return (
            make_check(
                "acp_discovery",
                "ACP discovery document",
                "warn",
                "The discovery document matches the schema, with a warning.",
                items,
                " ".join(warnings),
            ),
            document,
            "ok",
        )
    return (
        make_check(
            "acp_discovery",
            "ACP discovery document",
            "pass",
            "/.well-known/acp.json matches the 2026-04-17 discovery schema and advertises checkout.",
            items,
            "",
        ),
        document,
        "ok",
    )


def _format_error(error: ValidationError) -> str:
    path = ".".join(str(part) for part in error.absolute_path) or "$"
    return f"{path}: {error.message}"
