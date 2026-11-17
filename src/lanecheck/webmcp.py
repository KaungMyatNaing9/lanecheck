"""Detect WebMCP tool registrations in HTML. Does not execute tools.

The Web Machine Learning Community Group draft exposes
document.modelContext.registerTool(). Chrome also documents a declarative
toolname attribute. Neither is a W3C Recommendation. This check only reads
source text.
"""

from __future__ import annotations

import re

from lanecheck.http_client import Client, is_block
from lanecheck.model import evidence, make_check
from lanecheck.signatures import AGENT_UA

_REGISTER = re.compile(
    r"""registerTool\s*\(\s*\{[\s\S]{0,800}?name\s*:\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_TOOLNAME = re.compile(r"""\btoolname\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_COMMERCE = re.compile(r"search|catalog|product|cart|checkout|buy", re.IGNORECASE)


def find_tools(html: str) -> list[str]:
    names = _REGISTER.findall(html) + _TOOLNAME.findall(html)
    unique = []
    for name in names:
        if name not in unique:
            unique.append(name)
    return unique


def check_webmcp(origin: str, timeout: float) -> dict:
    client = Client(AGENT_UA, origin, timeout=timeout)
    page = client.get(origin + "/", headers={"Accept": "text/html, */*;q=0.1"})
    if is_block(page) or page.status != 200:
        check = make_check(
            "webmcp",
            "WebMCP commerce tools in page source",
            "warn",
            f"The agent user-agent could not read HTML (HTTP {page.status or 'error'}), so in-page WebMCP tools are not visible to it. WebMCP is optional.",
            [evidence(f"GET / → {page.status}", status=page.status, error=page.error)],
            "If you rely on WebMCP, the browser agent has to be able to load the page. Server-side UCP or ACP does not require WebMCP.",
        )
        check["requests"] = client.calls
        return check
    tools = find_tools(page.text())
    commerce = [name for name in tools if _COMMERCE.search(name)]
    items = [evidence("Tools named in the homepage source", tools=tools, commerce=commerce)]
    if commerce:
        check = make_check(
            "webmcp",
            "WebMCP commerce tools in page source",
            "pass",
            f"The homepage source registers commerce-looking WebMCP tools: {', '.join(commerce)}.",
            items,
            "This only proves the registration text is present. It does not call the tools.",
        )
    elif tools:
        check = make_check(
            "webmcp",
            "WebMCP commerce tools in page source",
            "warn",
            "The page registers WebMCP tools, and none of the names look like catalog, cart, or checkout.",
            items,
            "Register tools whose names and descriptions cover search, cart, and checkout if a browser agent should shop.",
        )
    else:
        check = make_check(
            "webmcp",
            "WebMCP commerce tools in page source",
            "warn",
            "No document.modelContext.registerTool or toolname attribute was found. WebMCP is a draft browser API, not a requirement for UCP or ACP.",
            items,
            "Add WebMCP only if a browser agent should call page tools. Absence is a warning, not a failed checkout path.",
        )
    check["requests"] = client.calls
    return check
