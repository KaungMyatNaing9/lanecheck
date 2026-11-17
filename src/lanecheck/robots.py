"""RFC 9309 robots.txt parser and the agent-token check.

Matching follows the rules read from RFC 9309 on 2026-11-13:
exact case-insensitive product-token match, merged duplicate groups,
`*` only when no group matches, longest matching path, Allow wins an
equal-length tie, `*` and `$` are the special characters in section 2.2.3.
An empty allow or disallow pattern matches nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urljoin, urlparse

from lanecheck.agents import TOKENS, AgentToken
from lanecheck.http_client import Client
from lanecheck.model import evidence, make_check, worst

_COMMENT = re.compile(r"\s+#.*$")
_HREF = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)


@dataclass
class Rule:
    allow: bool
    pattern: str


@dataclass
class Group:
    agents: list[str] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)


def parse_robots(text: str) -> list[Group]:
    groups: list[Group] = []
    current = Group()
    seen_rule = False
    for raw in text.splitlines():
        line = _COMMENT.sub("", raw).strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            if seen_rule:
                groups.append(current)
                current = Group()
                seen_rule = False
            current.agents.append(value)
        elif key in {"allow", "disallow"}:
            seen_rule = True
            current.rules.append(Rule(allow=key == "allow", pattern=value))
    if current.agents:
        groups.append(current)
    return groups


def allowed(groups: list[Group], token: str, path: str) -> bool:
    """Return True when RFC 9309 allows `token` to fetch `path`."""
    exact = [group for group in groups if any(agent.lower() == token.lower() for agent in group.agents)]
    chosen = exact or [group for group in groups if any(agent == "*" for agent in group.agents)]
    rules = [rule for group in chosen for rule in group.rules]
    return _allowed_by_rules(rules, path)


def _allowed_by_rules(rules: list[Rule], path: str) -> bool:
    best_len = -1
    best_allow = True
    for rule in rules:
        matched = _match_length(rule.pattern, path)
        if matched is None:
            continue
        if matched > best_len or (matched == best_len and rule.allow and not best_allow):
            best_len = matched
            best_allow = rule.allow
    return best_allow


def _match_length(pattern: str, path: str) -> int | None:
    if pattern == "":
        return None
    anchor = pattern.endswith("$")
    body = pattern[:-1] if anchor else pattern
    regex = "^" + ".*".join(re.escape(part) for part in body.split("*"))
    if anchor:
        regex += "$"
    if re.match(regex, path) is None:
        return None
    return len(body)


def normalize_path(path: str) -> str:
    decoded = unquote(path or "/")
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    return decoded


def check_robots(client: Client, origin: str) -> dict:
    result = client.get(
        origin + "/robots.txt",
        headers={"Accept": "text/plain, */*;q=0.1"},
    )
    if result.status == 0 or 500 <= result.status <= 599:
        return make_check(
            "robots_txt",
            "robots.txt policy for known agent tokens",
            "fail",
            f"robots.txt is unreachable (HTTP {result.status or 'error'}). RFC 9309 says a 5xx or network failure means crawlers must assume complete disallow.",
            [evidence(result.error or f"GET /robots.txt returned {result.status}", url=result.url, status=result.status)],
            "Serve a 200 robots.txt. While it is unreachable, crawlers that follow RFC 9309 section 2.3.1.4 stop.",
        )
    if 400 <= result.status <= 499:
        return make_check(
            "robots_txt",
            "robots.txt policy for known agent tokens",
            "warn",
            f"robots.txt returned HTTP {result.status}. RFC 9309 section 2.3.1.3 says crawlers may then access any resource, so there is no explicit agent policy.",
            [evidence(f"GET /robots.txt → {result.status}", status=result.status)],
            "Publish /robots.txt with an explicit group for each shopping or search agent you intend to allow.",
        )
    if result.status != 200:
        return make_check(
            "robots_txt",
            "robots.txt policy for known agent tokens",
            "warn",
            f"robots.txt returned HTTP {result.status}, which this probe does not treat as a policy.",
            [evidence(f"GET /robots.txt → {result.status}", status=result.status)],
            "Serve the policy as HTTP 200 text/plain.",
        )

    groups = parse_robots(result.text())
    paths = _paths_to_check(client, origin)
    findings = []
    statuses = []
    for token in TOKENS:
        blocked_paths = [path for path in paths if not allowed(groups, token.token, path)]
        token_status = "pass"
        if blocked_paths:
            token_status = "fail" if token.effect == "blocks" else "warn"
        statuses.append(token_status)
        findings.append(
            evidence(
                f"{token.token}: {token_status}",
                token=token.token,
                operator=token.operator,
                role=token.role,
                robots=token.robots,
                source=token.source,
                effect=token.effect,
                blocked_paths=blocked_paths,
                paths_checked=paths,
            )
        )
    status = worst(statuses)
    if status == "fail":
        summary = "At least one shopping or search token that honors robots.txt is disallowed from a catalog, cart, or checkout path."
        fix = (
            "Allow Storebot-Google, OAI-SearchBot, Claude-SearchBot, Claude-User, and PerplexityBot "
            "on product, cart, and checkout paths if those agents should discover and retrieve the store. "
            "A Disallow for GPTBot, ClaudeBot, or Google-Extended is a training opt-out and is only a warning."
        )
    elif status == "warn":
        summary = "Shopping tokens that honor robots.txt are allowed. A training opt-out or a user-triggered token is disallowed; that disallow may not stop the fetch."
        fix = "Read the evidence for each warned token. Leave training opt-outs in place if that is the policy you want."
    else:
        summary = "Every checked agent token is allowed on the homepage, product, cart, and checkout paths."
        fix = ""
    return make_check(
        "robots_txt",
        "robots.txt policy for known agent tokens",
        status,
        summary,
        findings,
        fix,
    )


def _paths_to_check(client: Client, origin: str) -> list[str]:
    paths = ["/", "/cart", "/checkout"]
    page = client.get(origin + "/", headers={"Accept": "text/html, */*;q=0.1"})
    if page.status == 200:
        for href in _HREF.findall(page.text()):
            absolute = urljoin(origin + "/", href)
            parsed = urlparse(absolute)
            if parsed.netloc and parsed.netloc != urlparse(origin).netloc:
                continue
            path = normalize_path(parsed.path)
            if path.startswith("/products/") or path in {"/cart", "/checkout"}:
                if path not in paths:
                    paths.append(path)
            if len(paths) >= 8:
                break
    return paths
