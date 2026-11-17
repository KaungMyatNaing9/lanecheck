"""Product tokens whose operator documentation was checked on 2026-11-13.

`blocks` means a robots.txt disallow is treated as a failed discovery or
user-triggered fetch, because the operator says the token honors robots.txt
and the token is how shopping or live retrieval is controlled.

`signal` means a disallow is reported, but it does not fail the check by
itself: it is a training opt-out, an ads crawler, or a user-triggered fetcher
whose operator says robots.txt may not apply.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentToken:
    token: str
    operator: str
    role: str
    effect: str
    robots: str
    source: str


TOKENS: tuple[AgentToken, ...] = (
    AgentToken(
        token="Storebot-Google",
        operator="Google",
        role="Crawls product, cart, and checkout pages for Google Shopping surfaces.",
        effect="blocks",
        robots="Honors the Storebot-Google robots.txt token. Preferences affect all Google Shopping surfaces.",
        source="https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers",
    ),
    AgentToken(
        token="Google-Agent",
        operator="Google",
        role="Agents on Google infrastructure that navigate and act on a user request.",
        effect="signal",
        robots="Google lists it with user-triggered fetchers, which generally ignore robots.txt because a user requested the fetch.",
        source="https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers",
    ),
    AgentToken(
        token="Google-Extended",
        operator="Google",
        role="Control token for Gemini training and grounding. It has no separate request user-agent.",
        effect="signal",
        robots="A robots.txt token only. Disallowing it is a training and grounding opt-out, not a fetch block.",
        source="https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers",
    ),
    AgentToken(
        token="OAI-SearchBot",
        operator="OpenAI",
        role="Indexes pages for ChatGPT search answers.",
        effect="blocks",
        robots="OpenAI tells sites to allow OAI-SearchBot in robots.txt to appear in search results. Opting out removes the site from ChatGPT search answers.",
        source="https://developers.openai.com/api/docs/bots",
    ),
    AgentToken(
        token="GPTBot",
        operator="OpenAI",
        role="Crawls content that may train OpenAI foundation models.",
        effect="signal",
        robots="Disallowing GPTBot is a training opt-out. It is independent of OAI-SearchBot and is not the user-triggered fetcher.",
        source="https://developers.openai.com/api/docs/bots",
    ),
    AgentToken(
        token="ChatGPT-User",
        operator="OpenAI",
        role="Fetches a page when a person uses ChatGPT or a custom GPT.",
        effect="signal",
        robots="OpenAI says robots.txt rules may not apply because a user initiated the fetch. It does not control Search inclusion.",
        source="https://developers.openai.com/api/docs/bots",
    ),
    AgentToken(
        token="OAI-AdsBot",
        operator="OpenAI",
        role="Visits landing pages submitted as ChatGPT ads. Not used for foundation-model training.",
        effect="signal",
        robots="Only visits pages submitted as ads. A disallow is not a catalog-discovery failure.",
        source="https://developers.openai.com/api/docs/bots",
    ),
    AgentToken(
        token="ClaudeBot",
        operator="Anthropic",
        role="Collects web content that may contribute to model training.",
        effect="signal",
        robots="Anthropic says its bots honor robots.txt. Disallowing ClaudeBot is the training opt-out.",
        source="https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler",
    ),
    AgentToken(
        token="Claude-SearchBot",
        operator="Anthropic",
        role="Indexes pages to improve Claude search results.",
        effect="blocks",
        robots="Anthropic says Claude-SearchBot honors robots.txt. Disabling it keeps the site out of that search index.",
        source="https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler",
    ),
    AgentToken(
        token="Claude-User",
        operator="Anthropic",
        role="Retrieves a page when a person asks Claude a question.",
        effect="blocks",
        robots="Anthropic says Claude-User honors robots.txt, including for user-initiated retrieval.",
        source="https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler",
    ),
    AgentToken(
        token="PerplexityBot",
        operator="Perplexity",
        role="Surfaces and links sites in Perplexity search results. Not the training crawler.",
        effect="blocks",
        robots="Perplexity documents PerplexityBot as the robots.txt token for search inclusion.",
        source="https://docs.perplexity.ai/docs/resources/perplexity-crawlers",
    ),
    AgentToken(
        token="Perplexity-User",
        operator="Perplexity",
        role="Fetches a page when a person asks Perplexity a question.",
        effect="signal",
        robots="Perplexity says this fetcher generally ignores robots.txt because a user requested the fetch.",
        source="https://docs.perplexity.ai/docs/resources/perplexity-crawlers",
    ),
)

# Tokens the fixture stores treat as an agent identity at the HTTP layer.
AGENT_TOKENS = tuple(item.token for item in TOKENS if item.token != "Google-Extended")
