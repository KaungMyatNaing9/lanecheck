"""Command line for lanecheck."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from lanecheck import __version__
from lanecheck.model import DISCLAIMER
from lanecheck.report import render_json, render_markdown, render_text
from lanecheck.runner import run_probe
from lanecheck.safety import SafetyError


def main(argv: list[str] | None = None) -> int:
    args_in = list(sys.argv[1:] if argv is None else argv)
    if args_in and args_in[0] == "scan":
        return scan_cli(args_in[1:])
    parser = argparse.ArgumentParser(
        prog="lanecheck",
        description="Probe a store you own. Finds whether an agent can reach a checkout session. Never pays.",
    )
    parser.add_argument("target", nargs="?", help="http(s) origin to probe. Loopback is allowed. Anything else needs --i-own-this.")
    parser.add_argument("--i-own-this", action="store_true", help="Confirm you own or are authorized to test a non-loopback origin.")
    parser.add_argument("--json", dest="json_path", help="Write the JSON report to this path.")
    parser.add_argument("--markdown", dest="markdown_path", help="Write the Markdown report to this path.")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Stdout format. Files are written either way.")
    parser.add_argument("--demo", choices=["friendly", "blocked", "shoddy"], help="Probe a built-in localhost fixture instead of a target.")
    parser.add_argument("--acp-token", help="Optional staging bearer token for ACP. Never required by the fixtures.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds.")
    parser.add_argument("--version", action="version", version=f"lanecheck {__version__}")
    args = parser.parse_args(args_in)
    print(DISCLAIMER, file=sys.stderr)
    if args.demo and args.target:
        print("Pass either a target or --demo, not both.", file=sys.stderr)
        return 2
    if not args.demo and not args.target:
        print("Pass a target URL, or --demo friendly|blocked|shoddy.", file=sys.stderr)
        return 2

    server = None
    target = args.target
    try:
        if args.demo:
            server, target = _start_demo(args.demo)
        report = run_probe(
            target,
            i_own_this=args.i_own_this,
            acp_token=args.acp_token,
            timeout=args.timeout,
        )
    except SafetyError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        if server is not None:
            server.close()

    if args.json_path:
        Path(args.json_path).write_text(render_json(report), encoding="utf-8")
    if args.markdown_path:
        Path(args.markdown_path).write_text(render_markdown(report), encoding="utf-8")
    sys.stdout.write(render_json(report) if args.format == "json" else render_text(report))
    return 1 if report["summary"]["fail"] else 0


def scan_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lanecheck scan",
        description="Read public pages only. Does not create carts or checkout sessions.",
    )
    parser.add_argument("--readonly", action="store_true", help="Required. Limits the scan to GET of public pages.")
    parser.add_argument("--input", required=True, help="CSV of origins to scan.")
    parser.add_argument("--out", default="data/scan", help="Directory for results.json and results.csv.")
    parser.add_argument("--delay", type=float, default=2.0, help="Seconds between requests to one host. Public scans require at least 2.")
    parser.add_argument("--timeout", type=float, default=12.0)
    args = parser.parse_args(argv)
    if not args.readonly:
        print("Refusing to scan without --readonly.", file=sys.stderr)
        return 2
    from lanecheck.readonly import load_store_csv, scan_rows, write_results

    rows = load_store_csv(Path(args.input))
    results = []
    out = Path(args.out)
    try:
        for index, row in enumerate(rows, start=1):
            print(f"[{index}/{len(rows)}] {row.get('origin', '')}", file=sys.stderr, flush=True)
            try:
                results.extend(scan_rows([row], delay=args.delay, timeout=args.timeout))
            except Exception as exc:
                print(f"  error {exc}", file=sys.stderr, flush=True)
                results.append(
                    {
                        "origin": row.get("origin", ""),
                        "listed_platform": row.get("listed_platform", ""),
                        "source_name": row.get("source_name", ""),
                        "source_url": row.get("source_url", ""),
                        "platform_basis": row.get("platform_basis", ""),
                        "observed_platform": "",
                        "platform_signals": [],
                        "reachability": "unreachable",
                        "blocked_reason": f"scanner error: {exc}",
                        "robots": {},
                        "ucp": {"state": "not_fetched"},
                        "acp": {"state": "not_fetched"},
                        "products": {"state": "not_fetched", "pages": [], "fields": {}},
                        "fixable_gaps": [],
                        "requests": [],
                    }
                )
            write_results(results, out)
    except SafetyError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    blocked = sum(1 for row in results if row["reachability"] == "blocked")
    gaps = sum(1 for row in results if row["fixable_gaps"])
    print(
        f"Scanned {len(results)} origins. blocked={blocked} fixable_gap={gaps}. Wrote {args.out}",
        file=sys.stderr,
    )
    return 0


def _start_demo(mode: str):
    try:
        from fixtures.store import FixtureServer
    except ImportError as exc:
        raise SafetyError(
            "The demo fixtures are not importable. Run lanecheck from the repository root."
        ) from exc
    server = FixtureServer(mode)
    print(f"Demo fixture ({mode}) at {server.url}", file=sys.stderr)
    return server, server.url
