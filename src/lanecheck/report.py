"""Terminal, JSON, and Markdown reports."""

from __future__ import annotations

import json
from typing import Any

from lanecheck.model import DISCLAIMER

_LABEL = {"pass": "PASS", "fail": "FAIL", "warn": "WARN"}


def render_text(report: dict[str, Any]) -> str:
    counts = report["summary"]
    lines = [
        f"lanecheck {report['version']}",
        f"Target: {report['target']}",
        "",
        DISCLAIMER,
        "",
    ]
    for check in report["checks"]:
        lines.append(f"[{_LABEL[check['status']]}] {check['id']} — {check['summary']}")
        for item in check.get("evidence", []):
            lines.append(f"       {item.get('summary', '')}")
        if check.get("fix") and check["status"] != "pass":
            lines.append(f"       fix: {check['fix']}")
    lines.extend(
        [
            "",
            f"{counts['pass']} pass, {counts['fail']} fail, {counts['warn']} warn",
            f"{len(report['requests'])} HTTP requests on {report['target']}. Payment endpoints called: 0.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_markdown(report: dict[str, Any]) -> str:
    counts = report["summary"]
    lines = [
        f"# lanecheck report",
        "",
        f"- Target: `{report['target']}`",
        f"- Generated: {report['generated_at']}",
        f"- Result: {counts['pass']} pass, {counts['fail']} fail, {counts['warn']} warn",
        "",
        f"> {DISCLAIMER}",
        "",
        "## Checks",
        "",
    ]
    for check in report["checks"]:
        lines.append(f"### {_LABEL[check['status']]} {check['title']}")
        lines.append("")
        lines.append(check["summary"])
        lines.append("")
        for item in check.get("evidence", []):
            lines.append(f"- {item.get('summary', '')}")
            data = item.get("data")
            if data:
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(data, indent=2, sort_keys=True)[:4000])
                lines.append("```")
                lines.append("")
        if check.get("fix") and check["status"] != "pass":
            lines.append(f"Fix: {check['fix']}")
            lines.append("")
    lines.append("## Requests")
    lines.append("")
    lines.append("| Method | Status | URL |")
    lines.append("| --- | --- | --- |")
    for call in report["requests"]:
        lines.append(f"| {call['method']} | {call['status']} | `{call['url']}` |")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    for item in report["limitations"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"
