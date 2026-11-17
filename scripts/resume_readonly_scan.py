"""Continue a read-only scan from the rows not yet in results.json."""

from __future__ import annotations

import csv
import sys
import traceback
from pathlib import Path

from lanecheck.readonly import load_store_csv, scan_origin, write_results


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    out = root / "data/scan"
    stores = load_store_csv(out / "stores.csv")
    import json

    existing = json.loads((out / "results.json").read_text(encoding="utf-8"))
    done = {row["origin"] for row in existing}
    pending = [row for row in stores if row["origin"] not in done]
    print(f"resuming {len(pending)} of {len(stores)}", flush=True)
    for index, row in enumerate(pending, start=1):
        print(f"[{len(existing)+1}/{len(stores)}] {row['origin']}", flush=True)
        try:
            result = scan_origin(
                row["origin"],
                listed_platform=row.get("listed_platform", ""),
                source_name=row.get("source_name", ""),
                source_url=row.get("source_url", ""),
                platform_basis=row.get("platform_basis", ""),
                delay=2.0,
                timeout=12.0,
            )
        except Exception as exc:
            traceback.print_exc()
            result = {
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
        existing.append(result)
        write_results(existing, out)
        print(f"  {result['reachability']} gaps={len(result.get('fixable_gaps') or [])}", flush=True)
    print("DONE", len(existing), flush=True)
    return 0 if len(existing) == len(stores) else 1


if __name__ == "__main__":
    sys.exit(main())
