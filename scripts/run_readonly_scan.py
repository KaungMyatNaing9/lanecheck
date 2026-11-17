"""Collect 100 non-Shopify results from the read-only scanner.

Shopify hosts are fetched once, then left out of stores.csv and results.
The script is the batch driver for `scan_origin`, the same function
`lanecheck scan --readonly` calls.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

from lanecheck.readonly import scan_origin, write_results

FIELDS = ["origin", "listed_platform", "source_name", "source_url", "platform_basis"]


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    rows = list(csv.DictReader((root / "data/scan/candidates.csv").open(encoding="utf-8")))
    kept: list[dict] = []
    dropped: list[str] = []
    out = root / "data/scan"
    considered = 0
    for index, row in enumerate(rows, start=1):
        if len(kept) >= 100:
            break
        considered = index
        print(f"[{index}] kept={len(kept)} {row['origin']}", flush=True)
        result = scan_origin(
            row["origin"],
            listed_platform=row["listed_platform"],
            source_name=row["source_name"],
            source_url=row["source_url"],
            platform_basis=row["platform_basis"],
            delay=2.0,
            timeout=10.0,
        )
        if result.get("observed_platform") == "Shopify":
            dropped.append(result["origin"])
            print("  drop shopify", flush=True)
            (out / "dropped-shopify.txt").write_text("\n".join(dropped) + "\n", encoding="utf-8")
            continue
        kept.append(result)
        write_results(kept, out)
        with (out / "stores.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            for item in kept:
                writer.writerow({key: item.get(key, "") for key in FIELDS})
        print(
            f"  {result['reachability']} {result.get('observed_platform') or '-'} "
            f"gaps={len(result.get('fixable_gaps') or [])}",
            flush=True,
        )
    summary = {"kept": len(kept), "dropped_shopify": dropped, "candidates_considered": considered}
    (out / "run-meta.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("DONE", summary["kept"], "dropped", len(dropped), flush=True)


if __name__ == "__main__":
    sys.exit(main())
